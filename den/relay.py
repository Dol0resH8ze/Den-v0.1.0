"""A bounded, memory-only relay. Only encrypted payloads cross this service.

Run behind a Tor onion service which forwards to the loopback listener. The
relay authenticates device keys and room membership, but it cannot decrypt
nicknames or chat text. It necessarily sees room membership and traffic timing.
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass, field
import ipaddress
import json
import re
import secrets
import time
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .crypto import validate_box_key
from .transport import STREAM_LIMIT, read_frame, write_frame

MAX_ROOMS = 128
MAX_SESSIONS = 256
MAX_ROOM_SESSIONS = 32
MAX_MEMBERS = 16
MAX_CIPHERTEXT = 16 * 1024
MAX_SUBMIT_CIPHERTEXT = 384 * 1024
MAX_QUEUED_FRAMES = 32
MAX_QUEUED_BYTES = 1024 * 1024
HANDSHAKE_TIMEOUT = 15.0
WRITE_TIMEOUT = 5.0
MAX_SEQUENCE = (1 << 53) - 1
_ROOM_ID = re.compile(r"[0-9a-f]{64}\Z")
_B64 = re.compile(r"[A-Za-z0-9_-]*\Z")


class ProtocolError(ValueError):
    """A peer sent an invalid or unauthorized protocol frame."""


def _fields(value: Any, expected: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProtocolError("Invalid request.")
    return value


def _b64(value: Any, length: int | None = None, *, maximum: int = MAX_CIPHERTEXT) -> bytes:
    if not isinstance(value, str) or len(value) > (maximum * 4 + 2) // 3:
        raise ProtocolError("Invalid encoded data.")
    if not _B64.fullmatch(value):
        raise ProtocolError("Invalid encoded data.")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ProtocolError("Invalid encoded data.") from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ProtocolError("Invalid encoded data.")
    if len(decoded) > maximum or (length is not None and len(decoded) != length):
        raise ProtocolError("Invalid encoded data.")
    return decoded


def _sealed(value: Any, *, maximum: int = MAX_CIPHERTEXT) -> None:
    if len(_b64(value, maximum=maximum)) < 48:
        raise ProtocolError("Invalid encrypted payload.")


def _verify(body: dict, signature: Any, sign_key: str) -> None:
    try:
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        VerifyKey(_b64(sign_key, 32)).verify(b"HUSH/1\x00" + encoded, _b64(signature, 64))
    except (BadSignatureError, ValueError, TypeError, OverflowError) as exc:
        raise ProtocolError("Invalid signature.") from exc


@dataclass(eq=False)
class _Session:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(MAX_QUEUED_FRAMES))
    room: _Room | None = None
    sign_key: str = ""
    box_key: str = ""
    closing: bool = False
    last_sequence: int = 0
    tokens: float = 40.0
    token_time: float = field(default_factory=time.monotonic)
    output_task: asyncio.Task | None = None
    queued_bytes: int = 0

    def send(self, frame: dict) -> None:
        if self.closing:
            return
        try:
            size = len(json.dumps(frame, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
            if self.queued_bytes + size > MAX_QUEUED_BYTES:
                raise asyncio.QueueFull
            self.queue.put_nowait((frame, size))
            self.queued_bytes += size
        except asyncio.QueueFull:
            self.closing = True
            self.writer.close()
            if self.output_task is not None:
                self.output_task.cancel()

    def finish(self, frame: dict | None = None) -> None:
        if self.closing:
            return
        if frame is not None:
            self.send(frame)
        if self.closing:
            return
        self.closing = True
        try:
            self.queue.put_nowait(None)
        except asyncio.QueueFull:
            self.writer.close()
            if self.output_task is not None:
                self.output_task.cancel()

    def rate_limit(self) -> None:
        now = time.monotonic()
        self.tokens = min(40.0, self.tokens + (now - self.token_time) * 20.0)
        self.token_time = now
        if self.tokens < 1.0:
            raise ProtocolError("Sending too quickly.")
        self.tokens -= 1.0


@dataclass
class _Room:
    room_id: str
    owner: str
    connections: dict[str, _Session] = field(default_factory=dict)
    members: dict[str, str] = field(default_factory=dict)
    revision: int = 0
    locked: bool = False
    roster: dict | None = None
    released_sequences: dict[str, int] = field(default_factory=dict)


class Relay:
    """Loopback-only relay with no disk persistence or message/access logging."""

    def __init__(self) -> None:
        self.server: asyncio.Server | None = None
        self.rooms: dict[str, _Room] = {}
        self._sessions: set[_Session] = set()
        self._tasks: set[asyncio.Task] = set()
        self._stopping = False

    @property
    def address(self) -> tuple:
        if self.server is None or not self.server.sockets:
            raise RuntimeError("Relay is not listening.")
        return self.server.sockets[0].getsockname()

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> asyncio.Server:
        try:
            loopback = isinstance(host, str) and "%" not in host and ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ValueError("Relay must bind to a numeric loopback address.")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Relay port must be between 0 and 65535.")
        if self.server is not None:
            raise RuntimeError("Relay is already started.")
        self._stopping = False
        self.server = await asyncio.start_server(self._accept, host, port, limit=STREAM_LIMIT)
        return self.server

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._stopping or len(self._sessions) >= MAX_SESSIONS:
            writer.close()
            return
        session = _Session(reader, writer)
        self._sessions.add(session)
        task = asyncio.create_task(self._handle(session))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _output(self, session: _Session) -> None:
        try:
            while True:
                item = await session.queue.get()
                if item is None:
                    break
                frame, size = item
                session.queued_bytes -= size
                await asyncio.wait_for(write_frame(session.writer, frame), WRITE_TIMEOUT)
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            session.closing = True
            session.writer.close()
            try:
                await asyncio.wait_for(session.writer.wait_closed(), WRITE_TIMEOUT)
            except (Exception, asyncio.CancelledError):
                pass

    async def _handle(self, session: _Session) -> None:
        session.output_task = asyncio.create_task(self._output(session))
        try:
            async with asyncio.timeout(HANDSHAKE_TIMEOUT):
                await self._handshake(session)
            while not session.closing:
                frame = await read_frame(session.reader)
                session.rate_limit()
                self._dispatch(session, frame)
                # Buffered malicious peers must yield to other connections.
                await asyncio.sleep(0)
        except ProtocolError as exc:
            session.finish({"type": "error", "reason": str(exc)})
        except TimeoutError:
            session.finish({"type": "error", "reason": "Handshake timed out."})
        except asyncio.CancelledError:
            session.finish()
            raise
        except (EOFError, ConnectionError, asyncio.IncompleteReadError):
            session.finish()
        except Exception:
            # Parsing errors never echo untrusted input or identifiers into logs.
            session.finish({"type": "error", "reason": "Invalid request."})
        finally:
            self._depart(session)
            session.finish()
            if session.output_task is not None:
                await asyncio.gather(session.output_task, return_exceptions=True)
            self._sessions.discard(session)

    async def _handshake(self, session: _Session) -> None:
        hello = _fields(await read_frame(session.reader), {"type", "room", "sign_key", "box_key", "create"})
        if hello["type"] != "hello" or type(hello["create"]) is not bool:
            raise ProtocolError("Invalid greeting.")
        room_id = hello["room"]
        if not isinstance(room_id, str) or not _ROOM_ID.fullmatch(room_id):
            raise ProtocolError("Invalid room.")
        _b64(hello["sign_key"], 32)
        _b64(hello["box_key"], 32)
        try:
            validate_box_key(hello["box_key"])
        except ValueError as exc:
            raise ProtocolError("Invalid encryption key.") from exc
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        session.send({"type": "challenge", "challenge": challenge})
        proof = _fields(await read_frame(session.reader), {"type", "body", "signature"})
        body = _fields(proof["body"], {"kind", "room", "challenge", "sign_key", "box_key"})
        expected = {"kind": "proof", "room": room_id, "challenge": challenge, "sign_key": hello["sign_key"], "box_key": hello["box_key"]}
        if proof["type"] != "proof" or body != expected:
            raise ProtocolError("Invalid identity proof.")
        _verify(body, proof["signature"], hello["sign_key"])
        if hello["create"]:
            if room_id in self.rooms:
                raise ProtocolError("Room already exists.")
            if len(self.rooms) >= MAX_ROOMS:
                raise ProtocolError("Relay room capacity reached.")
            room = _Room(room_id, hello["sign_key"])
            self.rooms[room_id] = room
        else:
            room = self.rooms.get(room_id)
            if room is None or room.owner not in room.connections or room.connections[room.owner].closing:
                raise ProtocolError("Room is unavailable.")
            if room.locked:
                raise ProtocolError("Room is locked.")
            if len(room.connections) >= MAX_ROOM_SESSIONS:
                raise ProtocolError("Room connection capacity reached.")
            if hello["sign_key"] in room.connections or hello["sign_key"] in room.members:
                raise ProtocolError("Identity is already present.")
            if any(peer.box_key == hello["box_key"] for peer in room.connections.values()):
                raise ProtocolError("Encryption key is already present.")
        session.sign_key, session.box_key = hello["sign_key"], hello["box_key"]
        session.room = room
        room.connections[session.sign_key] = session
        session.send({"type": "ready", "owner": room.owner})
        if room.roster is not None:
            session.send(room.roster)

    def _dispatch(self, session: _Session, frame: Any) -> None:
        if not isinstance(frame, dict) or not isinstance(frame.get("type"), str):
            raise ProtocolError("Invalid request.")
        room = session.room
        if room is None or self.rooms.get(room.room_id) is not room:
            raise ProtocolError("Room is unavailable.")
        match frame["type"]:
            case "roster":
                self._roster(session, room, frame)
            case "join_request":
                _fields(frame, {"type", "ciphertext"})
                if session.sign_key == room.owner or session.sign_key in room.members or room.locked:
                    raise ProtocolError("Join request is not allowed.")
                _sealed(frame["ciphertext"])
                owner = room.connections.get(room.owner)
                if owner is None or owner.closing:
                    raise ProtocolError("Room is unavailable.")
                owner.send({"type": "join_request", "sender": session.sign_key, "box_key": session.box_key, "ciphertext": frame["ciphertext"]})
            case "reject":
                _fields(frame, {"type", "target"})
                if session.sign_key != room.owner:
                    raise ProtocolError("Only the owner can reject a join request.")
                target = frame["target"]
                _b64(target, 32)
                peer = room.connections.get(target)
                if target == room.owner or target in room.members:
                    raise ProtocolError("Target is not pending approval.")
                if peer is not None:
                    peer.finish({"type": "closed", "reason": "Join request rejected."})
            case "submit":
                self._submit(session, room, frame)
            case "release":
                self._release(session, room, frame)
            case _:
                raise ProtocolError("Unknown request.")

    def _roster(self, session: _Session, room: _Room, frame: dict) -> None:
        _fields(frame, {"type", "body", "signature"})
        if session.sign_key != room.owner:
            raise ProtocolError("Only the owner can change membership.")
        body = _fields(frame["body"], {"kind", "room", "revision", "locked", "members", "details"})
        if body["kind"] != "roster" or body["room"] != room.room_id:
            raise ProtocolError("Invalid roster.")
        if type(body["revision"]) is not int or body["revision"] != room.revision + 1 or body["revision"] > MAX_SEQUENCE:
            raise ProtocolError("Invalid roster revision.")
        if type(body["locked"]) is not bool:
            raise ProtocolError("Invalid lock state.")
        if not isinstance(body["members"], list) or not 1 <= len(body["members"]) <= MAX_MEMBERS:
            raise ProtocolError("Invalid member count.")
        members: dict[str, str] = {}
        encryption_keys: set[str] = set()
        for entry in body["members"]:
            _fields(entry, {"sign_key", "box_key"})
            signing, encryption = entry["sign_key"], entry["box_key"]
            _b64(signing, 32)
            _b64(encryption, 32)
            peer = room.connections.get(signing)
            was_approved = room.members.get(signing) == encryption
            connected_key = peer is not None and not peer.closing and peer.box_key == encryption
            if signing in members or encryption in encryption_keys or not (was_approved or connected_key):
                raise ProtocolError("Invalid roster member.")
            members[signing] = encryption
            encryption_keys.add(encryption)
        if room.owner not in members:
            raise ProtocolError("The owner must remain a member.")
        if not isinstance(body["details"], dict) or set(body["details"]) != set(members):
            raise ProtocolError("Invalid roster recipients.")
        for ciphertext in body["details"].values():
            _sealed(ciphertext)
        _verify(body, frame["signature"], room.owner)
        previous_members = set(room.members)
        room.members = members
        room.revision = body["revision"]
        room.locked = body["locked"]
        room.roster = frame
        room.released_sequences = {key: sequence for key, sequence in room.released_sequences.items() if key in members}
        for key, peer in tuple(room.connections.items()):
            peer.send(frame)
            if key in previous_members and key not in members:
                peer.finish({"type": "closed", "reason": "Removed from room."})
            elif room.locked and key not in members:
                peer.finish({"type": "closed", "reason": "Room is locked."})

    def _submit(self, session: _Session, room: _Room, frame: dict) -> None:
        _fields(frame, {"type", "body", "signature"})
        body = _fields(frame["body"], {"kind", "room", "revision", "sender", "sequence", "ciphertext"})
        if session.sign_key == room.owner or session.sign_key not in room.members:
            raise ProtocolError("Approved non-owner membership is required.")
        if body["kind"] != "submit" or body["room"] != room.room_id or body["sender"] != session.sign_key:
            raise ProtocolError("Invalid submission sender.")
        if type(body["revision"]) is not int:
            raise ProtocolError("Invalid submission revision.")
        sequence = body["sequence"]
        if type(sequence) is not int or not session.last_sequence < sequence <= MAX_SEQUENCE:
            raise ProtocolError("Invalid message sequence.")
        _sealed(body["ciphertext"], maximum=MAX_SUBMIT_CIPHERTEXT)
        _verify(body, frame["signature"], session.sign_key)
        if body["revision"] != room.revision:
            session.send({"type": "notice", "code": "stale_message"})
            return
        owner = room.connections.get(room.owner)
        if owner is None or owner.closing:
            raise ProtocolError("Room is unavailable.")
        session.last_sequence = sequence
        owner.send(frame)

    def _release(self, session: _Session, room: _Room, frame: dict) -> None:
        _fields(frame, {"type", "body", "signature"})
        if session.sign_key != room.owner:
            raise ProtocolError("Only the owner can release messages.")
        body = _fields(frame["body"], {"kind", "room", "revision", "packet"})
        if body["kind"] != "release" or body["room"] != room.room_id or type(body["revision"]) is not int:
            raise ProtocolError("Invalid release.")
        _verify(body, frame["signature"], room.owner)
        if body["revision"] != room.revision:
            session.send({"type": "notice", "code": "stale_message"})
            return
        sender, sequence = self._message(room, body["packet"])
        room.released_sequences[sender] = sequence
        for key in room.members:
            if key != sender and (peer := room.connections.get(key)) is not None:
                peer.send(frame)

    def _message(self, room: _Room, frame: dict) -> tuple[str, int]:
        _fields(frame, {"type", "body", "signature"})
        body = _fields(frame["body"], {"kind", "room", "revision", "sender", "sequence", "boxes"})
        sender = body["sender"]
        if not isinstance(sender, str) or sender not in room.members:
            raise ProtocolError("Membership approval is required.")
        if frame["type"] != "message" or body["kind"] != "message" or body["room"] != room.room_id:
            raise ProtocolError("Invalid message sender.")
        if type(body["revision"]) is not int or body["revision"] != room.revision:
            raise ProtocolError("Message uses an outdated roster.")
        sequence = body["sequence"]
        if type(sequence) is not int or not room.released_sequences.get(sender, 0) < sequence <= MAX_SEQUENCE:
            raise ProtocolError("Invalid message sequence.")
        boxes = body["boxes"]
        if not isinstance(boxes, dict) or set(boxes) != set(room.members) - {sender}:
            raise ProtocolError("Invalid message recipients.")
        for ciphertext in boxes.values():
            _sealed(ciphertext)
        _verify(body, frame["signature"], sender)
        return sender, sequence

    def _depart(self, session: _Session) -> None:
        room = session.room
        if room is None or room.connections.get(session.sign_key) is not session:
            return
        room.connections.pop(session.sign_key, None)
        if session.sign_key == room.owner:
            self.rooms.pop(room.room_id, None)
            for peer in tuple(room.connections.values()):
                peer.finish({"type": "closed", "reason": "Room owner disconnected."})
            room.connections.clear()
            room.members.clear()
            room.roster = None
        else:
            owner = room.connections.get(room.owner)
            if owner is not None:
                owner.send({"type": "departed", "sender": session.sign_key})
        session.room = None

    async def close(self) -> None:
        self._stopping = True
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        for session in tuple(self._sessions):
            session.finish({"type": "closed", "reason": "Relay stopped."})
        tasks = tuple(self._tasks)
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=WRITE_TIMEOUT + 1)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        self.rooms.clear()
        self.server = None


async def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    relay = Relay()
    await relay.start(host, port)
    print(f"Den relay listening on {host}:{relay.address[1]} (loopback only).")
    print("Memory only; no chat or access logs. Connect through a Tor onion service.")
    try:
        assert relay.server is not None
        await relay.server.serve_forever()
    finally:
        await relay.close()
