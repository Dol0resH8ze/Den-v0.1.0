"""Live room client. UI-independent so multi-device flows can be tested."""

import asyncio
import contextlib
import hmac

from .crypto import (Identity, Invite, MAX_MEMBERS, check_roster, decrypt_message,
                     encrypt_message, fingerprint, make_roster, seal, username, verify,
                     make_submit, open_submit, make_release, open_release, validate_box_key)
from .transport import open_connection, read_frame, validate_endpoint, write_frame


class RoomClient:
    def __init__(self, name, invite, identity, *, owner=False):
        self.name = username(name)
        self.invite = invite
        self.identity = identity
        self.is_owner = owner
        self.members = {}
        self.names = {}
        self.pending = {}
        self.revision = 0
        self.locked = False
        self.admitted = False
        self.sequence = 0
        self.seen = {}
        self.events = asyncio.Queue(maxsize=256)
        self.closed = asyncio.Event()
        self.reader = self.writer = self.receiver = None
        self.last_roster = None
        self._mutation = asyncio.Lock()

    @classmethod
    async def create(cls, name, host, port, **network):
        validate_endpoint(host, port, local_test=network.get("local_test", False))
        identity = Identity()
        invite = Invite.create(host, port, identity)
        client = cls(name, invite, identity, owner=True)
        await client._connect(create=True, **network)
        try:
            await client._publish({identity.sign_key: identity.member()}, {identity.sign_key: client.name})
        except BaseException:
            await client.close()
            raise
        return client

    @classmethod
    async def join(cls, name, invite_code, **network):
        invite = Invite.parse(invite_code, local_test=network.get("local_test", False))
        client = cls(name, invite, Identity())
        await client._connect(create=False, **network)
        try:
            body = {"kind": "join", "room": invite.room, "name": client.name,
                    **client.identity.member(), "invite_secret": invite.secret}
            await client._send({"type": "join_request", "ciphertext": seal(client.identity.sign(body), invite.owner_box)})
        except BaseException:
            await client.close()
            raise
        return client

    async def _connect(self, *, create, **network):
        try:
            self.reader, self.writer = await open_connection(self.invite.host, self.invite.port, **network)
            async with asyncio.timeout(20):
                await self._send({"type": "hello", "room": self.invite.room,
                                  **self.identity.member(), "create": create})
                challenge = await read_frame(self.reader)
                if challenge.get("type") != "challenge":
                    raise ConnectionError("Relay did not accept the connection.")
                from .crypto import b64d
                b64d(challenge.get("challenge"), 32)
                proof = {"kind": "proof", "room": self.invite.room,
                         "challenge": challenge["challenge"], **self.identity.member()}
                await self._send({"type": "proof", **self.identity.sign(proof)})
                ready = await read_frame(self.reader)
                if ready.get("type") != "ready" or ready.get("owner") != self.invite.owner:
                    raise ConnectionError("Room unavailable, locked, or owner key does not match the invite.")
            self.receiver = asyncio.create_task(self._receive())
        except BaseException:
            await self.close()
            raise

    def _emit(self, kind, **values):
        self.events.put_nowait({"type": kind, **values})

    async def _send(self, packet):
        if self.closed.is_set() or self.writer is None:
            raise ConnectionError("Disconnected from the room.")
        await write_frame(self.writer, packet)

    async def _publish(self, members, names, locked=None):
        if not self.is_owner:
            raise ValueError("Only the room owner can change membership.")
        lock_state = self.locked if locked is None else locked
        packet = make_roster(self.identity, self.invite, self.revision + 1, lock_state, members, names)
        # Apply synchronously before yielding so no new outgoing message uses old membership.
        self._apply_roster(packet)
        await self._send(packet)

    def _apply_roster(self, packet):
        body, members, names = check_roster(packet, self.invite, self.identity, self.revision)
        was_admitted = self.admitted
        self.revision = body["revision"]
        self.locked = body["locked"]
        self.members, self.names = members, names
        self.last_roster = packet
        self.admitted = self.identity.sign_key in members
        self._emit("roster", admitted=self.admitted, count=len(members), locked=self.locked)
        if was_admitted and not self.admitted:
            raise ConnectionError("You were removed from the room.")

    async def _receive(self):
        reason = "Room connection closed."
        try:
            while not self.closed.is_set():
                packet = await read_frame(self.reader)
                kind = packet.get("type")
                if kind == "roster":
                    if packet == self.last_roster:
                        continue  # The relay echoes the owner's own accepted roster.
                    if self.is_owner:
                        body = verify(packet, self.invite.owner)
                        if type(body.get("revision")) is int and body["revision"] <= self.revision:
                            continue  # An earlier owner update may still be in flight.
                    self._apply_roster(packet)
                elif kind == "submit" and self.is_owner:
                    async with self._mutation:
                        try:
                            inner = open_submit(packet, self.identity, self.invite, self.revision, self.members)
                            sender, text = decrypt_message(inner, self.identity, self.invite, self.revision, self.members, self.seen)
                        except ValueError:
                            self._emit("notice", text="Dropped an invalid or outdated message submission.")
                            continue
                        await self._send(make_release(self.identity, self.invite, inner))
                        self._emit("chat", name=self.names[sender], fingerprint=fingerprint(sender), text=text)
                elif kind == "release":
                    if self.is_owner:
                        continue  # Only this device can sign releases; already processed locally.
                    if not self.admitted:
                        raise ValueError("Message before admission.")
                    # Old revision traffic queued before a membership update cannot be rendered.
                    if type(packet.get("body", {}).get("revision")) is int and packet["body"]["revision"] < self.revision:
                        continue
                    inner = open_release(packet, self.invite, self.revision)
                    sender, text = decrypt_message(inner, self.identity, self.invite, self.revision, self.members, self.seen)
                    self._emit("chat", name=self.names[sender], fingerprint=fingerprint(sender), text=text)
                elif kind == "notice":
                    self._emit("notice", text="Membership changed while sending. Check /members and send again.")
                elif kind == "join_request" and self.is_owner:
                    await self._join_request(packet)
                elif kind == "departed" and self.is_owner:
                    key = packet.get("sender")
                    async with self._mutation:
                        self.pending.pop(key, None)
                        if key in self.members and key != self.identity.sign_key:
                            name = self.names[key]
                            await self._publish({k: m for k, m in self.members.items() if k != key},
                                                {k: n for k, n in self.names.items() if k != key})
                            self._emit("notice", text=f"{name} left the room.")
                elif kind in ("closed", "error"):
                    # Do not render arbitrary relay-provided strings in the terminal.
                    reason = "Room closed, request rejected, or relay disconnected."
                    break
                else:
                    raise ValueError("Unexpected relay packet.")
        except asyncio.CancelledError:
            return
        except (ValueError, KeyError, TypeError, OverflowError, AttributeError, RecursionError):
            reason = "Invalid or unauthenticated room traffic; disconnected."
        except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            reason = "Room connection lost. No direct-network retry was attempted."
        except asyncio.QueueFull:
            reason = "Too much unread room traffic; disconnected."
        finally:
            self.closed.set()
            if self.writer is not None:
                self.writer.close()
            with contextlib.suppress(asyncio.QueueFull):
                self._emit("closed", text=reason)

    async def _join_request(self, packet):
        key = packet.get("sender")
        try:
            signed = self.identity.open(packet["ciphertext"])
            body = verify(signed, key)
            if (body.get("kind") != "join" or body.get("room") != self.invite.room
                    or body.get("sign_key") != key or body.get("box_key") != packet.get("box_key")
                    or not isinstance(body.get("invite_secret"), str)
                    or not hmac.compare_digest(body["invite_secret"], self.invite.secret)):
                raise ValueError("Invalid join proof.")
            from .crypto import b64d
            b64d(body["box_key"], 32)
            validate_box_key(body["box_key"])
            name = username(body.get("name"))
            names = list(self.names.values()) + [p["name"] for k, p in self.pending.items() if k != key]
            if (self.locked or key in self.members or len(self.pending) >= 32
                    or len(self.members) >= MAX_MEMBERS or name.casefold() in {n.casefold() for n in names}):
                raise ValueError("Name unavailable or room full.")
            self.pending[key] = {"name": name, "sign_key": key, "box_key": body["box_key"]}
            self._emit("join_request", name=name, fingerprint=fingerprint(key))
        except (ValueError, TypeError, KeyError):
            if isinstance(key, str):
                await self._send({"type": "reject", "target": key})

    def _find(self, selector, collection):
        matches = [key for key in collection if selector == key or
                   fingerprint(key).startswith(selector.lower()) or
                   selector.casefold() == (collection[key].get("name", "").casefold())]
        if len(matches) != 1:
            raise ValueError("Choose one username or unique device fingerprint from /pending or /members.")
        return matches[0]

    def _owner_only(self):
        if not self.is_owner:
            raise ValueError("Only the room owner can do that.")

    async def approve(self, selector):
        self._owner_only()
        async with self._mutation:
            if self.locked or len(self.members) >= MAX_MEMBERS:
                raise ValueError("Room is locked or full.")
            key = self._find(selector, self.pending)
            pending = self.pending.pop(key)
            await self._publish({**self.members, key: {"sign_key": key, "box_key": pending["box_key"]}},
                                {**self.names, key: pending["name"]})

    async def reject(self, selector):
        self._owner_only()
        async with self._mutation:
            key = self._find(selector, self.pending)
            self.pending.pop(key)
            await self._send({"type": "reject", "target": key})

    async def kick(self, selector):
        self._owner_only()
        async with self._mutation:
            key = self._find(selector, {k: {"name": n} for k, n in self.names.items()})
            if key == self.identity.sign_key:
                raise ValueError("Use /quit to close your room.")
            await self._publish({k: m for k, m in self.members.items() if k != key},
                                {k: n for k, n in self.names.items() if k != key})

    async def set_locked(self, locked):
        self._owner_only()
        async with self._mutation:
            await self._publish(self.members, self.names, locked=locked)
            if locked:
                self.pending.clear()

    async def send_text(self, text):
        async with self._mutation:
            if not self.admitted:
                raise ValueError("Wait for the room owner to approve your device.")
            if len(self.members) < 2:
                raise ValueError("You are the only participant. Invite someone first.")
            self.sequence += 1
            packet = encrypt_message(self.identity, self.invite, self.revision,
                                     self.sequence, self.members, text)
            await self._send(make_release(self.identity, self.invite, packet) if self.is_owner
                             else make_submit(self.identity, self.invite, packet))

    async def close(self):
        self.closed.set()
        if self.receiver is not None and self.receiver is not asyncio.current_task():
            self.receiver.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.receiver
        if self.writer is not None:
            self.writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(self.writer.wait_closed(), 2)
