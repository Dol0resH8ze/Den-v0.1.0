"""Real loopback clients exercise relay authentication and room boundaries."""

import asyncio
import base64
from dataclasses import dataclass
import json
import secrets

from nacl.public import PrivateKey, SealedBox
from nacl.signing import SigningKey
import pytest

from den import relay as module
from den.relay import Relay
from den.transport import STREAM_LIMIT, read_frame, write_frame


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass
class Peer:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    signing: SigningKey
    encryption: PrivateKey

    @property
    def key(self):
        return b64(bytes(self.signing.verify_key))

    @property
    def box(self):
        return b64(bytes(self.encryption.public_key))

    def member(self):
        return {"sign_key": self.key, "box_key": self.box}

    def signed(self, kind, body):
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        return {"type": kind, "body": body, "signature": b64(self.signing.sign(b"HUSH/1\x00" + encoded).signature)}

    async def receive(self, kind=None):
        frame = await asyncio.wait_for(read_frame(self.reader), 3)
        if kind:
            assert frame["type"] == kind, frame
        return frame

    async def send(self, frame):
        await write_frame(self.writer, frame)

    async def close(self):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except ConnectionError:
            pass


class Room:
    def __init__(self, relay):
        self.relay = relay
        self.room = secrets.token_hex(32)
        self.peers = []
        self.owner = None
        self.revision = 0
        self.approved = []

    async def raw_peer(self):
        reader, writer = await asyncio.open_connection(*self.relay.address[:2], limit=STREAM_LIMIT)
        peer = Peer(reader, writer, SigningKey.generate(), PrivateKey.generate())
        self.peers.append(peer)
        return peer

    async def hello(self, peer, create=False):
        await peer.send({"type": "hello", "room": self.room, "sign_key": peer.key, "box_key": peer.box, "create": create})
        challenge = (await peer.receive("challenge"))["challenge"]
        body = {"kind": "proof", "room": self.room, "challenge": challenge, "sign_key": peer.key, "box_key": peer.box}
        proof = peer.signed("proof", body)
        await peer.send(proof)
        return proof

    async def connect(self, create=False):
        peer = await self.raw_peer()
        await self.hello(peer, create)
        ready = await peer.receive("ready")
        if create:
            self.owner = peer
        assert ready["owner"] == self.owner.key
        if self.revision:
            await peer.receive("roster")
        return peer

    def roster(self, members, *, locked=False, revision=None):
        revision = self.revision + 1 if revision is None else revision
        body = {"kind": "roster", "room": self.room, "revision": revision, "locked": locked,
                "members": [peer.member() for peer in members],
                "details": {peer.key: b64(SealedBox(peer.encryption.public_key).encrypt(b"names")) for peer in members}}
        return self.owner.signed("roster", body)

    async def approve(self, members, *, locked=False, recipients=None):
        packet = self.roster(members, locked=locked)
        await self.owner.send(packet)
        self.revision += 1
        self.approved = members
        for peer in (self.peers if recipients is None else recipients):
            assert await peer.receive("roster") == packet

    def message(self, sender, text=b"private message", sequence=1, members=None):
        members = self.approved if members is None else members
        body = {"kind": "message", "room": self.room, "revision": self.revision, "sender": sender.key,
                "sequence": sequence,
                "boxes": {peer.key: b64(SealedBox(peer.encryption.public_key).encrypt(text)) for peer in members if peer is not sender}}
        return sender.signed("message", body)

    def submit(self, sender, packet):
        inner = packet["body"]
        ciphertext = b64(SealedBox(self.owner.encryption.public_key).encrypt(json.dumps(packet).encode("ascii")))
        return sender.signed("submit", {"kind": "submit", "room": self.room, "revision": inner["revision"],
                                        "sender": sender.key, "sequence": inner["sequence"], "ciphertext": ciphertext})

    def release(self, packet):
        return self.owner.signed("release", {"kind": "release", "room": self.room,
                                            "revision": self.revision, "packet": packet})


@pytest.fixture
async def room():
    relay = Relay()
    await relay.start()
    room = Room(relay)
    try:
        yield room
    finally:
        for peer in room.peers:
            await peer.close()
        await relay.close()


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.1", "::", "localhost", "::1%eth0", 2130706433, None])
async def test_relay_rejects_non_numeric_loopback(host):
    with pytest.raises(ValueError, match="loopback"):
        await Relay().start(host)


async def test_three_devices_opaque_messages_only_reach_approved_members(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    bob = await room.connect()
    pending = await room.connect()
    await room.approve([owner, alice, bob])
    ciphertext = b64(SealedBox(owner.encryption.public_key).encrypt(b"secret invite proof"))
    await pending.send({"type": "join_request", "ciphertext": ciphertext})
    request = await owner.receive("join_request")
    assert request == {"type": "join_request", "sender": pending.key, "box_key": pending.box, "ciphertext": ciphertext}
    packet = room.message(alice)
    submission = room.submit(alice, packet)
    await alice.send(submission)
    assert await owner.receive("submit") == submission
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(read_frame(bob.reader), 0.05)
    release = room.release(packet)
    await owner.send(release)
    assert await owner.receive("release") == release
    assert await bob.receive("release") == release
    for peer in (owner, bob):
        encoded = packet["body"]["boxes"][peer.key]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        assert SealedBox(peer.encryption).decrypt(raw) == b"private message"
    assert "private message" not in json.dumps(packet)
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(read_frame(pending.reader), 0.05)
    assert room.relay.rooms[room.room].roster["type"] == "roster"
    assert not hasattr(room.relay.rooms[room.room], "messages")


async def test_pending_cannot_send_chat(room):
    owner = await room.connect(create=True)
    pending = await room.connect()
    await room.approve([owner])
    await pending.send(room.submit(pending, room.message(pending)))
    assert "membership" in (await pending.receive("error"))["reason"]
    with pytest.raises(ConnectionError):
        await pending.receive()
    assert room.room in room.relay.rooms


async def test_impersonation_proof_rejected(room):
    peer = await room.raw_peer()
    await peer.send({"type": "hello", "room": room.room, "sign_key": peer.key, "box_key": peer.box, "create": True})
    challenge = (await peer.receive("challenge"))["challenge"]
    body = {"kind": "proof", "room": room.room, "challenge": challenge, "sign_key": peer.key, "box_key": peer.box}
    peer.signing = SigningKey.generate()
    await peer.send(peer.signed("proof", body))
    assert "signature" in (await peer.receive("error"))["reason"]
    assert not room.relay.rooms


async def test_challenge_replay_rejected(room):
    first = await room.raw_peer()
    proof = await room.hello(first, create=True)
    await first.receive("ready")
    second = await room.raw_peer()
    second.signing, second.encryption = first.signing, first.encryption
    await second.send({"type": "hello", "room": room.room, "sign_key": second.key, "box_key": second.box, "create": False})
    challenge = await second.receive("challenge")
    assert challenge["challenge"] != proof["body"]["challenge"]
    await second.send(proof)
    assert "proof" in (await second.receive("error"))["reason"]


async def test_tampered_message_cannot_reach_recipient(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    await room.approve([owner, alice])
    packet = room.submit(alice, room.message(alice))
    packet["body"]["sequence"] = 2
    await alice.send(packet)
    assert "signature" in (await alice.receive("error"))["reason"]
    assert (await owner.receive("departed"))["sender"] == alice.key


async def test_message_replay_disconnects_sender(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    await room.approve([owner, alice])
    packet = room.submit(alice, room.message(alice))
    await alice.send(packet)
    assert await owner.receive("submit") == packet
    await alice.send(packet)
    assert "sequence" in (await alice.receive("error"))["reason"]
    await owner.receive("departed")


async def test_membership_and_exact_recipient_set_enforced(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    bob = await room.connect()
    await room.approve([owner, alice, bob])
    packet = room.message(alice, members=[alice, owner])
    await owner.send(room.release(packet))
    assert "recipients" in (await owner.receive("error"))["reason"]
    assert (await alice.receive("closed"))["reason"] == "Room owner disconnected."


async def test_nonowner_cannot_change_roster(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    await room.approve([owner, alice])
    await alice.send(alice.signed("roster", room.roster([owner, alice])["body"]))
    assert "owner" in (await alice.receive("error"))["reason"]
    await owner.receive("departed")


async def test_removal_broadcast_precedes_close_and_future_messages(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    bob = await room.connect()
    await room.approve([owner, alice, bob])
    await room.approve([owner, alice])
    assert (await bob.receive("closed"))["reason"] == "Removed from room."
    await owner.receive("departed")
    packet = room.message(alice, text=b"after removal")
    assert bob.key not in packet["body"]["boxes"]
    submission = room.submit(alice, packet)
    await alice.send(submission)
    assert await owner.receive("submit") == submission
    release = room.release(packet)
    await owner.send(release)
    assert await owner.receive("release") == release
    with pytest.raises(ConnectionError):
        await bob.receive()


async def test_locked_room_closes_pending_and_rejects_new_join(room):
    owner = await room.connect(create=True)
    pending = await room.connect()
    await room.approve([owner], locked=True)
    assert (await pending.receive("closed"))["reason"] == "Room is locked."
    outsider = await room.raw_peer()
    await room.hello(outsider)
    assert "locked" in (await outsider.receive("error"))["reason"]


async def test_owner_disconnect_closes_everyone_and_forgets_room(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    pending = await room.connect()
    await room.approve([owner, alice])
    await owner.close()
    for peer in (alice, pending):
        assert (await peer.receive("closed"))["reason"] == "Room owner disconnected."
    assert not room.relay.rooms


async def test_departure_then_new_roster(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    bob = await room.connect()
    await room.approve([owner, alice, bob])
    await bob.close()
    assert (await owner.receive("departed"))["sender"] == bob.key
    # Already in-flight chat may still include the departed recipient until
    # the owner publishes the next roster; it remains deliverable to others.
    packet = room.message(alice)
    submission = room.submit(alice, packet)
    await alice.send(submission)
    assert await owner.receive("submit") == submission
    release = room.release(packet)
    await owner.send(release)
    assert await owner.receive("release") == release
    await room.approve([owner, alice], recipients=[owner, alice])


async def test_duplicate_identity_cannot_replace_connection(room):
    owner = await room.connect(create=True)
    second = await room.raw_peer()
    second.signing, second.encryption = owner.signing, owner.encryption
    await room.hello(second)
    assert "already present" in (await second.receive("error"))["reason"]
    assert room.relay.rooms[room.room].connections[owner.key].closing is False


async def test_handshake_deadline_releases_capacity(room, monkeypatch):
    monkeypatch.setattr(module, "HANDSHAKE_TIMEOUT", 0.03)
    peer = await room.raw_peer()
    assert (await peer.receive("error"))["reason"] == "Handshake timed out."
    with pytest.raises(ConnectionError):
        await peer.receive()


async def test_total_connection_capacity_is_finite(room, monkeypatch):
    monkeypatch.setattr(module, "MAX_SESSIONS", 1)
    await room.connect(create=True)
    peer = await room.raw_peer()
    with pytest.raises(ConnectionError):
        await peer.receive()


async def test_room_capacity_is_finite(room, monkeypatch):
    monkeypatch.setattr(module, "MAX_ROOMS", 1)
    await room.connect(create=True)
    other = Room(room.relay)
    peer = await other.raw_peer()
    room.peers.append(peer)
    await other.hello(peer, create=True)
    assert "capacity" in (await peer.receive("error"))["reason"]


async def test_invalid_frame_does_not_affect_other_room_connections(room):
    owner = await room.connect(create=True)
    attacker = await room.connect()
    attacker.writer.write(b'{"type":"join_request","ciphertext":"bad","ciphertext":"duplicate"}\n')
    await attacker.writer.drain()
    assert (await attacker.receive("error"))["reason"] == "Invalid request."
    await owner.receive("departed")
    await room.approve([owner], recipients=[owner])


async def test_rate_limit_disconnects_abusive_peer(room):
    owner = await room.connect(create=True)
    attacker = await room.connect()
    await room.approve([owner])
    session = room.relay.rooms[room.room].connections[attacker.key]
    session.tokens = 0
    session.token_time = __import__("time").monotonic()
    ciphertext = b64(SealedBox(owner.encryption.public_key).encrypt(b"join"))
    await attacker.send({"type": "join_request", "ciphertext": ciphertext})
    assert "quickly" in (await attacker.receive("error"))["reason"]


async def test_ungated_direct_message_is_rejected(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    await room.approve([owner, alice])
    await alice.send(room.message(alice))
    assert (await alice.receive("error"))["reason"] == "Unknown request."
    await owner.receive("departed")


async def test_nonowner_cannot_forge_a_release(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    await room.approve([owner, alice])
    release = room.release(room.message(alice))
    await alice.send(release)
    assert "owner" in (await alice.receive("error"))["reason"]
    await owner.receive("departed")


async def test_stale_submission_is_nonfatal_and_never_forwarded(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    await room.approve([owner, alice])
    stale_packet = room.message(alice)
    await room.approve([owner, alice])
    await alice.send(room.submit(alice, stale_packet))
    assert await alice.receive("notice") == {"type": "notice", "code": "stale_message"}
    fresh = room.submit(alice, room.message(alice, sequence=2))
    await alice.send(fresh)
    assert await owner.receive("submit") == fresh


async def test_stale_owner_release_is_nonfatal(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    await room.approve([owner, alice])
    stale_release = room.release(room.message(owner))
    await room.approve([owner, alice])
    await owner.send(stale_release)
    assert await owner.receive("notice") == {"type": "notice", "code": "stale_message"}
    fresh = room.release(room.message(owner, sequence=2))
    await owner.send(fresh)
    assert await alice.receive("release") == fresh


async def test_released_message_replay_is_rejected(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    await room.approve([owner, alice])
    release = room.release(room.message(owner))
    await owner.send(release)
    assert await alice.receive("release") == release
    await owner.send(release)
    assert "sequence" in (await owner.receive("error"))["reason"]


async def test_disconnected_approved_roster_race_is_allowed(room):
    owner = await room.connect(create=True)
    alice = await room.connect()
    await room.approve([owner, alice])
    await alice.close()
    await owner.receive("departed")
    # The next roster might have been composed before the departure arrived.
    await room.approve([owner, alice], recipients=[owner])
    await room.approve([owner], recipients=[owner])
    assert list(room.relay.rooms[room.room].members) == [owner.key]


async def test_disconnected_pending_cannot_be_approved(room):
    owner = await room.connect(create=True)
    pending = await room.connect()
    await room.approve([owner])
    await pending.close()
    await owner.receive("departed")
    await owner.send(room.roster([owner, pending]))
    assert "member" in (await owner.receive("error"))["reason"]


async def test_low_order_encryption_key_rejected_before_challenge(room):
    peer = await room.raw_peer()
    await peer.send({"type": "hello", "room": room.room, "sign_key": peer.key,
                     "box_key": b64(bytes(32)), "create": True})
    assert "encryption key" in (await peer.receive("error"))["reason"]
    assert not room.relay.rooms
