"""Real TCP relay/client integration; explicit loopback development mode only.

These tests exercise independent devices/keys and connections in one process.
They do not establish cross-platform or real-Tor deployment validation.
"""

import asyncio
import copy
from dataclasses import replace
import json

import pytest
import pytest_asyncio

from den.client import RoomClient
from den.crypto import Identity, b64e, fingerprint, encrypt_message, make_submit, open_release
from den.relay import Relay


async def eventually(predicate, message="state did not settle"):
    try:
        async with asyncio.timeout(4):
            while not predicate():
                await asyncio.sleep(0.005)
    except TimeoutError:
        raise AssertionError(message) from None


async def next_event(client, kind):
    async with asyncio.timeout(4):
        while True:
            event = await client.events.get()
            if event["type"] == kind:
                return event
            if event["type"] == "closed":
                raise AssertionError(f"Client closed while waiting for {kind}: {event}")


class RoomHarness:
    def __init__(self, relay):
        self.relay = relay
        self.clients = []
        self.owner = None

    async def create(self, name="owner"):
        host, port = self.relay.address[:2]
        self.owner = await RoomClient.create(name, host, port, local_test=True)
        self.clients.append(self.owner)
        await eventually(lambda: self.relay.rooms[self.owner.invite.room].revision == self.owner.revision)
        return self.owner

    async def join(self, name, invite=None):
        client = await RoomClient.join(name, (invite or self.owner.invite).encode(), local_test=True)
        self.clients.append(client)
        return client

    async def add(self, name):
        client = await self.join(name)
        await eventually(lambda: client.identity.sign_key in self.owner.pending, "join request missing")
        await self.owner.approve(name)
        await self.sync()
        return client

    async def sync(self, *clients):
        clients = clients or tuple(c for c in self.clients if not c.closed.is_set())
        revision = self.owner.revision
        await eventually(
            lambda: all(c.revision == revision for c in clients)
            and self.relay.rooms[self.owner.invite.room].revision == revision,
            "rosters did not converge",
        )


@pytest_asyncio.fixture
async def room():
    relay = Relay()
    await relay.start("127.0.0.1", 0)
    harness = RoomHarness(relay)
    try:
        await harness.create()
        yield harness
    finally:
        for client in reversed(harness.clients):
            await client.close()
        await relay.close()


async def test_three_devices_exchange_in_both_directions(room):
    alice = await room.add("alice")
    bob = await room.add("bob")
    clients = [room.owner, alice, bob]
    assert len({c.identity.sign_key for c in clients}) == 3
    assert len({c.identity.box_key for c in clients}) == 3
    assert all(c.admitted and len(c.members) == 3 for c in clients)

    for sender in clients:
        text = f"hello from {sender.name}: 世界 🌍"
        await sender.send_text(text)
        for receiver in clients:
            if receiver is not sender:
                event = await next_event(receiver, "chat")
                assert event["name"] == sender.name
                assert event["fingerprint"] == fingerprint(sender.identity.sign_key)
                assert event["text"] == text
    assert all(not c.closed.is_set() for c in clients)


async def test_pending_device_cannot_send_or_read_room_chat(room):
    alice = await room.add("alice")
    pending = await room.join("pending")
    await eventually(lambda: pending.identity.sign_key in room.owner.pending)
    assert not pending.admitted
    with pytest.raises(ValueError, match="approv"):
        await pending.send_text("not authorized")
    await room.owner.send_text("members only")
    assert (await next_event(alice, "chat"))["text"] == "members only"
    assert pending.names == {}
    assert all(event["type"] != "chat" for event in list(pending.events._queue))
    assert not pending.closed.is_set()


async def test_wrong_invite_secret_is_rejected_by_owner(room):
    altered = replace(room.owner.invite, secret=b64e(b"\x00" * 32))
    intruder = await room.join("intruder", altered)
    await eventually(intruder.closed.is_set, "invalid invite holder stayed connected")
    assert not intruder.admitted
    assert intruder.identity.sign_key not in room.owner.pending
    assert intruder.identity.sign_key not in room.owner.members
    assert not room.owner.closed.is_set()


async def test_owner_identity_is_pinned_by_invite(room):
    imposter = Identity()
    altered = replace(room.owner.invite, owner=imposter.sign_key, owner_box=imposter.box_key)
    with pytest.raises(ConnectionError, match="owner key"):
        await room.join("alice", altered)
    assert not room.owner.closed.is_set()
    assert len(room.owner.members) == 1


async def test_lock_rejects_pending_and_new_joins_then_unlock_allows_them(room):
    alice = await room.add("alice")
    pending = await room.join("pending")
    await eventually(lambda: pending.identity.sign_key in room.owner.pending)
    await room.owner.set_locked(True)
    await eventually(pending.closed.is_set)
    await room.sync(room.owner, alice)
    assert room.owner.pending == {}
    assert alice.locked
    with pytest.raises(ConnectionError):
        await room.join("locked_out")
    await alice.send_text("existing members can still chat")
    assert (await next_event(room.owner, "chat"))["text"] == "existing members can still chat"

    await room.owner.set_locked(False)
    await room.sync(room.owner, alice)
    new_member = await room.add("new_member")
    assert new_member.admitted
    assert not new_member.locked


@pytest.mark.parametrize("duplicate", ["OWNER", "ALICE", "PENDING"])
async def test_duplicate_usernames_are_case_insensitively_rejected(room, duplicate):
    await room.add("alice")
    pending = await room.join("pending")
    await eventually(lambda: pending.identity.sign_key in room.owner.pending)
    duplicate_client = await room.join(duplicate)
    await eventually(duplicate_client.closed.is_set, "duplicate username was not rejected")
    assert not duplicate_client.admitted
    assert duplicate_client.identity.sign_key not in room.owner.pending
    assert len(room.owner.members) == 2


async def test_approval_by_device_fingerprint_and_explicit_rejection(room):
    alice = await room.join("alice")
    await eventually(lambda: alice.identity.sign_key in room.owner.pending)
    await room.owner.approve(fingerprint(alice.identity.sign_key))
    await room.sync()
    assert alice.admitted

    bob = await room.join("bob")
    await eventually(lambda: bob.identity.sign_key in room.owner.pending)
    await room.owner.reject("bob")
    await eventually(bob.closed.is_set)
    assert bob.identity.sign_key not in room.owner.pending
    assert bob.identity.sign_key not in room.owner.members
    with pytest.raises(ValueError, match="owner"):
        await alice.set_locked(True)


async def test_removed_member_is_disconnected_and_excluded_from_future_delivery(room):
    alice = await room.add("alice")
    bob = await room.add("bob")
    await room.owner.kick("bob")
    await eventually(bob.closed.is_set)
    await room.sync(room.owner, alice)
    assert not bob.admitted
    assert bob.identity.sign_key not in alice.members
    await alice.send_text("only current members receive this")
    assert (await next_event(room.owner, "chat"))["text"] == "only current members receive this"
    assert all(event["type"] != "chat" for event in list(bob.events._queue))
    with pytest.raises((ValueError, ConnectionError)):
        await bob.send_text("removed members cannot send")


async def test_owner_disconnect_closes_admitted_and_pending_clients_and_erases_room(room):
    alice = await room.add("alice")
    bob = await room.add("bob")
    pending = await room.join("pending")
    await eventually(lambda: pending.identity.sign_key in room.owner.pending)
    await room.owner.close()
    await eventually(lambda: all(c.closed.is_set() for c in (alice, bob, pending)))
    await eventually(lambda: not room.relay.rooms and not room.relay._sessions)


async def test_member_disconnect_updates_remaining_membership(room):
    alice = await room.add("alice")
    bob = await room.add("bob")
    await bob.close()
    await eventually(lambda: bob.identity.sign_key not in room.owner.members)
    await room.sync(room.owner, alice)
    assert len(alice.members) == 2
    await alice.send_text("remaining room still works")
    assert (await next_event(room.owner, "chat"))["text"] == "remaining room still works"


async def test_pending_disconnect_removes_stale_approval_request(room):
    pending = await room.join("pending")
    await eventually(lambda: pending.identity.sign_key in room.owner.pending)
    await pending.close()
    await eventually(
        lambda: pending.identity.sign_key not in room.owner.pending,
        "owner retained a disconnected pending device",
    )
    replacement = await room.add("pending")
    assert replacement.admitted
    assert not room.owner.closed.is_set()


async def test_malicious_relay_cannot_forge_membership(room):
    alice = await room.add("alice")
    bob = await room.add("bob")
    forged = copy.deepcopy(room.owner.last_roster)
    forged["body"]["revision"] += 1
    forged["body"]["locked"] = True
    victim_session = room.relay.rooms[room.owner.invite.room].connections[alice.identity.sign_key]
    victim_session.send(forged)
    await eventually(alice.closed.is_set, "forged owner roster was accepted")
    assert not alice.locked
    assert not room.owner.closed.is_set()
    assert not bob.closed.is_set()


async def test_chat_text_is_encrypted_on_every_client_write(room, monkeypatch):
    alice = await room.add("alice")
    bob = await room.add("bob")
    captured = []
    for client in (room.owner, alice, bob):
        original = client._send

        async def capture(packet, original=original):
            captured.append(copy.deepcopy(packet))
            await original(packet)

        monkeypatch.setattr(client, "_send", capture)

    secret_text = "unique-plaintext-marker-4cb937b1"
    await alice.send_text(secret_text)
    assert (await next_event(room.owner, "chat"))["text"] == secret_text
    assert (await next_event(bob, "chat"))["text"] == secret_text
    wire = json.dumps(captured, sort_keys=True)
    assert secret_text not in wire
    assert room.owner.invite.secret not in wire
    roster_wire = json.dumps(room.relay.rooms[room.owner.invite.room].roster)
    assert '"alice"' not in roster_wire
    assert '"bob"' not in roster_wire
    assert captured


async def test_relay_withholding_removal_cannot_release_stale_ciphertext(room, monkeypatch):
    alice = await room.add("alice")
    bob = await room.add("bob")
    previous_revision = alice.revision
    previous_members = copy.deepcopy(alice.members)
    await room.owner.kick("bob")
    await eventually(bob.closed.is_set)
    await room.sync(room.owner, alice)
    releases = []
    original_send = room.owner._send

    async def capture(packet):
        if packet["type"] == "release":
            releases.append(packet)
        await original_send(packet)

    monkeypatch.setattr(room.owner, "_send", capture)
    # Simulate a relay withholding the removal roster from Alice, then bypassing
    # its own honest checks to forward the stale submit directly to the owner.
    message = encrypt_message(alice.identity, alice.invite, previous_revision, 1,
                              previous_members, "created after Bob was removed")
    gate = make_submit(alice.identity, alice.invite, message)
    owner_session = room.relay.rooms[room.owner.invite.room].connections[room.owner.identity.sign_key]
    owner_session.send(gate)
    event = await next_event(room.owner, "notice")
    assert "outdated" in event["text"]
    assert not releases
    assert not room.owner.closed.is_set()
    with pytest.raises(ValueError):
        bob.identity.open(gate["body"]["ciphertext"])


async def test_removed_recipient_cannot_decrypt_remaining_member_ciphertext(room, monkeypatch):
    alice = await room.add("alice")
    bob = await room.add("bob")
    await room.owner.kick("bob")
    await eventually(bob.closed.is_set)
    await room.sync(room.owner, alice)
    released = []
    original_send = room.owner._send

    async def capture(packet):
        if packet["type"] == "release":
            released.append(copy.deepcopy(packet))
        await original_send(packet)

    monkeypatch.setattr(room.owner, "_send", capture)
    await room.owner.send_text("a new message for Alice only")
    assert (await next_event(alice, "chat"))["text"] == "a new message for Alice only"
    packet = open_release(released[0], room.owner.invite, room.owner.revision)
    assert bob.identity.sign_key not in packet["body"]["boxes"]
    for box in packet["body"]["boxes"].values():
        with pytest.raises(ValueError):
            bob.identity.open(box)


async def test_relay_cannot_tamper_with_released_message(room, monkeypatch):
    alice = await room.add("alice")
    victim = room.relay.rooms[room.owner.invite.room].connections[alice.identity.sign_key]
    original_send = victim.send

    def corrupt(packet):
        if packet["type"] == "release":
            packet = copy.deepcopy(packet)
            packet["body"]["packet"]["body"]["sequence"] += 1
        original_send(packet)

    monkeypatch.setattr(victim, "send", corrupt)
    await room.owner.send_text("authenticated content")
    await eventually(alice.closed.is_set)
    assert all(event["type"] != "chat" for event in list(alice.events._queue))
    assert not room.owner.closed.is_set()


async def test_relay_replayed_release_is_not_rendered_twice(room, monkeypatch):
    alice = await room.add("alice")
    victim = room.relay.rooms[room.owner.invite.room].connections[alice.identity.sign_key]
    original_send = victim.send

    def duplicate(packet):
        original_send(packet)
        if packet["type"] == "release":
            original_send(copy.deepcopy(packet))

    monkeypatch.setattr(victim, "send", duplicate)
    await room.owner.send_text("render once")
    assert (await next_event(alice, "chat"))["text"] == "render once"
    await eventually(alice.closed.is_set)
    assert all(event["type"] != "chat" for event in list(alice.events._queue))
