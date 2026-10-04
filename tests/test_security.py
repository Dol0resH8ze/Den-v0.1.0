"""Hostile-input and confidentiality regressions for the experimental protocol."""

import copy
import unicodedata

import pytest
from nacl.public import SealedBox

from hush.crypto import (
    Identity,
    Invite,
    b64d,
    b64e,
    canonical,
    check_roster,
    decrypt_message,
    encrypt_message,
    make_roster,
    make_release,
    make_submit,
    message_text,
    open_release,
    open_submit,
    safe_text,
    seal,
    validate_box_key,
)


@pytest.fixture
def room():
    owner, alice, bob = Identity(), Identity(), Identity()
    invite = Invite.create("127.0.0.1", 8787, owner)
    identities = (owner, alice, bob)
    members = {i.sign_key: i.member() for i in identities}
    names = dict(zip(members, ("Owner", "Alice", "Bob")))
    return owner, alice, bob, invite, members, names


def test_three_party_message_confidentiality_and_sender_authentication(room):
    owner, alice, bob, invite, members, _ = room
    packet = encrypt_message(alice, invite, 1, 1, members, "Only approved devices can read this.")
    wire = canonical(packet)
    assert b"Only approved devices" not in wire
    assert invite.secret.encode() not in wire
    for recipient in (owner, bob):
        assert decrypt_message(packet, recipient, invite, 1, members, {}) == (
            alice.sign_key,
            "Only approved devices can read this.",
        )
    with pytest.raises(ValueError):
        Identity().open(packet["body"]["boxes"][bob.sign_key])


def test_tampering_does_not_advance_replay_state(room):
    _, alice, bob, invite, members, _ = room
    packet = encrypt_message(alice, invite, 1, 1, members, "original")
    tampered = copy.deepcopy(packet)
    tampered["body"]["sequence"] = 2
    seen = {}
    with pytest.raises(ValueError):
        decrypt_message(tampered, bob, invite, 1, members, seen)
    assert seen == {}
    assert decrypt_message(packet, bob, invite, 1, members, seen)[1] == "original"


def test_replays_rejected_across_membership_revisions(room):
    _, alice, bob, invite, members, _ = room
    seen = {}
    first = encrypt_message(alice, invite, 1, 7, members, "first")
    decrypt_message(first, bob, invite, 1, members, seen)
    with pytest.raises(ValueError):
        decrypt_message(first, bob, invite, 1, members, seen)
    # Changing the roster does not authorize a sender to reset their counter.
    reset = encrypt_message(alice, invite, 2, 1, members, "reused counter")
    with pytest.raises(ValueError):
        decrypt_message(reset, bob, invite, 2, members, seen)
    next_message = encrypt_message(alice, invite, 2, 8, members, "next")
    assert decrypt_message(next_message, bob, invite, 2, members, seen)[1] == "next"


def test_cross_room_and_stale_roster_messages_rejected(room):
    owner, alice, bob, invite, members, _ = room
    packet = encrypt_message(alice, invite, 1, 1, members, "old room")
    other_room = Invite.create("127.0.0.1", 8787, owner)
    with pytest.raises(ValueError):
        decrypt_message(packet, bob, other_room, 1, members, {})
    with pytest.raises(ValueError):
        decrypt_message(packet, bob, invite, 2, members, {})


@pytest.mark.parametrize("field,value", [
    ("room", "f" * 64),
    ("revision", 99),
    ("sender", "different sender"),
    ("sequence", 99),
    ("kind", "join"),
    ("recipient", "different recipient"),
])
def test_even_signed_ciphertext_must_bind_to_its_envelope(room, field, value):
    _, alice, bob, invite, members, _ = room
    packet = encrypt_message(alice, invite, 1, 1, members, "text")
    payload = bob.open(packet["body"]["boxes"][bob.sign_key])
    payload[field] = value
    packet["body"]["boxes"][bob.sign_key] = seal(payload, bob.box_key)
    packet = alice.sign(packet["body"])
    with pytest.raises(ValueError):
        decrypt_message(packet, bob, invite, 1, members, {})


def test_messages_must_target_exact_approved_roster(room):
    owner, alice, bob, invite, members, _ = room
    packet = encrypt_message(alice, invite, 1, 1, members, "text")
    del packet["body"]["boxes"][owner.sign_key]
    packet = alice.sign(packet["body"])
    with pytest.raises(ValueError):
        decrypt_message(packet, bob, invite, 1, members, {})


def test_removed_member_cannot_decrypt_new_roster_or_messages(room):
    owner, alice, bob, invite, members, names = room
    del members[bob.sign_key]
    del names[bob.sign_key]
    roster = make_roster(owner, invite, 2, False, members, names)
    _, approved, visible_names = check_roster(roster, invite, bob, 1)
    assert bob.sign_key not in approved
    assert visible_names == {}
    packet = encrypt_message(alice, invite, 2, 1, members, "after removal")
    assert bob.sign_key not in packet["body"]["boxes"]
    with pytest.raises(ValueError):
        bob.open(packet["body"]["boxes"][owner.sign_key])


def test_roster_names_are_encrypted_and_owner_is_pinned(room):
    owner, _, bob, invite, members, names = room
    roster = make_roster(owner, invite, 1, False, members, names)
    assert all(name.encode() not in canonical(roster) for name in names.values())
    _, parsed_members, parsed_names = check_roster(roster, invite, bob)
    assert parsed_members == members
    assert parsed_names == names
    with pytest.raises(ValueError):
        check_roster(Identity().sign(roster["body"]), invite, bob)
    with pytest.raises(ValueError):
        check_roster(roster, invite, bob, previous_revision=1)


def test_owner_cannot_silently_replace_our_encryption_key(room):
    owner, _, bob, invite, members, names = room
    members[bob.sign_key]["box_key"] = Identity().box_key
    with pytest.raises(ValueError, match="device key"):
        check_roster(make_roster(owner, invite, 1, False, members, names), invite, bob)


def test_duplicate_case_insensitive_names_rejected(room):
    owner, alice, bob, invite, members, names = room
    names[alice.sign_key] = "bob"
    with pytest.raises(ValueError, match="Duplicate usernames"):
        check_roster(make_roster(owner, invite, 1, False, members, names), invite, bob)


@pytest.mark.parametrize("packet", [
    {}, {"body": None}, {"body": []}, {"body": "not an object"},
    {"body": {"sender": []}}, {"body": {"sender": {}}},
])
def test_hostile_message_shapes_raise_controlled_errors(room, packet):
    _, _, bob, invite, members, _ = room
    with pytest.raises(ValueError):
        decrypt_message(packet, bob, invite, 1, members, {})


@pytest.mark.parametrize("raw", [
    b'{"x":NaN}',
    b'{"x":Infinity}',
    b'{"x":1,"x":2}',
    b'{"x":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}",
])
def test_decrypted_payload_uses_strict_bounded_json(raw):
    recipient = Identity()
    ciphertext = b64e(SealedBox(recipient.encryption.public_key).encrypt(raw))
    with pytest.raises(ValueError):
        recipient.open(ciphertext)


def test_invalid_box_key_is_a_controlled_error():
    with pytest.raises(ValueError):
        seal({"text": "test"}, b64e(bytes(32)))
    with pytest.raises(ValueError):
        validate_box_key(b64e(bytes(32)))


def test_terminal_controls_and_bidi_are_not_rendered():
    hostile = "hello\x1b[2J\x1b]52;c;c2VjcmV0\x07\r\n\t\x85\u202e\u2066world"
    clean = safe_text(hostile)
    assert all(not unicodedata.category(c).startswith("C") for c in clean)
    assert "hello" in clean and "world" in clean


def test_sanitized_message_size_is_bounded():
    with pytest.raises(ValueError):
        message_text("\x01" * 4000)


def test_invite_requires_explicit_local_mode_and_rejects_downgrade(room):
    _, _, _, invite, _, _ = room
    with pytest.raises(ValueError):
        Invite.parse(invite.encode())
    assert Invite.parse(invite.encode(), local_test=True) == invite


def test_key_encodings_are_canonical():
    raw = bytes(32)
    canonical_encoding = b64e(raw)
    assert b64d(canonical_encoding, 32) == raw
    with pytest.raises(ValueError):
        b64d(canonical_encoding + "=")


def test_gate_hides_all_recipient_boxes_until_owner_releases(room):
    owner, alice, bob, invite, members, _ = room
    original = encrypt_message(alice, invite, 1, 1, members, "secret gated text")
    gate = make_submit(alice, invite, original)
    wire = canonical(gate)
    assert b"secret gated text" not in wire
    assert all(box.encode() not in wire for box in original["body"]["boxes"].values())
    with pytest.raises(ValueError):
        bob.open(gate["body"]["ciphertext"])
    opened = open_submit(gate, owner, invite, 1, members)
    assert opened == original
    # The owner fully authenticates/decrypts before releasing recipient boxes.
    assert decrypt_message(opened, owner, invite, 1, members, {})[1] == "secret gated text"
    released = make_release(owner, invite, opened)
    assert decrypt_message(open_release(released, invite, 1), bob, invite, 1, members, {})[1] == "secret gated text"


def test_withheld_removal_roster_cannot_release_new_ciphertext_to_removed_member(room):
    owner, alice, bob, invite, old_members, _ = room
    # Alice has not received revision 2 removing Bob, so she sends using revision 1.
    stale_message = encrypt_message(alice, invite, 1, 5, old_members, "after owner removed Bob")
    gate = make_submit(alice, invite, stale_message)
    current_members = {k: v for k, v in old_members.items() if k != bob.sign_key}
    with pytest.raises(ValueError, match="Stale"):
        open_submit(gate, owner, invite, 2, current_members)
    with pytest.raises(ValueError):
        bob.open(gate["body"]["ciphertext"])


def test_removed_sender_cannot_submit(room):
    owner, alice, bob, invite, members, _ = room
    original = encrypt_message(bob, invite, 1, 1, members, "no longer allowed")
    gate = make_submit(bob, invite, original)
    del members[bob.sign_key]
    with pytest.raises(ValueError, match="unapproved"):
        open_submit(gate, owner, invite, 1, members)


@pytest.mark.parametrize("field,value", [("sequence", 9), ("sender", "other"), ("room", "a" * 64)])
def test_signed_gate_still_must_match_its_encrypted_message(room, field, value):
    owner, alice, _, invite, members, _ = room
    original = encrypt_message(alice, invite, 1, 1, members, "bound")
    gate = make_submit(alice, invite, original)
    gate["body"][field] = value
    gate = alice.sign(gate["body"])
    with pytest.raises(ValueError):
        open_submit(gate, owner, invite, 1, members)


def test_only_pinned_owner_can_release(room):
    owner, alice, _, invite, members, _ = room
    original = encrypt_message(alice, invite, 1, 1, members, "text")
    release = make_release(owner, invite, original)
    forged = alice.sign(release["body"])
    with pytest.raises(ValueError):
        open_release(forged, invite, 1)
    with pytest.raises(ValueError):
        make_release(alice, invite, original)
    with pytest.raises(ValueError):
        open_release(release, invite, 2)


def test_owner_cannot_relabel_old_message_as_new_revision(room):
    owner, alice, _, invite, members, _ = room
    original = encrypt_message(alice, invite, 1, 1, members, "text")
    release = make_release(owner, invite, original)
    release["body"]["revision"] = 2
    relabeled = owner.sign(release["body"])
    with pytest.raises(ValueError):
        open_release(relabeled, invite, 2)


def test_max_members_and_max_unicode_message_fit_transport_frame():
    from hush.crypto import MAX_MEMBERS, MAX_MESSAGE_BYTES
    from hush.transport import MAX_FRAME_BYTES

    identities = [Identity() for _ in range(MAX_MEMBERS)]
    owner, sender, *others = identities
    invite = Invite.create("127.0.0.1", 8787, owner)
    members = {i.sign_key: i.member() for i in identities}
    text = "😀" * (MAX_MESSAGE_BYTES // len("😀".encode("utf-8")))
    packet = encrypt_message(sender, invite, 1, 1, members, text)
    submission = make_submit(sender, invite, packet)
    release = make_release(owner, invite, packet)
    assert len(canonical(submission)) + 1 <= MAX_FRAME_BYTES
    assert len(canonical(release)) + 1 <= MAX_FRAME_BYTES
    assert decrypt_message(packet, others[0], invite, 1, members, {})[1] == text

