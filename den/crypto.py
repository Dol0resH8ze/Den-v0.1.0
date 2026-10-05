"""Small envelopes built with libsodium, not an audited messaging protocol.

All private keys live in process memory. No forward secrecy is claimed.
"""

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field

from nacl.exceptions import BadSignatureError, CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

DOMAIN = b"HUSH/1\x00"
NAME = re.compile(r"[A-Za-z0-9_\-]{1,24}\Z")
MAX_MEMBERS = 16
MAX_MESSAGE_BYTES = 4000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def b64e(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value, length=None):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Invalid encoding.")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid encoding.") from exc
    if b64e(raw) != value or (length is not None and len(raw) != length):
        raise ValueError("Invalid encoding length.")
    return raw


def username(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError("Use 1–24 letters, digits, underscores or hyphens for a username.")
    return value


def fingerprint(key):
    return hashlib.sha256(b64d(key, 32)).hexdigest()[:16]


def safe_text(value):
    """Keep untrusted chat from injecting terminal controls or bidi overrides."""
    import unicodedata
    if not isinstance(value, str):
        raise ValueError("Expected text.")
    return "".join(c if not unicodedata.category(c).startswith("C") else "�" for c in value)


def message_text(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Messages must contain 1–4000 UTF-8 bytes.")
    value = safe_text(value)
    if len(value.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise ValueError("Messages must contain 1–4000 UTF-8 bytes after removing terminal controls.")
    return value


def _json_object(raw):
    # Apply the same duplicate-key, numeric, nesting and Unicode checks inside
    # encryption as on the transport. Authenticated senders can still be hostile.
    from .transport import _object_from_pairs, _reject_constant, _validate_json
    result = json.loads(raw, object_pairs_hook=_object_from_pairs, parse_constant=_reject_constant)
    if not isinstance(result, dict):
        raise ValueError("Invalid encrypted payload.")
    _validate_json(result)
    return result


@dataclass
class Identity:
    signing: SigningKey = field(default_factory=SigningKey.generate)
    encryption: PrivateKey = field(default_factory=PrivateKey.generate)

    @property
    def sign_key(self):
        return b64e(bytes(self.signing.verify_key))

    @property
    def box_key(self):
        return b64e(bytes(self.encryption.public_key))

    def member(self):
        return {"sign_key": self.sign_key, "box_key": self.box_key}

    def sign(self, body):
        return {"body": body, "signature": b64e(self.signing.sign(DOMAIN + canonical(body)).signature)}

    def open(self, ciphertext):
        try:
            data = SealedBox(self.encryption).decrypt(b64d(ciphertext))
            return _json_object(data)
        except (CryptoError, ValueError, UnicodeError, TypeError, RecursionError) as exc:
            raise ValueError("Invalid encrypted payload.") from exc


def verify(packet, key):
    try:
        body = packet["body"]
        if not isinstance(body, dict):
            raise ValueError("Invalid signed payload.")
        VerifyKey(b64d(key, 32)).verify(DOMAIN + canonical(body), b64d(packet["signature"], 64))
        return body
    except (KeyError, TypeError, BadSignatureError, ValueError, RecursionError) as exc:
        raise ValueError("Invalid signed payload.") from exc


def seal(value, public_key):
    try:
        return b64e(SealedBox(PublicKey(b64d(public_key, 32))).encrypt(canonical(value)))
    except (CryptoError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Invalid encryption key or payload.") from exc


def validate_box_key(key):
    """Reject noncontributory/low-order X25519 keys before admitting a member."""
    from nacl.bindings import crypto_scalarmult
    try:
        crypto_scalarmult(bytes(PrivateKey.generate()), b64d(key, 32))
    except (CryptoError, ValueError, TypeError) as exc:
        raise ValueError("Invalid encryption key.") from exc


@dataclass(frozen=True)
class Invite:
    host: str
    port: int
    room: str
    secret: str
    owner: str
    owner_box: str

    @classmethod
    def create(cls, host, port, identity):
        return cls(host, port, secrets.token_hex(32), b64e(secrets.token_bytes(32)),
                   identity.sign_key, identity.box_key)

    def encode(self):
        return "den1." + b64e(canonical(self.__dict__))

    @classmethod
    def parse(cls, value, *, local_test=False):
        from .transport import validate_endpoint
        if not isinstance(value, str) or not value.startswith(("den1.", "hush1.")) or len(value) > 2048:
            raise ValueError("Invalid Den invite.")
        try:
            data = _json_object(b64d(value.split(".", 1)[1]))
            result = cls(**data)
            if not isinstance(result.room, str) or not re.fullmatch(r"[0-9a-f]{64}", result.room):
                raise ValueError("Invalid room.")
            for v in (result.secret, result.owner, result.owner_box):
                b64d(v, 32)
            validate_endpoint(result.host, result.port, local_test=local_test)
            return result
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            raise ValueError("Invalid invite or endpoint (local invites require --local-test).") from exc


def make_roster(identity, invite, revision, locked, members, names):
    details = {"room": invite.room, "revision": revision, "names": names}
    body = {"kind": "roster", "room": invite.room, "revision": revision,
            "locked": locked, "members": list(members.values()),
            "details": {key: seal(details, member["box_key"]) for key, member in members.items()}}
    return {"type": "roster", **identity.sign(body)}


def check_roster(packet, invite, identity, previous_revision=0):
    body = verify(packet, invite.owner)
    revision = body.get("revision")
    if (body.get("kind") != "roster" or body.get("room") != invite.room
            or type(revision) is not int or revision <= previous_revision
            or type(body.get("locked")) is not bool):
        raise ValueError("Invalid or replayed room roster.")
    entries = body.get("members")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_MEMBERS:
        raise ValueError("Invalid room membership.")
    members = {}
    box_keys = set()
    for member in entries:
        if not isinstance(member, dict) or set(member) != {"sign_key", "box_key"}:
            raise ValueError("Invalid member.")
        key = member["sign_key"]
        b64d(key, 32)
        validate_box_key(member["box_key"])
        if key in members or member["box_key"] in box_keys:
            raise ValueError("Duplicate member key.")
        members[key] = member
        box_keys.add(member["box_key"])
    if members.get(invite.owner) != {"sign_key": invite.owner, "box_key": invite.owner_box}:
        raise ValueError("Room owner key changed.")
    if identity.sign_key in members and members[identity.sign_key] != identity.member():
        raise ValueError("Your device key changed.")
    if not isinstance(body.get("details"), dict) or set(body["details"]) != set(members):
        raise ValueError("Incomplete membership details.")
    names = {}
    if identity.sign_key in members:
        details = identity.open(body["details"][identity.sign_key])
        if details.get("room") != invite.room or details.get("revision") != revision:
            raise ValueError("Membership details do not match room.")
        names = details.get("names")
        if not isinstance(names, dict) or set(names) != set(members):
            raise ValueError("Invalid usernames.")
        for name in names.values():
            username(name)
        if len({n.casefold() for n in names.values()}) != len(names):
            raise ValueError("Duplicate usernames.")
    return body, members, names


def encrypt_message(identity, invite, revision, sequence, members, text):
    payload = {"kind": "text", "room": invite.room, "revision": revision,
               "sender": identity.sign_key, "sequence": sequence, "text": message_text(text)}
    body = {"kind": "message", "room": invite.room, "revision": revision,
            "sender": identity.sign_key, "sequence": sequence,
            "boxes": {key: seal({**payload, "recipient": key}, m["box_key"])
                      for key, m in members.items() if key != identity.sign_key}}
    return {"type": "message", **identity.sign(body)}


def decrypt_message(packet, identity, invite, revision, members, seen):
    if not isinstance(packet, dict) or not isinstance(packet.get("body"), dict):
        raise ValueError("Invalid message packet.")
    sender = packet["body"].get("sender")
    if not isinstance(sender, str) or sender not in members or sender == identity.sign_key:
        raise ValueError("Message from an unapproved participant.")
    body = verify(packet, sender)
    seq = body.get("sequence")
    if (body.get("kind") != "message" or body.get("room") != invite.room
            or type(body.get("revision")) is not int or body.get("revision") != revision or type(seq) is not int
            or seq <= seen.get(sender, 0) or seq > 2**53):
        raise ValueError("Stale or invalid message.")
    boxes = body.get("boxes")
    if (not isinstance(boxes, dict) or identity.sign_key not in boxes
            or set(boxes) != set(members) - {sender}):
        raise ValueError("Message recipient list does not match membership.")
    payload = identity.open(boxes[identity.sign_key])
    for key in ("room", "revision", "sender", "sequence"):
        if payload.get(key) != body[key]:
            raise ValueError("Encrypted message binding failed.")
    if payload.get("kind") != "text" or payload.get("recipient") != identity.sign_key:
        raise ValueError("Wrong recipient or message type.")
    text = message_text(payload.get("text"))
    seen[sender] = seq
    return sender, text


def _message_header(packet, invite, revision=None):
    if not isinstance(packet, dict) or not isinstance(packet.get("body"), dict):
        raise ValueError("Invalid message packet.")
    body = packet["body"]
    sender = body.get("sender")
    if not isinstance(sender, str):
        raise ValueError("Invalid message sender.")
    body = verify(packet, sender)
    if (body.get("kind") != "message" or body.get("room") != invite.room
            or type(body.get("revision")) is not int or body["revision"] < 1
            or (revision is not None and body["revision"] != revision)
            or type(body.get("sequence")) is not int or not 1 <= body["sequence"] <= 2**53):
        raise ValueError("Stale or invalid message.")
    return body


def make_submit(identity, invite, packet):
    """Hide ALL recipient ciphertext behind the owner's current-roster gate.

    A relay withholding a removal roster cannot extract boxes for removed
    devices from a stale sender's submission. Only the owner can release them.
    """
    message = _message_header(packet, invite)
    if message["sender"] != identity.sign_key:
        raise ValueError("Cannot submit another device's message.")
    body = {"kind": "submit", "room": invite.room,
            "revision": message["revision"], "sender": identity.sign_key,
            "sequence": message["sequence"], "ciphertext": seal(packet, invite.owner_box)}
    return {"type": "submit", **identity.sign(body)}


def open_submit(packet, owner_identity, invite, current_revision, members):
    """Authenticate a submission; caller must decrypt_message before release."""
    if owner_identity.sign_key != invite.owner or owner_identity.box_key != invite.owner_box:
        raise ValueError("Only the pinned owner can open submissions.")
    if not isinstance(packet, dict) or not isinstance(packet.get("body"), dict):
        raise ValueError("Invalid submission.")
    sender = packet["body"].get("sender")
    if not isinstance(sender, str) or sender not in members or sender == invite.owner:
        raise ValueError("Submission from an unapproved device.")
    body = verify(packet, sender)
    if (body.get("kind") != "submit" or body.get("room") != invite.room
            or type(body.get("revision")) is not int or body["revision"] != current_revision
            or type(body.get("sequence")) is not int or not 1 <= body["sequence"] <= 2**53):
        raise ValueError("Stale or invalid submission.")
    message_packet = owner_identity.open(body.get("ciphertext"))
    message = _message_header(message_packet, invite, current_revision)
    for key in ("room", "revision", "sender", "sequence"):
        if message[key] != body[key]:
            raise ValueError("Submission binding failed.")
    return message_packet


def make_release(owner_identity, invite, message_packet):
    """Certify that the owner authorized release of this exact message packet."""
    if owner_identity.sign_key != invite.owner or owner_identity.box_key != invite.owner_box:
        raise ValueError("Only the pinned owner can release messages.")
    message = _message_header(message_packet, invite)
    body = {"kind": "release", "room": invite.room,
            "revision": message["revision"], "packet": message_packet}
    return {"type": "release", **owner_identity.sign(body)}


def open_release(packet, invite, current_revision):
    body = verify(packet, invite.owner)
    if (body.get("kind") != "release" or body.get("room") != invite.room
            or type(body.get("revision")) is not int or body["revision"] != current_revision):
        raise ValueError("Stale or invalid owner release.")
    message_packet = body.get("packet")
    _message_header(message_packet, invite, current_revision)
    return message_packet
