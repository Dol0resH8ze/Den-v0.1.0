# Den v0.1 protocol and implementation

This is an implementation note, not a security proof or interoperability standard.

## Components

- `den/cli.py`: interactive commands and terminal UI; hidden invite prompt.
- `den/client.py`: room session state, approval, rosters and encrypted messages.
- `den/crypto.py`: libsodium envelopes, invites and verification.
- `den/transport.py`: Tor SOCKS5, endpoint validation and bounded JSON frames.
- `den/relay.py`: loopback TCP relay with memory-only rooms and bounded queues.
- `den/demo.py`: three-client demonstration of the real protocol over loopback.

The owner is a client participant, distinct from the relay process even when
they run on the same computer. Production client connections flow through a local
Tor SOCKS proxy to the relay's onion service. Den never performs onion DNS lookups
itself. Tor forwards incoming connections to the relay's loopback listener.

## Framing and keys

Frames are JSON objects followed by one newline, limited to 524288 bytes including
the newline. JSON objects cannot contain duplicate keys, non-finite numbers,
invalid Unicode, or more than 64 nesting levels. Invalid framing closes a stream.

Binary fields are canonical URL-safe Base64 without padding. Room IDs are 32
random bytes represented as 64 lowercase hexadecimal characters. Each session
generates one Ed25519 signing key and one Curve25519 encryption key. All signing
uses `HUSH/1` followed by a NUL byte, then deterministic JSON with sorted keys,
no whitespace, ASCII escaping, and finite numeric values only.

## Creating and joining

1. The owner generates session keys, a room ID, and a 32-byte random invite secret.
2. The client sends a `hello` containing room ID, public keys, and `create` flag.
3. The relay issues a fresh random challenge. The client signs a `proof` binding
   that challenge to the room and both public keys.
4. After verification, the relay sends `ready` with the owner's public signing key.
5. The owner publishes signed roster revision 1, containing itself.
6. A joiner learns the room ID, onion endpoint, secret and owner public keys from
   the invite; it performs the same challenge exchange and checks the owner pin.
7. The joiner's signed `join` payload contains its name, keys and invite secret,
   sealed to the owner's encryption key. The relay routes it as `join_request`.
8. The owner checks the signature, keys, name uniqueness and secret, then asks
   the user to approve. Pending devices cannot decrypt room names or chat.

New invites start with `den1.` followed by Base64-encoded JSON; the parser also
accepts legacy `hush1.` invites. The signature domain remains `HUSH/1` for wire
compatibility with the original protocol. The invite is a secret
capability, not an encrypted document. The CLI never accepts it as a positional
argument, and rejects joining from non-interactive standard input.

## Roster updates

A `roster` has owner-signed fields: room, increasing revision, lock state, a list
of members' public key pairs, and `details` sealed separately to each member.
The encrypted details contain usernames and repeat the room and revision. The
relay validates the owner's signature and connection/key correspondence; each
client validates its own key, owner pin, membership uniqueness and encrypted
details. Names are case-insensitively unique within the current room.

The relay requires each roster revision to increase by exactly one. A pending
client can start from the current revision. The owner applies its own new state
before writing it, preventing its next outgoing packet from using an old roster.
Own signed echoes from prior revisions are ignored by that owner.

## Message flow

1. The sender creates a `message` with room, revision, sender key, increasing
   sequence and one sealed `text` payload for every other member. Each payload
   repeats the room, revision, sender, sequence and its recipient key.
2. A non-owner signs the message, seals the entire packet to the owner, and signs
   an outer `submit`. The relay only forwards this opaque submission to the owner.
3. The owner opens and verifies it, checks current membership and replay state,
   decrypts its copy, then signs a `release` containing the original signed packet.
4. The relay verifies both signatures, current revision, recipients and sequence,
   and forwards the release to approved recipients other than the sender.
5. Recipients validate the owner release, original sender signature, roster,
   sequence, ciphertext integrity and payload bindings before rendering the text.

Owner-authored messages go directly through the same signed release format.
The owner does not need to submit a message to itself. Direct ungated message
frames from clients are refused by the relay.

## Leaving and resource limits

Non-owner disconnects notify the owner, which removes the device and publishes
a new roster. Pending disconnects also clear their pending approval request.
Owner disconnects close the whole room and discard relay state. No room can be
recovered after its owner's process ends.

Limits include 16 approved members per room, 32 connections per room including
pending devices, 128 rooms and 256 connections per relay. Per-recipient sealed
payloads are limited to 16 KiB; the whole owner submission can be up to 384 KiB.
Messages are limited to 4000 UTF-8 bytes after control-character sanitization.
Relay outgoing queues allow up to 32 frames and 1 MiB per connection, and slow
clients are disconnected. These are prototype bounds, not a production sizing
or denial-of-service guarantee.

See `SECURITY.md` for trust assumptions, metadata exposure, missing forward
secrecy, lack of delivery guarantees and the need for independent review.
