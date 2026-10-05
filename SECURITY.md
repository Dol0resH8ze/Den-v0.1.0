# Security scope of Den 0.1

Den is an experimental implementation, not an audited anonymity product. Do not
interpret its UI, test results, or Tor routing as a guarantee that everything is
hidden. This file states what the code attempts to protect and where it stops.

## Cryptography and trust

Den uses PyNaCl/libsodium's sealed boxes and Ed25519 signatures, rather than
implementing cipher algorithms. Sealed boxes provide encryption and integrity,
but do not authenticate the sender on their own. Den's signed envelopes bind
the sender, room, membership revision, sequence and recipient data.

This composition is a **new application protocol**, not MLS, Signal Protocol,
or an independently reviewed group messenger. Standard algorithms alone do not
establish overall security. See the primary documentation for
[sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes),
[PyNaCl encryption](https://pynacl.readthedocs.io/en/latest/public/),
[signatures](https://pynacl.readthedocs.io/en/latest/signing/), and the established
[MLS protocol](https://www.rfc-editor.org/info/rfc9420/).

The secret invite pins the room owner's signing and encryption keys. Distribution
of that invite is a trust bootstrap: an attacker who replaces the entire invite
can direct someone to a different room. The owner sees pending users' names and
keys and approves them. Usernames alone do not prove an individual's identity.
There is no durable username registration or account recovery.

## Membership and removal

Only the owner can sign membership updates. Clients refuse invalid signatures,
changed owner keys, duplicate names or keys, invalid encryption keys, replacement
of their own encryption key, and unexpected old roster revisions. Message
sequences are checked across membership revisions.

Each message has separate sealed ciphertext for every other approved device.
A non-owner puts the **entire signed message packet** inside an additional
sealed box addressed only to the owner. The owner verifies it against its current
roster, decrypts its own copy, and signs a release before the recipient ciphertext
is exposed to the relay. Recipient clients require that release signature.

This extra step addresses a specific removal problem: a malicious relay might
withhold a new roster from a sender. The resulting stale packet remains encrypted
to the owner and is not released for removed recipients. It does not solve all
consistency, availability or malicious-participant problems. The owner must stay
online and trustworthy. A colluding remaining member or owner can always share
plaintext with a removed person. Data already released before removal cannot be
retracted, even if it arrives afterward.

There is no shared group key to rotate. Removing a participant changes the signed
recipient roster; subsequent authorized packets exclude their public key.

## Explicit limitations

- **No forward secrecy:** session encryption keys remain valid for that room
  session. Captured messages may become readable after recipient private-key
  compromise. The extra sealed-box sender ephemeral key is not a full ratchet.
- **No post-compromise recovery:** leave and establish a new trusted session on
  clean devices; the current session cannot automatically heal a stolen key.
- **Visible metadata:** the relay sees room membership, public keys, lengths,
  timing, connection activity and the room lifecycle. There is no padding or
  cover traffic. Tor does not eliminate correlation attacks.
- **Endpoint traces:** terminal scrollback, clipboard, swap, hibernation, crash
  dumps, screen recording, OS telemetry, backups and malware are outside Den's
  control. Memory-only state is not a secure-deletion guarantee.
- **Availability:** any relay operator can drop, delay or reorder traffic, close
  rooms or deny service. Basic capacity/rate/queue bounds are not comprehensive
  denial-of-service protection. Connections can occupy slots while idle.
- **Owner authority:** the owner controls admission and message releases and can
  inspect every room message. It can admit an unwanted device. Signatures do not
  prove the human behind a username, and there is no deniability guarantee.
- **No consistent transcript proof:** a malicious sender can construct different
  recipient plaintexts. Den does not prove every member saw identical content.
- **No delivery guarantees:** there are no acknowledgements, reconnects, offline
  queues or automatic retries. Stale messages can be dropped during roster changes.
- **Local mode:** `--local-test` intentionally bypasses Tor, only for numeric
  loopback addresses. It is not an anonymous networking mode or a LAN mode.
- **External software:** Tor must be installed and correctly configured by the
  operator. Den does not authenticate that the local SOCKS process really is Tor.
- **Not yet verified:** real Tor networking and independent Linux device testing
  have not been performed for this build. CI configuration is not a passed CI run.

## Defensive implementation choices

Normal endpoints must be checksummed v3 onion addresses. The SOCKS proxy must
be a numeric loopback address; hostname resolution is remote. A failed SOCKS
connection never triggers a direct connection. Relay binding is also limited to
numeric loopback addresses so it can sit behind an onion service.

Frames have bounded sizes and strict JSON parsing, including rejection of
duplicate keys, non-finite numbers, excessive nesting and invalid Unicode.
Handshakes and writes have timeouts. The relay limits rooms, connections,
participants, per-connection traffic and outgoing queues. It does not record
request contents, room IDs or addresses in logs. Network errors are reported
without echoing arbitrary untrusted server text.

Usernames accept a limited ASCII set. Chat output removes terminal control and
Unicode formatting/control characters, preventing escape-sequence and bidi
injection through ordinary message display. Text is printed without markup
interpretation. Secret invites are entered interactively rather than passed as
command-line arguments.

Dependencies used in development are pinned in `pyproject.toml` at the direct
dependency level. There is not yet a hashed, reproducible distribution or a
signed binary release. Reassess dependencies before publishing or distributing
the application broadly.

