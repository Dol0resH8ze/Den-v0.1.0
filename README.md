# Hush

Private, live text rooms in a terminal. Pick a username, create a room, share a
secret invite, and approve the devices that can participate. No account, email,
phone number, or password is required.

**Status: working experimental prototype, not an independently audited secure
messenger.** Normal connections require Tor. A separate, explicitly named local
test mode makes it possible to try the app on one computer without Tor.

## What this version does

- Supports up to **16 devices per room**, including the owner.
- Generates fresh signing and encryption keys for each room session. Your
  username is a display name, not a globally reserved identity.
- Creates a long random invite containing the room address, secret, and pinned
  owner keys. The room ID alone is not sufficient for approval.
- Prompts privately for the invite when joining, keeping it out of command-line
  arguments and shell command history.
- Requires the room owner to approve each joining device. Names are unique
  within a room, ignoring letter case.
- Encrypts usernames and message content on the clients. The relay forwards
  encrypted data and cannot read these fields from protocol traffic.
- Authenticates message authors and the owner's membership updates using
  signatures. Device fingerprints distinguish sessions.
- Lets the owner lock/unlock rooms, reject requests, and remove participants.
- Stops releasing new messages for removed participants. The owner validates
  each message against current membership before its recipient ciphertext is
  released, including when a sender has an outdated roster.
- Uses Tor SOCKS5 with remote hostname resolution. Normal mode accepts only
  valid v3 onion addresses and has **no direct-network fallback**.
- Keeps rooms and identities in memory. Hush writes no chat history, user
  database, message logs, or invite files.
- Closes the entire room when its owner disconnects. There is no reconnection,
  offline inbox, history recovery, file transfer, audio, or video in version 0.1.

## Try it on this Windows computer

The local virtual environment and dependencies have already been installed.
Open Windows Terminal / PowerShell in this project directory and run:

```powershell
.\.venv\Scripts\hush.exe demo
```

The demo starts a temporary loopback relay and three clients using real
encryption. It exercises admission, chat, locking, removal, and room closure,
then stops all of them. **It does not use Tor or demonstrate network anonymity.**

For an interactive local test, keep each command running in a separate terminal
tab, with the project directory as its working directory:

```powershell
# Tab 1: relay
.\.venv\Scripts\hush.exe relay

# Tab 2: room owner
.\.venv\Scripts\hush.exe create --server 127.0.0.1 --local-test --name Alice

# Tab 3: another participant; paste the invite at the hidden prompt
.\.venv\Scripts\hush.exe join --local-test --name Bob

# Tab 4: third participant
.\.venv\Scripts\hush.exe join --local-test --name Cara
```

In Alice's tab, type `/approve Bob` and `/approve Cara` after their requests
appear. All three can now type messages. Use `/quit` to leave; quitting the
owner's session ends the room. Local test invites only work on the same
computer and only with `--local-test`.

## Install on another computer

Requires Python **3.12 or newer**. Copy the project source, not `.venv` or any
Tor secret keys, to the other device. Installation needs internet access.

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\hush.exe --help
```

Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/hush --help
```

You can activate the environment to use the short command `hush`. Otherwise use
the full executable path above. The equivalent `python -m hush` also works when
using this environment's Python.

## Connect Windows and Linux over Tor

One computer runs the relay, and each participant runs Tor locally. The relay
can be on the owner's computer or a separate machine. It must remain running
throughout the session. Hush does not bundle, download, start, or configure Tor,
and no shared public relay is supplied.

1. Install and configure Tor using the
   [Tor Project's installation guidance](https://support.torproject.org/little-t-tor/).
   The [official Tor downloads](https://download.torproject.org/tor/) include
   expert bundles for Windows and Linux. Verify downloads according to Tor's
   instructions.
2. On the relay machine, run `hush relay --port 8765`. It binds only to
   `127.0.0.1`, so it is not exposed to the LAN or public internet.
3. Configure a Tor onion service to forward virtual port 8765 to
   `127.0.0.1:8765`. See [examples/torrc.relay.example](examples/torrc.relay.example)
   and the [official onion service guide](https://community.torproject.org/onion-services/setup/).
   The directory Tor creates contains a `hostname` file with your onion address.
4. On each participant's computer, configure a local Tor SOCKS port, normally
   `127.0.0.1:9050`. See [examples/torrc.client.example](examples/torrc.client.example).
   `SafeSocks 1` blocks unsafe SOCKS requests; Tor also documents
   [DNS leak checks](https://support.torproject.org/little-t-tor/troubleshooting/check-for-leaks/).
5. The owner creates a room, then shares the full invite privately:

```text
hush create --server YOUR_REAL_V3_ADDRESS.onion --name Alice
```

Other participants run:

```text
hush join --name Bob
```

They paste the invite at the hidden prompt and wait for approval. If their Tor
SOCKS listener uses another port, add `--proxy-port PORT` to `create` or `join`.
Do not add `--local-test` for connections between computers.

**Real Tor and separate Windows/Linux devices have not yet been exercised in
this workspace.** The implemented SOCKS transport was tested against a local
SOCKS5 server with DNS lookups disabled. A real Tor deployment remains a separate
validation step, not an assurance provided by passing the local tests.

## Commands inside a room

| Command | What it does |
| --- | --- |
| ordinary text + Enter | Sends a message, up to 4000 UTF-8 bytes |
| `/members` | Lists approved names and device fingerprints |
| `/pending` | Lists requests waiting for the owner |
| `/approve NAME_OR_ID` | Owner admits one pending device |
| `/reject NAME_OR_ID` | Owner declines one pending device |
| `/kick NAME_OR_ID` | Owner removes a participant |
| `/lock` | Owner closes admission and rejects current pending requests |
| `/unlock` | Owner reopens admission |
| `/invite` | Owner displays the secret invite again |
| `/help` | Shows command help |
| `/quit` or `/leave` | Leaves; the owner's departure closes the room |
| `//text` | Sends a message beginning with a literal slash |

A device ID is its displayed fingerprint; a unique prefix also works. Compare
fingerprints with your intended contacts through a trusted channel before
approval. A familiar username alone does not identify a real person.

Chat lines look like `<Alice#1575b149>Hello!`, with a consistent color for each
username and plain message text. Your own messages use the same format. The code
is the first eight characters of the device fingerprint; `/members` shows the
full fingerprint. Colors are derived from usernames consistently on every client.

Your own displayed message means it was submitted, not that every
participant received it. Messages racing a membership update can be dropped;
there are no delivery receipts or automatic retries. Check `/members` and resend
if a membership-change notice appears.

## Privacy boundaries

| Observer | Visible information |
| --- | --- |
| Approved room participants | Usernames, device fingerprints, membership and chat text |
| Room owner | The above, plus pending usernames and admission requests |
| Relay operator | Random room IDs, public device keys, room membership, connection timing, traffic sizes and encrypted payloads |
| Relay over normal Tor connections | Tor-side connections; no participant IP field is sent by Hush |
| Someone with an invite | Relay onion address, room ID, admission secret, owner public keys; ability to request entry |

The invite is **encoded, not encrypted**. Treat it as a secret. Any admitted
participant can copy a message or share what they know. Reusing a recognizable
username or disclosing personal information can identify you. Tor cannot promise
perfect anonymity, and traffic correlation remains possible.

No app history does not mean no traces: terminal scrollback, clipboard tools,
screen recording, OS swap, crash dumps and compromised endpoints may retain
content. Session keys are not written by Hush, but Python does not guarantee
secure memory erasure. The current protocol has no forward secrecy or
post-compromise recovery: stolen recipient keys can decrypt previously captured
ciphertext for that session. The owner is a trusted participant and controls
membership and release availability. See [SECURITY.md](SECURITY.md) for details.

The project is currently inside OneDrive. Keep any actual Tor identity keys
outside this synced folder; the supplied configuration is only an example.

## Development and verification

```text
python -m pip install -e ".[dev]"
python -m pytest -q
python -m hush demo
```

Use the virtual environment's Python. Tests cover a real loopback relay with
three independent client identities, admission, lock/unlock, disconnect cleanup,
encryption, signatures, replay rejection, removal, malformed traffic, and SOCKS
transport failure behavior. A Windows/Linux CI matrix is supplied under
`.github/workflows/test.yml`; it has not been run on a remote CI service.

Architecture and the wire flow are documented in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Next milestones

1. Validate an actual onion deployment between independent Windows/Linux devices.
2. Review the protocol and implementation externally, and evaluate migrating
   to an established group protocol such as MLS with suitable library support.
3. Add delivery acknowledgements and safer recovery around membership changes.
4. Package signed standalone executables after the protocol and dependency
   choices are reviewed. Current installation uses Python, not an installer.

