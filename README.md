# Den

Previously named Hush. The `hush` command is
retained as an alias. Existing Tor configuration directories (such as `HushTor`)
and onion addresses do not need to change. New invites start with `den1.`;
Den also accepts legacy `hush1.` invites.

Version 0.2 adds automatic Tor startup and single-command room hosting. Existing
Tor configurations remain usable through explicit external-Tor mode.

Private, live text rooms in a terminal. Pick a username, create a room, share a
secret invite, and approve the devices that can participate. No account, email,
phone number, or password is required.

**Status: working experimental prototype, not an independently audited secure
messenger.** Normal connections require Tor. A separate, explicitly named local
test mode makes it possible to try the app on one computer without Tor.

## Installation

Requires Python **3.12 or newer**. Tor is a separate prerequisite for networking
between devices; it is not bundled or installed by pip. The package name is
[`den-terminal`](https://pypi.org/project/den-terminal/), and its command is `den`.
Use `pip install den-terminal`, with the hyphen; `denterminal` is not the
published package name.

Install it on **each computer** into a virtual environment:

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install den-terminal
.\.venv\Scripts\den.exe --help
.\.venv\Scripts\Activate.ps1
```

Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install den-terminal
.venv/bin/den --help
source .venv/bin/activate
```

The remaining networking examples use `den` with this environment activated.
Activate it again in each new terminal, or replace `den` with the full executable
path shown above if PowerShell blocks activation. `python -m den` also works
using the environment's Python. If you already installed the package into your
current Python environment and `den --help` works, continue to the Tor setup.
For development, use the source installation instructions below.

## What this version does

- Starts and stops its own Tor process; `den create` can also host the relay and
  a fresh onion service automatically. Tor must be installed once on each PC.
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
- Keeps rooms and identities in memory. Den writes no chat history, user
  database, message logs, or invite files.
- Closes the entire room when its owner disconnects. There is no reconnection,
  offline inbox, history recovery, file transfer, audio, or video in this version.

## Try a local room

After installation, open Windows Terminal / PowerShell in the directory where
you created the virtual environment and run:

```powershell
.\.venv\Scripts\den.exe demo
```

The demo starts a temporary loopback relay and three clients using real
encryption. It exercises admission, chat, locking, removal, and room closure,
then stops all of them. **It does not use Tor or demonstrate network anonymity.**

For an interactive local test, keep each command running in a separate terminal
tab, with that same directory as its working directory. On Linux, replace
`.\.venv\Scripts\den.exe` with `.venv/bin/den`:

```powershell
# Tab 1: relay
.\.venv\Scripts\den.exe relay

# Tab 2: room owner
.\.venv\Scripts\den.exe create --server 127.0.0.1 --local-test --name Alice

# Tab 3: another participant; paste the invite at the hidden prompt
.\.venv\Scripts\den.exe join --local-test --name Bob

# Tab 4: third participant
.\.venv\Scripts\den.exe join --local-test --name Cara
```

In Alice's tab, type `/approve Bob` and `/approve Cara` after their requests
appear. All three can now type messages. Use `/quit` to leave; quitting the
owner's session ends the room. Local test invites only work on the same
computer and only with `--local-test`.

## Install from source

Clone the repository, then install from the checkout. Copy source rather than
an existing `.venv` when transferring the project between machines. Tor private
keys are not part of this project and should not be copied with it.

Windows PowerShell:

```powershell
git clone https://github.com/Dol0resH8ze/hush.git
cd hush
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\den.exe --help
```

Linux:

```bash
git clone https://github.com/Dol0resH8ze/hush.git
cd hush
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/den --help
```

You can activate the environment to use the short command `den`. Otherwise use
the full executable path above. The equivalent `python -m den` also works when
using this environment's Python.

## Connect Windows and Linux over Tor

**New in 0.2: one terminal per participant.** Den starts and configures Tor
for you. Creating a room without `--server` also starts a temporary loopback
relay and a fresh onion service on the owner's computer.

This behavior requires version 0.2.0 or newer. The earlier 0.1.0 PyPI release
requires the manual setup. Install this checkout to try the update before it
is published, or upgrade with `python -m pip install --upgrade den-terminal`
after publication.

### Install Tor once on each PC

Tor is still a separate prerequisite; pip does not install it. You do not need
to prepare a `torrc`, start a separate Tor terminal, or look up a hostname file
for automatic mode.

- **Windows:** download and verify the appropriate Expert Bundle from the
  [Tor Project](https://www.torproject.org/download/tor/), then extract the entire
  bundle, keeping its DLLs beside `tor.exe`. Den checks `PATH` and existing
  bundles beneath `%LOCALAPPDATA%\DenTor\bundle`,
  `%LOCALAPPDATA%\HushTor\bundle`, and `%LOCALAPPDATA%\DenDropTor\bundle`.
- **Linux:** install the `tor` executable using the
  [Tor Project's distribution instructions](https://support.torproject.org/little-t-tor/).
  Den discovers it on `PATH`.
- If discovery does not find your installation, pass `--tor-exe` followed by
  the full path to the executable on that PC.

Den launches an isolated Tor instance with a dynamically selected loopback
SOCKS port and a private temporary data directory. Existing Tor processes,
configuration, and onion keys are left alone. A missing or failed Tor instance
never causes a direct-network connection.

### Host a room on either PC

In an activated environment, run:

```text
den create --name Alice
```

Without activation, from the Windows project folder:

```powershell
.\.venv\Scripts\den.exe create --name Alice
```

Wait for the Tor bootstrap progress and room creation. Share the full `den1.`
invite privately and keep this terminal open. No separate `den relay`, router
port forwarding, or public server is needed.

### Join on another PC

```text
den join --name Bob
```

Paste the invite at the hidden prompt. Den starts its own Tor client and sends
the admission request. On Alice's terminal, type `/approve Bob` after checking
the participant's session fingerprint. Repeat for additional participants.

The PCs can be on different networks. Do not add `--local-test` for cross-device
connections. Use distinct usernames within the room.

If Tor's path must be specified, use it on either command, for example:

```powershell
den create --name Alice --tor-exe "C:\Tools\tor\tor.exe"
den join --name Bob --tor-exe "C:\Tools\tor\tor.exe"
```

These are alternative commands for the owner and joining PC, respectively.

### Ending and starting again

Use `/quit` or Ctrl+C. Den stops the Tor process it started and attempts to
remove its temporary configuration, data and onion keys. Owner departure closes
both the room and its automatic relay; other clients leave when the room closes.
Den does not stop a Tor process or relay that you started separately.

A new automatic hosting session gets a new onion address, room and invite.
Start with `den create` again and share the new invite. Normal cleanup is not
secure erasure; a crash, forced kill, power loss or file-lock error can leave
Tor runtime files behind. Den's own chat history remains unsaved.

### Existing relays and manually managed Tor

Your earlier setup remains available:

| Command | Behavior |
| --- | --- |
| `den create --name Alice` | Start a local relay, Tor, and fresh onion service |
| `den create --server ADDRESS.onion --name Alice` | Start only a Tor client and connect to that existing relay |
| `den join --name Bob` | Start a Tor client and join the invite's relay |
| `den create --server ADDRESS.onion --external-tor --name Alice` | Use an already-running Tor SOCKS proxy on port 9050 |
| `den join --external-tor --name Bob` | Join through an already-running Tor SOCKS proxy on port 9050 |
| `den join --proxy-port 9150 --name Bob` | Explicit proxy port also selects externally managed Tor |
| `den relay` | Run the separate loopback relay, as before |

Use a real v3 onion address in place of `ADDRESS.onion`. An externally managed
Tor client requires an existing relay for `create`; supply `--server`. An
explicit `--proxy-port` preserves the earlier manually managed behavior.
`--tor-exe` cannot be combined with `--external-tor`, `--proxy-port`, or
`--local-test`. Automatic hosting uses onion port 8765; `create --port` selects
a destination port only when connecting to an existing server.

See [manual Tor setup](https://github.com/Dol0resH8ze/hush/blob/main/docs/MANUAL-TOR.md)
for the earlier multi-terminal workflow, persistent onion addresses, and custom
Tor configurations such as bridges. The current automatic mode does not configure
bridges. The supplied [relay](https://github.com/Dol0resH8ze/hush/blob/main/examples/torrc.relay.example)
and [client](https://github.com/Dol0resH8ze/hush/blob/main/examples/torrc.client.example)
configuration examples remain available.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `den` is not recognized | Install Den on that PC and activate its environment, or use the full executable path. |
| `create` still requires `--server` | You are running the older release. Install this checkout or upgrade after version 0.2.0 is published. |
| `Tor was not found` | Install/extract Tor once, or pass `--tor-exe` with its actual executable path. |
| Tor could not start | Keep its bundle files/DLLs together; check that the binary matches your OS and architecture. |
| Tor bootstrap times out | Check internet access and whether the network blocks Tor. Automatic startup waits up to three minutes; use external Tor if you need bridges/custom configuration. |
| Tor reached 100%, but connection failed | A new onion service may still be propagating. For an existing relay, check that it remains online and its port mapping is correct. No direct fallback is attempted. |
| SOCKS connection refused in external mode | Start your own Tor and check `--proxy-port` (9050 by default). |
| `HushTor` or `onion/hostname` is missing | Automatic mode requires only the installed executable; it manages runtime paths itself. Those fixed files are relevant only to the manual setup guide. |
| Join is waiting | The owner must stay connected and approve the pending request; check `/pending` and whether the room is locked. |
| An old invite no longer works | Ask for the current room's invite. Closed rooms cannot be restored. |
| `Could not find platform independent libraries <prefix>` | This is a Python runtime issue. If commands fail, repair Python and recreate the virtual environment. |

Onion connection setup can take up to two minutes after Tor bootstrap. Keep
invites and Tor private keys out of bug reports. A successful connection is not
a guarantee of anonymity.

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
The input line clears after submission, so your own message appears once in
the chat rather than remaining duplicated as typed input.

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
| Relay over normal Tor connections | Tor-side connections; no participant IP field is sent by Den |
| Someone with an invite | Relay onion address, room ID, admission secret, owner public keys; ability to request entry |

The invite is **encoded, not encrypted**. Treat it as a secret. Any admitted
participant can copy a message or share what they know. Reusing a recognizable
username or disclosing personal information can identify you. Tor cannot promise
perfect anonymity, and traffic correlation remains possible.

No app history does not mean no traces: terminal scrollback, clipboard tools,
screen recording, OS swap, crash dumps and compromised endpoints may retain
content. Session keys are not written by Den, but Python does not guarantee
secure memory erasure. The current protocol has no forward secrecy or
post-compromise recovery: stolen recipient keys can decrypt previously captured
ciphertext for that session. The owner is a trusted participant and controls
membership and release availability. See [SECURITY.md](https://github.com/Dol0resH8ze/hush/blob/main/SECURITY.md) for details.

Keep actual Tor identity keys outside source control and shared or synced
folders; the supplied Tor configuration is only an example.

## Development and verification

```text
python -m pip install -e ".[dev]"
python -m pytest -q
python -m den demo
```

Use the virtual environment's Python. Tests cover a real loopback relay with
three independent client identities, admission, lock/unlock, disconnect cleanup,
encryption, signatures, replay rejection, removal, malformed traffic, and SOCKS
transport failure behavior. A Windows/Linux CI matrix is supplied under
`.github/workflows/test.yml`. See the repository's Actions tab for remote run
results and [the validation notes](https://github.com/Dol0resH8ze/hush/blob/main/docs/VALIDATION.md)
for recorded checks and their limits.

Architecture and the wire flow are documented in [the protocol notes](https://github.com/Dol0resH8ze/hush/blob/main/docs/PROTOCOL.md).
Maintainers can follow [the release guide](https://github.com/Dol0resH8ze/hush/blob/main/docs/RELEASING.md).

## Next milestones

1. Expand repeatable real-onion testing across independent Windows/Linux devices.
2. Review the protocol and implementation externally, and evaluate migrating
   to an established group protocol such as MLS with suitable library support.
3. Add delivery acknowledgements and safer recovery around membership changes.
4. Package signed standalone executables after the protocol and dependency
   choices are reviewed. Current installation uses Python, not an installer.

