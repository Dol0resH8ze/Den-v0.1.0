# Den

Previously named Hush. The `hush` command is
retained as an alias. Existing Tor configuration directories (such as `HushTor`)
and onion addresses do not need to change. New invites start with `den1.`;
Den also accepts legacy `hush1.` invites.

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
  offline inbox, history recovery, file transfer, audio, or video in version 0.1.

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

**Either computer can host**, regardless of which one originally installed Den.
For the simplest setup, the host runs both the relay and the room owner's client.

| Computer | Keep running | Tor configuration |
| --- | --- | --- |
| Host / owner | Tor, `den relay`, `den create` (three terminals) | SOCKS listener and onion service |
| Each joining device | Tor, `den join` (two terminals) | SOCKS listener only |

A relay forwards encrypted traffic between clients. Den does not bundle,
download, start, or configure Tor, and no shared public relay is supplied.
The relay binds to loopback; no router port forwarding is needed. The computers
can be on different networks. Do not use `--local-test` between computers.

### Windows: install Tor on each PC once

If Tor is already configured and working, reuse it and skip the installation.
Do not overwrite an existing `torrc` or start a second Tor on the same SOCKS port.

1. Download a stable Windows Expert Bundle matching your architecture from the
   [official Tor downloads](https://download.torproject.org/tor/). Follow the
   [Tor installation guidance](https://support.torproject.org/little-t-tor/)
   to verify it. These steps use the Expert Bundle, not Tor Browser.
2. Save the archive in Downloads as `hush-tor.tar.gz`.
3. In PowerShell, extract it and create a client configuration. These paths
   automatically use the current Windows account:

```powershell
$torRoot = "$env:LOCALAPPDATA\HushTor"
New-Item -ItemType Directory -Force "$torRoot\bundle" | Out-Null
tar.exe -xf "$env:USERPROFILE\Downloads\hush-tor.tar.gz" -C "$torRoot\bundle"
$torConfigRoot = $torRoot.Replace('\', '/')
if (-not (Test-Path "$torRoot\torrc")) {
    @"
DataDirectory "$torConfigRoot/data"
SocksPort 127.0.0.1:9050
SafeSocks 1
Log notice stdout
"@ | Set-Content "$torRoot\torrc" -Encoding ascii
}
```

The `HushTor` directory name is retained for compatibility with earlier setup
instructions; it works with Den. Installing the Python package does not create it.

### Windows: enable hosting on the chosen PC

Only the host needs this step. If Tor is running in a terminal, stop it with
Ctrl+C before editing its configuration. Open the file:

```powershell
$torRoot = "$env:LOCALAPPDATA\HushTor"
$torConfigRoot = $torRoot.Replace('\', '/')
Write-Output "HiddenServiceDir `"$torConfigRoot/onion`""
Write-Output 'HiddenServicePort 8765 127.0.0.1:8765'
notepad "$torRoot\torrc"
```

Copy the **two lines printed by PowerShell** into the end of that file and save
it. Keep the existing settings. Add these lines only once; if this onion service
is already configured, reuse it. This also converts a previously joining PC
into a host. See the [onion service guide](https://community.torproject.org/onion-services/setup/)
for how Tor creates the service's keys and `hostname` file.

### Windows: start the host

**Terminal 1 — Tor:**

```powershell
$torRoot = "$env:LOCALAPPDATA\HushTor"
$torExe = Get-ChildItem "$torRoot\bundle" -Filter tor.exe -Recurse |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $torExe) { throw 'Tor was not found. Extract the Expert Bundle first.' }
& $torExe -f "$torRoot\torrc"
```

Wait for `Bootstrapped 100% (done): Done` and keep this terminal open.
That means Tor connected; the onion service may still need time to become
reachable. Use `Log notice stdout` as above to avoid verbose debug output.

**Terminal 2 — relay:** activate your Den environment, then run:

```powershell
den relay --port 8765
```

Keep this terminal open too.

**Terminal 3 — room owner:** activate your Den environment, then run:

```powershell
$hostnameFile = "$env:LOCALAPPDATA\HushTor\onion\hostname"
if (-not (Test-Path $hostnameFile)) {
    throw 'No hostname yet. Check the host torrc and restart Tor with that file.'
}
$onionAddress = (Get-Content $hostnameFile -Raw).Trim()
den create --server $onionAddress --name Alice
```

Replace `Alice` with your display name. Share the entire `den1.` invite privately
with the people joining. Keep the owner client running: closing it ends the room.

### Windows: join from another PC

Install Den and set up Tor on that PC using the steps above. A joining PC does
not need `HiddenServiceDir`, a `hostname` file, or its own relay.

In terminal 1, run the same Tor startup block shown above and wait for 100%.
In terminal 2, activate your Den environment and run:

```powershell
den join --name Bob
```

Paste the owner's full invite at the hidden prompt and press Enter. The invite
will not appear while you paste it. On the **owner's** terminal, after the request
arrives, type:

```text
/approve Bob
```

Repeat for each device with a different username. If the other PC is the host,
run all three host terminals there and just Tor plus `den join` on your PC.

### Linux participants and hosts

Install Tor using the [Tor Project's installation guidance](https://support.torproject.org/little-t-tor/)
for your distribution. Configure its active `torrc` with a local SOCKS listener:

```text
SocksPort 127.0.0.1:9050
SafeSocks 1
```

If Linux is hosting the relay, also add the following, using a private directory
writable by the account running Tor. `/var/lib/tor/den/` is an example for a
system Tor service; consult your distribution's permissions and service setup.

```text
HiddenServiceDir /var/lib/tor/den/
HiddenServicePort 8765 127.0.0.1:8765
```

Restart Tor with the edited configuration and check its log for successful
bootstrap. A service-managed Tor can run in the background. On a Linux host,
run `den relay` in one terminal, read the onion address from the service's
`hostname` file with the required permissions, then run in another terminal:

```bash
den create --server YOUR_REAL_V3_ADDRESS.onion --name Alice
```

Replace the placeholder with the actual address, with no `http://` prefix.
A Linux participant joining either a Windows or Linux host runs:

```bash
den join --name Bob
```

Paste the invite and wait for the owner to approve you. See the supplied
[relay](https://github.com/Dol0resH8ze/hush/blob/main/examples/torrc.relay.example)
and [client](https://github.com/Dol0resH8ze/hush/blob/main/examples/torrc.client.example)
configuration examples. If Tor uses another SOCKS port, add `--proxy-port PORT`
to `den create` or `den join` on that computer.

### Starting again another day

Reuse the installed packages and Tor configuration. Start Tor on each computer,
then the host's relay and owner client. Share the **new** invite, join, and approve
each participant again. The onion address persists while the host's Tor service
keys remain intact, but rooms, invites, device fingerprints, and chat history do
not survive the room closing. Do not copy a `.venv` or Tor private keys to move
hosting to another computer; set up that computer with its own onion service.

Initial manual cross-device use has been reported successful. Automated transport
checks use a local SOCKS5 server with DNS lookups disabled. Neither local tests
nor a successful connection establish a guarantee of anonymity.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `den` is not recognized | Activate the environment where Den was installed, or use its full executable path. Install Den separately on every PC. |
| `.\.venv\Scripts\hush.exe` is not recognized | That relative path only works in the folder containing that environment. Use the installed `den` command or the correct full path. |
| `HushTor` or `bundle` does not exist | Download and extract Tor on that PC. `pip install` installs Den only. |
| `onion\hostname` does not exist | Hosting requires both hidden-service lines in the configuration Tor actually loads. Restart Tor with `-f` pointing to that file and check its errors. Joining alone does not create this file. Do not create it manually. |
| Lots of Tor output, no visible bootstrap percentage | Set `Log notice stdout`, restart with that configuration, and inspect the startup log. Look for bootstrap completion and any errors. |
| Connection failed even after Tor reached 100% | Keep the relay running, check the onion address and port mapping, and allow time for the onion service to become reachable. Bootstrap alone does not prove the relay is reachable. |
| SOCKS connection refused | Check that Tor is running and listening on the port Den uses (9050 by default). Set `--proxy-port` if it differs. |
| Address/port already in use | Reuse the existing Tor or relay process, or stop your duplicate process before starting another. |
| Join is waiting | The owner must remain connected and approve the pending request. Check `/pending` and whether the room is locked. |
| An old invite no longer works | Ask the owner for the current room's invite. Closed rooms cannot be restored. |
| `Could not find platform independent libraries <prefix>` | This is a Python runtime warning. If commands fail, repair the Python installation and recreate the virtual environment; it does not by itself diagnose a Tor failure. |

Onion connection setup can take up to 120 seconds before Den times out. Normal
mode never retries over a direct internet connection. Keep invites and Tor
private keys out of bug reports.

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

