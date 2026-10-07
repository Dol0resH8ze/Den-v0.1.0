# Manual Tor and relay setup

**Either computer can host**, regardless of which one originally installed Den.
For the simplest setup, the host runs both the relay and the room owner's client.

| Computer | Keep running | Tor configuration |
| --- | --- | --- |
| Host / owner | Tor, `den relay`, `den create` (three terminals) | SOCKS listener and onion service |
| Each joining device | Tor, `den join` (two terminals) | SOCKS listener only |

A relay forwards encrypted traffic between clients. In this manual mode, you
start and configure Tor yourself. No shared public relay is supplied. Den 0.2
also offers automatic hosting as described in the README.
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
den create --server $onionAddress --external-tor --name Alice
```

Replace `Alice` with your display name. Share the entire `den1.` invite privately
with the people joining. Keep the owner client running: closing it ends the room.

### Windows: join from another PC

Install Den and set up Tor on that PC using the steps above. A joining PC does
not need `HiddenServiceDir`, a `hostname` file, or its own relay.

In terminal 1, run the same Tor startup block shown above and wait for 100%.
In terminal 2, activate your Den environment and run:

```powershell
den join --external-tor --name Bob
```

Paste the owner's full invite at the hidden prompt and press Enter. The invite
will not appear while you paste it. On the **owner's** terminal, after the request
arrives, type:

```text
/approve Bob
```

Repeat for each device with a different username. If the other PC is the host,
run all three host terminals there and just Tor plus `den join --external-tor` on your PC.

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
den create --server YOUR_REAL_V3_ADDRESS.onion --external-tor --name Alice
```

Replace the placeholder with the actual address, with no `http://` prefix.
A Linux participant joining either a Windows or Linux host runs:

```bash
den join --external-tor --name Bob
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

