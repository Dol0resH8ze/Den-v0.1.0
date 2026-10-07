# Validation record

Initial build: Hush 0.1.0, 4 October 2026. Renamed to Den on 5 October 2026.

## Automatic Tor update — 7 October 2026

- Den 0.2.0: **229 tests passed** on Windows with Python 3.12.14.
- The existing three-client encrypted loopback demo passed, including approval,
  messages, locking, removal and owner-triggered closure.
- A managed host/join integration test substituted a local SOCKS server for the
  Tor process, while using the real relay, client, onion SOCKS requests,
  encryption, approval and message delivery. The owner still used the Tor
  transport path, without a hidden local-test bypass.
- Independent tests covered wrong-mode invites and real client/prompt cleanup
  on EOF, relay closure, cancellation and cancellation during Tor startup.
- Controlled process tests covered bootstrap, invalid logs/hostname, startup
  timeout, owned-process cleanup and automatic executable discovery in DenTor,
  HushTor and DenDropTor bundle directories. Proxy failures have no fallback.
- Create/join help and PowerShell example syntax were checked. The manual Tor
  workflow remains available with explicit external-Tor options.
- Both 0.2.0 release archives passed `twine check --strict`. The wheel was
  installed into a separate environment; isolated imports confirmed version
  0.2.0 and the managed Tor module came from `site-packages`. Its encrypted
  room demo, `pip check`, and the legacy `hush --version` entry point passed.
- These are local automated checks, not a public Tor deployment or an external
  security audit. Real public onion startup with this Den update, separate
  physical devices and Linux execution still require validation. Earlier user
  reports of manual Den/Den Drop use do not independently validate this update.
- The 0.2.0 update is prepared locally; it has not been uploaded to PyPI.

## Release packaging verification — 5 October 2026

- All 172 application tests passed.
- Built a source distribution and a universal Python wheel from that source
  distribution using the standard `build` frontend and setuptools.
- Both artifacts passed `twine check --strict`. Inspected their contents and
  confirmed the MIT license, README metadata and intended source files were
  included without virtual environments, Tor state or legacy source packages.
- Installed the wheel and declared dependencies into a separate environment
  using a complete Python 3.12.14 runtime. Confirmed that imports came from that
  environment's `site-packages` with Python isolated mode (`-I`).
- The installed CLI version command, three-client demo and `pip check` passed.
- No TestPyPI or PyPI upload was performed during these local checks; account
  setup and authenticated upload are separate release steps.

## Rename verification — 5 October 2026

- All 172 tests passed after renaming the Python package and commands to `den`.
- `python -m den demo` passed the encrypted three-client room flow.
- Existing Tor directories and signature-domain bytes were preserved. New
  invites use `den1.`; the parser continues to accept `hush1.` invites.

## Executed here

- Windows with Python 3.12.6: `python -m pytest -q -p no:cacheprovider` —
  **168 passed**.
- `hush demo` (the original command) — passed actual three-client encrypted room flow over loopback,
  including approval, messages, lock, removal, and owner-triggered closure.
- Interactive Windows pseudo-terminal sessions: started relay and owner,
  entered a secret invite without echo in a second client, approved that client,
  sent a message, confirmed receipt, quit the owner, observed the guest exit,
  and stopped the relay. No service was left running.
- SOCKS integration test: a local SOCKS5 server received the onion hostname as
  a domain request; local DNS functions were disabled to catch accidental
  resolution. Proxy failures had no direct-network fallback.
- Adversarial tests cover forged membership, tampered/replayed releases,
  invalid signatures and keys, malformed JSON, wrong secrets and owner pins,
  removed-recipient decryption attempts, and a relay forwarding a stale
  submission after withholding a removal roster.

The integration tests use independent identities and sockets in one process;
they are not independent physical devices. The interactive test additionally
used separate client processes on the same Windows computer.

## Still unverified

- A real Tor daemon and public onion service connection.
- Networking between independent Windows and Linux computers.
- Running the supplied Linux/Windows CI matrix on a remote CI service.
- External cryptographic review, comprehensive penetration testing,
  traffic-analysis resistance, or production-scale load.

Passing local tests is evidence for the implemented behaviors, not a guarantee
of anonymity or a substitute for the above work. The current Python installation
also emits a `Could not find platform independent libraries <prefix>` startup
warning in this environment; imports, installed commands, and all listed checks
nevertheless completed successfully. This appears to be a host Python setup
issue, not a Den message or privacy diagnostic.
