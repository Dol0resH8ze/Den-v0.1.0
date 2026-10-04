# Validation record

Build: Hush 0.1.0, 4 October 2026.

## Executed here

- Windows with Python 3.12.6: `python -m pytest -q -p no:cacheprovider` —
  **168 passed**.
- `hush demo` — passed actual three-client encrypted room flow over loopback,
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
issue, not a Hush message or privacy diagnostic.
