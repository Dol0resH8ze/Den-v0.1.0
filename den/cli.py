"""Interactive command line; no on-disk input history or client configuration."""

import argparse
import asyncio
import contextlib
import colorsys
import copy
import getpass
import hashlib
from pathlib import Path
import sys

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.formatted_text import FormattedText, to_plain_text
from prompt_toolkit.patch_stdout import patch_stdout
from python_socks import ProxyError, ProxyConnectionError

from . import __version__
from .client import RoomClient
from .crypto import Invite, fingerprint, safe_text, username
from .relay import Relay
from .tor import ManagedTor, TorError
from .transport import validate_endpoint

HELP = """Type a message and press Enter to send.
  /members                Show approved usernames and device fingerprints
  /pending                Show devices waiting for approval (owner)
  /approve NAME_OR_ID     Approve one waiting device (owner)
  /reject NAME_OR_ID      Reject one waiting device (owner)
  /kick NAME_OR_ID        Remove a participant (owner)
  /lock /unlock          Stop / allow new join requests (owner)
  /invite                 Display the secret invite (owner)
  /help                   Show this help
  /quit                   Leave; owner leaving closes the room
Use // at the start of a message to send a literal slash.
"""


def user_label(name, code, *, full_code=False):
    """Stable username color on every client; peer text is never parsed as markup."""
    digest = hashlib.sha256(name.casefold().encode("utf-8")).digest()
    hue = int.from_bytes(digest[:3], "big") / 0x1000000
    red, green, blue = colorsys.hls_to_rgb(hue, 0.70, 0.75)
    color = "#{:02x}{:02x}{:02x}".format(*(round(c * 255) for c in (red, green, blue)))
    visible_code = safe_text(code) if full_code else safe_text(code)[:8]
    return FormattedText([(f"fg:{color} bold", f"<{safe_text(name)}#{visible_code}>")])


def print_styled(fragments):
    if sys.stdout.isatty():
        print_formatted_text(fragments)
    else:
        print(to_plain_text(fragments))


def print_message(name, code, text):
    print_styled(FormattedText([*user_label(name, code), ("", safe_text(text))]))


def port_number(value):
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Port must be an integer between 1 and 65535.") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("Port must be an integer between 1 and 65535.")
    return port


def parser():
    p = argparse.ArgumentParser(prog="den", description="Den — experimental private terminal rooms.")
    p.add_argument("--version", action="version", version=f"Den {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Run a local three-client demonstration (no Tor anonymity)")
    relay = sub.add_parser("relay", help="Run a memory-only relay bound to loopback")
    relay.add_argument("--host", default="127.0.0.1")
    relay.add_argument("--port", type=int, default=8765)
    create = sub.add_parser("create", help="Start a private Tor relay and create a room")
    create.add_argument("--server", help="Use an existing relay's v3 .onion hostname (no scheme)")
    create.add_argument("--port", type=port_number, default=8765, help="Existing relay destination port (default 8765)")
    join = sub.add_parser("join", help="Join using a secret invite entered privately at the prompt")
    for command in (create, join):
        command.add_argument("--name", help="Display name; prompted if omitted")
        command.add_argument("--tor-exe", type=Path, help="Installed Tor executable; Den starts and stops its own process")
        command.add_argument("--external-tor", action="store_true", help="Use an already running Tor SOCKS proxy (default port 9050)")
        command.add_argument("--proxy-port", type=port_number, help="Use an already running Tor proxy at this local port (implies --external-tor)")
        command.add_argument("--local-test", action="store_true", help="Development only: permit direct connections to numeric loopback")
    return p


async def events(client):
    while True:
        event = await client.events.get()
        kind = event["type"]
        if kind == "chat":
            print_message(event["name"], event["fingerprint"], event["text"])
        elif kind == "join_request":
            print_styled(FormattedText([
                ("", "\nJoin request: "),
                *user_label(event["name"], event["fingerprint"], full_code=True),
                ("", f". Use /approve {event['fingerprint']}"),
            ]))
        elif kind == "roster":
            if event["admitted"]:
                print(f"Room: {event['count']} participant(s), {'locked' if event['locked'] else 'open to requests'}.")
            else:
                print("Waiting for the room owner to approve your device.")
        elif kind in ("notice", "closed"):
            print(event["text"])
            if kind == "closed":
                return


async def command(client, line):
    if not line.strip():
        return True
    if not line.startswith("/") or line.startswith("//"):
        text = line[1:] if line.startswith("//") else line
        await client.send_text(text)
        print_message(client.name, fingerprint(client.identity.sign_key), text)
        return True
    name, _, arg = line.strip().partition(" ")
    arg = arg.strip()
    if name in ("/quit", "/leave"):
        return False
    if name == "/help":
        print(HELP)
    elif name == "/members":
        if not client.admitted:
            print("Waiting for approval.")
        for key, nick in client.names.items():
            role = " owner" if key == client.invite.owner else ""
            print_styled(FormattedText([
                ("", "  "), *user_label(nick, fingerprint(key), full_code=True), ("", role),
            ]))
    elif name == "/pending":
        client._owner_only()
        if not client.pending:
            print("No pending requests.")
        for key, pending in client.pending.items():
            print_styled(FormattedText([
                ("", "  "), *user_label(pending["name"], fingerprint(key), full_code=True),
            ]))
    elif name in ("/approve", "/reject", "/kick"):
        if not arg:
            raise ValueError(f"Usage: {name} NAME_OR_DEVICE_ID")
        await {"/approve": client.approve, "/reject": client.reject, "/kick": client.kick}[name](arg)
    elif name in ("/lock", "/unlock"):
        await client.set_locked(name == "/lock")
    elif name == "/invite":
        client._owner_only()
        print("Secret invite — share privately. Anyone holding it can request admission:")
        print(client.invite.encode())
    else:
        raise ValueError("Unknown command. Type /help.")
    return True


async def chat(args, name, invite=None):
    # Validate all destinations and mode combinations before opening a listener
    # or starting Tor. In particular, do not launch Tor for a malformed invite.
    args = copy.copy(args)
    external = args.external_tor or args.proxy_port is not None
    if args.local_test and (args.tor_exe is not None or external):
        raise ValueError("--local-test cannot be combined with Tor options.")
    if args.tor_exe is not None and external:
        raise ValueError("--tor-exe cannot be combined with --external-tor or --proxy-port.")
    if args.command == "create":
        if args.server is not None:
            validate_endpoint(args.server, args.port, local_test=args.local_test)
        elif args.local_test:
            raise ValueError("--local-test requires --server with a numeric loopback address.")
        elif external:
            raise ValueError("Creating with external Tor requires --server with an existing onion relay.")
        elif args.port != 8765:
            raise ValueError("Automatic hosting uses onion port 8765; --port requires --server.")
    else:
        Invite.parse(invite, local_test=args.local_test)

    print("DEN  /  live private rooms")
    print("Experimental protocol; not independently audited. No saved chat history.")
    if args.local_test:
        print("LOCAL TEST MODE: direct loopback traffic; Tor anonymity is DISABLED.")
    else:
        print("Tor-only connection. No direct-network fallback.")
        print("Onion connection setup may take up to two minutes.")
    if args.local_test or external:
        args.proxy_port = args.proxy_port or 9050
        await _chat_session(args, name, invite)
        return

    relay = None
    try:
        if args.command == "create" and args.server is None:
            relay = Relay()
            await relay.start("127.0.0.1", 0)
            print("Starting your room relay (loopback only)...")
        async with ManagedTor(
            executable=args.tor_exe,
            service_port=relay.address[1] if relay is not None else None,
            status=print,
        ) as tor:
            try:
                args.proxy_port = tor.socks_port
                if relay is not None:
                    args.server = tor.onion_host
                    # Both the owner and remote participants connect via Tor.
                    validate_endpoint(args.server, args.port)
                await _chat_session(args, name, invite)
            finally:
                # Close accepted connections before stopping their Tor transport.
                if relay is not None:
                    await relay.close()
                    relay = None
    finally:
        # This also covers Tor startup failure or cancellation before entry.
        if relay is not None:
            await relay.close()


async def _chat_session(args, name, invite=None):
    print("Connecting…")
    network = {"proxy_port": args.proxy_port, "local_test": args.local_test}
    client = (await RoomClient.create(name, args.server, args.port, **network)
              if args.command == "create" else await RoomClient.join(name, invite, **network))
    try:
        print_styled(FormattedText([
            ("", "Your session: "), *user_label(name, fingerprint(client.identity.sign_key), full_code=True),
        ]))
        print("Fresh device identity for this room. /help lists commands; /quit leaves.")
        if client.is_owner:
            print("Room created. Secret invite — share privately:")
            print(client.invite.encode())
        else:
            print("Join request sent. Waiting for owner approval.")
        # Clear the submitted input line; command() prints the formatted message once.
        session = PromptSession(history=None, enable_history_search=False, erase_when_done=True)
        with patch_stdout():
            printer = asyncio.create_task(events(client))
            closed = asyncio.create_task(client.closed.wait())
            try:
                while not client.closed.is_set():
                    label = FormattedText([*user_label(name, fingerprint(client.identity.sign_key)), ("", " ")])
                    prompt = asyncio.create_task(session.prompt_async(label))
                    try:
                        done, _ = await asyncio.wait({prompt, closed}, return_when=asyncio.FIRST_COMPLETED)
                        if closed in done:
                            break
                        line = prompt.result()
                        if not await command(client, line):
                            break
                    except (EOFError, KeyboardInterrupt):
                        break
                    except ValueError as exc:
                        print(str(exc))
                    finally:
                        if not prompt.done():
                            prompt.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await prompt
            finally:
                closed.cancel()
                printer.cancel()
                await asyncio.gather(closed, printer, return_exceptions=True)
    finally:
        await client.close()
    print("Left room. Den did not save the conversation; terminal scrollback may still contain it.")


def main():
    args = parser().parse_args()
    try:
        if args.command == "demo":
            from .demo import run
            asyncio.run(run())
        elif args.command == "relay":
            from .relay import serve
            asyncio.run(serve(args.host, args.port))
        else:
            if args.command == "join" and not sys.stdin.isatty():
                raise ValueError("Join from an interactive terminal so the secret invite can be entered without echo.")
            name = username(args.name if args.name else input("Username: ").strip())
            invite = getpass.getpass("Secret room invite (hidden): ").strip() if args.command == "join" else None
            asyncio.run(chat(args, name, invite))
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\nDen stopped.")
        return 0
    except TorError as exc:
        print(f"Den: {exc}", file=sys.stderr)
        return 1
    except ProxyConnectionError:
        print("Cannot reach the local Tor SOCKS proxy. Retry the command; in external-Tor mode, "
              "start Tor and check --proxy-port. No fallback attempted.", file=sys.stderr)
        return 1
    except asyncio.TimeoutError:
        print("Connection timed out while opening the onion connection or waiting for the relay. "
              "Retry after allowing time for the onion service to become reachable. With an existing "
              "relay, check that it is online. No fallback attempted.", file=sys.stderr)
        return 1
    except ProxyError as exc:
        code = getattr(exc, "error_code", None)
        detail = f" (SOCKS code 0x{code:02x})" if type(code) is int and 0 <= code <= 255 else ""
        print(f"Tor could not establish the onion connection{detail}. Check the onion service and Tor's logs. No fallback attempted.", file=sys.stderr)
        return 1
    except (OSError, ConnectionError):
        print("Connection failed. Check the relay address, Tor SOCKS port, and room owner. No fallback attempted.", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Den: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
