"""Automatic hosting exercises the real relay and SOCKS path without public Tor."""

import asyncio
import base64
import contextlib
import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from den import cli
from den.client import RoomClient
from den.crypto import Identity, Invite
from den.relay import Relay
from den.tor import TorError
from den.transport import STREAM_LIMIT, read_frame


def onion_address():
    key, version = bytes(range(32)), b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + key + version).digest()[:2]
    return base64.b32encode(key + checksum + version).decode().lower() + ".onion"


def invite_code():
    return Invite.create(onion_address(), 8765, Identity()).encode()


def arguments(*values):
    return cli.parser().parse_args(values)


@pytest.mark.parametrize("values,invite,match", [
    (("create", "--local-test"), None, "requires --server"),
    (("create", "--external-tor"), None, "requires --server"),
    (("create", "--proxy-port", "9050"), None, "requires --server"),
    (("create", "--port", "80"), None, "--port requires --server"),
    (("create", "--server", "127.0.0.1"), None, "v3 .onion"),
    (("create", "--server", "example.com", "--external-tor"), None, "v3 .onion"),
    (("create", "--local-test", "--server", "192.168.1.2"), None, "loopback"),
    (("create", "--local-test", "--tor-exe", "tor.exe"), None, "cannot be combined"),
    (("create", "--local-test", "--external-tor"), None, "cannot be combined"),
    (("create", "--local-test", "--proxy-port", "9050"), None, "cannot be combined"),
    (("create", "--tor-exe", "tor.exe", "--external-tor"), None, "cannot be combined"),
    (("create", "--tor-exe", "tor.exe", "--proxy-port", "9050"), None, "cannot be combined"),
    (("join",), "private-malformed-invite", "Invalid Den invite"),
    (("join", "--external-tor"), "den1.bad", "Invalid invite"),
])
async def test_invalid_input_never_starts_resources(monkeypatch, values, invite, match):
    no_resource = Mock(side_effect=AssertionError("Resources must not be started"))
    monkeypatch.setattr(cli, "ManagedTor", no_resource)
    monkeypatch.setattr(cli, "Relay", no_resource)
    with pytest.raises(ValueError, match=match):
        await cli.chat(arguments(*values), "Alice", invite)
    no_resource.assert_not_called()


@pytest.mark.parametrize("flag,value", [("--port", "0"), ("--port", "65536"),
    ("--port", "oops"), ("--proxy-port", "-1"), ("--proxy-port", "65536")])
def test_invalid_ports_rejected_by_parser(flag, value):
    with pytest.raises(SystemExit):
        arguments("create", flag, value)


@pytest.mark.parametrize("values,expected", [
    (("--external-tor",), 9050), (("--proxy-port", "9150"), 9150),
    (("--external-tor", "--proxy-port", "19050"), 19050),
])
@pytest.mark.parametrize("command", ["create", "join"])
async def test_external_tor_does_not_start_process_or_relay(monkeypatch, values, expected, command):
    no_resource = Mock(side_effect=AssertionError("External mode must reuse Tor"))
    session = AsyncMock()
    monkeypatch.setattr(cli, "ManagedTor", no_resource)
    monkeypatch.setattr(cli, "Relay", no_resource)
    monkeypatch.setattr(cli, "_chat_session", session)
    server = ("--server", onion_address(), "--port", "12345") if command == "create" else ()
    args = arguments(command, *server, *values)
    await cli.chat(args, "Alice", invite_code() if command == "join" else None)
    actual = session.await_args.args[0]
    assert actual.proxy_port == expected
    assert not actual.local_test
    if command == "create":
        assert actual.port == 12345
    no_resource.assert_not_called()


async def test_local_mode_uses_existing_loopback_without_tor(monkeypatch):
    no_resource = Mock(side_effect=AssertionError("Local mode does not start Tor"))
    session = AsyncMock()
    monkeypatch.setattr(cli, "ManagedTor", no_resource)
    monkeypatch.setattr(cli, "Relay", no_resource)
    monkeypatch.setattr(cli, "_chat_session", session)
    await cli.chat(arguments("create", "--local-test", "--server", "127.0.0.1"), "Alice")
    assert session.await_args.args[0].local_test
    no_resource.assert_not_called()


@pytest.mark.parametrize("command", ["create", "join"])
async def test_managed_client_for_existing_onion_does_not_host(monkeypatch, command):
    tor = Mock(socks_port=19051, onion_host=None)
    manager = Mock(__aenter__=AsyncMock(return_value=tor), __aexit__=AsyncMock())
    factory = Mock(return_value=manager)
    session = AsyncMock()
    monkeypatch.setattr(cli, "ManagedTor", factory)
    monkeypatch.setattr(cli, "Relay", Mock(side_effect=AssertionError("Not a new host")))
    monkeypatch.setattr(cli, "_chat_session", session)
    server = ("--server", onion_address()) if command == "create" else ()
    await cli.chat(arguments(command, *server, "--tor-exe", "installed-tor.exe"), "Alice",
                   invite_code() if command == "join" else None)
    assert factory.call_args.kwargs["service_port"] is None
    assert factory.call_args.kwargs["executable"] == Path("installed-tor.exe")
    assert session.await_args.args[0].proxy_port == 19051
    manager.__aexit__.assert_awaited_once()


async def test_tor_startup_failure_closes_auto_relay(monkeypatch):
    relay = Relay()
    monkeypatch.setattr(cli, "Relay", lambda: relay)
    manager = Mock(__aenter__=AsyncMock(side_effect=TorError("Tor startup failed")),
                   __aexit__=AsyncMock())
    monkeypatch.setattr(cli, "ManagedTor", Mock(return_value=manager))
    with pytest.raises(TorError, match="startup failed"):
        await cli.chat(arguments("create"), "Alice")
    assert relay.server is None
    assert not relay._sessions


@pytest.mark.parametrize("cancel", [False, True])
async def test_auto_relay_closes_before_tor_after_failure_or_cancellation(monkeypatch, cancel):
    relay = Relay()
    monkeypatch.setattr(cli, "Relay", lambda: relay)
    tor = Mock(socks_port=19051, onion_host=onion_address())

    async def tor_exit(*_):
        assert relay.server is None
        assert not relay._sessions

    manager = Mock(__aenter__=AsyncMock(return_value=tor), __aexit__=AsyncMock(side_effect=tor_exit))
    monkeypatch.setattr(cli, "ManagedTor", Mock(return_value=manager))
    reader = writer = None
    entered = asyncio.Event()

    async def session(*_):
        nonlocal reader, writer
        reader, writer = await asyncio.open_connection(*relay.address[:2])
        await asyncio.sleep(0)
        entered.set()
        if cancel:
            await asyncio.Event().wait()
        raise ConnectionError("connection interrupted")

    monkeypatch.setattr(cli, "_chat_session", session)
    task = asyncio.create_task(cli.chat(arguments("create"), "Alice"))
    try:
        async with asyncio.timeout(10):
            await entered.wait()
            if cancel:
                task.cancel()
            with pytest.raises(asyncio.CancelledError if cancel else ConnectionError):
                await task
            assert await read_frame(reader) == {"type": "closed", "reason": "Relay stopped."}
            assert await reader.read() == b""
        manager.__aexit__.assert_awaited_once()
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_managed_host_and_join_use_real_socks_and_encrypted_room(monkeypatch):
    """Only Tor's process is replaced: SOCKS, authentication and chat are real."""
    destinations = []
    instances = []
    host_relay = Relay()
    monkeypatch.setattr(cli, "Relay", lambda: host_relay)

    class TestTor:
        def __init__(self, *, executable, service_port, status):
            self.service_port = service_port
            self.onion_host = onion_address() if service_port else None
            self.tasks = set()
            self.writers = set()
            instances.append(self)

        async def __aenter__(self):
            self.server = await asyncio.start_server(self.accept, "127.0.0.1", 0, limit=STREAM_LIMIT)
            self.socks_port = self.server.sockets[0].getsockname()[1]
            return self

        def accept(self, reader, writer):
            self.writers.add(writer)
            task = asyncio.create_task(self.forward(reader, writer))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

        async def forward(self, reader, writer):
            upstream = None
            pumps = []
            try:
                assert await reader.readexactly(3) == b"\x05\x01\x00"
                writer.write(b"\x05\x00")
                await writer.drain()
                assert await reader.readexactly(4) == b"\x05\x01\x00\x03"
                size = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(size)).decode("ascii")
                port = int.from_bytes(await reader.readexactly(2), "big")
                destinations.append((host, port))
                assert (host, port) == (onion_address(), 8765)
                upstream_reader, upstream = await asyncio.open_connection(*host_relay.address[:2])
                self.writers.add(upstream)
                writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
                await writer.drain()

                async def pump(source, target):
                    while data := await source.read(65536):
                        target.write(data)
                        await target.drain()

                pumps = [asyncio.create_task(pump(reader, upstream)),
                         asyncio.create_task(pump(upstream_reader, writer))]
                await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in pumps:
                    task.cancel()
                await asyncio.gather(*pumps, return_exceptions=True)
                for stream in (writer, upstream):
                    if stream is not None:
                        stream.close()
                        with contextlib.suppress(ConnectionError):
                            await stream.wait_closed()
                        self.writers.discard(stream)

        async def __aexit__(self, *_):
            if self.service_port:
                assert host_relay.server is None
            self.server.close()
            for writer in tuple(self.writers):
                writer.close()
            if self.tasks:
                await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
            await self.server.wait_closed()

    monkeypatch.setattr(cli, "ManagedTor", TestTor)
    owner_ready = asyncio.Event()
    delivered = asyncio.Event()
    clients = {}

    async def session(args, name, invite=None):
        assert args.local_test is False
        network = {"proxy_port": args.proxy_port, "local_test": args.local_test}
        if args.command == "create":
            client = await RoomClient.create(name, args.server, args.port, **network)
        else:
            client = await RoomClient.join(name, invite, **network)
        clients[name] = client
        try:
            if client.is_owner:
                owner_ready.set()
                while not client.pending:
                    await asyncio.sleep(0.01)
                await client.approve("Bob")
                await client.send_text("private managed-Tor message")
                await delivered.wait()
            else:
                while True:
                    event = await client.events.get()
                    if event["type"] == "chat":
                        assert event["name"] == "Alice"
                        assert event["text"] == "private managed-Tor message"
                        delivered.set()
                        break
        finally:
            await client.close()

    monkeypatch.setattr(cli, "_chat_session", session)
    owner = asyncio.create_task(cli.chat(arguments("create"), "Alice"))
    joiner = None
    try:
        async with asyncio.timeout(10):
            await owner_ready.wait()
            joiner = asyncio.create_task(cli.chat(arguments("join"), "Bob", clients["Alice"].invite.encode()))
            await asyncio.gather(owner, joiner)
        assert destinations == [(onion_address(), 8765)] * 2
        assert instances[0].service_port is not None
        assert instances[1].service_port is None
        assert all(client.closed.is_set() for client in clients.values())
        assert host_relay.server is None
        assert not host_relay._sessions
    finally:
        for task in (owner, joiner):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(*(task for task in (owner, joiner) if task is not None), return_exceptions=True)


def test_managed_tor_failure_is_reported_without_traceback(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["den", "create", "--name", "Alice"])
    monkeypatch.setattr(cli, "chat", AsyncMock(side_effect=TorError("Tor was not found. Use --tor-exe.")))
    assert cli.main() == 1
    output = capsys.readouterr().err
    assert "Tor was not found" in output
    assert "Traceback" not in output
