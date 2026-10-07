import asyncio
import base64
import hashlib
from pathlib import Path
import socket
from unittest.mock import AsyncMock

import pytest

from den import tor


def onion_address():
    key = bytes(range(32))
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + key + version).digest()[:2]
    return base64.b32encode(key + checksum + version).decode().lower() + ".onion"


class FakeProcess:
    def __init__(self, output=b"", exited=False):
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(output)
        self.returncode = 1 if exited else None
        self.terminated = False
        self.killed = False
        self.done = asyncio.Event()
        if exited:
            self.stdout.feed_eof()
            self.done.set()

    def terminate(self):
        self.terminated = True
        self.returncode = 0
        self.stdout.feed_eof()
        self.done.set()

    def kill(self):
        self.killed = True
        self.terminate()

    async def wait(self):
        await self.done.wait()
        return self.returncode


READY = (
    b"Oct 07 12:00:00.000 [notice] Opened Socks listener connection (ready) on 127.0.0.1:41234\n"
    b"Oct 07 12:00:00.000 [notice] Bootstrapped 100% (done): Done\n"
)


@pytest.fixture
def fake_launch(monkeypatch, tmp_path):
    launched = {}
    monkeypatch.setattr(tor, "find_tor_executable", lambda _: Path("tor.exe"))
    real_tempdir = tor.tempfile.TemporaryDirectory
    monkeypatch.setattr(
        tor.tempfile, "TemporaryDirectory",
        lambda **kw: real_tempdir(dir=tmp_path, **kw),
    )

    def configure(output=READY, *, hostname=None, exited=False):
        process = FakeProcess(output, exited=exited)

        async def launch(*args, **kwargs):
            launched.update(args=args, kwargs=kwargs, process=process)
            root = Path(kwargs["cwd"])
            launched["root"] = root
            launched["config"] = (root / "torrc").read_text(encoding="utf-8")
            if hostname is not None:
                (root / "onion").mkdir()
                (root / "onion" / "hostname").write_text(hostname, encoding="ascii")
            return process

        monkeypatch.setattr(tor.asyncio, "create_subprocess_exec", launch)
        return process

    return configure, launched


async def test_isolated_host_bootstraps_and_cleans_its_runtime(fake_launch):
    configure, launched = fake_launch
    process = configure(hostname=onion_address() + "\n")
    messages = []
    manager = tor.ManagedTor(service_port=54321, status=messages.append)
    async with manager:
        assert manager.socks_port == 41234
        assert manager.onion_host == onion_address()
        config = launched["config"]
        assert "SocksPort 127.0.0.1:auto OnionTrafficOnly\n" in config
        assert "HiddenServicePort 8765 127.0.0.1:54321\n" in config
        assert "RunAsDaemon 0\n" in config
        assert "SafeSocks 1\n" in config
        assert "--defaults-torrc" in launched["args"]
        assert "SocksPortWriteToFile" not in config
        assert launched["root"].exists()
    assert process.terminated
    assert not launched["root"].exists()
    assert manager.socks_port == 0
    assert manager.onion_host is None
    assert messages == ["Starting a private Tor session...", "Tor connecting: 100%"]


async def test_client_has_no_onion_keys(fake_launch):
    configure, launched = fake_launch
    configure()
    async with tor.ManagedTor() as manager:
        assert manager.onion_host is None
        assert "HiddenService" not in launched["config"]


async def test_startup_timeout_kills_only_owned_process(fake_launch):
    configure, launched = fake_launch
    process = configure(output=b"[notice] Bootstrapped 10% (conn): Connecting\n")
    with pytest.raises(tor.TorError, match="startup timeout"):
        async with tor.ManagedTor(startup_timeout=0.02):
            pytest.fail("Unbootstrapped Tor cannot become ready")
    assert process.terminated
    assert not launched["root"].exists()


async def test_failed_startup_does_not_expose_raw_logs(fake_launch):
    configure, launched = fake_launch
    configure(output=b"[warn] Private hostname secret and C:/private/path\n", exited=True)
    messages = []
    with pytest.raises(tor.TorError, match="stopped before") as error:
        async with tor.ManagedTor(status=messages.append):
            pass
    assert "secret" not in str(error.value)
    assert all("private/path" not in message for message in messages)
    assert not launched["root"].exists()


async def test_cancelled_startup_cleans_process_and_keys(fake_launch):
    configure, launched = fake_launch
    process = configure(output=b"")
    manager = tor.ManagedTor()
    task = asyncio.create_task(manager.__aenter__())
    for _ in range(100):
        if manager._log_task is not None:
            break
        await asyncio.sleep(0)
    assert manager._log_task is not None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert process.terminated
    assert not launched["root"].exists()


async def test_bad_hostname_is_rejected_and_cleaned(fake_launch):
    configure, launched = fake_launch
    process = configure(hostname="a" * 56 + ".onion\n")
    with pytest.raises(tor.TorError, match="invalid onion-service"):
        async with tor.ManagedTor(service_port=12345):
            pass
    assert process.terminated
    assert not launched["root"].exists()


async def test_non_loopback_listener_notice_does_not_enable_connections(fake_launch):
    configure, _ = fake_launch
    configure(output=READY.replace(b"127.0.0.1:41234", b"0.0.0.0:41234"))
    with pytest.raises(tor.TorError, match="startup timeout"):
        async with tor.ManagedTor(startup_timeout=0.02):
            pass


async def test_oversized_log_line_fails_closed(fake_launch):
    configure, _ = fake_launch
    configure(output=b"x" * 100_000 + b"\n")
    with pytest.raises(tor.TorError, match="stopped before"):
        async with tor.ManagedTor(startup_timeout=0.1):
            pass


@pytest.mark.parametrize("bundle_name", ["DenTor", "HushTor", "DenDropTor"])
def test_discovery_uses_existing_bundle_and_missing_explicit_path_fails(monkeypatch, tmp_path, bundle_name):
    monkeypatch.setattr(tor.shutil, "which", lambda _: None)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    with pytest.raises(tor.TorNotFoundError, match="Tor was not found"):
        tor.find_tor_executable()
    executable = tmp_path / bundle_name / "bundle" / "tor" / "tor.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"fake-for-discovery-only")
    assert tor.find_tor_executable() == executable.resolve()
    with pytest.raises(tor.TorNotFoundError, match="existing"):
        tor.find_tor_executable(tmp_path / "missing.exe")


@pytest.mark.parametrize("host", ["example.com", "127.0.0.1", "a" * 56 + ".onion", "https://" + onion_address()])
async def test_invalid_destination_never_touches_network(monkeypatch, host):
    connect = AsyncMock()
    monkeypatch.setattr(tor.asyncio, "open_connection", connect)
    with pytest.raises(ValueError):
        await tor.ManagedTor().connect(host)
    connect.assert_not_called()


async def test_socks_connection_uses_remote_onion_dns_and_streams():
    observed = []

    async def socks(reader, writer):
        try:
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            writer.write(b"\x05\x00")
            await writer.drain()
            assert await reader.readexactly(4) == b"\x05\x01\x00\x03"
            length = (await reader.readexactly(1))[0]
            observed.append((await reader.readexactly(length)).decode("ascii"))
            observed.append(int.from_bytes(await reader.readexactly(2), "big"))
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
            await writer.drain()
            assert await reader.readexactly(4) == b"ping"
            writer.write(b"pong")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(socks, host="127.0.0.1", port=0)
    manager = tor.ManagedTor()
    manager._process = FakeProcess()
    manager.socks_port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await manager.connect(onion_address())
        writer.write(b"ping")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(4), timeout=2) == b"pong"
        writer.close()
        await writer.wait_closed()
        assert observed == [onion_address(), tor.SERVICE_PORT]
    finally:
        server.close()
        await server.wait_closed()
        await manager._cleanup()


async def test_no_direct_fallback_on_proxy_failure(monkeypatch):
    proxy = AsyncMock()
    proxy.connect.side_effect = OSError("proxy refused")
    monkeypatch.setattr(tor, "Proxy", lambda **kwargs: proxy)
    direct = AsyncMock()
    monkeypatch.setattr(tor.asyncio, "open_connection", direct)
    manager = tor.ManagedTor()
    manager._process = FakeProcess()
    manager.socks_port = 12345
    with pytest.raises(OSError, match="proxy refused"):
        await manager.connect(onion_address())
    direct.assert_not_called()
    await manager._cleanup()


async def test_proxy_socket_closed_if_asyncio_wrapping_fails(monkeypatch):
    sock = socket.socket()
    proxy = AsyncMock()
    proxy.connect.return_value = sock
    monkeypatch.setattr(tor, "Proxy", lambda **kwargs: proxy)
    monkeypatch.setattr(tor.asyncio, "open_connection", AsyncMock(side_effect=OSError("failed")))
    manager = tor.ManagedTor()
    manager._process = FakeProcess()
    manager.socks_port = 12345
    with pytest.raises(OSError):
        await manager.connect(onion_address())
    assert sock.fileno() == -1
    await manager._cleanup()

