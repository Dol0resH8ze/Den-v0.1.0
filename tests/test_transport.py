"""Privacy boundary and hostile framing tests; no Tor service is required."""

import asyncio
import base64
import hashlib
import socket
from unittest.mock import AsyncMock, Mock

import pytest

from den import transport


def onion_address(public_key: bytes = bytes(range(32)), version: bytes = b"\x03") -> str:
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    return base64.b32encode(public_key + checksum + version).decode().lower() + ".onion"


def reader_for(raw: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader(limit=transport.STREAM_LIMIT)
    reader.feed_data(raw)
    reader.feed_eof()
    return reader


def test_valid_v3_onion_and_tor_spec_example():
    transport.validate_endpoint(onion_address(), 80)
    transport.validate_endpoint("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion", 65535)


@pytest.mark.parametrize("host", [
    "example.com", "localhost", "127.0.0.1", "::1", "a" * 16 + ".onion",
    "a" * 56 + ".onion", onion_address().upper(), onion_address() + ".",
    "https://" + onion_address(), "sub." + onion_address(), onion_address(version=b"\x04"),
])
def test_production_rejects_invalid_onion(host):
    with pytest.raises(ValueError):
        transport.validate_endpoint(host, 80)


def test_checksum_corruption_rejected():
    host = onion_address()
    corrupted = ("b" if host[0] == "a" else "a") + host[1:]
    with pytest.raises(ValueError, match="checksum"):
        transport.validate_endpoint(corrupted, 80)


@pytest.mark.parametrize("port", [0, -1, 65536, True, False, "80", None, 80.0])
def test_invalid_ports(port):
    with pytest.raises(ValueError):
        transport.validate_endpoint(onion_address(), port)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1", "0:0:0:0:0:0:0:1"])
def test_local_test_allows_numeric_loopback_only(host):
    transport.validate_endpoint(host, 8080, local_test=True)


@pytest.mark.parametrize("host", ["localhost", "127.1", "127.0.0.1.example.com", "192.168.0.1", "0.0.0.0", "::", "::1%eth0", onion_address()])
def test_local_test_rejects_dns_and_non_loopback(host):
    with pytest.raises(ValueError):
        transport.validate_endpoint(host, 8080, local_test=True)


@pytest.mark.asyncio
async def test_proxy_failure_never_opens_direct_connection(monkeypatch):
    proxy = Mock(connect=AsyncMock(side_effect=OSError("Tor is unavailable")))
    factory = Mock(return_value=proxy)
    direct_open = AsyncMock()
    monkeypatch.setattr(transport, "Proxy", factory)
    monkeypatch.setattr(transport.asyncio, "open_connection", direct_open)
    with pytest.raises(OSError, match="Tor is unavailable"):
        await transport.open_connection(onion_address(), 8080)
    direct_open.assert_not_called()
    assert factory.call_args.kwargs["rdns"] is True
    assert factory.call_args.kwargs["proxy_type"] == transport.ProxyType.SOCKS5
    proxy.connect.assert_awaited_once_with(dest_host=onion_address(), dest_port=8080, timeout=transport.CONNECT_TIMEOUT)


@pytest.mark.asyncio
async def test_proxy_socket_is_only_connection_used(monkeypatch):
    sock = Mock()
    streams = (Mock(), Mock())
    proxy = Mock(connect=AsyncMock(return_value=sock))
    monkeypatch.setattr(transport, "Proxy", Mock(return_value=proxy))
    direct_open = AsyncMock(return_value=streams)
    monkeypatch.setattr(transport.asyncio, "open_connection", direct_open)
    assert await transport.open_connection(onion_address(), 8080) == streams
    direct_open.assert_awaited_once_with(sock=sock, limit=transport.STREAM_LIMIT)
    sock.close.assert_not_called()


@pytest.mark.asyncio
async def test_socket_closed_if_stream_wrapping_fails(monkeypatch):
    sock = Mock()
    proxy = Mock(connect=AsyncMock(return_value=sock))
    monkeypatch.setattr(transport, "Proxy", Mock(return_value=proxy))
    monkeypatch.setattr(transport.asyncio, "open_connection", AsyncMock(side_effect=OSError("broken")))
    with pytest.raises(OSError):
        await transport.open_connection(onion_address(), 8080)
    sock.close.assert_called_once()


@pytest.mark.asyncio
async def test_real_socks_handshake_sends_onion_without_local_dns(monkeypatch):
    """Exercise the installed proxy library, not just mocked connect calls."""
    loop = asyncio.get_running_loop()
    observed = loop.create_future()

    async def socks_peer(reader, writer):
        try:
            assert await reader.readexactly(3) == b"\x05\x01\x00"
            writer.write(b"\x05\x00")
            await writer.drain()
            assert await reader.readexactly(4) == b"\x05\x01\x00\x03"
            size = (await reader.readexactly(1))[0]
            hostname = (await reader.readexactly(size)).decode("ascii")
            port = int.from_bytes(await reader.readexactly(2), "big")
            observed.set_result((hostname, port))
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
            await writer.drain()
            await transport.write_frame(writer, await transport.read_frame(reader))
        except Exception as exc:
            if not observed.done():
                observed.set_exception(exc)
            raise
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(socks_peer, "127.0.0.1", 0, limit=transport.STREAM_LIMIT)
    no_dns = Mock(side_effect=AssertionError("Local DNS must not be called"))
    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    monkeypatch.setattr(loop, "getaddrinfo", AsyncMock(side_effect=AssertionError("Local DNS must not be called")))
    writer = None
    try:
        async with asyncio.timeout(5):
            reader, writer = await transport.open_connection(
                onion_address(), 12345, proxy_port=server.sockets[0].getsockname()[1]
            )
            assert await observed == (onion_address(), 12345)
            await transport.write_frame(writer, {"message": "through socks"})
            assert await transport.read_frame(reader) == {"message": "through socks"}
            no_dns.assert_not_called()
            loop.getaddrinfo.assert_not_called()
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("proxy_host", ["localhost", "proxy.example.com", "192.168.0.1", "::1%eth0"])
async def test_invalid_proxy_rejected_before_network(monkeypatch, proxy_host):
    factory = Mock()
    direct_open = AsyncMock()
    monkeypatch.setattr(transport, "Proxy", factory)
    monkeypatch.setattr(transport.asyncio, "open_connection", direct_open)
    with pytest.raises(ValueError):
        await transport.open_connection(onion_address(), 8080, proxy_host=proxy_host)
    factory.assert_not_called()
    direct_open.assert_not_called()


@pytest.mark.asyncio
async def test_no_hostname_is_ever_resolved_in_local_test(monkeypatch):
    direct_open = AsyncMock()
    monkeypatch.setattr(transport.asyncio, "open_connection", direct_open)
    with pytest.raises(ValueError):
        await transport.open_connection("localhost", 8080, local_test=True)
    direct_open.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_explicit_local_mode_never_constructs_proxy(monkeypatch, host):
    factory = Mock()
    direct_open = AsyncMock(return_value=(Mock(), Mock()))
    monkeypatch.setattr(transport, "Proxy", factory)
    monkeypatch.setattr(transport.asyncio, "open_connection", direct_open)
    await transport.open_connection(host, 8080, local_test=True)
    factory.assert_not_called()
    direct_open.assert_awaited_once_with(host=host, port=8080, limit=transport.STREAM_LIMIT)


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [
    b"[]\n", b"null\n", b"42\n", b"\n", b"{\n", b'{"a":1} garbage\n',
    b'{"a":1,"a":2}\n', b'{"nested":{"a":1,"a":2}}\n',
    b'{"n":NaN}\n', b'{"n":Infinity}\n', b'{"n":-Infinity}\n', b'{"n":1e999}\n',
    b'{"s":"\xff"}\n', b'{"s":"\\ud800"}\n', b'{"s":"raw\x00control"}\n',
])
async def test_malformed_frames_rejected(raw):
    with pytest.raises(ValueError):
        await transport.read_frame(reader_for(raw))


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [b"", b"{}", b'{"partial":'])
async def test_eof_before_newline_is_connection_error(raw):
    with pytest.raises(ConnectionError):
        await transport.read_frame(reader_for(raw))


@pytest.mark.asyncio
async def test_multiple_frames_and_unicode():
    reader = reader_for('{"text":"hello 世界 🌍"}\n{"next":true}\n'.encode())
    assert await transport.read_frame(reader) == {"text": "hello 世界 🌍"}
    assert await transport.read_frame(reader) == {"next": True}


@pytest.mark.asyncio
async def test_wire_size_boundary_includes_newline():
    raw = b'{"x":"' + b"x" * (transport.MAX_FRAME_BYTES - 9) + b'"}\n'
    assert len(raw) == transport.MAX_FRAME_BYTES
    assert len((await transport.read_frame(reader_for(raw)))["x"]) == transport.MAX_FRAME_BYTES - 9
    with pytest.raises(ValueError, match="size"):
        await transport.read_frame(reader_for(raw[:-2] + b"x" + raw[-2:]))


@pytest.mark.asyncio
async def test_unterminated_oversized_frame_is_rejected():
    with pytest.raises(ValueError, match="size"):
        await transport.read_frame(reader_for(b"x" * (transport.MAX_FRAME_BYTES + 1)))


@pytest.mark.asyncio
async def test_excessive_nesting_is_rejected():
    raw = b'{"x":' + b"[" * 70 + b"0" + b"]" * 70 + b"}\n"
    with pytest.raises(ValueError, match="nesting"):
        await transport.read_frame(reader_for(raw))


@pytest.mark.asyncio
async def test_write_round_trip_and_escaped_newline():
    writer = Mock(drain=AsyncMock())
    frame = {"text": "hello\n世界", "values": [None, True, 1, 2.5]}
    await transport.write_frame(writer, frame)
    raw = writer.write.call_args.args[0]
    assert raw.count(b"\n") == 1
    assert await transport.read_frame(reader_for(raw)) == frame
    writer.drain.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("frame", [
    [], None, {"x": float("nan")}, {"x": float("inf")}, {1: "not a string"},
    {"x": "\ud800"}, {"x": object()}, {"x": "x" * transport.MAX_FRAME_BYTES},
])
async def test_invalid_outbound_payload_never_written(frame):
    writer = Mock(drain=AsyncMock())
    with pytest.raises(ValueError):
        await transport.write_frame(writer, frame)
    writer.write.assert_not_called()
    writer.drain.assert_not_called()
