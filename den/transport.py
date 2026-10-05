"""Fail-closed Tor transport and bounded JSON framing.

Normal connections accept only checksummed v3 onion destinations and a numeric
loopback SOCKS5 proxy. The explicit ``local_test`` switch BYPASSES TOR and is
only for development on one computer; it accepts numeric loopback destinations.
There is no fallback from Tor to a direct connection.

Listeners must use ``asyncio.start_server(..., limit=STREAM_LIMIT)``. A framing
error is fatal: callers must close the connection rather than try to resync it.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import re
from typing import Any

from python_socks import ProxyType
from python_socks.async_.asyncio import Proxy


MAX_FRAME_BYTES = 524_288  # Includes newline; sealed 16-member fanout needs room.
STREAM_LIMIT = MAX_FRAME_BYTES
IO_TIMEOUT = 30.0
CONNECT_TIMEOUT = 120.0  # Onion circuit setup can exceed an ordinary socket timeout.
MAX_JSON_DEPTH = 64
_ONION_PATTERN = re.compile(r"[a-z2-7]{56}\.onion", re.ASCII)


def _validate_port(port: int) -> None:
    if type(port) is not int or not 1 <= port <= 65_535:
        raise ValueError("Port must be an integer between 1 and 65535.")


def _loopback_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(host, str) or "%" in host:
        raise ValueError("A numeric loopback address is required.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("A numeric loopback address is required; DNS names are refused.") from exc
    if not address.is_loopback:
        raise ValueError("Only a numeric loopback address is permitted.")
    return address


def validate_endpoint(host: str, port: int, local_test: bool = False) -> None:
    """Reject invalid destinations before performing any network operations.

    Production hosts must be lowercase, canonical v3 onion names (no URL,
    subdomain, or trailing dot). Development mode is restricted to numeric
    IPv4/IPv6 loopback addresses and provides no network anonymity.
    """
    _validate_port(port)
    if type(local_test) is not bool:
        raise ValueError("local_test must be an explicit boolean.")
    if local_test:
        _loopback_address(host)
        return
    if not isinstance(host, str) or _ONION_PATTERN.fullmatch(host) is None:
        raise ValueError("A valid lowercase v3 .onion address is required.")
    decoded = base64.b32decode(host[:-6].upper())
    public_key, checksum, version = decoded[:32], decoded[32:34], decoded[34:]
    expected = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    if version != b"\x03" or not hmac.compare_digest(checksum, expected):
        raise ValueError("The v3 onion address has an invalid version or checksum.")


async def open_connection(
    host: str,
    port: int,
    *,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 9050,
    local_test: bool = False,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect via a local SOCKS5 proxy, or explicitly to loopback for tests.

    Onion destination resolution is sent to Tor, never to local DNS. A missing
    or failed proxy raises an error. Tor is not started or downloaded here.
    """
    validate_endpoint(host, port, local_test)
    if local_test:
        async with asyncio.timeout(IO_TIMEOUT):
            return await asyncio.open_connection(host=host, port=port, limit=STREAM_LIMIT)

    _loopback_address(proxy_host)
    _validate_port(proxy_port)
    proxy = Proxy(
        proxy_type=ProxyType.SOCKS5,
        host=proxy_host,
        port=proxy_port,
        rdns=True,
    )
    sock = None
    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            sock = await proxy.connect(dest_host=host, dest_port=port, timeout=CONNECT_TIMEOUT)
            streams = await asyncio.open_connection(sock=sock, limit=STREAM_LIMIT)
            sock = None  # Ownership transferred to StreamWriter's transport.
            return streams
    finally:
        if sock is not None:
            sock.close()


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object keys are not permitted.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON numbers are not permitted.")


def _validate_json(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting is too deep.")
    if value is None or type(value) in (bool, int):
        return
    if type(value) is str:
        value.encode("utf-8", errors="strict")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("Non-finite JSON numbers are not permitted.")
        return
    if type(value) is list:
        for entry in value:
            _validate_json(entry, depth + 1)
        return
    if type(value) is dict:
        for key, entry in value.items():
            if type(key) is not str:
                raise ValueError("JSON object keys must be strings.")
            _validate_json(key, depth + 1)
            _validate_json(entry, depth + 1)
        return
    raise ValueError("Only JSON-compatible values are permitted.")


async def read_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
    """Read one strict, size-bounded JSON object followed by a newline.

    Idle reads deliberately have no deadline; impose a timeout at the protocol
    layer for handshakes. Malformed/oversized input raises ValueError; EOF before
    a complete frame raises ConnectionError. Both require closing the stream.
    """
    try:
        raw = await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError("Connection closed before a complete frame arrived.") from exc
    except asyncio.LimitOverrunError as exc:
        raise ValueError("Frame exceeds the permitted size.") from exc
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError("Frame exceeds the permitted size.")
    try:
        result = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_object_from_pairs,
            parse_constant=_reject_constant,
        )
        if type(result) is not dict:
            raise ValueError("A frame must contain a JSON object.")
        _validate_json(result)
    except (UnicodeError, RecursionError, TypeError) as exc:
        raise ValueError("Frame contains invalid JSON data.") from exc
    return result


async def write_frame(writer: asyncio.StreamWriter, frame: dict[str, Any]) -> None:
    """Serialize a strict JSON object and drain with a 30-second deadline."""
    if type(frame) is not dict:
        raise ValueError("A frame must contain a JSON object.")
    try:
        _validate_json(frame)
        raw = (
            json.dumps(frame, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            + "\n"
        ).encode("utf-8", errors="strict")
    except (UnicodeError, RecursionError, TypeError) as exc:
        raise ValueError("Frame contains invalid JSON data.") from exc
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError("Frame exceeds the permitted size.")
    writer.write(raw)
    async with asyncio.timeout(IO_TIMEOUT):
        await writer.drain()
