"""Start one private Tor client per session; never fall back to direct networking.

Only the process launched here is stopped. Existing Tor instances/configuration
are untouched. Temporary runtime data includes onion keys and is removed on a
normal shutdown; this is deletion, not a secure-erasure guarantee.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Callable

from python_socks import ProxyType
from python_socks.async_.asyncio import Proxy

SERVICE_PORT = 8765
CONNECT_TIMEOUT = 120.0
_ONION = re.compile(r"[a-z2-7]{56}\.onion", re.ASCII)
_SOCKS_READY = re.compile(
    r"\[notice\] Opened Socks listener connection \(ready\) on 127\.0\.0\.1:([0-9]{1,5})(?:\s|$)"
)
_BOOTSTRAP = re.compile(r"\[notice\] Bootstrapped ([0-9]{1,3})% \(")


class TorError(RuntimeError):
    """A bounded, user-facing managed-Tor failure."""


class TorNotFoundError(TorError):
    """No existing Tor executable was available."""


def validate_onion(host: str) -> None:
    """Require a canonical lowercase v3 address, including its checksum."""
    if not isinstance(host, str) or _ONION.fullmatch(host) is None:
        raise ValueError("A valid lowercase v3 .onion address is required.")
    decoded = base64.b32decode(host[:-6].upper())
    key, checksum, version = decoded[:32], decoded[32:34], decoded[34:]
    expected = hashlib.sha3_256(b".onion checksum" + key + version).digest()[:2]
    if version != b"\x03" or not hmac.compare_digest(checksum, expected):
        raise ValueError("The onion address has an invalid checksum or version.")


def _port(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Port must be an integer from 1 to 65535.")
    return value


def find_tor_executable(executable: Path | None = None) -> Path:
    """Discover an installed binary; never download or install executable code."""
    if executable is not None:
        path = Path(executable).expanduser().resolve()
        if not path.is_file():
            raise TorNotFoundError("--tor-exe must point to an existing Tor executable.")
        return path
    found = shutil.which("tor")
    if found:
        return Path(found).resolve()
    local_data = os.environ.get("LOCALAPPDATA")
    if local_data:
        for name in ("DenTor", "HushTor", "DenDropTor"):
            root = Path(local_data) / name / "bundle"
            if root.is_dir():
                for candidate in sorted(root.rglob("tor.exe")):
                    if candidate.is_file():
                        return candidate.resolve()
    raise TorNotFoundError(
        "Tor was not found. Install the official Tor Expert Bundle on Windows "
        "(then pass --tor-exe PATH_TO_TOR_EXE), or install your Linux distribution's "
        "tor package. Den will start and configure it automatically. "
        "No direct-network fallback was attempted."
    )


def _quoted_path(path: Path) -> str:
    # Tor accepts C-style escapes in quoted configuration strings.
    value = str(path.resolve()).replace("\\", "/")
    if any(ord(char) < 32 for char in value):
        raise TorError("The Tor runtime path contains unsupported control characters.")
    return '"' + value.replace('"', '\\"') + '"'


class ManagedTor:
    """Async context manager exposing an isolated SOCKS port and optional onion.

    ``service_port`` is the already listening loopback relay port. When
    supplied, Tor exposes it as onion port 8765. ``connect`` returns asyncio
    streams and accepts only validated v3 onion destinations.
    """

    def __init__(
        self,
        executable: Path | None = None,
        service_port: int | None = None,
        status: Callable[[str], None] | None = None,
        *,
        startup_timeout: float = 180.0,
    ) -> None:
        if service_port is not None:
            _port(service_port)
        if not math.isfinite(startup_timeout) or startup_timeout <= 0:
            raise ValueError("Tor startup timeout must be a positive finite number.")
        self.executable = executable
        self.service_port = service_port
        self.status = status
        self.startup_timeout = startup_timeout
        self.socks_port = 0
        self.onion_host: str | None = None
        self._directory: tempfile.TemporaryDirectory[str] | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._log_task: asyncio.Task[None] | None = None
        self._changed = asyncio.Event()
        self._bootstrap = -1
        self._log_ended = False
        self._entered = False

    async def __aenter__(self) -> ManagedTor:
        if self._entered:
            raise TorError("A managed Tor session cannot be entered twice.")
        self._entered = True
        try:
            executable = find_tor_executable(self.executable)
            self._directory = tempfile.TemporaryDirectory(prefix="den-tor-")
            root = Path(self._directory.name)
            if os.name != "nt":
                root.chmod(0o700)
            config = [
                f"DataDirectory {_quoted_path(root / 'data')}",
                "SocksPort 127.0.0.1:auto OnionTrafficOnly",
                "SafeSocks 1",
                "ClientOnly 1",
                "RunAsDaemon 0",
                "AvoidDiskWrites 1",
                "Log notice stdout",
            ]
            if self.service_port is not None:
                config += [
                    f"HiddenServiceDir {_quoted_path(root / 'onion')}",
                    "HiddenServiceVersion 3",
                    f"HiddenServicePort {SERVICE_PORT} 127.0.0.1:{self.service_port}",
                ]
            torrc = root / "torrc"
            torrc.write_text("\n".join(config) + "\n", encoding="utf-8")
            defaults = root / "defaults-torrc"
            defaults.write_text("", encoding="utf-8")
            if self.status:
                self.status("Starting a private Tor session...")
            # Providing our own defaults file prevents system Tor settings from
            # introducing other listeners, log files, or a daemonized process.
            try:
                self._process = await asyncio.create_subprocess_exec(
                    str(executable), "--defaults-torrc", str(defaults), "-f", str(torrc),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    stdin=asyncio.subprocess.DEVNULL,
                    cwd=str(root),
                    limit=16_384,
                    creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
                )
            except OSError as exc:
                raise TorError(
                    "Tor could not start. Check --tor-exe and keep its bundled DLLs "
                    "beside the executable."
                ) from exc
            self._log_task = asyncio.create_task(self._read_log())
            try:
                async with asyncio.timeout(self.startup_timeout):
                    await self._wait_ready(root)
            except TimeoutError as exc:
                raise TorError(
                    "Tor did not become ready before the startup timeout. Check your "
                    "internet connection and whether your network blocks Tor. "
                    "No direct-network fallback was attempted."
                ) from exc
            return self
        except BaseException:
            await self._cleanup_shielded()
            raise

    async def _read_log(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        try:
            while raw := await self._process.stdout.readline():
                line = raw.decode("utf-8", errors="replace")
                listener = _SOCKS_READY.search(line)
                if listener:
                    candidate = int(listener.group(1))
                    if 1 <= candidate <= 65535:
                        self.socks_port = candidate
                bootstrap = _BOOTSTRAP.search(line)
                if bootstrap:
                    progress = int(bootstrap.group(1))
                    if self._bootstrap < progress <= 100:
                        self._bootstrap = progress
                        if self.status:
                            # Do not forward arbitrary Tor logs, addresses or paths.
                            self.status(f"Tor connecting: {progress}%")
                self._changed.set()
        except (ValueError, OSError):
            pass  # A broken/oversized log stream is treated as startup failure.
        finally:
            self._log_ended = True
            self._changed.set()

    async def _wait_ready(self, root: Path) -> None:
        while True:
            self._changed.clear()
            assert self._process is not None
            if self._process.returncode is not None or self._log_ended:
                raise TorError(
                    "Tor stopped before it was ready. Check the Tor installation "
                    "and network access. No direct-network fallback was attempted."
                )
            if self._bootstrap == 100 and self.socks_port:
                if self.service_port is None:
                    return
                hostname = root / "onion" / "hostname"
                try:
                    with hostname.open("r", encoding="ascii") as handle:
                        name = handle.read(128).strip()
                    validate_onion(name)
                except FileNotFoundError:
                    pass
                except (ValueError, UnicodeError) as exc:
                    raise TorError("Tor produced an invalid onion-service address.") from exc
                else:
                    self.onion_host = name
                    return
            try:
                await asyncio.wait_for(self._changed.wait(), timeout=0.1)
            except TimeoutError:
                pass

    async def connect(
        self, host: str, port: int = SERVICE_PORT,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        validate_onion(host)
        _port(port)
        if self._process is None or self._process.returncode is not None or not self.socks_port:
            raise TorError("The managed Tor session is not running.")
        proxy = Proxy(
            proxy_type=ProxyType.SOCKS5, host="127.0.0.1", port=self.socks_port, rdns=True,
        )
        sock = None
        try:
            async with asyncio.timeout(CONNECT_TIMEOUT):
                sock = await proxy.connect(dest_host=host, dest_port=port, timeout=CONNECT_TIMEOUT)
                streams = await asyncio.open_connection(sock=sock)
                sock = None  # StreamWriter now owns the socket.
                return streams
        finally:
            if sock is not None:
                sock.close()

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self._cleanup_shielded()

    async def _cleanup_shielded(self) -> None:
        cleanup = asyncio.create_task(self._cleanup())
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            await asyncio.shield(cleanup)
            raise

    async def _cleanup(self) -> None:
        process, self._process = self._process, None
        try:
            if process is not None and process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except TimeoutError:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    await process.wait()
        finally:
            if self._log_task is not None:
                self._log_task.cancel()
                await asyncio.gather(self._log_task, return_exceptions=True)
                self._log_task = None
            if self._directory is not None:
                directory, self._directory = self._directory, None
                try:
                    # TemporaryDirectory owns this exact path; it never targets
                    # discovered installations or another session's data.
                    await asyncio.to_thread(directory.cleanup)
                except OSError:
                    if self.status:
                        self.status("Tor stopped, but temporary runtime data could not be removed.")
            self.socks_port = 0
            self.onion_host = None

