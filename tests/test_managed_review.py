"""Independent lifecycle and fail-closed checks for managed Tor integration."""

import asyncio
import base64
import contextlib
import hashlib
from unittest.mock import Mock

import pytest

from den import cli
from den.crypto import Identity, Invite
from den.relay import Relay


def onion_address():
    key, version = bytes(range(32)), b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + key + version).digest()[:2]
    return base64.b32encode(key + checksum + version).decode().lower() + ".onion"


@pytest.mark.parametrize("invite_host,flags", [
    ("127.0.0.1", ()),
    (onion_address(), ("--local-test",)),
])
async def test_valid_invite_cannot_cross_tor_local_mode_boundary(monkeypatch, invite_host, flags):
    invite = Invite.create(invite_host, 8765, Identity()).encode()
    forbidden = Mock(side_effect=AssertionError("No network resource may be created"))
    monkeypatch.setattr(cli, "ManagedTor", forbidden)
    monkeypatch.setattr(cli, "Relay", forbidden)
    monkeypatch.setattr(cli, "_chat_session", forbidden)
    args = cli.parser().parse_args(["join", *flags])
    with pytest.raises(ValueError, match="Invalid invite"):
        await cli.chat(args, "Bob", invite)
    forbidden.assert_not_called()


@pytest.mark.parametrize("stop", ["relay_shutdown", "prompt_eof", "task_cancel"])
async def test_actual_chat_session_releases_prompt_and_client(monkeypatch, stop):
    """Run the real room client and UI loop, replacing only terminal input."""
    relay = Relay()
    await relay.start()
    prompt_entered = asyncio.Event()
    release_prompt = asyncio.Event()
    prompt_stopped = asyncio.Event()
    created = []
    original_create = cli.RoomClient.create

    async def create(*args, **kwargs):
        client = await original_create(*args, **kwargs)
        created.append(client)
        return client

    class Prompt:
        def __init__(self, **kwargs):
            assert kwargs["history"] is None

        async def prompt_async(self, *_args):
            prompt_entered.set()
            try:
                await release_prompt.wait()
                raise EOFError
            finally:
                prompt_stopped.set()

    monkeypatch.setattr(cli.RoomClient, "create", create)
    monkeypatch.setattr(cli, "PromptSession", Prompt)
    monkeypatch.setattr(cli, "patch_stdout", contextlib.nullcontext)
    monkeypatch.setattr(cli, "print_styled", lambda *_: None)
    args = cli.parser().parse_args([
        "create", "--server", "127.0.0.1", "--port", str(relay.address[1]), "--local-test",
    ])
    args.proxy_port = 9050
    task = asyncio.create_task(cli._chat_session(args, "Alice"))
    try:
        async with asyncio.timeout(5):
            await prompt_entered.wait()
            if stop == "relay_shutdown":
                await relay.close()
                await task
            elif stop == "prompt_eof":
                release_prompt.set()
                await task
            else:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            assert prompt_stopped.is_set()
            assert len(created) == 1
            assert created[0].closed.is_set()
            assert created[0].writer.is_closing()
            assert created[0].receiver.done()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await relay.close()
    assert not relay.rooms and not relay._sessions


async def test_cancel_during_tor_entry_closes_already_accepted_relay_peer(monkeypatch):
    relay = Relay()
    monkeypatch.setattr(cli, "Relay", lambda: relay)
    tor_starting = asyncio.Event()
    tor_cleaned = asyncio.Event()

    class StartingTor:
        def __init__(self, *, service_port, **_kwargs):
            assert service_port == relay.address[1]

        async def __aenter__(self):
            try:
                tor_starting.set()
                await asyncio.Event().wait()
            finally:
                tor_cleaned.set()

        async def __aexit__(self, *_args):
            pytest.fail("A failed context entry must clean itself, not call __aexit__")

    monkeypatch.setattr(cli, "ManagedTor", StartingTor)
    args = cli.parser().parse_args(["create"])
    task = asyncio.create_task(cli.chat(args, "Alice"))
    writer = None
    try:
        async with asyncio.timeout(5):
            await tor_starting.wait()
            reader, writer = await asyncio.open_connection(*relay.address[:2])
            # Complete a scheduling turn so the pending handshake is registered.
            while not relay._sessions:
                await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert tor_cleaned.is_set()
            assert relay.server is None
            assert not relay._sessions and not relay.rooms
            assert b"Relay stopped." in await reader.read()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        await relay.close()
