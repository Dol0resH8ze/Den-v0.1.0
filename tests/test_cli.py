"""User-facing privacy/error behavior that is not covered by protocol tests."""

import io

import pytest

from python_socks import ProxyError, ProxyConnectionError, ProxyTimeoutError

from den import cli


def test_join_rejects_noninteractive_input_before_requesting_secret(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["den", "join", "--name", "Alice"])
    monkeypatch.setattr("sys.stdin", io.StringIO("secret-that-must-not-be-read\n"))

    def should_not_prompt(*args, **kwargs):
        raise AssertionError("Secret prompt must not run without a terminal")

    monkeypatch.setattr(cli.getpass, "getpass", should_not_prompt)
    assert cli.main() == 1
    output = capsys.readouterr()
    assert "interactive terminal" in output.err
    assert "secret-that-must-not-be-read" not in output.out + output.err


def test_proxy_protocol_failure_gets_generic_error_without_traceback(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["den", "create", "--server", "placeholder.onion", "--name", "Alice"])

    async def fail(*args, **kwargs):
        raise ProxyError("server-controlled-details-must-not-be-printed")

    monkeypatch.setattr(cli, "chat", fail)
    assert cli.main() == 1
    output = capsys.readouterr()
    assert "No fallback attempted" in output.err
    assert "server-controlled-details" not in output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize("error,expected", [
    (ProxyConnectionError("private-details"), "Cannot reach the local Tor SOCKS proxy"),
    (ProxyTimeoutError("private-details"), "Connection timed out"),
    (TimeoutError("private-details"), "Connection timed out"),
    (ProxyError("private-details", error_code=0xF0), "SOCKS code 0xf0"),
])
def test_connection_failures_explain_stage_without_echoing_raw_errors(monkeypatch, capsys, error, expected):
    monkeypatch.setattr("sys.argv", ["den", "create", "--server", "placeholder.onion", "--name", "Alice"])

    async def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(cli, "chat", fail)
    assert cli.main() == 1
    output = capsys.readouterr().err
    assert expected in output
    assert "private-details" not in output
    assert "No fallback attempted" in output
