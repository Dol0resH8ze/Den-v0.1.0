"""User-facing privacy/error behavior that is not covered by protocol tests."""

import io

from python_socks import ProxyError

from hush import cli


def test_join_rejects_noninteractive_input_before_requesting_secret(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["hush", "join", "--name", "Alice"])
    monkeypatch.setattr("sys.stdin", io.StringIO("secret-that-must-not-be-read\n"))

    def should_not_prompt(*args, **kwargs):
        raise AssertionError("Secret prompt must not run without a terminal")

    monkeypatch.setattr(cli.getpass, "getpass", should_not_prompt)
    assert cli.main() == 1
    output = capsys.readouterr()
    assert "interactive terminal" in output.err
    assert "secret-that-must-not-be-read" not in output.out + output.err


def test_proxy_protocol_failure_gets_generic_error_without_traceback(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["hush", "create", "--server", "placeholder.onion", "--name", "Alice"])

    async def fail(*args, **kwargs):
        raise ProxyError("server-controlled-details-must-not-be-printed")

    monkeypatch.setattr(cli, "chat", fail)
    assert cli.main() == 1
    output = capsys.readouterr()
    assert "No fallback attempted" in output.err
    assert "server-controlled-details" not in output.err
    assert "Traceback" not in output.err
