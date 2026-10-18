import json

import httpx
import pytest
import typer
from typer.testing import CliRunner

from adp import cli


def test_pause_waits_until_running_jobs_yield(monkeypatch):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        running = 1 if request.method == "POST" else 0
        return httpx.Response(200, json={"paused": True, "running_jobs": running})

    monkeypatch.setattr(cli, "_control_client", lambda url, token_env: httpx.Client(base_url=url, transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)
    result = CliRunner().invoke(cli.app, ["pause", "http://127.0.0.1:8000", "--wait-seconds", "1"])
    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"paused": True, "running_jobs": 0}
    assert calls == [("POST", "/control/pause"), ("GET", "/control")]


def test_pause_reports_when_drain_is_incomplete(monkeypatch):
    monkeypatch.setattr(cli, "_control_client", lambda url, token_env: httpx.Client(base_url=url, transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"paused": True, "running_jobs": 1}))))
    result = CliRunner().invoke(cli.app, ["pause", "http://127.0.0.1:8000", "--wait-seconds", "0"])
    assert result.exit_code == 2
    assert "active jobs remain" in result.output


def test_control_client_rejects_disguised_remote_http(monkeypatch):
    monkeypatch.setenv("CONTROL_TOKEN", "secret")
    with pytest.raises(typer.BadParameter):
        cli._control_client("http://127.0.0.1:8000@evil.example", "CONTROL_TOKEN")
    with cli._control_client("http://127.0.0.1:8000", "CONTROL_TOKEN") as client:
        assert client.base_url.host == "127.0.0.1"
