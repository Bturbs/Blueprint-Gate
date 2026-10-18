import asyncio
from pathlib import Path

import httpx
import pytest

from adp.github import GitHubClient, dependencies
from adp.runtimes import RUNTIMES, candidate_runtimes, select_runtime
from adp.scheduler import order
from adp.threat_models import discover, in_place_controls, reject_unverified_controls, verify


@pytest.mark.asyncio
async def test_github_poll_excludes_pr_and_paginates():
    calls = []

    def handler(request):
        calls.append(request.url.params["page"])
        if request.url.params["page"] == "1":
            return httpx.Response(200, json=[{"number": n, "title": "x"} for n in range(1, 100)] + [{"number": 100, "pull_request": {}}])
        return httpx.Response(200, json=[{"number": 101, "title": "second"}])

    issues = await GitHubClient(token="test", transport=httpx.MockTransport(handler)).list_issues("owner/repo")
    assert len(issues) == 100
    assert calls == ["1", "2"]
    assert dependencies("Depends on #2\nBlocked by: #3\nDepends on #2") == [2, 3]


def test_dependency_order_and_cycle():
    assert order({1: [], 2: [1], 3: []}, {3: 10}) == [3, 1, 2]
    with pytest.raises(ValueError, match="cycle"):
        order({1: [2], 2: [1]})


def test_provider_routing_is_allowlisted():
    assert select_runtime({"routing": {"default_provider": "claude", "allowed_providers": ["claude"]}}, "architect") is RUNTIMES["claude"]
    with pytest.raises(ValueError):
        select_runtime({"routing": {"default_provider": "claude", "allowed_providers": ["codex"]}}, "architect")
    routing = {"data_classification": "restricted", "routing": {"default_provider": "codex", "allowed_providers": ["codex", "claude"], "provider_classifications": {"codex": ["restricted"], "claude": ["internal"]}, "fallback": {"enabled": True, "order": ["claude"]}}}
    assert candidate_runtimes(routing, "engineer") == [RUNTIMES["codex"]]
    with pytest.raises(ValueError, match="not approved"):
        candidate_runtimes({"data_classification": "restricted", "routing": {"default_provider": "claude", "allowed_providers": ["claude"]}}, "engineer")


@pytest.mark.asyncio
async def test_threat_model_discovery_and_missing_verifier(tmp_path):
    model = tmp_path / "Project" / "Project.yaml"
    model.parent.mkdir()
    model.write_text("ID: Project\nschemaVersion: 2\n")
    (tmp_path / "Project" / "other.yaml").write_text("ID: Other\n")
    assert discover(tmp_path) == [model]
    result = await verify(model, tmp_path / "missing-tool")
    assert not result["passed"]
    assert "not installed" in result["error"]


def test_new_in_place_countermeasures_are_rejected(tmp_path):
    directory = tmp_path / "Project"
    directory.mkdir()
    model = directory / "Project.yaml"
    model.write_text("threats:\n  - ID: A\n    countermeasures:\n      - ID: CM1\n        inPlace: false\n")
    before = in_place_controls(directory)
    model.write_text("threats:\n  - ID: A\n    countermeasures:\n      - ID: CM1\n        inPlace: true\n")
    with pytest.raises(ValueError, match="unverified controls"):
        reject_unverified_controls(before, in_place_controls(directory))
