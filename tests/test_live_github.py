"""Opt-in read-only staging integration; never targets an implicit repository."""
import os

import pytest

from adp.github import GitHubClient
from adp.projects import GitHubProjectsClient


@pytest.mark.asyncio
@pytest.mark.skipif(not (os.getenv("ADP_LIVE_GITHUB_REPO") and os.getenv("GITHUB_TOKEN")), reason="requires explicit dedicated staging repository and token")
async def test_live_github_issue_and_optional_project_read():
    repo = os.environ["ADP_LIVE_GITHUB_REPO"]
    issues = await GitHubClient().list_issues(repo)
    assert isinstance(issues, list)
    assert all("pull_request" not in issue for issue in issues)
    project = os.getenv("ADP_LIVE_GITHUB_PROJECT_ID")
    if project:
        items = await GitHubProjectsClient().issue_items(project, repo)
        assert isinstance(items, dict)
