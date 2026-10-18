import httpx
import pytest

from adp.projects import GitHubProjectsClient


@pytest.mark.asyncio
async def test_project_membership_paginates_and_status_updates():
    calls = []

    def handler(request):
        data = __import__("json").loads(request.content)
        calls.append(data)
        if "updateProjectV2ItemFieldValue" in data["query"]:
            assert data["variables"]["option"] == "option-1"
            return httpx.Response(200, json={"data": {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "item-1"}}}})
        cursor = data["variables"]["after"]
        if cursor is None:
            page = {"nodes": [{"id": "item-1", "content": {"number": 7, "repository": {"nameWithOwner": "example/project"}}}], "pageInfo": {"hasNextPage": True, "endCursor": "next"}}
        else:
            page = {"nodes": [{"id": "other", "content": {"number": 8, "repository": {"nameWithOwner": "another/project"}}}], "pageInfo": {"hasNextPage": False, "endCursor": None}}
        return httpx.Response(200, json={"data": {"node": {"items": page}}})

    client = GitHubProjectsClient(token="test", transport=httpx.MockTransport(handler))
    assert await client.issue_items("project-1", "example/project") == {7: "item-1"}
    await client.set_status("project-1", "item-1", "field-1", "option-1")
    assert len(calls) == 3
