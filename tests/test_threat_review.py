import httpx
import pytest

from adp.threat_review import ThreatReviewClient


@pytest.mark.asyncio
async def test_threat_review_requires_approval_on_exact_head():
    def handler(request):
        if request.url.path.endswith("/pulls/3"):
            return httpx.Response(200, json={"merged": True, "head": {"sha": "abc"}, "user": {"login": "author"}})
        return httpx.Response(200, json=[{"commit_id": "older", "state": "APPROVED", "user": {"login": "alice"}}, {"commit_id": "abc", "state": "APPROVED", "user": {"login": "bob", "type": "User"}}])

    client = ThreatReviewClient(token="test", transport=httpx.MockTransport(handler))
    assert await client.review_state({"repository": "example/models", "number": 3, "head_sha": "abc"}) == {"approved": True, "merged": True}
    assert await client.review_state({"repository": "example/models", "number": 3, "head_sha": "new"}) == {"approved": False, "merged": False}
