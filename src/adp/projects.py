"""GitHub Projects V2 backlog selection and status reconciliation."""
import httpx

from adp.github_auth import tokens
from adp.settings import settings


class GitHubProjectsClient:
    def __init__(self, token: str | None = None, transport=None):
        self.token = token
        self.transport = transport

    async def _query(self, query: str, variables: dict) -> dict:
        token = self.token or await tokens.get()
        async with httpx.AsyncClient(base_url=settings.github_api_url, transport=self.transport, timeout=30) as client:
            response = await client.post("/graphql", headers={"Authorization": f"Bearer {token}"}, json={"query": query, "variables": variables})
            response.raise_for_status()
            body = response.json()
        if body.get("errors"):
            raise RuntimeError(f"GitHub Projects GraphQL error: {body['errors'][0].get('message', 'unknown')}")
        if not isinstance(body.get("data"), dict):
            raise RuntimeError("GitHub Projects returned no data")
        return body["data"]

    async def issue_items(self, project_id: str, repository: str) -> dict[int, str]:
        query = """query($id:ID!,$after:String){node(id:$id){... on ProjectV2{items(first:100,after:$after){nodes{id content{... on Issue{number repository{nameWithOwner}}}} pageInfo{hasNextPage endCursor}}}}}"""
        found: dict[int, str] = {}
        cursor = None
        for _ in range(100):
            data = await self._query(query, {"id": project_id, "after": cursor})
            node = data.get("node") or {}
            page = node.get("items")
            if not page:
                raise RuntimeError("Project not found or inaccessible")
            for item in page["nodes"]:
                content = item.get("content") or {}
                if (content.get("repository") or {}).get("nameWithOwner", "").lower() == repository.lower():
                    found[content["number"]] = item["id"]
            if not page["pageInfo"]["hasNextPage"]:
                return found
            cursor = page["pageInfo"]["endCursor"]
        raise RuntimeError("GitHub Projects pagination limit exceeded")

    async def set_status(self, project_id: str, item_id: str, field_id: str, option_id: str) -> None:
        mutation = """mutation($project:ID!,$item:ID!,$field:ID!,$option:String!){updateProjectV2ItemFieldValue(input:{projectId:$project,itemId:$item,fieldId:$field,value:{singleSelectOptionId:$option}}){projectV2Item{id}}}"""
        data = await self._query(mutation, {"project": project_id, "item": item_id, "field": field_id, "option": option_id})
        if not (data.get("updateProjectV2ItemFieldValue") or {}).get("projectV2Item", {}).get("id"):
            raise RuntimeError("Project status update was not confirmed")
