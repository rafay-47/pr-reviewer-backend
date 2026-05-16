"""
GitLab API client for project management.

Provides async functions for:
- Listing user/group projects
"""

import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote_plus

import httpx

logger = logging.getLogger(__name__)


@dataclass
class GitLabProject:
    """GitLab project information."""
    id: int
    name: str
    full_name: str
    owner: str
    private: bool
    description: Optional[str]
    default_branch: str
    html_url: str
    access_level: int


class GitLabClient:
    """Async GitLab API client."""

    def __init__(self, access_token: str, base_url: str = "https://gitlab.com"):
        self.access_token = access_token
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
    ) -> tuple[list | dict | None, httpx.Headers]:
        """Make an authenticated request to GitLab API."""
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/api/v4{endpoint}"
            response = await client.request(
                method,
                url,
                headers=self.headers,
                params=params,
                timeout=30.0,
            )

            if response.status_code == 404:
                return None, response.headers

            response.raise_for_status()

            if response.status_code == 204:
                return {}, response.headers

            return response.json(), response.headers

    @staticmethod
    def _extract_access_level(project_payload: dict) -> int:
        permissions = project_payload.get("permissions") or {}
        project_access = (permissions.get("project_access") or {}).get("access_level") or 0
        group_access = (permissions.get("group_access") or {}).get("access_level") or 0
        return max(project_access, group_access)

    async def _list_project_ids_with_min_access(self, min_access_level: int, max_projects: int = 500) -> set[int]:
        """Return project IDs where token has at least min_access_level."""
        project_ids: set[int] = set()
        page = 1
        per_page = 100

        while len(project_ids) < max_projects:
            data, headers = await self._request(
                "GET",
                "/projects",
                params={
                    "membership": True,
                    "archived": False,
                    "per_page": per_page,
                    "page": page,
                    "order_by": "last_activity_at",
                    "sort": "desc",
                    "min_access_level": min_access_level,
                },
            )

            if not data:
                break

            for project in data:
                project_id = project.get("id")
                if isinstance(project_id, int):
                    project_ids.add(project_id)

            next_page = headers.get("X-Next-Page")
            if not next_page:
                break

            page = int(next_page)

        return project_ids

    async def list_projects(self, max_projects: int = 500) -> list[GitLabProject]:
        """List projects accessible to the token."""
        all_projects: list[GitLabProject] = []

        # Derive writable/admin project sets from dedicated access-filtered queries.
        # This avoids false read-only results when simple project payloads omit permissions.
        writable_project_ids = await self._list_project_ids_with_min_access(30, max_projects=max_projects)
        admin_project_ids = await self._list_project_ids_with_min_access(40, max_projects=max_projects)

        page = 1
        per_page = 100

        while len(all_projects) < max_projects:
            data, headers = await self._request(
                "GET",
                "/projects",
                params={
                    "membership": True,
                    "archived": False,
                    "per_page": per_page,
                    "page": page,
                    "order_by": "last_activity_at",
                    "sort": "desc",
                },
            )

            if not data:
                break

            for project in data:
                path_with_namespace = project.get("path_with_namespace", "")
                owner = path_with_namespace.split("/")[0] if "/" in path_with_namespace else path_with_namespace
                visibility = project.get("visibility", "private")
                project_id = project.get("id")

                inferred_access_level = self._extract_access_level(project)
                if isinstance(project_id, int):
                    if project_id in admin_project_ids:
                        inferred_access_level = max(inferred_access_level, 40)
                    elif project_id in writable_project_ids:
                        inferred_access_level = max(inferred_access_level, 30)

                all_projects.append(
                    GitLabProject(
                        id=project["id"],
                        name=project["name"],
                        full_name=path_with_namespace,
                        owner=owner,
                        private=visibility != "public",
                        description=project.get("description"),
                        default_branch=project.get("default_branch") or "main",
                        html_url=project.get("web_url", ""),
                        access_level=inferred_access_level,
                    )
                )

            next_page = headers.get("X-Next-Page")
            if not next_page:
                break

            page = int(next_page)

        return all_projects[:max_projects]

    async def get_project(self, repo_name: str) -> Optional[GitLabProject]:
        """Get a project by full path (namespace/project)."""
        encoded = quote_plus(repo_name)
        data, _ = await self._request("GET", f"/projects/{encoded}")
        if not data:
            return None

        path_with_namespace = data.get("path_with_namespace", repo_name)
        owner = path_with_namespace.split("/")[0] if "/" in path_with_namespace else path_with_namespace
        visibility = data.get("visibility", "private")

        return GitLabProject(
            id=data["id"],
            name=data["name"],
            full_name=path_with_namespace,
            owner=owner,
            private=visibility != "public",
            description=data.get("description"),
            default_branch=data.get("default_branch") or "main",
            html_url=data.get("web_url", ""),
            access_level=self._extract_access_level(data),
        )

    async def list_project_hooks(self, project_id: int) -> list[dict]:
        """List webhooks configured for a project."""
        data, _ = await self._request("GET", f"/projects/{project_id}/hooks", params={"per_page": 100})
        return data or []

    async def create_project_hook(self, project_id: int, callback_url: str, secret_token: str) -> dict:
        """Create a merge request webhook for a project."""
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/api/v4/projects/{project_id}/hooks"
            response = await client.post(
                url,
                headers=self.headers,
                json={
                    "url": callback_url,
                    "token": secret_token,
                    "enable_ssl_verification": True,
                    "push_events": False,
                    "issues_events": False,
                    "merge_requests_events": True,
                    "tag_push_events": False,
                    "note_events": True,
                },
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def ensure_merge_request_webhook(self, project_id: int, callback_url: str, secret_token: str) -> dict:
        """Ensure project has a merge request webhook to callback_url."""
        hooks = await self.list_project_hooks(project_id)
        for hook in hooks:
            if hook.get("url") == callback_url:
                return {"success": True, "action": "exists", "hook_id": hook.get("id")}

        created = await self.create_project_hook(project_id, callback_url, secret_token)
        return {"success": True, "action": "created", "hook_id": created.get("id")}

    async def get_merge_request_changes(self, project_id: int, merge_request_iid: int) -> dict:
        """Fetch merge request metadata and file changes."""
        data, _ = await self._request(
            "GET",
            f"/projects/{project_id}/merge_requests/{merge_request_iid}/changes",
        )
        return data or {}

    @staticmethod
    def build_unified_diff_from_payload(mr_data: dict) -> str:
        """Build unified diff text from merge request changes payload."""
        changes = mr_data.get("changes") or []

        if not changes:
            return ""

        chunks: list[str] = []
        for change in changes:
            old_path = change.get("old_path") or change.get("new_path") or "unknown"
            new_path = change.get("new_path") or old_path
            diff = change.get("diff") or ""
            chunks.append(f"diff --git a/{old_path} b/{new_path}\n{diff}")

        return "\n".join(chunks)

    async def build_unified_diff_from_changes(self, project_id: int, merge_request_iid: int) -> str:
        """Build a unified diff string from GitLab merge request changes payload."""
        mr_data = await self.get_merge_request_changes(project_id, merge_request_iid)
        return self.build_unified_diff_from_payload(mr_data)

    async def post_merge_request_note(self, project_id: int, merge_request_iid: int, body: str) -> dict:
        """Post a note comment to a merge request."""
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/api/v4/projects/{project_id}/merge_requests/{merge_request_iid}/notes"
            response = await client.post(
                url,
                headers=self.headers,
                json={"body": body},
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def post_merge_request_discussion(
        self,
        project_id: int,
        merge_request_iid: int,
        body: str,
        file_path: str,
        line: int,
        diff_refs: dict,
    ) -> dict:
        """Post a line-level discussion comment on a merge request."""
        base_sha = diff_refs.get("base_sha")
        start_sha = diff_refs.get("start_sha")
        head_sha = diff_refs.get("head_sha")

        if not base_sha or not start_sha or not head_sha:
            raise ValueError("Missing merge request diff refs for inline discussion")

        payload = {
            "body": body,
            "position": {
                "position_type": "text",
                "base_sha": base_sha,
                "start_sha": start_sha,
                "head_sha": head_sha,
                "new_path": file_path,
                "old_path": file_path,
                "new_line": line,
            },
        }

        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/api/v4/projects/{project_id}/merge_requests/{merge_request_iid}/discussions"
            response = await client.post(
                url,
                headers=self.headers,
                json=payload,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def list_merge_request_notes(self, project_id: int, merge_request_iid: int) -> list[dict]:
        """List notes on a merge request."""
        data, _ = await self._request(
            "GET",
            f"/projects/{project_id}/merge_requests/{merge_request_iid}/notes",
            params={"per_page": 100, "order_by": "created_at", "sort": "desc"},
        )
        return data or []

    async def update_merge_request_note(
        self,
        project_id: int,
        merge_request_iid: int,
        note_id: int,
        body: str,
    ) -> dict:
        """Update an existing merge request note."""
        async with httpx.AsyncClient() as client:
            url = f"{self.base_url}/api/v4/projects/{project_id}/merge_requests/{merge_request_iid}/notes/{note_id}"
            response = await client.put(
                url,
                headers=self.headers,
                json={"body": body},
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def upsert_review_note(
        self,
        project_id: int,
        merge_request_iid: int,
        body: str,
        marker: str = "<!-- AI_APPSEC_REVIEW -->",
    ) -> dict:
        """Create a review note or update the existing marked review note."""
        notes = await self.list_merge_request_notes(project_id, merge_request_iid)
        for note in notes:
            note_body = note.get("body") or ""
            if marker in note_body:
                updated = await self.update_merge_request_note(
                    project_id=project_id,
                    merge_request_iid=merge_request_iid,
                    note_id=note.get("id"),
                    body=body,
                )
                return {
                    "success": True,
                    "action": "updated",
                    "note_id": updated.get("id", note.get("id")),
                }

        created = await self.post_merge_request_note(project_id, merge_request_iid, body)
        return {
            "success": True,
            "action": "created",
            "note_id": created.get("id"),
        }

    async def get_merge_request_webhook_status(self, project_id: int, callback_url: str) -> dict:
        """Return whether merge request webhook is configured for callback URL."""
        hooks = await self.list_project_hooks(project_id)
        for hook in hooks:
            if hook.get("url") == callback_url:
                return {
                    "configured": True,
                    "hook_id": hook.get("id"),
                }

        return {
            "configured": False,
            "hook_id": None,
        }
