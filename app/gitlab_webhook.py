"""
GitLab webhook helpers.

GitLab webhook processing for merge request reviews.
"""

import hmac
import hashlib
import logging
import asyncio
from datetime import datetime, UTC
from typing import Any, Dict, Optional

from .config import Settings, get_settings
from .database import get_supabase_client
from .database import get_repo_config
from .review_service import ReviewService, ReviewContext
from .tenants import TenantContext
from .github_webhook import detect_language
from .gitlab_client import GitLabClient

logger = logging.getLogger(__name__)


def _finding_to_dict(finding: Any) -> Dict[str, Any]:
    """Normalize finding object to dict for webhook comment formatting."""
    if hasattr(finding, "model_dump"):
        return finding.model_dump()
    if isinstance(finding, dict):
        return finding
    return {}


async def _post_inline_finding_discussions(
    client: GitLabClient,
    project_id: int,
    merge_request_iid: int,
    findings: list[Any],
    diff_refs: Dict[str, Any],
    max_inline_comments: int = 5,
) -> None:
    """Post best-effort inline discussions for findings with line context."""
    posted = 0
    for finding in findings:
        if posted >= max_inline_comments:
            break

        finding_data = _finding_to_dict(finding)
        file_path = finding_data.get("file_path")
        line = finding_data.get("line_start") or finding_data.get("line")

        if not file_path or not isinstance(line, int):
            continue

        title = finding_data.get("title", "Security finding")
        risk = str(finding_data.get("risk", "MEDIUM"))
        recommendation = finding_data.get("recommendation") or finding_data.get("description") or "Please review this code path."
        body = f"**[{risk}] {title}**\n\n{recommendation}"

        try:
            await client.post_merge_request_discussion(
                project_id=project_id,
                merge_request_iid=merge_request_iid,
                body=body,
                file_path=file_path,
                line=line,
                diff_refs=diff_refs,
            )
            posted += 1
        except Exception as e:
            logger.warning(f"Skipping inline discussion for {file_path}:{line}: {e}")


def verify_webhook_token(payload: bytes, token: str, secret: str) -> bool:
    """
    Verify GitLab webhook token.

    Supports either plain token comparison (default GitLab behavior) or
    HMAC-SHA256 digest comparison for deployments that choose digest tokens.
    """
    if not token or not secret:
        return False

    if hmac.compare_digest(token, secret):
        return True

    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(token, expected)


async def resolve_org_from_gitlab_repo(repo_name: str) -> Optional[str]:
    """Resolve organization by GitLab repo config mapping."""
    try:
        client = get_supabase_client()
        result = await asyncio.to_thread(
            lambda: client.table("repo_configs").select("org_id").eq(
                "repo_name", repo_name
            ).eq("source", "gitlab").eq("enabled", True).limit(1).execute()
        )
        row = (result.data or [None])[0]
        return row.get("org_id") if row else None
    except Exception as e:
        logger.error(f"Failed to resolve org for GitLab repo {repo_name}: {e}")
        return None


async def get_gitlab_token_for_org(org_id: str) -> Optional[str]:
    """Get active GitLab token for org from persisted connections."""
    try:
        client = get_supabase_client()
        result = await asyncio.to_thread(
            lambda: client.table("gitlab_connections").select("encrypted_access_token").eq(
                "org_id", org_id
            ).eq("is_active", True).order("connected_at", desc=True).limit(1).execute()
        )
        row = (result.data or [None])[0]
        return row.get("encrypted_access_token") if row else None
    except Exception as e:
        logger.error(f"Failed to get GitLab token for org {org_id}: {e}")
        return None


async def record_webhook_event(
    event_type: str,
    action: str,
    repo_name: str,
    mr_number: int,
    org_id: Optional[str],
    installation_id: Optional[str],
    status: str,
    error_message: Optional[str] = None,
    review_id: Optional[str] = None,
) -> None:
    """Record GitLab webhook event for observability."""
    try:
        client = get_supabase_client()
        await asyncio.to_thread(
            lambda: client.table("gitlab_webhook_events").insert({
                "event_type": event_type,
                "action": action,
                "repo_name": repo_name,
                "mr_number": mr_number,
                "org_id": org_id,
                "installation_id": installation_id,
                "status": status,
                "error_message": error_message,
                "review_id": review_id,
                "created_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
            }).execute()
        )
    except Exception as e:
        logger.error(f"Failed to record GitLab webhook event: {e}")


async def process_merge_request_webhook(
    payload: Dict[str, Any],
    settings: Optional[Settings] = None,
) -> Dict[str, Any]:
    """Process GitLab merge request webhook event and run security review."""
    if settings is None:
        settings = get_settings()

    mr = payload.get("object_attributes", {})
    project = payload.get("project", {})

    action = mr.get("action") or payload.get("event_name")
    iid = mr.get("iid")
    project_id = project.get("id")
    repo_name = project.get("path_with_namespace")
    installation_id = str(project_id) if project_id is not None else None

    if not action or not iid or not repo_name or not project_id:
        raise ValueError("Missing required merge request fields")

    if action not in ["open", "update", "reopen"]:
        return {
            "status": "ignored",
            "reason": f"Action '{action}' not processed"
        }

    org_id = await resolve_org_from_gitlab_repo(repo_name)
    if not org_id:
        return {
            "status": "skipped",
            "reason": "Repository is not configured for GitLab reviews",
            "repo": repo_name,
            "mr_number": iid,
        }

    await record_webhook_event(
        event_type="merge_request",
        action=action,
        repo_name=repo_name,
        mr_number=iid,
        org_id=org_id,
        installation_id=installation_id,
        status="processing",
    )

    repo_config = await get_repo_config(org_id, repo_name)
    if not repo_config or not repo_config.get("enabled", True):
        return {
            "status": "skipped",
            "reason": "Repository is not enabled",
            "repo": repo_name,
            "mr_number": iid,
        }

    token = await get_gitlab_token_for_org(org_id)
    if not token:
        await record_webhook_event(
            event_type="merge_request",
            action=action,
            repo_name=repo_name,
            mr_number=iid,
            org_id=org_id,
            installation_id=installation_id,
            status="error",
            error_message="Missing GitLab connection token",
        )
        raise ValueError("Missing GitLab connection token")

    client = GitLabClient(token, settings.gitlab_instance_url)
    mr_changes = await client.get_merge_request_changes(project_id, iid)
    diff_text = client.build_unified_diff_from_payload(mr_changes)
    diff_refs = mr_changes.get("diff_refs") or {}

    if not diff_text.strip():
        return {
            "status": "skipped",
            "reason": "No merge request diff content available",
            "repo": repo_name,
            "mr_number": iid,
        }

    context = ReviewContext(
        org_id=org_id,
        org_name=None,
        repo=repo_name,
        pr_number=iid,
        diff=diff_text,
        language=detect_language(repo_name),
        framework="express",
        policy=None,
        pr_title=mr.get("title"),
        pr_author=(mr.get("last_commit") or {}).get("author", {}).get("name") or (mr.get("author") or {}).get("name"),
    )

    tenant = TenantContext(
        org_id=org_id,
        org_name=None,
        token_scopes=["admin:policy", "read:metrics", "write:findings"],
        user_id=None,
    )

    service = ReviewService(settings)
    result = await service.review_pr(context, tenant)

    if result.should_post_comment:
        try:
            body = result.response.findings_markdown or result.response.summary or "Security review completed."
            await client.upsert_review_note(project_id, iid, body)

            findings = result.response.findings or []
            if findings and diff_refs:
                await _post_inline_finding_discussions(
                    client=client,
                    project_id=project_id,
                    merge_request_iid=iid,
                    findings=findings,
                    diff_refs=diff_refs,
                )
        except Exception as e:
            logger.error(f"Failed to post GitLab MR note for {repo_name}!{iid}: {e}")

    await record_webhook_event(
        event_type="merge_request",
        action=action,
        repo_name=repo_name,
        mr_number=iid,
        org_id=org_id,
        installation_id=installation_id,
        status="completed" if result.success else "error",
        error_message=result.error_message if not result.success else None,
        review_id=result.review_id,
    )

    return {
        "status": "success" if result.success else "error",
        "provider": "gitlab",
        "action": action,
        "repo_name": repo_name,
        "mr_number": iid,
        "review_id": result.review_id,
        "findings_count": len(result.response.findings or []),
        "should_block": result.response.should_block if result.success else False,
    }


async def process_note_webhook(
    payload: Dict[str, Any],
    settings: Optional[Settings] = None,
) -> Dict[str, Any]:
    """Process GitLab note webhook commands for merge requests."""
    if settings is None:
        settings = get_settings()

    object_attributes = payload.get("object_attributes", {})
    noteable_type = object_attributes.get("noteable_type")
    note_body = (object_attributes.get("note") or "").strip()

    if noteable_type != "MergeRequest":
        return {"status": "ignored", "reason": "Note is not for a merge request"}

    if not note_body.startswith("/"):
        return {"status": "ignored", "reason": "Not a command"}

    project = payload.get("project", {})
    project_id = project.get("id")
    repo_name = project.get("path_with_namespace")
    mr = payload.get("merge_request", {})
    mr_iid = mr.get("iid")

    if not project_id or not repo_name or not mr_iid:
        raise ValueError("Missing required note command fields")

    command = note_body.split()[0].lower()

    org_id = await resolve_org_from_gitlab_repo(repo_name)
    if not org_id:
        return {"status": "ignored", "reason": "Repository is not configured"}

    token = await get_gitlab_token_for_org(org_id)
    if not token:
        raise ValueError("Missing GitLab connection token")

    client = GitLabClient(token, settings.gitlab_instance_url)

    if command == "/help":
        help_body = (
            "## AI AppSec Commands\n\n"
            "- `/review` re-runs security analysis for this merge request\n"
            "- `/help` shows this help message"
        )
        await client.upsert_review_note(project_id, mr_iid, help_body)
        return {
            "status": "completed",
            "command": "help",
            "repo_name": repo_name,
            "mr_number": mr_iid,
        }

    if command == "/review":
        synthetic_payload = {
            "object_kind": "merge_request",
            "object_attributes": {
                "action": "update",
                "iid": mr_iid,
                "title": mr.get("title"),
                "author": mr.get("author") or {},
                "last_commit": mr.get("last_commit") or {},
            },
            "project": {
                "id": project_id,
                "path_with_namespace": repo_name,
            },
        }
        result = await process_merge_request_webhook(synthetic_payload, settings)
        result["command"] = "review"
        return result

    return {
        "status": "ignored",
        "reason": f"Command '{command}' not supported",
    }


async def store_gitlab_app_installation(
    org_id: str,
    installation_id: str,
    account_login: str,
    account_type: str,
    account_id: int,
    gitlab_instance_url: str,
    scopes: Optional[list[str]] = None,
) -> Dict[str, Any]:
    """Store or update GitLab installation metadata for an organization."""
    client = get_supabase_client()

    payload = {
        "org_id": org_id,
        "installation_id": installation_id,
        "account_login": account_login,
        "account_type": account_type,
        "account_id": account_id,
        "gitlab_instance_url": gitlab_instance_url,
        "scopes": scopes or [],
        "is_active": True,
    }

    result = await asyncio.to_thread(
        lambda: client.table("gitlab_app_installations").upsert(
            payload,
            on_conflict="org_id,installation_id"
        ).execute()
    )

    if not result.data:
        raise ValueError("Failed to persist GitLab installation")

    return {
        "success": True,
        "installation_id": installation_id,
        "org_id": org_id,
        "account_login": account_login,
        "message": "GitLab installation linked successfully",
    }
