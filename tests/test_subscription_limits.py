"""Tests for subscription limit enforcement in repository management flows."""

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from types import SimpleNamespace
from unittest.mock import MagicMock
from unittest.mock import AsyncMock, patch

from fastapi.security import HTTPAuthorizationCredentials
from app.auth import UserContext, require_review_pr_auth
from app.database import regenerate_cicd_token
from app.invitations import accept_invitation
from app.main import import_github_repos, update_repo
from app.models import GitHubImportRequest, RepoConfigRequest
from app.review_service import ReviewContext, ReviewService
from app.subscriptions import UsageStatus, require_feature
from app.tenants import TenantContext, resolve_tenant_from_request


@pytest.mark.asyncio
async def test_update_repo_allows_existing_enabled_repo_at_limit():
    """Updating an already enabled repo should not be blocked by add-repo limits."""
    tenant = TenantContext(org_id="org-1", token_scopes=["admin:policy"])
    request = RepoConfigRequest(repo_name="owner/repo", enabled=True)

    with (
        patch("app.main.get_repo_config", new=AsyncMock(return_value={"repo_name": "owner/repo", "enabled": True})),
        patch("app.main.check_can_add_repo", new=AsyncMock(return_value=(False, "limit reached"))) as mock_check_can_add,
        patch(
            "app.main.upsert_repo_config",
            new=AsyncMock(
                return_value={
                    "id": "cfg-1",
                    "repo_name": "owner/repo",
                    "policy": {},
                    "enabled": True,
                    "created_at": "2026-02-18T00:00:00Z",
                    "updated_at": "2026-02-18T00:00:00Z",
                    "source": "manual",
                }
            ),
        ) as mock_upsert,
    ):
        response = await update_repo("owner/repo", request, tenant)

    assert response.repo_name == "owner/repo"
    assert response.enabled is True
    mock_check_can_add.assert_not_awaited()
    mock_upsert.assert_awaited_once()


@pytest.mark.asyncio
async def test_import_github_repos_rejects_over_quota_batch():
    """Bulk import should reject the full request when selected repos exceed remaining quota."""
    tenant = TenantContext(org_id="org-1", token_scopes=["admin:policy"])
    request = GitHubImportRequest(repos=["org/new-repo"])

    usage = UsageStatus(
        within_limits=False,
        repos_used=1,
        repos_limit=1,
        repos_remaining=0,
        prs_used=0,
        prs_limit=30,
        prs_remaining=30,
        members_used=1,
        members_limit=1,
        members_remaining=0,
        plan_id="free",
        plan_name="Free",
    )

    with (
        patch("app.database.list_repo_configs", new=AsyncMock(return_value=[])),
        patch("app.main.get_usage_status", new=AsyncMock(return_value=usage)),
        patch("app.main.upsert_repo_config", new=AsyncMock()) as mock_upsert,
    ):
        with pytest.raises(HTTPException) as exc:
            await import_github_repos(request, tenant)

    assert exc.value.status_code == 403
    assert "Repository limit reached" in str(exc.value.detail)
    mock_upsert.assert_not_awaited()


@pytest.mark.asyncio
async def test_import_github_repos_allows_existing_enabled_repos_at_limit():
    """Re-importing already enabled repos should not consume additional quota."""
    tenant = TenantContext(org_id="org-1", token_scopes=["admin:policy"])
    request = GitHubImportRequest(repos=["org/existing-repo"])

    with (
        patch(
            "app.database.list_repo_configs",
            new=AsyncMock(return_value=[{"repo_name": "org/existing-repo", "enabled": True}]),
        ),
        patch("app.main.get_usage_status", new=AsyncMock()) as mock_usage,
        patch(
            "app.main.upsert_repo_config",
            new=AsyncMock(
                return_value={
                    "id": "cfg-2",
                    "repo_name": "org/existing-repo",
                    "policy": {},
                    "enabled": True,
                    "created_at": "2026-02-18T00:00:00Z",
                    "updated_at": "2026-02-18T00:00:00Z",
                    "source": "github",
                }
            ),
        ) as mock_upsert,
    ):
        response = await import_github_repos(request, tenant)

    assert response.total_imported == 1
    assert response.total_failed == 0
    mock_usage.assert_not_awaited()
    mock_upsert.assert_awaited_once()


@pytest.mark.asyncio
async def test_review_service_blocks_when_pr_limit_reached():
    """PR reviews should be blocked when monthly review quota is exhausted."""
    service = ReviewService(settings=SimpleNamespace(llm_api_key="test-key"))
    context = ReviewContext(
        org_id="org-1",
        repo="owner/repo",
        pr_number=101,
        diff="diff --git a/a.py b/a.py",
    )

    with patch(
        "app.review_service.check_can_review_pr",
        new=AsyncMock(return_value=(False, "Monthly PR review limit reached (30/30)")),
    ):
        result = await service.review_pr(context)

    assert result.success is False
    assert result.error_message is not None
    assert "Monthly PR review limit reached" in result.error_message


@pytest.mark.asyncio
async def test_accept_invitation_blocks_when_member_limit_reached():
    """Invitation acceptance should be blocked when member quota is already full."""
    invitation_query = MagicMock()
    invitation_query.select.return_value = invitation_query
    invitation_query.eq.return_value = invitation_query
    invitation_query.is_.return_value = invitation_query
    invitation_query.gt.return_value = invitation_query
    invitation_query.maybe_single.return_value = SimpleNamespace(
        execute=lambda: SimpleNamespace(
            data={
                "invite_token": "a" * 32,
                "org_id": "org-1",
            }
        )
    )

    supabase_client = MagicMock()
    supabase_client.table.return_value = invitation_query

    with (
        patch("app.invitations.get_supabase_client", return_value=supabase_client),
        patch(
            "app.invitations.check_can_add_member",
            new=AsyncMock(return_value=(False, "Team member limit reached (1/1)")),
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            await accept_invitation("a" * 32, "user-1")

    assert exc.value.status_code == 403
    assert "Team member limit reached" in str(exc.value.detail)
    supabase_client.rpc.assert_not_called()


def _make_request(headers: dict[str, str]) -> Request:
    """Build a minimal Starlette request object for dependency tests."""
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/test",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_resolve_tenant_rejects_missing_bearer_token():
    """Tenant resolution must reject unauthenticated header-only org selection."""
    request = _make_request({"X-Tenant-ID": "org-1"})

    with pytest.raises(HTTPException) as exc:
        await resolve_tenant_from_request(request)

    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_resolve_tenant_rejects_non_cicd_bearer_token():
    """Tenant resolution should only accept CI/CD API tokens on token-based flow."""
    request = _make_request({
        "Authorization": "Bearer ey.fake.jwt",
        "X-Tenant-ID": "org-1",
    })

    with pytest.raises(HTTPException) as exc:
        await resolve_tenant_from_request(request)

    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_resolve_tenant_rejects_mismatched_tenant_header_and_token_org():
    """Explicit tenant header must match token org_id."""
    request = _make_request({
        "Authorization": "Bearer aiappsec_validtoken",
        "X-Tenant-ID": "org-header",
    })

    with (
        patch(
            "app.tenants.validate_api_token",
            new=AsyncMock(return_value={"id": "tok-1", "org_id": "org-token", "scopes": ["review:pr"]}),
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            await resolve_tenant_from_request(request)

    assert exc.value.status_code == 403
    assert "Token does not belong" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_resolve_tenant_accepts_valid_cicd_token_without_tenant_header():
    """Valid CI/CD token should resolve tenant org from token payload."""
    request = _make_request({
        "Authorization": "Bearer aiappsec_validtoken",
    })

    with (
        patch(
            "app.tenants.validate_api_token",
            new=AsyncMock(return_value={"id": "tok-1", "org_id": "org-1", "scopes": ["review:pr"]}),
        ),
        patch(
            "app.tenants.get_organization_by_id",
            new=AsyncMock(return_value={"id": "org-1", "name": "Org One", "slug": "org-one"}),
        ),
    ):
        tenant = await resolve_tenant_from_request(request)

    assert tenant.org_id == "org-1"
    assert tenant.token_scopes == ["review:pr"]


@pytest.mark.asyncio
async def test_require_review_pr_auth_allows_jwt_when_github_app_installed():
    """JWT auth should be accepted for /review-pr when GitHub App is installed for the org."""
    request = _make_request({"Authorization": "Bearer ey.valid.jwt"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="ey.valid.jwt")
    jwt_user = UserContext(user_id="user-1", email="u@example.com")
    user_with_org = UserContext(
        user_id="user-1",
        email="u@example.com",
        org_id="org-1",
        org_name="Org One",
        role="member",
    )

    with (
        patch("app.auth.require_jwt_only", new=AsyncMock(return_value=jwt_user)),
        patch("app.auth.get_user_with_org", new=AsyncMock(return_value=user_with_org)),
        patch("app.auth._has_active_github_app_installation", new=AsyncMock(return_value=True)),
        patch("app.auth.require_cicd_token", new=AsyncMock()) as mock_cicd,
    ):
        result = await require_review_pr_auth(request, credentials, settings=SimpleNamespace())

    assert result.org_id == "org-1"
    mock_cicd.assert_not_awaited()


@pytest.mark.asyncio
async def test_require_review_pr_auth_rejects_jwt_without_github_app_installation():
    """JWT auth should be rejected for /review-pr when org does not have GitHub App installed."""
    request = _make_request({"Authorization": "Bearer ey.valid.jwt"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="ey.valid.jwt")
    jwt_user = UserContext(user_id="user-1", email="u@example.com")
    user_with_org = UserContext(
        user_id="user-1",
        email="u@example.com",
        org_id="org-1",
        org_name="Org One",
        role="member",
    )

    with (
        patch("app.auth.require_jwt_only", new=AsyncMock(return_value=jwt_user)),
        patch("app.auth.get_user_with_org", new=AsyncMock(return_value=user_with_org)),
        patch("app.auth._has_active_github_app_installation", new=AsyncMock(return_value=False)),
    ):
        with pytest.raises(HTTPException) as exc:
            await require_review_pr_auth(request, credentials, settings=SimpleNamespace())

    assert exc.value.status_code == 403
    assert "CI/CD token is required" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_require_review_pr_auth_uses_cicd_path_for_api_tokens():
    """API tokens should continue to authenticate through the CI/CD token flow."""
    request = _make_request({"Authorization": "Bearer aiappsec_token"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="aiappsec_token")
    cicd_user = UserContext(user_id="token_1", org_id="org-1", role="admin")

    with patch("app.auth.require_cicd_token", new=AsyncMock(return_value=cicd_user)) as mock_cicd:
        result = await require_review_pr_auth(request, credentials, settings=SimpleNamespace())

    assert result.user_id == "token_1"
    mock_cicd.assert_awaited_once()


@pytest.mark.asyncio
async def test_regenerate_cicd_token_revokes_existing_and_creates_new_token():
    """Regeneration should revoke existing CI/CD tokens and issue one new token."""
    query = MagicMock()
    query.eq.return_value = query
    query.update.return_value = query
    query.execute.return_value = SimpleNamespace(data=[])

    table = MagicMock(return_value=query)
    client = MagicMock()
    client.table = table

    with (
        patch("app.database.get_supabase_client", return_value=client),
        patch(
            "app.database.create_api_token",
            new=AsyncMock(return_value=("aiappsec_newtoken", {"id": "new-1", "token_type": "cicd"})),
        ) as mock_create,
    ):
        token, token_data = await regenerate_cicd_token(
            org_id="org-1",
            created_by="user-1",
            ip_address="127.0.0.1",
            user_agent="pytest",
        )

    assert token == "aiappsec_newtoken"
    assert token_data["id"] == "new-1"
    assert table.call_count >= 2
    mock_create.assert_awaited_once_with(
        org_id="org-1",
        name="Default CI/CD Token",
        token_type="cicd",
        created_by="user-1",
        expires_in_days=0,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )


@pytest.mark.asyncio
async def test_require_feature_resolves_tenant_via_jwt_path():
    """Feature checks should use JWT tenant resolution, not CI/CD-only tenant parsing."""
    request = _make_request({"Authorization": "Bearer ey.valid.jwt"})
    dependency = require_feature("dashboard")

    with (
        patch(
            "app.main.require_tenant_context_flexible",
            new=AsyncMock(return_value=TenantContext(org_id="org-1", token_scopes=["read:metrics"])),
        ) as mock_tenant_resolver,
        patch("app.subscriptions.check_feature_access", new=AsyncMock(return_value=(True, None))) as mock_check_feature,
    ):
        result = await dependency(request=request, settings=SimpleNamespace())

    assert result is True
    mock_tenant_resolver.assert_awaited_once()
    mock_check_feature.assert_awaited_once_with("org-1", "dashboard")
