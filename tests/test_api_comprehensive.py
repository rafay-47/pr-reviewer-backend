"""Comprehensive API and flow tests for the backend service.

These tests focus on:
- Endpoint behavior across all API domains
- Frontend request flows (dashboard/subscription/repository/finding workflows)
- PR review workflows used by CI/CD and GitHub integrations

All network/database/third-party interactions are mocked to keep tests fast and deterministic.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

import app.chat_handler as chat_handler
import app.database as database
import app.github_app_auth as github_app_auth
import app.github_client as github_client
import app.github_webhook as github_webhook
import app.gitlab_client as gitlab_client
import app.gitlab_webhook as gitlab_webhook
import app.invitations as invitations
import app.main as main
import app.stripe_integration as stripe_integration
import app.subscriptions as subscriptions
from app.auth import UserContext
from app.models import ConfidenceLevel, ExplainFindingResponse, ReviewResponse, RiskLevel, SecurityFinding
from app.tenants import TenantContext


class _DummyLimiter:
    def is_allowed(self, _key: str) -> bool:
        return True

    def get_remaining(self, _key: str) -> int:
        return 999

    def get_reset_time(self, _key: str) -> int:
        return 0


class _DummyAudit:
    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


class _DummyMetrics:
    def record_review(self, **_kwargs):
        return None

    def get_aggregated_metrics(self):
        return {
            "total_prs_reviewed": 3,
            "total_findings": 5,
            "findings_by_category": {"injection": 2},
            "findings_by_risk": {"HIGH": 1, "MEDIUM": 2, "LOW": 2},
            "avg_review_time_ms": 120.0,
            "success_rate": 100.0,
            "total_success": 3,
            "total_failure": 0,
            "uptime_seconds": 60,
        }


@pytest.fixture
def test_settings():
    settings = SimpleNamespace(
        # Core app
        environment="test",
        host="127.0.0.1",
        port=8000,
        log_level="INFO",
        llm_provider="claude",
        effective_model="claude-3.5-sonnet",
        llm_api_key="test-llm-key",
        is_production=False,
        # Auth and security
        multi_tenant_mode=True,
        api_auth_token="",
        hmac_enabled=False,
        hmac_secret="",
        hmac_timestamp_tolerance=300,
        enable_security_headers=False,
        enable_audit_logging=False,
        # Limits
        rate_limit_requests=100,
        rate_limit_window=60,
        max_request_size=2_000_000,
        max_diff_size=200_000,
        rate_limit_token_creation=25,
        token_max_lifetime_days=365,
        token_default_lifetime_days=90,
        # DB/URLs
        database_configured=True,
        redis_configured=False,
        redis_url=None,
        supabase_url="",
        stripe_secret_key="sk_test_123",
        github_app_webhook_secret="webhook_secret",
        gitlab_app_webhook_secret="gitlab_webhook_secret",
        gitlab_app_client_id="gitlab-client-id",
        gitlab_app_client_secret="gitlab-client-secret",
        gitlab_instance_url="https://gitlab.com",
        cors_origins_list=["http://localhost:3000"],
        api_base_url="https://api.example.com",
        log_diff_content=False,
        shutdown_timeout_seconds=1,
    )
    settings.validate_config = lambda: []
    settings.get_warnings = lambda: []
    return settings


@pytest.fixture
def admin_tenant():
    return TenantContext(
        org_id="org-1",
        org_name="Org One",
        org_slug="org-one",
        token_scopes=[
            "review:pr",
            "explain:finding",
            "read:metrics",
            "feedback:write",
            "admin:policy",
            "admin:tokens",
        ],
        user_id="user-1",
        user_role="owner",
        user_email="owner@example.com",
    )


@pytest.fixture
def admin_user():
    return UserContext(
        user_id="user-1",
        email="owner@example.com",
        org_id="org-1",
        org_name="Org One",
        org_slug="org-one",
        role="owner",
    )


@pytest.fixture
def api_client(monkeypatch, test_settings, admin_tenant, admin_user):
    # Global deterministic test behavior
    monkeypatch.setattr(main, "get_rate_limiter", lambda *args, **kwargs: _DummyLimiter())
    monkeypatch.setattr(main, "get_token_rate_limiter", lambda *args, **kwargs: _DummyLimiter())
    monkeypatch.setattr(main, "get_audit_logger", lambda *args, **kwargs: _DummyAudit())
    monkeypatch.setattr(main, "get_metrics_tracker", lambda: _DummyMetrics())
    monkeypatch.setattr(subscriptions, "check_feature_access", AsyncMock(return_value=(True, None)))

    app = main.app

    async def _tenant_override():
        return admin_tenant

    async def _user_override():
        return admin_user

    async def _review_auth_override():
        return admin_user

    async def _cicd_override():
        return admin_user

    async def _verify_auth_override():
        return True

    app.dependency_overrides[main.get_settings] = lambda: test_settings
    app.dependency_overrides[main.require_tenant_context] = _tenant_override
    app.dependency_overrides[main.require_tenant_context_flexible] = _tenant_override
    app.dependency_overrides[main.get_user_with_org] = _user_override
    app.dependency_overrides[main.get_user_from_jwt] = _user_override
    app.dependency_overrides[main.require_jwt_only] = _user_override
    app.dependency_overrides[main.require_review_pr_auth] = _review_auth_override
    app.dependency_overrides[main.require_cicd_token] = _cicd_override
    app.dependency_overrides[main.verify_auth_token] = _verify_auth_override

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
def sample_review_response():
    return ReviewResponse(
        summary="Found 1 issue",
        findings=[
            SecurityFinding(
                title="Potential SQL injection",
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                file_path="src/db.py",
                line_range="12-13",
                fingerprint="abc123ef",
                description="Unsafe string concatenation in query",
            )
        ],
        findings_markdown="## Review\n\nOne finding.",
        should_block=False,
    )


def _supabase_query(data):
    query = MagicMock()
    query._maybe_single = False
    query.select.return_value = query
    query.eq.return_value = query
    query.order.return_value = query
    def _mark_maybe_single(*_args, **_kwargs):
        query._maybe_single = True
        return query
    query.maybe_single.side_effect = _mark_maybe_single
    query.limit.return_value = query
    query.update.return_value = query
    query.in_.return_value = query
    def _execute():
        if query._maybe_single and isinstance(data, list):
            return SimpleNamespace(data=data[0] if data else None)
        return SimpleNamespace(data=data)
    query.execute.side_effect = _execute
    return query


def test_route_inventory_has_expected_api_surface():
    routes = {(method, route.path) for route in main.app.routes for method in route.methods if method != "HEAD"}

    expected_subset = {
        ("GET", "/health"),
        ("POST", "/review-pr"),
        ("POST", "/explain-finding"),
        ("GET", "/metrics"),
        ("POST", "/api/auth/tokens"),
        ("POST", "/api/auth/switch-organization"),
        ("POST", "/api/tokens"),
        ("GET", "/api/tokens"),
        ("GET", "/api/dashboard/stats"),
        ("GET", "/api/findings"),
        ("POST", "/api/feedback"),
        ("GET", "/api/repos"),
        ("PUT", "/api/repos/{repo_name:path}"),
        ("GET", "/api/github/repos"),
        ("POST", "/api/github/import"),
        ("POST", "/api/github/workflows/install"),
        ("POST", "/api/organizations"),
        ("POST", "/api/invitations"),
        ("POST", "/api/subscription/upgrade"),
        ("POST", "/api/webhooks/github"),
    }

    missing = expected_subset - routes
    assert not missing


def test_public_health_and_root_endpoints(api_client):
    root = api_client.get("/")
    health = api_client.get("/health")

    assert root.status_code == 200
    assert health.status_code == 200
    assert root.json()["docs"] == "/docs"
    assert health.json()["status"] in {"healthy", "degraded"}


def test_review_and_explain_endpoints(api_client, monkeypatch, sample_review_response):
    monkeypatch.setattr(main, "check_can_review_pr", AsyncMock(return_value=(True, None)))
    monkeypatch.setattr(main, "get_tenant_repo_policy", AsyncMock(return_value=None))
    monkeypatch.setattr(main, "get_tenant_suppressions", AsyncMock(return_value=[]))
    monkeypatch.setattr(main, "validate_request_security", AsyncMock(return_value={
        "repo": "org/repo",
        "pr_number": 42,
        "language": "python",
        "framework": "fastapi",
        "diff": "diff --git a/a.py b/a.py\n+print('ok')",
    }))
    monkeypatch.setattr(main, "analyze_diff", AsyncMock(return_value=sample_review_response))

    # Disable DB persistence path for this focused API behavior test.
    original_get_settings = main.app.dependency_overrides[main.get_settings]

    def _db_off_settings():
        settings = original_get_settings()
        settings.database_configured = False
        return settings

    main.app.dependency_overrides[main.get_settings] = _db_off_settings

    resp = api_client.post(
        "/review-pr",
        json={
            "repo": "org/repo",
            "pr_number": 42,
            "diff": "diff --git a/a.py b/a.py\n+print('ok')",
        },
        headers={"Authorization": "Bearer aiappsec_token"},
    )

    assert resp.status_code == 200
    assert resp.json()["summary"] == "Found 1 issue"

    monkeypatch.setattr(
        main,
        "explain_sast_finding",
        AsyncMock(
            return_value=ExplainFindingResponse(
                explanation="User input reaches a sink.",
                risk_justification="Could allow SQLi.",
                remediation="Use parameterized queries.",
                example_fix="db.execute('SELECT * FROM users WHERE id = %s', (uid,))",
                severity=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                references=["OWASP A03"],
                tool="semgrep",
                original_rule_id="python.sql.injection",
            )
        ),
    )

    explain = api_client.post(
        "/explain-finding",
        json={
            "tool": "semgrep",
            "finding_text": "Possible SQL injection",
            "language": "python",
        },
    )

    assert explain.status_code == 200
    assert explain.json()["tool"] == "semgrep"


def test_token_management_endpoints(api_client, monkeypatch):
    monkeypatch.setattr(
        main,
        "create_api_token",
        AsyncMock(return_value=(
            "aiappsec_newtoken",
            {
                "id": "tok-1",
                "name": "CI token",
                "prefix": "aiappsec_1234",
                "token_type": "cicd",
                "scopes": ["review:pr", "explain:finding"],
                "created_at": "2026-03-28T00:00:00Z",
                "expires_at": None,
            },
        )),
    )
    monkeypatch.setattr(
        database,
        "get_cicd_token",
        AsyncMock(return_value={
            "id": "tok-cicd",
            "name": "Default CI/CD Token",
            "prefix": "aiappsec_abcd",
            "token_type": "cicd",
            "scopes": ["review:pr", "explain:finding"],
            "created_at": "2026-03-28T00:00:00Z",
            "revoked_at": None,
            "last_used_at": None,
            "expires_at": None,
        }),
    )
    monkeypatch.setattr(
        database,
        "regenerate_cicd_token",
        AsyncMock(return_value=(
            "aiappsec_regenerated",
            {
                "id": "tok-regen",
                "name": "Default CI/CD Token",
                "prefix": "aiappsec_reg",
                "token_type": "cicd",
                "scopes": ["review:pr", "explain:finding"],
                "created_at": "2026-03-28T00:00:00Z",
            },
        )),
    )
    monkeypatch.setattr(
        main,
        "list_api_tokens",
        AsyncMock(return_value=[
            {
                "id": "tok-1",
                "name": "token-a",
                "prefix": "aiappsec_a",
                "token_type": "cicd",
                "scopes": ["review:pr"],
                "created_at": "2026-03-28T00:00:00Z",
                "expires_at": None,
                "revoked_at": None,
                "last_used_at": None,
            }
        ]),
    )
    monkeypatch.setattr(main, "rotate_api_token", AsyncMock(return_value=(
        "aiappsec_rotated",
        {
            "id": "tok-2",
            "name": "token-b",
            "prefix": "aiappsec_b",
            "scopes": ["review:pr"],
            "created_at": "2026-03-28T00:00:00Z",
            "expires_at": None,
        },
    )))
    monkeypatch.setattr(main, "revoke_api_token", AsyncMock(return_value=True))

    create_bootstrap = api_client.post(
        "/api/auth/tokens",
        json={"name": "Bootstrap", "token_type": "cicd"},
    )
    assert create_bootstrap.status_code == 200

    # Switch organization uses direct Supabase query.
    supabase = MagicMock()
    supabase.table.return_value = _supabase_query([
        {"role": "owner", "organizations": {"id": "org-2", "name": "Org Two", "slug": "org-two"}}
    ])
    monkeypatch.setattr(database, "get_supabase_client", lambda: supabase)

    switched = api_client.post("/api/auth/switch-organization?org_id=org-2")
    assert switched.status_code == 200
    assert switched.json()["org_id"] == "org-2"

    create = api_client.post("/api/tokens", json={"name": "Pipeline", "token_type": "cicd"})
    types_resp = api_client.get("/api/tokens/types")
    cicd_meta = api_client.get("/api/tokens/cicd")
    regenerated = api_client.post("/api/tokens/cicd/regenerate")
    listed = api_client.get("/api/tokens")
    rotated = api_client.post("/api/tokens/tok-1/rotate")
    revoked = api_client.delete("/api/tokens/tok-1")

    assert create.status_code == 200
    assert types_resp.status_code == 200
    assert cicd_meta.status_code == 200
    assert regenerated.status_code == 200
    assert listed.status_code == 200
    assert rotated.status_code == 200
    assert revoked.status_code == 200


def test_dashboard_findings_feedback_and_repo_endpoints(api_client, monkeypatch):
    monkeypatch.setattr(main, "get_dashboard_stats", AsyncMock(return_value={
        "total_reviews": 10,
        "total_findings": 20,
        "high_findings": 2,
        "medium_findings": 8,
        "low_findings": 10,
        "avg_review_time_ms": 120.0,
        "success_rate": 95.0,
        "blocked_count": 1,
        "resolved_findings": 4,
    }))
    monkeypatch.setattr(main, "get_findings_by_category", AsyncMock(return_value=[{"category": "injection", "count": 3}]))
    monkeypatch.setattr(main, "get_top_risky_repos", AsyncMock(return_value=[{
        "repo_name": "org/repo",
        "review_count": 5,
        "total_findings": 8,
        "high_findings": 2,
        "risk_score": 78.5,
    }]))
    monkeypatch.setattr(main, "get_review_trend", AsyncMock(return_value=[{
        "date": "2026-03-28",
        "review_count": 2,
        "findings_count": 3,
        "high_count": 1,
    }]))
    monkeypatch.setattr(main, "get_active_findings_stats", AsyncMock(return_value={
        "total_reviews": 8,
        "total_findings": 9,
        "high_findings": 2,
        "medium_findings": 3,
        "low_findings": 4,
        "avg_review_time_ms": 100.0,
        "success_rate": 98.0,
        "blocked_count": 0,
    }))
    monkeypatch.setattr(main, "get_active_findings_by_category", AsyncMock(return_value=[{"category": "secrets", "count": 2}]))
    monkeypatch.setattr(main, "get_active_findings_trend", AsyncMock(return_value=[{
        "date": "2026-03-28",
        "review_count": 1,
        "findings_count": 2,
        "high_count": 1,
    }]))
    monkeypatch.setattr(main, "get_top_risky_repos_active", AsyncMock(return_value=[{
        "repo_name": "org/repo",
        "review_count": 3,
        "total_findings": 4,
        "high_findings": 1,
        "risk_score": 55.0,
    }]))

    monkeypatch.setattr(database, "get_recent_reviews", AsyncMock(return_value=[{"id": "r1"}]))
    monkeypatch.setattr(database, "get_recent_findings", AsyncMock(return_value=[{
        "id": "f1",
        "title": "Issue",
        "severity": "HIGH",
        "status": "open",
    }]))
    monkeypatch.setattr(database, "get_finding_by_id_for_org", AsyncMock(return_value={
        "id": "f1",
        "title": "Issue",
        "severity": "HIGH",
        "status": "open",
    }))
    monkeypatch.setattr(main, "create_feedback", AsyncMock(return_value={
        "id": "fb-1",
        "fingerprint": "abc123ef",
        "label": "false_positive",
        "created_at": "2026-03-28T00:00:00Z",
    }))
    monkeypatch.setattr(main, "resolve_finding", AsyncMock(return_value=True))
    monkeypatch.setattr(main, "get_feedback_for_org", AsyncMock(return_value=[{"id": "fb-1"}]))
    monkeypatch.setattr(database, "get_feedback_stats", AsyncMock(return_value={"total": 1, "false_positive": 1}))

    monkeypatch.setattr(main, "get_active_suppressions", AsyncMock(return_value=[]))
    monkeypatch.setattr(main, "create_suppression_rule", AsyncMock(return_value={
        "id": "sr-1",
        "fingerprint": "abc123ef",
        "title_pattern": None,
        "file_pattern": None,
        "category": None,
        "reason": "noise",
        "is_active": True,
        "expires_at": None,
        "created_at": "2026-03-28T00:00:00Z",
    }))
    monkeypatch.setattr(main, "delete_suppression_rule", AsyncMock(return_value=True))

    monkeypatch.setattr(main, "list_repo_configs", AsyncMock(return_value=[{
        "id": "cfg-1",
        "repo_name": "org/repo",
        "policy": {},
        "enabled": True,
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:00Z",
        "source": "manual",
    }]))
    monkeypatch.setattr(main, "get_repo_config", AsyncMock(return_value={
        "id": "cfg-1",
        "repo_name": "org/repo",
        "policy": {},
        "enabled": True,
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:00Z",
        "source": "manual",
    }))
    monkeypatch.setattr(main, "check_can_add_repo", AsyncMock(return_value=(True, None)))
    monkeypatch.setattr(main, "upsert_repo_config", AsyncMock(return_value={
        "id": "cfg-1",
        "repo_name": "org/repo",
        "policy": {},
        "enabled": True,
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:00Z",
        "source": "manual",
    }))

    assert api_client.get("/api/dashboard/stats").status_code == 200
    assert api_client.get("/api/dashboard/findings-by-category").status_code == 200
    assert api_client.get("/api/dashboard/top-repos").status_code == 200
    assert api_client.get("/api/dashboard/trend").status_code == 200
    assert api_client.get("/api/dashboard/active/stats").status_code == 200
    assert api_client.get("/api/dashboard/active/findings-by-category").status_code == 200
    assert api_client.get("/api/dashboard/active/trend").status_code == 200
    assert api_client.get("/api/dashboard/active/top-repos").status_code == 200

    assert api_client.get("/api/reviews").status_code == 200
    assert api_client.get("/api/findings").status_code == 200
    assert api_client.get("/api/findings/f1").status_code == 200

    feedback = api_client.post("/api/feedback", json={
        "fingerprint": "abc123ef",
        "label": "false_positive",
        "finding_id": "f1",
        "comment": "false positive",
    })
    assert feedback.status_code == 200

    assert api_client.get("/api/feedback").status_code == 200
    assert api_client.get("/api/feedback/stats").status_code == 200

    assert api_client.get("/api/suppressions").status_code == 200
    assert api_client.post("/api/suppressions", json={
        "reason": "noise",
        "fingerprint": "abc123ef",
        "expires_in_days": 7,
    }).status_code == 200
    assert api_client.delete("/api/suppressions/sr-1").status_code == 200

    assert api_client.get("/api/repos").status_code == 200
    assert api_client.get("/api/repos/org/repo").status_code == 200
    assert api_client.put("/api/repos/org/repo", json={
        "repo_name": "org/repo",
        "enabled": True,
        "policy": {"mode": "advisory"},
    }).status_code == 200


def test_findings_resolution_and_chat_endpoints(api_client, monkeypatch):
    monkeypatch.setattr(main, "resolve_finding", AsyncMock(return_value=True))
    monkeypatch.setattr(main, "bulk_resolve_findings", AsyncMock(return_value=2))
    monkeypatch.setattr(main, "reopen_finding", AsyncMock(return_value=True))
    monkeypatch.setattr(main, "get_finding_status_history", AsyncMock(return_value=[{
        "id": "h1",
        "old_status": "open",
        "new_status": "resolved",
        "changed_by_user_id": "user-1",
        "change_method": "manual",
        "reason": "fixed",
        "notes": "done",
        "created_at": "2026-03-28T00:00:00Z",
    }]))

    monkeypatch.setattr(chat_handler, "handle_chat_command", AsyncMock(return_value=("Use parameterized queries.", "Potential SQL injection")))
    monkeypatch.setattr(database, "create_chat_interaction", AsyncMock(return_value={"id": "chat-1"}))

    assert api_client.post("/api/findings/resolve", json={
        "finding_id": "f1",
        "status": "resolved",
        "reason": "fixed",
    }).status_code == 200

    assert api_client.post("/api/findings/bulk-resolve", json={
        "finding_ids": ["f1", "f2"],
        "status": "accepted_risk",
        "reason": "accepted",
    }).status_code == 200

    assert api_client.post("/api/findings/reopen", json={
        "finding_id": "f1",
        "reason": "reopened",
    }).status_code == 200

    assert api_client.get("/api/findings/f1/history").status_code == 200

    assert api_client.post("/api/chat", json={
        "repo_name": "org/repo",
        "pr_number": 42,
        "command": "explain",
        "finding_number": 1,
        "github_user": "octocat",
    }).status_code == 200


def test_github_integration_endpoints(api_client, monkeypatch):
    # /api/github/repos and installation endpoints use direct Supabase calls.
    supabase = MagicMock()

    installations_query = _supabase_query([
        {
            "id": "inst-row-1",
            "installation_id": 12345,
            "account_login": "octo-org",
            "account_type": "Organization",
            "account_id": 1001,
            "repository_selection": "all",
            "permissions": {"contents": "write"},
            "events": ["pull_request"],
            "installed_at": "2026-03-28T00:00:00Z",
            "updated_at": "2026-03-28T00:00:00Z",
            "is_active": True,
            "suspended_at": None,
            "suspended_by": None,
        }
    ])

    def _table(name: str):
        if name == "github_app_installations":
            return installations_query
        if name == "org_members":
            return _supabase_query([{"role": "owner", "organizations": {"id": "org-1", "name": "Org", "slug": "org"}}])
        if name == "reviews":
            return _supabase_query([{"id": "review-1"}])
        if name == "findings":
            return _supabase_query([])
        return _supabase_query([])

    supabase.table.side_effect = _table
    monkeypatch.setattr(database, "get_supabase_client", lambda: supabase)

    monkeypatch.setattr(github_app_auth, "get_installation_token", AsyncMock(return_value=("ghs_xxx", {"contents": "write"})))
    monkeypatch.setattr(main, "list_repo_configs", AsyncMock(return_value=[]))

    class _Repo:
        def __init__(self):
            self.id = 111
            self.name = "repo"
            self.full_name = "octo-org/repo"
            self.owner = "octo-org"
            self.private = True
            self.description = "Repo"
            self.default_branch = "main"
            self.html_url = "https://github.com/octo-org/repo"
            self.permissions = {"push": True, "admin": True}

    gh_client = MagicMock()
    gh_client.list_installation_repos = AsyncMock(return_value=[_Repo()])
    gh_client.get_repo = AsyncMock(return_value=SimpleNamespace(permissions={"admin": True}))
    gh_client.set_repository_secret = AsyncMock(return_value={"success": True, "secret_name": "AI_REVIEW_TOKEN"})
    gh_client.list_repository_secrets = AsyncMock(return_value=["AI_REVIEW_TOKEN"])
    monkeypatch.setattr(github_client, "GitHubClient", lambda token: gh_client)

    monkeypatch.setattr(main, "upsert_repo_config", AsyncMock(return_value={
        "id": "cfg-2",
        "repo_name": "octo-org/repo",
        "policy": {},
        "enabled": True,
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:00Z",
        "source": "github",
    }))

    monkeypatch.setattr(main, "get_usage_status", AsyncMock(return_value=SimpleNamespace(
        repos_used=0,
        repos_limit=10,
        repos_remaining=10,
        prs_used=0,
        prs_limit=100,
        prs_remaining=100,
        members_used=1,
        members_limit=5,
        members_remaining=4,
        within_limits=True,
        plan_id="team",
        plan_name="Team",
    )))

    monkeypatch.setattr(github_client, "check_workflow_installed", AsyncMock(return_value={
        "installed": True,
        "path": ".github/workflows/ai-review.yml",
        "sha": "abc",
        "version": "1",
    }))
    monkeypatch.setattr(github_client, "install_workflow_to_repo", AsyncMock(return_value={
        "success": True,
        "action": "created",
        "commit_sha": "deadbeef",
    }))

    monkeypatch.setattr(github_webhook, "store_github_app_installation", AsyncMock(return_value={
        "success": True,
        "installation_id": 12345,
        "org_id": "org-1",
        "account_login": "octo-org",
        "message": "linked",
    }))
    monkeypatch.setattr(github_app_auth, "get_github_app_info", AsyncMock(return_value={
        "html_url": "https://github.com/apps/aiappsec-pr-reviewer",
        "name": "AI AppSec PR Reviewer",
        "slug": "aiappsec-pr-reviewer",
    }))
    monkeypatch.setattr(github_app_auth, "generate_app_jwt", lambda _settings: "jwt")

    class _HTTPResponse:
        status_code = 200

        @staticmethod
        def json():
            return [
                {
                    "id": 12345,
                    "account": {"login": "octo-org", "type": "Organization", "id": 1001},
                    "repository_selection": "all",
                    "permissions": {"contents": "write"},
                    "events": ["pull_request"],
                    "created_at": "2026-03-28T00:00:00Z",
                    "updated_at": "2026-03-28T00:00:00Z",
                }
            ]

        text = "ok"

    http_client = MagicMock()
    http_client.__aenter__.return_value = http_client
    http_client.__aexit__.return_value = False
    http_client.get = AsyncMock(return_value=_HTTPResponse())
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", lambda: http_client)

    assert api_client.get("/api/github/repos").status_code == 200
    assert api_client.post("/api/github/import", json={"repos": ["octo-org/repo"]}).status_code == 200
    assert api_client.get("/api/github/repos/octo-org/repo/workflow/status").status_code == 200
    assert api_client.post("/api/github/workflows/install", json={"repos": ["octo-org/repo"]}).status_code == 200
    assert api_client.post("/api/github/repos/octo-org/repo/secrets", json={"AI_REVIEW_TOKEN": "token"}).status_code == 200
    assert api_client.get("/api/github/repos/octo-org/repo/secrets").status_code == 200

    assert api_client.post("/api/github/app/installations", json={
        "installation_id": 12345,
        "account_login": "octo-org",
        "account_type": "Organization",
        "account_id": 1001,
    }).status_code == 200

    assert api_client.get("/api/github/app/installations").status_code == 200
    assert api_client.get("/api/github/app/installations/12345").status_code == 200
    assert api_client.get("/api/github/app/install-url").status_code == 200
    assert api_client.get("/api/github/app/my-installations").status_code == 200
    assert api_client.delete("/api/github/app/installations/12345").status_code == 200


def test_gitlab_integration_endpoints(api_client, monkeypatch):
    supabase = MagicMock()

    installations_query = _supabase_query([
        {
            "id": "gitlab-inst-row-1",
            "installation_id": "gitlab-inst-1",
            "account_login": "octo-group",
            "account_type": "Group",
            "account_id": 2001,
            "gitlab_instance_url": "https://gitlab.com",
            "scopes": ["api", "read_repository"],
            "installed_at": "2026-03-28T00:00:00Z",
            "updated_at": "2026-03-28T00:00:00Z",
            "is_active": True,
        }
    ])

    def _table(name: str):
        if name == "gitlab_app_installations":
            return installations_query
        if name == "org_members":
            return _supabase_query([{"role": "owner", "organizations": {"id": "org-1", "name": "Org", "slug": "org"}}])
        return _supabase_query([])

    supabase.table.side_effect = _table
    monkeypatch.setattr(database, "get_supabase_client", lambda: supabase)

    monkeypatch.setattr(gitlab_webhook, "store_gitlab_app_installation", AsyncMock(return_value={
        "success": True,
        "installation_id": "gitlab-inst-1",
        "org_id": "org-1",
        "account_login": "octo-group",
        "message": "linked",
    }))

    monkeypatch.setattr(main, "get_gitlab_token_for_tenant", AsyncMock(return_value="glpat_token"))
    monkeypatch.setattr(main, "list_repo_configs", AsyncMock(return_value=[]))
    monkeypatch.setattr(main, "upsert_repo_config", AsyncMock(return_value={
        "id": "cfg-gl-1",
        "repo_name": "octo-group/repo",
        "policy": {},
        "enabled": True,
        "created_at": "2026-03-28T00:00:00Z",
        "updated_at": "2026-03-28T00:00:00Z",
        "source": "gitlab",
    }))
    monkeypatch.setattr(main, "get_usage_status", AsyncMock(return_value=SimpleNamespace(
        repos_used=0,
        repos_limit=10,
        repos_remaining=10,
        prs_used=0,
        prs_limit=100,
        prs_remaining=100,
        members_used=1,
        members_limit=5,
        members_remaining=4,
        within_limits=True,
        plan_id="team",
        plan_name="Team",
    )))

    project = SimpleNamespace(
        id=9001,
        name="repo",
        full_name="octo-group/repo",
        owner="octo-group",
        private=True,
        description="Repo",
        default_branch="main",
        html_url="https://gitlab.com/octo-group/repo",
        access_level=40,
    )
    gl_client = MagicMock()
    gl_client.list_projects = AsyncMock(return_value=[project])
    gl_client.get_project = AsyncMock(return_value=project)
    gl_client.get_merge_request_webhook_status = AsyncMock(return_value={
        "configured": True,
        "hook_id": 7001,
    })
    gl_client.ensure_merge_request_webhook = AsyncMock(return_value={
        "success": True,
        "action": "created",
        "hook_id": 7001,
    })
    monkeypatch.setattr(gitlab_client, "GitLabClient", lambda token, base_url="https://gitlab.com": gl_client)

    assert api_client.post("/api/gitlab/app/installations", json={
        "installation_id": "gitlab-inst-1",
        "account_login": "octo-group",
        "account_type": "Group",
        "account_id": 2001,
        "gitlab_instance_url": "https://gitlab.com",
        "scopes": ["api", "read_repository"],
    }).status_code == 200

    assert api_client.get("/api/gitlab/app/installations").status_code == 200
    assert api_client.get("/api/gitlab/app/install-url").status_code == 200
    assert api_client.delete("/api/gitlab/app/installations/gitlab-inst-1").status_code == 200
    assert api_client.get("/api/gitlab/repos").status_code == 200
    assert api_client.post("/api/gitlab/import", json={"repos": ["octo-group/repo"]}).status_code == 200
    assert api_client.post("/api/gitlab/webhooks/install", json={"repos": ["octo-group/repo"]}).status_code == 200
    assert api_client.get("/api/gitlab/repos/octo-group/repo/webhook/status").status_code == 200


def test_gitlab_oauth_authorize_and_callback(api_client, monkeypatch):
    class _StateQuery:
        def __init__(self):
            self.inserted = None
            self.updated = None
            self.filters = {}
            self._mode = "select"

        def insert(self, payload):
            self.inserted = payload
            self._mode = "insert"
            return self

        def select(self, *_args, **_kwargs):
            self._mode = "select"
            return self

        def eq(self, key, value):
            self.filters[key] = value
            return self

        def maybe_single(self):
            return self

        def update(self, payload):
            self.updated = payload
            self._mode = "update"
            return self

        def execute(self):
            if self._mode == "insert":
                return SimpleNamespace(data=[{"id": "state-1"}])
            if self._mode == "update":
                return SimpleNamespace(data=[{"id": "state-1", **(self.updated or {})}])
            return SimpleNamespace(data={
                "id": "state-1",
                "state_hash": self.filters.get("state_hash"),
                "user_id": "user-1",
                "used": False,
            })

    class _ConnectionQuery:
        def __init__(self):
            self.payload = None

        def upsert(self, payload, **_kwargs):
            self.payload = payload
            return self

        def execute(self):
            return SimpleNamespace(data=[self.payload])

    state_query = _StateQuery()
    connection_query = _ConnectionQuery()

    supabase = MagicMock()

    def _table(name: str):
        if name == "oauth_states":
            return state_query
        if name == "gitlab_connections":
            return connection_query
        return _supabase_query([])

    supabase.table.side_effect = _table
    monkeypatch.setattr(database, "get_supabase_client", lambda: supabase)
    monkeypatch.setattr(database, "get_user_organizations", AsyncMock(return_value=[{"id": "org-1"}]))

    class _HTTPResponse:
        def __init__(self, status_code, payload, text="ok"):
            self.status_code = status_code
            self._payload = payload
            self.text = text

        def json(self):
            return self._payload

    http_client = MagicMock()
    http_client.__aenter__.return_value = http_client
    http_client.__aexit__.return_value = False
    http_client.post = AsyncMock(return_value=_HTTPResponse(200, {
        "access_token": "glpat_test_token",
        "scope": "api read_api read_repository",
    }))
    http_client.get = AsyncMock(return_value=_HTTPResponse(200, {
        "id": 9001,
        "username": "gitlab-user",
    }))

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", lambda: http_client)

    authorize_resp = api_client.get("/api/gitlab/oauth/authorize")
    assert authorize_resp.status_code == 200
    assert authorize_resp.json()["provider"] == "gitlab"
    assert "state=" in authorize_resp.json()["authorization_url"]

    state_value = authorize_resp.json()["state"]

    callback_resp = api_client.get(f"/api/gitlab/oauth/callback?code=test-code&state={state_value}")
    assert callback_resp.status_code == 200
    assert callback_resp.json()["connected"] is True
    assert callback_resp.json()["gitlab_username"] == "gitlab-user"


def test_organization_invitation_pricing_and_subscription_endpoints(api_client, monkeypatch):
    monkeypatch.setattr(database, "get_organization_by_slug", AsyncMock(return_value=None))
    monkeypatch.setattr(database, "create_organization", AsyncMock(return_value=(
        {"id": "org-1", "name": "Org One", "slug": "org-one"},
        "aiappsec_bootstrap",
    )))
    monkeypatch.setattr(database, "get_cicd_token", AsyncMock(return_value={"id": "tok", "prefix": "aiappsec_x"}))
    monkeypatch.setattr(database, "get_user_organizations", AsyncMock(return_value=[{"id": "org-1", "name": "Org One", "slug": "org-one", "role": "owner"}]))

    monkeypatch.setattr(main, "check_can_add_member", AsyncMock(return_value=(True, None)))
    monkeypatch.setattr(invitations, "create_invitation", AsyncMock(return_value={
        "id": "inv-1",
        "email": "invitee@example.com",
        "role": "member",
        "invite_token": "a" * 32,
        "expires_at": "2026-04-01T00:00:00Z",
        "created_at": "2026-03-28T00:00:00Z",
    }))
    monkeypatch.setattr(invitations, "get_pending_invitations", AsyncMock(return_value=[{
        "id": "inv-1",
        "email": "invitee@example.com",
        "role": "member",
        "invite_token": "a" * 32,
        "invited_by_email": "owner@example.com",
        "expires_at": "2026-04-01T00:00:00Z",
        "created_at": "2026-03-28T00:00:00Z",
    }]))
    monkeypatch.setattr(invitations, "accept_invitation", AsyncMock(return_value={
        "org_id": "org-1",
        "org_name": "Org One",
        "org_slug": "org-one",
        "role": "member",
    }))
    monkeypatch.setattr(invitations, "revoke_invitation", AsyncMock(return_value=True))

    monkeypatch.setattr(subscriptions, "get_all_plans", AsyncMock(return_value=[
        {
            "id": "free",
            "name": "Free",
            "description": "Starter",
            "price_monthly_cents": 0,
            "price_yearly_cents": 0,
            "max_repos": 1,
            "max_prs_per_month": 30,
            "max_team_members": 1,
            "feature_advisory_mode": True,
            "feature_enforcement_mode": False,
            "feature_dashboard": True,
            "feature_audit_logs": False,
            "feature_sso": False,
            "feature_policy_as_code": False,
            "feature_siem_integration": False,
            "feature_custom_rules": False,
            "feature_priority_support": False,
            "feature_dedicated_support": False,
        }
    ]))

    plan = subscriptions.PlanLimits(
        plan_id="team",
        plan_name="Team",
        max_repos=10,
        max_prs_per_month=500,
        max_team_members=10,
        feature_advisory_mode=True,
        feature_enforcement_mode=True,
        feature_dashboard=True,
        feature_audit_logs=False,
        feature_sso=False,
        feature_policy_as_code=False,
        feature_siem_integration=False,
        feature_custom_rules=False,
        feature_priority_support=True,
        feature_dedicated_support=False,
        price_monthly_cents=4900,
        price_yearly_cents=49900,
    )

    usage = subscriptions.UsageStatus(
        within_limits=True,
        repos_used=1,
        repos_limit=10,
        repos_remaining=9,
        prs_used=2,
        prs_limit=500,
        prs_remaining=498,
        members_used=2,
        members_limit=10,
        members_remaining=8,
        plan_id="team",
        plan_name="Team",
    )

    monkeypatch.setattr(subscriptions, "get_organization_plan", AsyncMock(return_value=plan))
    monkeypatch.setattr(subscriptions, "get_usage_status", AsyncMock(return_value=usage))
    monkeypatch.setattr(subscriptions, "get_subscription", AsyncMock(return_value={
        "id": "sub-1",
        "status": "active",
        "billing_cycle": "monthly",
        "current_period_start": "2026-03-01T00:00:00Z",
        "current_period_end": "2026-04-01T00:00:00Z",
    }))
    monkeypatch.setattr(subscriptions, "get_plan_limits", AsyncMock(return_value=plan))
    monkeypatch.setattr(subscriptions, "update_subscription_plan", AsyncMock(return_value={"id": "sub-1"}))

    monkeypatch.setattr(stripe_integration, "initialize_stripe", lambda _settings: None)
    monkeypatch.setattr(stripe_integration, "create_checkout_session", AsyncMock(return_value={
        "checkout_url": "https://stripe.test/checkout",
        "session_id": "cs_test_1",
    }))
    monkeypatch.setattr(stripe_integration, "cancel_subscription", AsyncMock(return_value={"success": True}))
    monkeypatch.setattr(stripe_integration, "get_customer_portal_url", AsyncMock(return_value="https://stripe.test/portal"))
    monkeypatch.setattr(stripe_integration, "handle_webhook_event", AsyncMock(return_value={"ok": True}))

    # Organization + invitations
    assert api_client.post("/api/organizations", json={"org_name": "Org One"}).status_code == 200
    assert api_client.get("/api/organizations").status_code == 200
    assert api_client.post("/api/invitations", json={"email": "invitee@example.com", "role": "member", "expires_in_days": 7}).status_code == 200
    assert api_client.get("/api/invitations").status_code == 200
    assert api_client.post("/api/invitations/accept", json={"invite_token": "a" * 32}).status_code == 200
    assert api_client.delete("/api/invitations/inv-1").status_code == 200

    # Legacy quick setup
    monkeypatch.setattr(database, "create_organization", AsyncMock(return_value={"id": "org-2", "name": "Bootstrap Org", "slug": "bootstrap-org"}))
    monkeypatch.setattr(main, "create_api_token", AsyncMock(return_value=(
        "aiappsec_bootstrap",
        {"prefix": "aiappsec_boot", "id": "tok-boot"},
    )))
    assert api_client.post("/api/setup/quick-start", json={"org_name": "Bootstrap Org", "token_name": "GitHub Actions Token"}).status_code == 200

    # Pricing + subscription
    assert api_client.get("/api/pricing/plans").status_code == 200
    assert api_client.get("/api/subscription").status_code == 200
    assert api_client.get("/api/subscription/usage").status_code == 200
    assert api_client.get("/api/subscription/features").status_code == 200
    assert api_client.post("/api/subscription/upgrade", json={"plan_id": "team", "billing_cycle": "monthly"}).status_code == 200
    assert api_client.post("/api/subscription/cancel").status_code == 200
    assert api_client.get("/api/subscription/portal").status_code == 200

    # Stripe webhook
    stripe = api_client.post(
        "/api/webhooks/stripe",
        data=b"{}",
        headers={"stripe-signature": "sig_test"},
    )
    assert stripe.status_code == 200


def test_github_webhook_endpoint_events(api_client, monkeypatch):
    monkeypatch.setattr(github_webhook, "verify_webhook_signature", lambda payload, signature, secret: True)
    monkeypatch.setattr(github_webhook, "process_pull_request_webhook", AsyncMock(return_value={"status": "completed"}))
    monkeypatch.setattr(github_webhook, "record_webhook_event", AsyncMock(return_value=True))
    monkeypatch.setattr(github_webhook, "process_installation_created", AsyncMock(return_value={"status": "created"}))
    monkeypatch.setattr(github_webhook, "process_installation_deleted", AsyncMock(return_value={"status": "deleted"}))
    monkeypatch.setattr(github_webhook, "process_installation_suspend", AsyncMock(return_value={"status": "suspended"}))
    monkeypatch.setattr(github_webhook, "resolve_org_from_installation", AsyncMock(return_value="org-1"))
    monkeypatch.setattr(github_webhook, "post_pr_comment", AsyncMock(return_value=True))

    # Pull request event
    pr_payload = {
        "action": "opened",
        "repository": {"full_name": "org/repo"},
        "pull_request": {"number": 10, "title": "PR title", "draft": False},
        "installation": {"id": 12345},
    }
    pr_resp = api_client.post(
        "/api/webhooks/github",
        json=pr_payload,
        headers={"X-Hub-Signature-256": "sha256=abc", "X-GitHub-Event": "pull_request"},
    )
    assert pr_resp.status_code == 200

    # Installation event
    inst_payload = {"action": "created", "installation": {"id": 12345}}
    inst_resp = api_client.post(
        "/api/webhooks/github",
        json=inst_payload,
        headers={"X-Hub-Signature-256": "sha256=abc", "X-GitHub-Event": "installation"},
    )
    assert inst_resp.status_code == 200


def test_gitlab_webhook_endpoint_events(api_client, monkeypatch):
    monkeypatch.setattr(gitlab_webhook, "verify_webhook_token", lambda payload, token, secret: True)
    monkeypatch.setattr(gitlab_webhook, "process_merge_request_webhook", AsyncMock(return_value={"status": "accepted"}))
    monkeypatch.setattr(gitlab_webhook, "process_note_webhook", AsyncMock(return_value={"status": "completed", "command": "review"}))

    mr_payload = {
        "object_kind": "merge_request",
        "object_attributes": {
            "action": "open",
            "iid": 33,
            "title": "MR title",
        },
        "project": {
            "path_with_namespace": "org/repo",
        },
    }

    resp = api_client.post(
        "/api/webhooks/gitlab",
        json=mr_payload,
        headers={"X-Gitlab-Token": "token"},
    )
    assert resp.status_code == 200

    note_payload = {
        "object_kind": "note",
        "object_attributes": {
            "noteable_type": "MergeRequest",
            "note": "/review",
        },
        "project": {
            "id": 99,
            "path_with_namespace": "org/repo",
        },
        "merge_request": {
            "iid": 33,
            "title": "MR title",
        },
    }
    note_resp = api_client.post(
        "/api/webhooks/gitlab",
        json=note_payload,
        headers={"X-Gitlab-Token": "token"},
    )
    assert note_resp.status_code == 200


@pytest.mark.asyncio
async def test_gitlab_webhook_processing_flow(monkeypatch, test_settings):
    payload = {
        "object_kind": "merge_request",
        "object_attributes": {
            "action": "open",
            "iid": 21,
            "title": "Secure update",
            "author": {"name": "alice"},
        },
        "project": {
            "id": 321,
            "path_with_namespace": "octo-group/repo",
        },
    }

    monkeypatch.setattr(gitlab_webhook, "resolve_org_from_gitlab_repo", AsyncMock(return_value="org-1"))
    monkeypatch.setattr(gitlab_webhook, "get_gitlab_token_for_org", AsyncMock(return_value="glpat_token"))
    monkeypatch.setattr(gitlab_webhook, "record_webhook_event", AsyncMock(return_value=None))
    monkeypatch.setattr(gitlab_webhook, "get_repo_config", AsyncMock(return_value={"enabled": True}))

    gl_client = MagicMock()
    gl_client.get_merge_request_changes = AsyncMock(return_value={
        "diff_refs": {
            "base_sha": "a" * 40,
            "start_sha": "b" * 40,
            "head_sha": "c" * 40,
        },
        "changes": [
            {
                "old_path": "a.py",
                "new_path": "a.py",
                "diff": "@@ -1,1 +1,2 @@\n print('x')\n+print('ok')",
            }
        ],
    })
    gl_client.upsert_review_note = AsyncMock(return_value={"id": 1, "action": "created"})
    gl_client.post_merge_request_discussion = AsyncMock(return_value={"id": "d1"})
    monkeypatch.setattr(gitlab_webhook, "GitLabClient", lambda token, base_url="https://gitlab.com": gl_client)

    mock_review_result = SimpleNamespace(
        success=True,
        response=SimpleNamespace(findings_markdown="## Review", summary="Done", findings=[SecurityFinding(
            title="Potential injection",
            risk=RiskLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            file_path="a.py",
            line_start=2,
            recommendation="Use parameterized queries",
        )], should_block=False),
        review_id="rev-1",
        error_message=None,
        should_post_comment=True,
    )

    service = MagicMock()
    service.review_pr = AsyncMock(return_value=mock_review_result)
    monkeypatch.setattr(gitlab_webhook, "ReviewService", lambda _settings: service)

    result = await gitlab_webhook.process_merge_request_webhook(payload, test_settings)

    assert result["status"] == "success"
    assert result["review_id"] == "rev-1"
    gl_client.upsert_review_note.assert_awaited_once()
    gl_client.post_merge_request_discussion.assert_awaited_once()


def test_frontend_request_flow(api_client, monkeypatch):
    """Frontend flow: org context -> subscription -> dashboard -> repos -> findings."""
    monkeypatch.setattr(database, "get_user_organizations", AsyncMock(return_value=[{"id": "org-1", "name": "Org One", "slug": "org-one", "role": "owner"}]))

    plan = subscriptions.PlanLimits(
        plan_id="free",
        plan_name="Free",
        max_repos=1,
        max_prs_per_month=30,
        max_team_members=1,
        feature_advisory_mode=True,
        feature_enforcement_mode=False,
        feature_dashboard=True,
        feature_audit_logs=False,
        feature_sso=False,
        feature_policy_as_code=False,
        feature_siem_integration=False,
        feature_custom_rules=False,
        feature_priority_support=False,
        feature_dedicated_support=False,
        price_monthly_cents=0,
        price_yearly_cents=0,
    )
    usage = subscriptions.UsageStatus(
        within_limits=True,
        repos_used=1,
        repos_limit=1,
        repos_remaining=0,
        prs_used=12,
        prs_limit=30,
        prs_remaining=18,
        members_used=1,
        members_limit=1,
        members_remaining=0,
        plan_id="free",
        plan_name="Free",
    )

    monkeypatch.setattr(subscriptions, "get_organization_plan", AsyncMock(return_value=plan))
    monkeypatch.setattr(subscriptions, "get_usage_status", AsyncMock(return_value=usage))
    monkeypatch.setattr(subscriptions, "get_subscription", AsyncMock(return_value={"id": "sub-1", "status": "active", "billing_cycle": "monthly"}))

    monkeypatch.setattr(main, "get_dashboard_stats", AsyncMock(return_value={"total_reviews": 4, "total_findings": 7, "high_findings": 1, "medium_findings": 2, "low_findings": 4, "avg_review_time_ms": 120, "success_rate": 100, "blocked_count": 0, "resolved_findings": 1}))
    monkeypatch.setattr(main, "get_findings_by_category", AsyncMock(return_value=[{"category": "injection", "count": 2}]))
    monkeypatch.setattr(main, "list_repo_configs", AsyncMock(return_value=[{"id": "cfg", "repo_name": "org/repo", "policy": {}, "enabled": True, "created_at": "2026-03-28T00:00:00Z", "updated_at": "2026-03-28T00:00:00Z", "source": "manual"}]))
    monkeypatch.setattr(database, "get_recent_findings", AsyncMock(return_value=[{"id": "f1", "severity": "HIGH", "status": "open"}]))

    assert api_client.get("/api/organizations").status_code == 200
    assert api_client.get("/api/subscription").status_code == 200
    assert api_client.get("/api/subscription/features").status_code == 200
    assert api_client.get("/api/dashboard/stats").status_code == 200
    assert api_client.get("/api/dashboard/findings-by-category").status_code == 200
    assert api_client.get("/api/repos").status_code == 200
    assert api_client.get("/api/findings").status_code == 200


def test_pr_review_flow_with_follow_up_feedback(api_client, monkeypatch, sample_review_response):
    """PR review flow used by CI/CD: review -> findings list -> feedback -> resolution history."""
    monkeypatch.setattr(main, "check_can_review_pr", AsyncMock(return_value=(True, None)))
    monkeypatch.setattr(main, "get_tenant_repo_policy", AsyncMock(return_value=None))
    monkeypatch.setattr(main, "get_tenant_suppressions", AsyncMock(return_value=[]))
    monkeypatch.setattr(main, "validate_request_security", AsyncMock(return_value={
        "repo": "org/repo",
        "pr_number": 88,
        "language": "python",
        "framework": "fastapi",
        "diff": "diff --git a/api.py b/api.py\n+query = f\"SELECT * FROM users WHERE id = {user_id}\"",
    }))
    monkeypatch.setattr(main, "analyze_diff", AsyncMock(return_value=sample_review_response))

    # Keep DB disabled for review endpoint; this flow validates API sequencing behavior.
    original_get_settings = main.app.dependency_overrides[main.get_settings]

    def _db_off_settings():
        settings = original_get_settings()
        settings.database_configured = False
        return settings

    main.app.dependency_overrides[main.get_settings] = _db_off_settings

    monkeypatch.setattr(database, "get_recent_findings", AsyncMock(return_value=[{"id": "f1", "severity": "HIGH", "status": "open", "fingerprint": "abc123ef"}]))
    monkeypatch.setattr(main, "create_feedback", AsyncMock(return_value={
        "id": "fb-1",
        "fingerprint": "abc123ef",
        "label": "true_positive",
        "created_at": "2026-03-28T00:00:00Z",
    }))
    monkeypatch.setattr(main, "resolve_finding", AsyncMock(return_value=True))
    monkeypatch.setattr(main, "get_finding_status_history", AsyncMock(return_value=[{
        "id": "h1",
        "old_status": "open",
        "new_status": "resolved",
        "changed_by_user_id": "user-1",
        "change_method": "manual",
        "reason": "confirmed",
        "notes": None,
        "created_at": "2026-03-28T00:00:00Z",
    }]))

    review = api_client.post(
        "/review-pr",
        json={
            "repo": "org/repo",
            "pr_number": 88,
            "diff": "diff --git a/api.py b/api.py\n+query = f\"SELECT * FROM users WHERE id = {user_id}\"",
        },
        headers={"Authorization": "Bearer aiappsec_pipeline"},
    )
    assert review.status_code == 200

    findings = api_client.get("/api/findings")
    assert findings.status_code == 200

    feedback = api_client.post(
        "/api/feedback",
        json={
            "fingerprint": "abc123ef",
            "label": "true_positive",
            "finding_id": "f1",
            "comment": "Confirmed and fixed",
        },
    )
    assert feedback.status_code == 200

    history = api_client.get("/api/findings/f1/history")
    assert history.status_code == 200
