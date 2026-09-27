"""
Tests for direct GitHub App installation without the web app.

Verifies:
1. Auto-provisioning organization when app is installed directly via GitHub
2. JIT organization provisioning during PR review when installation was not previously in DB
3. Upsert fallback in store_github_app_installation
4. Handling of installation.unsuspend and installation_repositories events
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from app.config import Settings
from app.github_webhook import (
    get_or_create_org_for_github_account,
    resolve_org_from_installation,
    store_github_app_installation,
    process_installation_created,
    process_installation_unsuspend,
    process_pull_request_webhook,
)


@pytest.fixture
def mock_supabase():
    """Mock Supabase client."""
    client = MagicMock()
    return client


@pytest.mark.asyncio
async def test_get_or_create_org_existing_by_settings():
    """Test finding existing org by settings->github_account_id."""
    mock_client = MagicMock()
    mock_result = MagicMock()
    mock_result.data = [{"id": "org-existing-123"}]
    
    mock_client.table.return_value.select.return_value.filter.return_value.limit.return_value.execute.return_value = mock_result
    
    with patch("app.github_webhook.get_supabase_client", return_value=mock_client):
        org_id = await get_or_create_org_for_github_account(
            account_login="octocat",
            account_id=583231,
            account_type="User"
        )
        
    assert org_id == "org-existing-123"


@pytest.mark.asyncio
async def test_get_or_create_org_creates_new():
    """Test creating a new org when no match exists."""
    mock_client = MagicMock()
    
    # settings filter returns empty
    mock_settings_res = MagicMock()
    mock_settings_res.data = []
    mock_client.table.return_value.select.return_value.filter.return_value.limit.return_value.execute.return_value = mock_settings_res
    
    # insert returns new org
    new_org = {
        "id": "org-new-456",
        "name": "octocat",
        "slug": "octocat",
        "plan_id": "free"
    }
    mock_insert_res = MagicMock()
    mock_insert_res.data = [new_org]
    mock_client.table.return_value.insert.return_value.execute.return_value = mock_insert_res
    
    with (
        patch("app.github_webhook.get_supabase_client", return_value=mock_client),
        patch("app.database.get_organization_by_slug", new=AsyncMock(return_value=None)),
        patch("app.database.create_api_token", new=AsyncMock(return_value=("token-xyz", {"prefix": "test"}))),
    ):
        org_id = await get_or_create_org_for_github_account(
            account_login="octocat",
            account_id=583231,
            account_type="User"
        )
        
    assert org_id == "org-new-456"
    # Verify insert was called with free plan and auto_created metadata
    mock_client.table.assert_any_call("organizations")


@pytest.mark.asyncio
async def test_resolve_org_from_installation_cached_in_db():
    """Test resolving org when installation is already present in DB."""
    mock_client = MagicMock()
    mock_query_res = MagicMock()
    mock_query_res.data = {"org_id": "org-existing-789", "is_active": True}
    
    mock_client.table.return_value.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = mock_query_res
    
    with patch("app.github_webhook.get_supabase_client", return_value=mock_client):
        org_id = await resolve_org_from_installation(164822973)
        
    assert org_id == "org-existing-789"


@pytest.mark.asyncio
async def test_resolve_org_from_installation_jit_provisioning_via_github_api():
    """Test JIT auto-provisioning when installation is NOT in DB, using GitHub API."""
    mock_client = MagicMock()
    
    # First query to github_app_installations returns None (the bug scenario!)
    mock_query_res = MagicMock()
    mock_query_res.data = None
    mock_client.table.return_value.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = mock_query_res
    
    # GitHub API returns installation details
    github_install_details = {
        "id": 164822973,
        "account": {
            "login": "octocat",
            "id": 583231,
            "type": "User"
        },
        "repository_selection": "all",
        "permissions": {"pull_requests": "write"},
        "events": ["pull_request"]
    }
    
    with (
        patch("app.github_webhook.get_supabase_client", return_value=mock_client),
        patch("app.github_webhook.get_installation_details", new=AsyncMock(return_value=github_install_details)),
        patch("app.github_webhook.get_or_create_org_for_github_account", new=AsyncMock(return_value="org-auto-jit-123")) as mock_get_or_create,
        patch("app.github_webhook.store_github_app_installation", new=AsyncMock(return_value={"success": True})) as mock_store,
    ):
        org_id = await resolve_org_from_installation(164822973)
        
    assert org_id == "org-auto-jit-123"
    mock_get_or_create.assert_awaited_once_with(
        account_login="octocat",
        account_id=583231,
        account_type="User"
    )
    mock_store.assert_awaited_once()


@pytest.mark.asyncio
async def test_resolve_org_from_installation_jit_provisioning_via_fallback():
    """Test JIT auto-provisioning when GitHub API call fails, using fallback payload info."""
    mock_client = MagicMock()
    
    # DB has no installation
    mock_query_res = MagicMock()
    mock_query_res.data = None
    mock_client.table.return_value.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = mock_query_res
    
    fallback_info = {
        "login": "octocat",
        "id": 583231,
        "type": "User"
    }
    
    with (
        patch("app.github_webhook.get_supabase_client", return_value=mock_client),
        patch("app.github_webhook.get_installation_details", new=AsyncMock(return_value=None)),  # GitHub API unavailable
        patch("app.github_webhook.get_or_create_org_for_github_account", new=AsyncMock(return_value="org-auto-fallback-456")) as mock_get_or_create,
        patch("app.github_webhook.store_github_app_installation", new=AsyncMock(return_value={"success": True})) as mock_store,
    ):
        org_id = await resolve_org_from_installation(
            installation_id=164822973,
            fallback_account_info=fallback_info
        )
        
    assert org_id == "org-auto-fallback-456"
    mock_get_or_create.assert_awaited_once_with(
        account_login="octocat",
        account_id=583231,
        account_type="User"
    )
    mock_store.assert_awaited_once()


@pytest.mark.asyncio
async def test_process_installation_created_saves_installation():
    """Test that installation.created webhook saves the installation and links org."""
    payload = {
        "action": "created",
        "installation": {
            "id": 164822973,
            "account": {
                "login": "my-org",
                "id": 998877,
                "type": "Organization"
            },
            "repository_selection": "all",
            "permissions": {"pull_requests": "write"},
            "events": ["pull_request"]
        },
        "repositories": [
            {"id": 12345, "name": "my-repo", "full_name": "my-org/my-repo"}
        ]
    }
    
    with (
        patch("app.github_webhook.get_or_create_org_for_github_account", new=AsyncMock(return_value="org-created-111")) as mock_get_or_create,
        patch("app.github_webhook.store_github_app_installation", new=AsyncMock(return_value={"success": True})) as mock_store,
        patch("app.database.upsert_repo_config", new=AsyncMock(return_value={})) as mock_upsert_repo,
    ):
        result = await process_installation_created(payload)
        
    assert result["status"] == "saved"
    assert result["org_id"] == "org-created-111"
    assert result["installation_id"] == 164822973
    mock_get_or_create.assert_awaited_once_with(
        account_login="my-org",
        account_id=998877,
        account_type="Organization"
    )
    mock_store.assert_awaited_once()
    mock_upsert_repo.assert_awaited_once()


@pytest.mark.asyncio
async def test_process_installation_unsuspend():
    """Test installation.unsuspend webhook reactivates the installation."""
    mock_client = MagicMock()
    mock_update_res = MagicMock()
    mock_update_res.data = [{"id": "inst-1", "is_active": True}]
    mock_client.table.return_value.update.return_value.eq.return_value.execute.return_value = mock_update_res
    
    payload = {
        "action": "unsuspend",
        "installation": {"id": 164822973}
    }
    
    with patch("app.github_webhook.get_supabase_client", return_value=mock_client):
        result = await process_installation_unsuspend(payload)
        
    assert result["status"] == "unsuspended"
    assert result["installation_id"] == 164822973


@pytest.mark.asyncio
async def test_store_github_app_installation_falls_back_to_table_upsert():
    """Test that store_github_app_installation falls back to table upsert if RPC fails."""
    mock_client = MagicMock()
    # RPC raises error
    mock_client.rpc.return_value.execute.side_effect = Exception("RPC function not found")
    # Table upsert succeeds
    mock_upsert_res = MagicMock()
    mock_upsert_res.data = [{"id": "row-1"}]
    mock_client.table.return_value.upsert.return_value.execute.return_value = mock_upsert_res
    
    with patch("app.github_webhook.get_supabase_client", return_value=mock_client):
        result = await store_github_app_installation(
            org_id="org-123",
            installation_id=164822973,
            account_login="octocat",
            account_type="User",
            account_id=583231,
            repository_selection="all"
        )
        
    assert result["success"] is True
    assert result["installation_id"] == 164822973
    mock_client.table.assert_called_with("github_app_installations")
    mock_client.table.return_value.upsert.assert_called_once()


@pytest.mark.asyncio
async def test_process_pull_request_webhook_with_direct_installation():
    """
    Test PR review webhook on an installation that was installed via installation/new
    and was not previously in the database (matches the user's issue log).
    """
    payload = {
        "action": "opened",
        "number": 42,
        "pull_request": {
            "number": 42,
            "title": "Add new feature",
            "user": {"login": "developer"},
            "head": {"sha": "abc123def456"}
        },
        "repository": {
            "name": "cool-repo",
            "full_name": "client-org/cool-repo",
            "owner": {
                "login": "client-org",
                "id": 887766,
                "type": "Organization"
            }
        },
        "installation": {
            "id": 164822973
        }
    }
    
    settings = Settings()
    
    mock_review_result = MagicMock()
    mock_review_result.success = True
    mock_review_result.should_post_comment = False
    mock_review_result.response = MagicMock(findings=[], should_block=False)
    
    with (
        # resolve_org_from_installation auto-provisions org-direct-999
        patch("app.github_webhook.resolve_org_from_installation", new=AsyncMock(return_value="org-direct-999")) as mock_resolve,
        patch("app.github_webhook.record_webhook_event", new=AsyncMock()),
        patch("app.github_webhook.get_repo_config", new=AsyncMock(return_value=None)),
        patch("app.github_webhook.update_pr_merge_status", new=AsyncMock()),
        patch("app.github_webhook.fetch_pr_diff_from_github", new=AsyncMock(return_value="diff --git a/file b/file")),
        patch("app.github_webhook.get_repo_policy_from_db", new=AsyncMock(return_value=None)),
        patch("app.review_service.ReviewService.review_pr", new=AsyncMock(return_value=mock_review_result)),
    ):
        result = await process_pull_request_webhook(payload, settings)
        
    mock_resolve.assert_awaited_once_with(
        installation_id=164822973,
        fallback_account_info={"login": "client-org", "id": 887766, "type": "Organization"},
        settings=settings
    )
    # PR review is NOT skipped!
    assert result.get("status") != "skipped"


@pytest.mark.asyncio
async def test_installation_repositories_webhook_added_and_removed():
    """Test handling installation_repositories event when repositories are added or removed."""
    from app.main import _handle_installation_repositories_webhook
    
    payload = {
        "action": "added",
        "installation": {
            "id": 164822973,
            "account": {"login": "client-org", "id": 887766, "type": "Organization"}
        },
        "repositories_added": [
            {"id": 101, "name": "repo-one", "full_name": "client-org/repo-one"}
        ],
        "repositories_removed": [
            {"id": 102, "name": "repo-two", "full_name": "client-org/repo-two"}
        ]
    }
    
    mock_client = MagicMock()
    
    with (
        patch("app.github_webhook.resolve_org_from_installation", new=AsyncMock(return_value="org-repo-sync-555")),
        patch("app.database.get_supabase_client", return_value=mock_client),
        patch("app.database.upsert_repo_config", new=AsyncMock(return_value={})) as mock_upsert_repo,
    ):
        result = await _handle_installation_repositories_webhook(payload, Settings())
        
    assert result["status"] == "processed"
    assert result["added_count"] == 1
    assert result["removed_count"] == 1
    mock_upsert_repo.assert_awaited_once()
    mock_client.table.return_value.update.assert_called_once()
