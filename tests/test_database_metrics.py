"""Tests for dashboard metrics and stats functions in database.py."""

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from app.database import (
    get_dashboard_stats,
    get_active_findings_stats,
    get_findings_by_category,
    get_active_findings_by_category,
    get_top_risky_repos,
    get_top_risky_repos_active,
    get_review_trend,
    get_active_findings_trend,
)


@pytest.mark.asyncio
async def test_get_dashboard_stats_counts_uppercase_severity():
    mock_reviews = SimpleNamespace(
        data=[{"id": "r1", "review_time_ms": 500, "success": True, "should_block": False}],
        count=1,
    )
    mock_findings = SimpleNamespace(
        data=[
            {"id": "f1", "risk": "HIGH", "severity": None, "status": "open"},
            {"id": "f2", "risk": "MEDIUM", "severity": "MEDIUM", "status": "open"},
            {"id": "f3", "risk": "LOW", "severity": "LOW", "status": "resolved"},
        ],
        count=3,
    )

    with patch("app.database._execute_query", side_effect=[mock_reviews, mock_findings]):
        stats = await get_dashboard_stats("org-1", 30)

    assert stats["total_reviews"] == 1
    assert stats["total_findings"] == 3
    assert stats["high_findings"] == 1
    assert stats["medium_findings"] == 1
    assert stats["low_findings"] == 1
    assert stats["resolved_findings"] == 1
    assert stats["success_rate"] == 100.0


@pytest.mark.asyncio
async def test_get_active_findings_stats_fallback():
    mock_reviews = SimpleNamespace(
        data=[{"id": "r1", "review_time_ms": 200, "success": True, "should_block": False}],
        count=1,
    )
    mock_findings = SimpleNamespace(
        data=[
            {"id": "f1", "risk": "HIGH", "severity": None, "status": None},  # Null status defaults to open
            {"id": "f2", "risk": "MEDIUM", "severity": "MEDIUM", "status": "OPEN"},
            {"id": "f3", "risk": "LOW", "severity": "LOW", "status": "resolved"},
        ],
        count=3,
    )

    # RPC fails, fallback queries run
    rpc_mock = MagicMock()
    rpc_mock.execute.side_effect = Exception("RPC not found")

    mock_client = MagicMock()
    mock_client.rpc.return_value = rpc_mock

    with patch("app.database.get_supabase_client", return_value=mock_client), \
         patch("app.database._execute_query", side_effect=[Exception("RPC failed"), mock_reviews, mock_findings]):
        stats = await get_active_findings_stats("org-1", 30)

    assert stats["total_reviews"] == 1
    assert stats["total_findings"] == 2
    assert stats["high_findings"] == 1
    assert stats["medium_findings"] == 1
    assert stats["low_findings"] == 0
    assert stats["resolved_findings"] == 1


@pytest.mark.asyncio
async def test_get_findings_by_category_groups_and_counts():
    mock_findings = SimpleNamespace(
        data=[
            {"category": "injection", "risk": "HIGH", "severity": None, "status": "open"},
            {"category": "injection", "risk": "MEDIUM", "severity": None, "status": "open"},
            {"category": "auth", "risk": "LOW", "severity": "LOW", "status": "open"},
        ]
    )

    with patch("app.database._execute_query", return_value=mock_findings):
        categories = await get_findings_by_category("org-1", 30)

    cat_map = {c["category"]: c for c in categories}
    assert "injection" in cat_map
    assert cat_map["injection"]["count"] == 2
    assert cat_map["injection"]["high"] == 1
    assert cat_map["injection"]["medium"] == 1
    assert "auth" in cat_map
    assert cat_map["auth"]["count"] == 1


@pytest.mark.asyncio
async def test_get_top_risky_repos_calculates_scores():
    mock_reviews = SimpleNamespace(
        data=[
            {"repo_name": "org/repo-a", "findings_count": 5, "high_count": 2, "medium_count": 2, "low_count": 1},
            {"repo_name": "org/repo-a", "findings_count": 3, "high_count": 1, "medium_count": 1, "low_count": 1},
            {"repo_name": "org/repo-b", "findings_count": 1, "high_count": 0, "medium_count": 0, "low_count": 1},
        ]
    )

    with patch("app.database._execute_query", return_value=mock_reviews):
        repos = await get_top_risky_repos("org-1", 30, 10)

    assert len(repos) == 2
    assert repos[0]["repo_name"] == "org/repo-a"
    assert repos[0]["review_count"] == 2
    assert repos[0]["total_findings"] == 8
    assert repos[0]["high_findings"] == 3
    assert repos[0]["risk_score"] > repos[1]["risk_score"]
