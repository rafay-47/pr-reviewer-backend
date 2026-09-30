"""
Automated Test Suite for GitHub App Code Scanning & Dismissal Request Reviews.

Tests GitHub App webhook operations (no YAML workflows required):
1. CodeQL publishes alert (action: created) -> Runs 6 stages -> Posts GitHub Check Run & PR comment
2. Developer submits dismissal request (action: closed_by_user):
   - AI confirms False Positive -> Validates dismissal & logs calibration outcome
   - AI determines True Positive -> Disputes dismissal with warning
"""

import json
import pytest
from unittest.mock import AsyncMock, patch

from app.alert_review.github_app_service import GitHubAppAlertHandler
from app.alert_review.service import AlertReviewService
from app.alert_review.models_alert import DeterminationType, AlertSeverity


SAMPLE_CREATED_WEBHOOK = {
    "action": "created",
    "installation": {"id": 12345},
    "repository": {"full_name": "acme/api-server", "name": "api-server", "owner": {"login": "acme"}},
    "alert": {
        "number": 55,
        "html_url": "https://github.com/acme/api-server/security/code-scanning/55",
        "rule": {
            "id": "js/sql-injection",
            "name": "SQL query built from user-controlled sources",
            "security_severity_level": "high",
            "description": "SQL injection vulnerability",
            "tags": ["external/cwe/cwe-089"]
        },
        "most_recent_instance": {
            "commit_sha": "abc123456",
            "ref": "refs/pull/10/merge",
            "location": {
                "path": "src/user.js",
                "start_line": 30
            },
            "message": {"text": "User input in query"}
        }
    }
}

SAMPLE_DISMISSAL_REQUEST_WEBHOOK = {
    "action": "closed_by_user",
    "installation": {"id": 12345},
    "repository": {"full_name": "acme/api-server", "name": "api-server", "owner": {"login": "acme"}},
    "alert": {
        "number": 55,
        "html_url": "https://github.com/acme/api-server/security/code-scanning/55",
        "dismissed_reason": "false positive",
        "dismissed_comment": "We use an ORM wrapper that escapes all inputs.",
        "dismissed_by": {"login": "dev-lead"},
        "rule": {
            "id": "js/sql-injection",
            "name": "SQL query built from user-controlled sources",
            "security_severity_level": "high",
            "description": "SQL injection vulnerability",
            "tags": ["external/cwe/cwe-089"]
        },
        "most_recent_instance": {
            "commit_sha": "abc123456",
            "ref": "refs/pull/10/merge",
            "location": {
                "path": "src/user.js",
                "start_line": 30
            },
            "message": {"text": "User input in query"}
        }
    }
}


@pytest.mark.asyncio
async def test_github_app_new_alert_created():
    """When CodeQL publishes an alert, GitHub App creates a Check Run and PR comment."""
    mock_inv_json = json.dumps({
        "claim_summary": "User input reaches database",
        "source_analysis": "req.body",
        "propagation_analysis": "No sanitization",
        "sink_analysis": "Raw string concatenation",
        "defenses_analysis": "None",
        "proposed_determination": "TRUE_POSITIVE",
        "preliminary_confidence": 0.95,
        "supporting_evidence": [
            {
                "id": "sup-1",
                "category": "SINK_EXPLOITABILITY",
                "title": "Raw query interpolation",
                "description": "Vulnerable sink",
                "weight": 3.0
            }
        ],
        "opposing_evidence": [],
        "reasoning": "True positive SQL injection"
    })

    mock_ver_json = json.dumps({
        "grounding_score": 1.0,
        "ungrounded_claims": [],
        "consensus_with_investigator": True,
        "suggested_determination": "TRUE_POSITIVE",
        "challenges": [],
        "missing_context_flags": [],
        "verifier_notes": "Verified vulnerable"
    })

    async def mock_caller(sys, user):
        if "Principal Application Security Engineer" in sys:
            return mock_inv_json
        return mock_ver_json

    service = AlertReviewService(llm_caller=mock_caller)
    async def mock_reader(p, c):
        return "const query = `SELECT * FROM users WHERE id = ${req.body.id}`;\ndb.query(query);"
    service.context_builder.file_reader_override = mock_reader

    handler = GitHubAppAlertHandler(service=service)

    # Mock GitHub API actions
    handler.get_token_for_payload = AsyncMock(return_value="mock-gh-app-token")
    handler.create_check_run = AsyncMock(return_value={"id": 999, "status": "completed"})
    handler.post_pull_request_comment = AsyncMock(return_value=True)

    result = await handler.process_webhook_event(SAMPLE_CREATED_WEBHOOK)

    assert result["status"] == "processed"
    assert result["event_type"] == "new_alert_triage"
    assert result["determination"] == "TRUE_POSITIVE"
    assert result["confidence"] >= 0.85

    # Verified that GitHub App created Check Run and posted PR comment
    handler.create_check_run.assert_called_once()
    check_args = handler.create_check_run.call_args[0]
    assert check_args[0] == "acme"
    assert check_args[1] == "api-server"
    assert check_args[2] == "abc123456"

    handler.post_pull_request_comment.assert_called_once()
    pr_args = handler.post_pull_request_comment.call_args[0]
    assert pr_args[2] == 10  # Extracted PR number 10 from refs/pull/10/merge


@pytest.mark.asyncio
async def test_github_app_dismissal_request_confirmed_false_positive():
    """When developer submits dismissal request as False Positive, and AI confirms it."""
    mock_inv_json = json.dumps({
        "claim_summary": "CodeQL flagged query",
        "source_analysis": "req.body.id",
        "propagation_analysis": "Converted to integer",
        "sink_analysis": "ORM parameterized",
        "defenses_analysis": "parseInt sanitizes input",
        "proposed_determination": "FALSE_POSITIVE",
        "preliminary_confidence": 0.94,
        "supporting_evidence": [],
        "opposing_evidence": [
            {
                "id": "opp-1",
                "category": "SANITIZATION_DEFENSE",
                "title": "Integer parsing",
                "description": "Safe integer",
                "weight": 3.0
            }
        ],
        "reasoning": "Safe from SQL injection"
    })

    mock_ver_json = json.dumps({
        "grounding_score": 1.0,
        "ungrounded_claims": [],
        "consensus_with_investigator": True,
        "suggested_determination": "FALSE_POSITIVE",
        "challenges": [],
        "missing_context_flags": [],
        "verifier_notes": "Confirmed false positive"
    })

    async def mock_caller(sys, user):
        if "Principal Application Security Engineer" in sys:
            return mock_inv_json
        return mock_ver_json

    service = AlertReviewService(llm_caller=mock_caller)
    async def mock_reader(p, c):
        return "const id = parseInt(req.body.id, 10);\ndb.query('SELECT * FROM users WHERE id = $1', [id]);"
    service.context_builder.file_reader_override = mock_reader

    handler = GitHubAppAlertHandler(service=service)
    handler.get_token_for_payload = AsyncMock(return_value="mock-gh-app-token")
    handler.create_check_run = AsyncMock(return_value={"id": 999})
    handler.post_pull_request_comment = AsyncMock(return_value=True)

    result = await handler.process_webhook_event(SAMPLE_DISMISSAL_REQUEST_WEBHOOK)

    assert result["status"] == "processed"
    assert result["event_type"] == "dismissal_request_review"
    assert result["ai_determination"] == "FALSE_POSITIVE"
    assert result["dismissal_validated"] is True

    # Check calibration record
    metrics = service.get_calibration_metrics()
    assert metrics.total_reviewed_by_human == 1
    assert metrics.false_positive_agreement_count == 1
    assert metrics.overall_accuracy == 1.0


@pytest.mark.asyncio
async def test_github_app_dismissal_request_disputed_true_positive():
    """When developer tries to dismiss an actual vulnerability, AI disputes and posts warning."""
    mock_inv_json = json.dumps({
        "claim_summary": "CodeQL flagged query",
        "source_analysis": "req.body.id",
        "propagation_analysis": "String concatenation",
        "sink_analysis": "Raw SQL injection",
        "defenses_analysis": "None",
        "proposed_determination": "TRUE_POSITIVE",
        "preliminary_confidence": 0.96,
        "supporting_evidence": [
            {
                "id": "sup-1",
                "category": "SINK_EXPLOITABILITY",
                "title": "String interpolation",
                "description": "Vulnerable sink",
                "weight": 3.0
            }
        ],
        "opposing_evidence": [],
        "reasoning": "Vulnerable to SQL injection"
    })

    mock_ver_json = json.dumps({
        "grounding_score": 1.0,
        "ungrounded_claims": [],
        "consensus_with_investigator": True,
        "suggested_determination": "TRUE_POSITIVE",
        "challenges": [],
        "missing_context_flags": [],
        "verifier_notes": "Confirmed true positive"
    })

    async def mock_caller(sys, user):
        if "Principal Application Security Engineer" in sys:
            return mock_inv_json
        return mock_ver_json

    service = AlertReviewService(llm_caller=mock_caller)
    async def mock_reader(p, c):
        return "const query = `SELECT * FROM users WHERE id = ${req.body.id}`;\ndb.query(query);"
    service.context_builder.file_reader_override = mock_reader

    handler = GitHubAppAlertHandler(service=service)
    handler.get_token_for_payload = AsyncMock(return_value="mock-gh-app-token")
    handler.create_check_run = AsyncMock(return_value={"id": 999})
    handler.post_pull_request_comment = AsyncMock(return_value=True)

    result = await handler.process_webhook_event(SAMPLE_DISMISSAL_REQUEST_WEBHOOK)

    assert result["status"] == "processed"
    assert result["event_type"] == "dismissal_request_review"
    assert result["ai_determination"] == "TRUE_POSITIVE"
    assert result["dismissal_validated"] is False  # AI rejected/disputed developer's false positive dismissal!

    # Verified warning was posted to PR
    handler.post_pull_request_comment.assert_called_once()
    pr_comment_body = handler.post_pull_request_comment.call_args[1]["report"].markdown_report
    assert "Disputed by AI AppSec Reviewer" in pr_comment_body
    assert "dev-lead" in pr_comment_body
