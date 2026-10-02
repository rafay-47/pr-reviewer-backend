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
from unittest.mock import AsyncMock, MagicMock, patch

from app.alert_review.github_app_service import GitHubAppAlertHandler
from app.alert_review.service import AlertReviewService
from app.alert_review.models_alert import (
    DeterminationType,
    AlertSeverity,
    TriageReport,
    ConfidenceScore,
    InvestigatorAssessment,
    VerificationReport,
    RemediationPlan,
)


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


@pytest.mark.asyncio
async def test_pr_diff_review_can_be_disabled():
    """Verify that when enable_pr_diff_review is False, pull_request events are ignored."""
    from app.main import _handle_pull_request_webhook
    from app.config import Settings

    settings = Settings(enable_pr_diff_review=False)
    payload = {
        "action": "opened",
        "pull_request": {"number": 1, "draft": False}
    }
    result = await _handle_pull_request_webhook(payload, settings, AsyncMock())
    assert result["status"] == "ignored"
    assert result["reason"] == "PR diff review disabled"


@pytest.mark.asyncio
async def test_check_run_codeql_triage():
    """Verify that completed CodeQL check_run events fetch alerts and review them."""
    service = AlertReviewService()
    handler = GitHubAppAlertHandler(service=service)
    handler.get_token_for_payload = AsyncMock(return_value="mock-token")
    handler.process_webhook_event = AsyncMock(return_value={"status": "processed", "determination": "TRUE_POSITIVE"})

    # Mock httpx GET for code scanning alerts
    from unittest.mock import MagicMock
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{
            "number": 77,
            "rule": {"id": "js/sql-injection", "description": "SQL Injection"},
            "most_recent_instance": {
                "commit_sha": "abc1234",
                "location": {"path": "test2.js", "start_line": 15}
            }
        }]
        mock_get.return_value = mock_resp

        payload = {
            "action": "completed",
            "check_run": {
                "id": 110067985142,
                "name": "Code scanning results / CodeQL",
                "head_sha": "abc1234",
                "conclusion": "failure"
            },
            "repository": {"full_name": "abdul-rafay-1/temp1"},
            "installation": {"id": 12345}
        }

        result = await handler.process_check_run_event(payload)
        assert result["status"] == "processed"
        assert result["alerts_reviewed"] == 1
        handler.process_webhook_event.assert_called_once()


@pytest.mark.asyncio
async def test_post_or_update_pull_request_comment_updates_in_place_via_patch():
    """Verify that existing bot comments are updated in-place via PATCH instead of creating duplicate comments."""
    service = AlertReviewService()
    handler = GitHubAppAlertHandler(service=service)

    from app.alert_review.models_alert import TriageReport, ConfidenceScore, InvestigatorAssessment, VerificationReport, RemediationPlan

    mock_report = TriageReport(
        alert_id="acme/api-server#55",
        repo="acme/api-server",
        commit_sha="abc1234",
        rule_id="js/sql-injection",
        rule_name="SQL Injection",
        severity=AlertSeverity.HIGH,
        determination=DeterminationType.TRUE_POSITIVE,
        confidence=ConfidenceScore(
            score=0.9, qualitative_level="HIGH", grounding_factor=1.0,
            flow_completeness_factor=1.0, consensus_factor=1.0, assumption_penalty=0.0,
            explanation="Valid finding"
        ),
        executive_summary="Finding summary",
        scanner_claim="Scanner message",
        investigator_assessment=InvestigatorAssessment(
            alert_id="acme/api-server#55",
            proposed_determination=DeterminationType.TRUE_POSITIVE,
            claim_summary="claim",
            reasoning="reason",
            source_analysis="s",
            propagation_analysis="p",
            sink_analysis="s",
            defenses_analysis="d",
            preliminary_confidence=0.9
        ),
        verification_report=VerificationReport(
            alert_id="acme/api-server#55",
            grounding_score=1.0,
            consensus_with_investigator=True,
            suggested_determination=DeterminationType.TRUE_POSITIVE,
            verifier_notes="notes"
        ),
        remediation=RemediationPlan(action_type="CODE_FIX"),
        markdown_report="<!-- AI_CODEQL_ALERT_REVIEW:acme/api-server#55 -->\nUpdated Report Content"
    )

    from unittest.mock import MagicMock
    with patch("httpx.AsyncClient.get") as mock_get, patch("httpx.AsyncClient.patch") as mock_patch:
        # Mock GET returning existing bot comment
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = [
            {
                "id": 98765,
                "body": "<!-- AI_CODEQL_ALERT_REVIEW:acme/api-server#55 -->\nOld content"
            }
        ]
        mock_get.return_value = mock_get_resp

        # Mock PATCH response
        mock_patch_resp = MagicMock()
        mock_patch_resp.status_code = 200
        mock_patch.return_value = mock_patch_resp

        cid = await handler.post_or_update_pull_request_comment(
            owner="acme",
            repo="api-server",
            pr_number=10,
            report=mock_report,
            token="test-token"
        )

        assert cid == 98765
        mock_patch.assert_called_once()
        patch_url = mock_patch.call_args[0][0]
        assert "98765" in patch_url


@pytest.mark.asyncio
async def test_handle_developer_comment_triggers_reassessment():
    """Verify that when a developer replies to an alert in a PR, the service reassesses and updates in-place."""
    service = AlertReviewService()
    handler = GitHubAppAlertHandler(service=service)
    handler.get_token_for_payload = AsyncMock(return_value="mock-token")

    # Seed alert cache
    from app.alert_review.alert_collector import parse_github_alert_webhook
    alert = parse_github_alert_webhook(SAMPLE_CREATED_WEBHOOK)
    service._normalized_alert_cache[alert.alert_id] = alert

    mock_reassess_report = AsyncMock()
    mock_reassess_report.determination = DeterminationType.FALSE_POSITIVE
    mock_reassess_report.recommendation = AsyncMock(value="dismiss")
    mock_reassess_report.confidence = AsyncMock(score=0.95)
    mock_reassess_report.markdown_report = "<!-- AI_CODEQL_ALERT_REVIEW:acme/api-server#55 -->\nReassessed"

    service.reassess_with_developer_response = AsyncMock(return_value=mock_reassess_report)
    handler.post_or_update_pull_request_comment = AsyncMock(return_value=12345)

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = [
            {
                "id": 12345,
                "body": "<!-- AI_CODEQL_ALERT_REVIEW:acme/api-server#55 -->\nOriginal Question"
            }
        ]
        mock_get.return_value = mock_get_resp

        payload = {
            "action": "created",
            "repository": {"full_name": "acme/api-server"},
            "issue": {"number": 10},
            "comment": {
                "id": 555,
                "body": "For Alert #55, we use parseInt to sanitize id in user.js:30",
                "user": {"login": "developer-bob", "type": "User"}
            }
        }

        result = await handler.handle_developer_comment(payload)
        assert result["status"] == "processed"
        assert result["event_type"] == "developer_evidence_reassessment"
        assert result["alert_id"] == "acme/api-server#55"
        service.reassess_with_developer_response.assert_called_once()
        handler.post_or_update_pull_request_comment.assert_called_once()


@pytest.mark.asyncio
async def test_handle_pull_request_synchronize_marks_comments_stale():
    """Verify that push to PR marks previous alert assessments as stale."""
    service = AlertReviewService()
    handler = GitHubAppAlertHandler(service=service)
    handler.get_token_for_payload = AsyncMock(return_value="mock-token")

    with patch("httpx.AsyncClient.get") as mock_get, patch("httpx.AsyncClient.patch") as mock_patch:
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = [
            {
                "id": 444,
                "body": "<!-- AI_CODEQL_ALERT_REVIEW:acme/api-server#55 -->\nActive assessment"
            }
        ]
        mock_get.return_value = mock_get_resp

        mock_patch_resp = MagicMock()
        mock_patch_resp.status_code = 200
        mock_patch.return_value = mock_patch_resp

        payload = {
            "action": "synchronize",
            "repository": {"full_name": "acme/api-server"},
            "pull_request": {"number": 10, "head": {"sha": "newcommitsha999"}},
            "after": "newcommitsha999"
        }

        result = await handler.handle_pull_request_synchronize(payload)
        assert result["status"] == "processed"
        assert result["stale_comments_updated"] == 1
        mock_patch.assert_called_once()
        patched_body = mock_patch.call_args[1]["json"]["body"]
        assert "STATUS: STALE ASSESSMENT" in patched_body
        assert "newcommi" in patched_body


@pytest.mark.asyncio
async def test_handle_appsec_command_approve():
    """Verify that AppSec approval dismisses GitHub alert and updates PR comment."""
    service = AlertReviewService()
    # Save a report in calibration store
    mock_report = TriageReport(
        alert_id="acme/api-server#55",
        repo="acme/api-server",
        commit_sha="commit123",
        rule_id="js/sql-injection",
        rule_name="SQL Injection",
        severity=AlertSeverity.HIGH,
        determination=DeterminationType.FALSE_POSITIVE,
        confidence=ConfidenceScore(
            score=0.92,
            qualitative_level="HIGH",
            explanation="Parameter binding found",
            grounding_factor=1.0,
            flow_completeness_factor=1.0,
            consensus_factor=1.0,
            assumption_penalty=0.0
        ),
        executive_summary="Executive summary",
        scanner_claim="Claim",
        investigator_assessment=InvestigatorAssessment(
            alert_id="acme/api-server#55",
            claim_summary="SQLi", source_analysis="src", propagation_analysis="prop",
            sink_analysis="sink", defenses_analysis="defense",
            proposed_determination=DeterminationType.FALSE_POSITIVE,
            preliminary_confidence=0.92, supporting_evidence=[], opposing_evidence=[],
            reasoning="Safe"
        ),
        verification_report=VerificationReport(
            alert_id="acme/api-server#55",
            grounding_score=1.0, ungrounded_claims=[], consensus_with_investigator=True,
            suggested_determination=DeterminationType.FALSE_POSITIVE, challenges=[],
            missing_context_flags=[], verifier_notes="Verified"
        ),
        remediation=RemediationPlan(action_type="DISMISS_ALERT", fix_explanation="Safe"),
        limitations=[],
        markdown_report="<!-- AI_CODEQL_ALERT_REVIEW:acme/api-server#55 -->\n> **AppSec Dismissal Decision:** `PENDING`  ",
        pr_comment_id=12345
    )
    await service.calibration_store.save_triage_report(mock_report)

    handler = GitHubAppAlertHandler(service=service)
    handler.get_token_for_payload = AsyncMock(return_value="mock-token")

    with patch("httpx.AsyncClient.patch") as mock_patch, \
         patch("httpx.AsyncClient.get") as mock_get, \
         patch("httpx.AsyncClient.post") as mock_post:

        mock_patch_resp = MagicMock()
        mock_patch_resp.status_code = 200
        mock_patch.return_value = mock_patch_resp

        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = [{"id": 12345, "body": "<!-- AI_CODEQL_ALERT_REVIEW:acme/api-server#55 -->"}]
        mock_get.return_value = mock_get_resp

        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 201
        mock_post.return_value = mock_post_resp

        payload = {
            "action": "created",
            "repository": {"full_name": "acme/api-server"},
            "issue": {"number": 10},
            "comment": {
                "id": 999,
                "body": "/appsec approve #55 Parameter binding verified in customer_repo.py",
                "user": {"login": "sec-lead", "type": "User"}
            }
        }

        result = await handler.handle_appsec_command(payload)
        assert result["status"] == "success"
        assert result["decision"] == "approved"
        assert "APPROVED by @sec-lead" in result["decision_text"]

        # Verify GitHub alert was dismissed via API
        alert_patch_calls = [c for c in mock_patch.call_args_list if "code-scanning/alerts/55" in c[0][0]]
        assert len(alert_patch_calls) == 1
        assert alert_patch_calls[0][1]["json"]["state"] == "dismissed"

        # Verify PR comment was updated with APPROVED badge
        comment_patch_calls = [c for c in mock_patch.call_args_list if "issues/comments/12345" in c[0][0]]
        assert len(comment_patch_calls) == 1
        assert "APPROVED by @sec-lead" in comment_patch_calls[0][1]["json"]["body"]


@pytest.mark.asyncio
async def test_handle_appsec_command_deny():
    """Verify that AppSec denial keeps alert open and updates PR comment."""
    service = AlertReviewService()
    mock_report = TriageReport(
        alert_id="acme/api-server#55",
        repo="acme/api-server",
        commit_sha="commit123",
        rule_id="js/sql-injection",
        rule_name="SQL Injection",
        severity=AlertSeverity.HIGH,
        determination=DeterminationType.TRUE_POSITIVE,
        confidence=ConfidenceScore(
            score=0.95,
            qualitative_level="HIGH",
            explanation="Vulnerable",
            grounding_factor=1.0,
            flow_completeness_factor=1.0,
            consensus_factor=1.0,
            assumption_penalty=0.0
        ),
        executive_summary="Executive summary",
        scanner_claim="Claim",
        investigator_assessment=InvestigatorAssessment(
            alert_id="acme/api-server#55",
            claim_summary="SQLi", source_analysis="src", propagation_analysis="prop",
            sink_analysis="sink", defenses_analysis="defense",
            proposed_determination=DeterminationType.TRUE_POSITIVE,
            preliminary_confidence=0.95, supporting_evidence=[], opposing_evidence=[],
            reasoning="Unsafe"
        ),
        verification_report=VerificationReport(
            alert_id="acme/api-server#55",
            grounding_score=1.0, ungrounded_claims=[], consensus_with_investigator=True,
            suggested_determination=DeterminationType.TRUE_POSITIVE, challenges=[],
            missing_context_flags=[], verifier_notes="Verified"
        ),
        remediation=RemediationPlan(action_type="CODE_FIX", fix_explanation="Unsafe"),
        limitations=[],
        markdown_report="<!-- AI_CODEQL_ALERT_REVIEW:acme/api-server#55 -->\n> **AppSec Dismissal Decision:** `PENDING`  ",
        pr_comment_id=12345
    )
    await service.calibration_store.save_triage_report(mock_report)

    handler = GitHubAppAlertHandler(service=service)
    handler.get_token_for_payload = AsyncMock(return_value="mock-token")

    with patch("httpx.AsyncClient.patch") as mock_patch, \
         patch("httpx.AsyncClient.get") as mock_get, \
         patch("httpx.AsyncClient.post") as mock_post:

        mock_patch_resp = MagicMock()
        mock_patch_resp.status_code = 200
        mock_patch.return_value = mock_patch_resp

        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = [{"id": 12345, "body": "<!-- AI_CODEQL_ALERT_REVIEW:acme/api-server#55 -->"}]
        mock_get.return_value = mock_get_resp

        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 201
        mock_post.return_value = mock_post_resp

        payload = {
            "action": "created",
            "repository": {"full_name": "acme/api-server"},
            "issue": {"number": 10},
            "comment": {
                "id": 999,
                "body": "/appsec deny #55 Still uses unsafe raw concatenation",
                "user": {"login": "sec-lead", "type": "User"}
            }
        }

        result = await handler.handle_appsec_command(payload)
        assert result["status"] == "success"
        assert result["decision"] == "denied"
        assert "DENIED by @sec-lead" in result["decision_text"]

        # Verify GitHub alert was marked open via API
        alert_patch_calls = [c for c in mock_patch.call_args_list if "code-scanning/alerts/55" in c[0][0]]
        assert len(alert_patch_calls) == 1
        assert alert_patch_calls[0][1]["json"]["state"] == "open"

        # Verify PR comment was updated with DENIED badge
        comment_patch_calls = [c for c in mock_patch.call_args_list if "issues/comments/12345" in c[0][0]]
        assert len(comment_patch_calls) == 1
        assert "DENIED by @sec-lead" in comment_patch_calls[0][1]["json"]["body"]




