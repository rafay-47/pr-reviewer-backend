"""
End-to-End Integration Test for AI CodeQL Alert Triage & AppSec Approval Lifecycle.

Simulates the complete client requirement lifecycle:
1. CodeQL flags a security finding (e.g. SQL Injection) on a PR.
2. AI reviews the finding; lacks wrapper context -> categorizes as INSUFFICIENT_EVIDENCE
   and posts targeted questions in a consolidated PR comment.
3. Developer stays in the PR and responds to the questions in the comment thread.
4. AI intercepts developer reply, verifies code references, re-assesses finding,
   and updates the PR comment in-place (no comment clutter).
5. AppSec engineer reviews consolidated evidence matrix and approves dismissal via `/appsec approve`.
6. System calls GitHub API to dismiss the alert, marks the PR comment as APPROVED,
   and records ground truth for continuous model calibration.
7. Subsequent commit push (`synchronize`) marks comments as STALE to prevent out-of-date approvals.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.alert_review.models_alert import (
    DeterminationType,
    AlertSeverity,
    TriageReport,
    ConfidenceScore,
    InvestigatorAssessment,
    VerificationReport,
    RemediationPlan,
    NormalizedAlert,
)
from app.alert_review.service import AlertReviewService
from app.alert_review.github_app_service import GitHubAppAlertHandler


@pytest.mark.asyncio
async def test_full_alert_review_and_appsec_approval_lifecycle():
    """
    Test the full round-trip from CodeQL alert creation to AppSec dismissal.
    """
    # -------------------------------------------------------------
    # Step 1: Mock LLM behavior for Insufficient Evidence -> Then Reassessment
    # -------------------------------------------------------------
    stage_inv_call_count = 0

    async def mock_llm(sys_prompt: str, user_prompt: str) -> str:
        nonlocal stage_inv_call_count
        if "Principal Application Security Engineer" in sys_prompt:
            stage_inv_call_count += 1
            if stage_inv_call_count == 1:
                # Initial review: lacks wrapper context -> Insufficient Evidence
                return json.dumps({
                    "claim_summary": "Potential SQL injection in customer lookup query",
                    "source_analysis": "req.query.customerId is passed to db.query",
                    "propagation_analysis": "Passed to custom query wrapper",
                    "sink_analysis": "Database query execution",
                    "defenses_analysis": "Unknown wrapper implementation",
                    "proposed_determination": "insufficient_evidence",
                    "preliminary_confidence": 0.50,
                    "code_references": [{"path": "src/customer_repository.py", "start_line": 42, "end_line": 51}],
                    "verified_evidence": [],
                    "missing_evidence": ["Implementation of the database wrapper"],
                    "developer_questions": ["Where does this wrapper bind customerId as a query parameter?"],
                    "recommendation": "request_evidence",
                    "supporting_evidence": [],
                    "opposing_evidence": [],
                    "reasoning": "Need wrapper implementation to verify parameter binding"
                })
            else:
                # Reassessment after developer points to parameter binding
                return json.dumps({
                    "claim_summary": "SQL query safely parameterized via db.query bindings",
                    "source_analysis": "req.query.customerId is parameterized",
                    "propagation_analysis": "Passed as bound parameter array",
                    "sink_analysis": "Database prepared statement",
                    "defenses_analysis": "Parameter binding prevents query structure alteration",
                    "proposed_determination": "likely_false_positive",
                    "preliminary_confidence": 0.94,
                    "code_references": [{"path": "src/customer_repository.py", "start_line": 42, "end_line": 51}],
                    "verified_evidence": ["Parameter array verified in db.query call"],
                    "missing_evidence": [],
                    "developer_questions": [],
                    "recommendation": "dismiss",
                    "supporting_evidence": [],
                    "opposing_evidence": [],
                    "reasoning": "Input is parameterized; finding is a false positive"
                })
        else:
            # Adversarial Verifier
            if stage_inv_call_count == 1:
                return json.dumps({
                    "grounding_score": 0.60,
                    "ungrounded_claims": [],
                    "consensus_with_investigator": True,
                    "suggested_determination": "insufficient_evidence",
                    "challenges": [],
                    "missing_context_flags": ["Missing wrapper implementation"],
                    "verifier_notes": "Awaiting developer evidence"
                })
            else:
                return json.dumps({
                    "grounding_score": 1.0,
                    "ungrounded_claims": [],
                    "consensus_with_investigator": True,
                    "suggested_determination": "likely_false_positive",
                    "challenges": [],
                    "missing_context_flags": [],
                    "developer_evidence_verified": True,
                    "unverified_developer_claims": [],
                    "verifier_notes": "Developer statement verified by repository code"
                })

    service = AlertReviewService(llm_caller=mock_llm)
    async def mock_reader(path: str, commit: str) -> str:
        return "const res = await db.query('SELECT * FROM customers WHERE id = $1', [customerId]);"
    service.context_builder.file_reader_override = mock_reader

    handler = GitHubAppAlertHandler(service=service)
    handler.get_token_for_payload = AsyncMock(return_value="gh-token-12345")
    handler.find_associated_pull_request = AsyncMock(return_value=42)

    # -------------------------------------------------------------
    # Step 2: CodeQL flags alert -> Webhook arrives
    # -------------------------------------------------------------
    created_payload = {
        "action": "created",
        "installation": {"id": 999},
        "repository": {"full_name": "company/ecommerce-api", "name": "ecommerce-api", "owner": {"login": "company"}},
        "alert": {
            "number": 101,
            "html_url": "https://github.com/company/ecommerce-api/security/code-scanning/101",
            "rule": {
                "id": "js/sql-injection",
                "name": "SQL query built from user-controlled sources",
                "security_severity_level": "high"
            },
            "most_recent_instance": {
                "ref": "refs/pull/42/merge",
                "commit_sha": "commit_sha_initial",
                "location": {
                    "path": "src/customer_repository.py",
                    "start_line": 42
                },
                "message": {"text": "Potential SQL injection in customer lookup query"}
            }
        }
    }

    with patch("httpx.AsyncClient.post") as mock_post, \
         patch("httpx.AsyncClient.patch") as mock_patch, \
         patch("httpx.AsyncClient.get") as mock_get:

        # Mock Check Run & Comment creation
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 201
        mock_post_resp.json.return_value = {"id": 55501}
        mock_post.return_value = mock_post_resp

        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = []
        mock_get.return_value = mock_get_resp

        init_res = await handler.process_webhook_event(created_payload)
        assert init_res["status"] == "processed"
        assert init_res["determination"] == "INSUFFICIENT_EVIDENCE"

        # Verify comment was created asking developer questions
        assert mock_post.call_count >= 1
        created_comment = None
        for call in mock_post.call_args_list:
            if "issues/42/comments" in call[0][0]:
                created_comment = call[1]["json"]["body"]
                break
        assert created_comment is not None
        assert "<!-- AI_CODEQL_ALERT_REVIEW:company/ecommerce-api#101 -->" in created_comment
        assert "Where does this wrapper bind customerId as a query parameter?" in created_comment

        # -------------------------------------------------------------
        # Step 3: Developer replies directly in PR thread
        # -------------------------------------------------------------
        dev_reply_payload = {
            "action": "created",
            "repository": {"full_name": "company/ecommerce-api"},
            "issue": {"number": 42},
            "comment": {
                "id": 88801,
                "body": "For Alert #101, customerId is bound via $1 parameter array in customer_repository.py:45",
                "user": {"login": "developer-jane", "type": "User"}
            }
        }

        # Mock existing PR comments containing the bot review comment
        mock_get_resp.json.return_value = [
            {"id": 55501, "body": created_comment}
        ]

        mock_patch_resp = MagicMock()
        mock_patch_resp.status_code = 200
        mock_patch.return_value = mock_patch_resp

        dev_res = await handler.handle_developer_comment(dev_reply_payload)
        assert dev_res["status"] == "processed"
        assert dev_res["determination"] == "FALSE_POSITIVE"
        assert dev_res["recommendation"] == "dismiss"

        # Verify the bot comment was updated in-place via PATCH (not POST)
        patch_comment_calls = [c for c in mock_patch.call_args_list if "issues/comments/55501" in c[0][0]]
        assert len(patch_comment_calls) == 1
        updated_comment_body = patch_comment_calls[0][1]["json"]["body"]
        assert "LIKELY FALSE POSITIVE" in updated_comment_body
        assert "Developer Feedback Received:" in updated_comment_body

        # -------------------------------------------------------------
        # Step 4: AppSec Reviews & Approves via `/appsec approve`
        # -------------------------------------------------------------
        appsec_comment_payload = {
            "action": "created",
            "repository": {"full_name": "company/ecommerce-api"},
            "issue": {"number": 42},
            "comment": {
                "id": 99901,
                "body": "/appsec approve #101 Verified parameterized queries in customer_repository.py",
                "user": {"login": "appsec-sam", "type": "User"}
            }
        }

        # Existing bot comment is now the updated comment
        mock_get_resp.json.return_value = [
            {"id": 55501, "body": updated_comment_body}
        ]

        appsec_res = await handler.handle_appsec_command(appsec_comment_payload)
        assert appsec_res["status"] == "success"
        assert appsec_res["decision"] == "approved"
        assert "APPROVED by @appsec-sam" in appsec_res["decision_text"]

        # Verify alert was dismissed on GitHub Code Scanning API
        alert_dismiss_calls = [c for c in mock_patch.call_args_list if "code-scanning/alerts/101" in c[0][0]]
        assert len(alert_dismiss_calls) == 1
        assert alert_dismiss_calls[0][1]["json"]["state"] == "dismissed"

        # Verify PR comment was updated with APPROVED status
        patch_comment_calls_appsec = [c for c in mock_patch.call_args_list if "issues/comments/55501" in c[0][0]]
        latest_body = patch_comment_calls_appsec[-1][1]["json"]["body"]
        assert "APPROVED by @appsec-sam" in latest_body

        # Verify Calibration Store retained human ground truth
        cal_metrics = service.get_calibration_metrics()
        assert cal_metrics.total_reviewed_by_human >= 1
        assert cal_metrics.false_positive_agreement_count >= 1

        # -------------------------------------------------------------
        # Step 5: New Commit pushed (`synchronize`) -> Invalidation
        # -------------------------------------------------------------
        sync_payload = {
            "action": "synchronize",
            "repository": {"full_name": "company/ecommerce-api"},
            "pull_request": {"number": 42, "head": {"sha": "new_commit_sha_789"}},
            "after": "new_commit_sha_789"
        }

        mock_get_resp.json.return_value = [
            {"id": 55501, "body": latest_body}
        ]

        sync_res = await handler.handle_pull_request_synchronize(sync_payload)
        assert sync_res["status"] == "processed"
        assert sync_res["stale_comments_updated"] == 1

        # Verify stale banner was prepended
        stale_patch_calls = [c for c in mock_patch.call_args_list if "issues/comments/55501" in c[0][0]]
        stale_body = stale_patch_calls[-1][1]["json"]["body"]
        assert "STATUS: STALE ASSESSMENT" in stale_body
        assert "new_comm" in stale_body
