"""
API endpoint tests for AI Code-Scanning Alert Review Service.
"""

import json
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from app.main import app
from app.alert_review.router import get_alert_service
from app.alert_review.service import AlertReviewService
from app.alert_review.models_alert import DeterminationType

client = TestClient(app)


def test_alert_service_health():
    response = client.get("/api/v1/alerts/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert len(data["stages"]) == 6


def test_alert_calibration_empty():
    response = client.get("/api/v1/alerts/calibration")
    assert response.status_code == 200
    data = response.json()
    assert "total_reviewed_by_human" in data
    assert "brier_score" in data


def test_alert_feedback_submission():
    payload = {
        "alert_id": "test-org/test-repo#101",
        "repo": "test-org/test-repo",
        "human_verdict": "FALSE_POSITIVE",
        "human_notes": "Reviewed by security lead: verified parameterized query.",
        "reviewer_id": "usr-sec-42"
    }
    response = client.post("/api/v1/alerts/feedback", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True


def test_review_sarif_endpoint():
    sample_sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "js/xss",
                                "name": "Cross-site scripting",
                                "shortDescription": {"text": "Reflected XSS"}
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "js/xss",
                        "message": {"text": "Untrusted input in HTML response"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/view.js"},
                                    "region": {"startLine": 12, "startColumn": 5}
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }

    # Mock the LLM caller
    mock_inv_json = json.dumps({
        "claim_summary": "Reflected XSS",
        "source_analysis": "User input from query",
        "propagation_analysis": "Passed to res.send",
        "sink_analysis": "Unescaped HTML",
        "defenses_analysis": "No escaping",
        "proposed_determination": "TRUE_POSITIVE",
        "preliminary_confidence": 0.95,
        "supporting_evidence": [
            {
                "id": "s1",
                "category": "SINK_EXPLOITABILITY",
                "title": "Unescaped HTML",
                "description": "HTML output",
                "weight": 3.0
            }
        ],
        "opposing_evidence": [],
        "reasoning": "Reflected XSS"
    })

    mock_ver_json = json.dumps({
        "grounding_score": 1.0,
        "ungrounded_claims": [],
        "consensus_with_investigator": True,
        "suggested_determination": "TRUE_POSITIVE",
        "challenges": [],
        "missing_context_flags": [],
        "verifier_notes": "Verified"
    })

    async def mock_caller(sys, user):
        if "Principal Application Security Engineer" in sys:
            return mock_inv_json
        return mock_ver_json

    # Override dependency with mock service
    mock_service = AlertReviewService(llm_caller=mock_caller)
    async def mock_reader(path, commit):
        return "res.send('<div>' + req.query.name + '</div>');"
    mock_service.context_builder.file_reader_override = mock_reader

    app.dependency_overrides[get_alert_service] = lambda: mock_service

    try:
        req_body = {
            "repo": "test-org/test-repo",
            "commit_sha": "def456",
            "sarif": sample_sarif
        }
        response = client.post("/api/v1/alerts/review-sarif", json=req_body)
        assert response.status_code == 200
        reports = response.json()
        assert len(reports) == 1
        assert reports[0]["determination"] == "TRUE_POSITIVE"
        assert reports[0]["confidence"]["score"] >= 0.85
        assert "TRUE POSITIVE" in reports[0]["markdown_report"]
    finally:
        app.dependency_overrides.clear()


def test_appsec_decision_endpoint():
    """Verify AppSec approval/denial via REST API."""
    mock_service = AlertReviewService()
    app.dependency_overrides[get_alert_service] = lambda: mock_service

    try:
        # 1. Submit approval
        payload = {
            "repo": "test-org/test-repo",
            "alert_id": "test-org/test-repo#77",
            "decision": "approve",
            "reason": "Parameter binding confirmed by AppSec lead",
            "reviewer_id": "appsec_lead"
        }
        response = client.post("/api/v1/alerts/decision", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["decision"] == "approved"
        assert "APPROVED by @appsec_lead" in data["decision_text"]

        # 2. Check queue
        queue_resp = client.get("/api/v1/alerts/queue")
        assert queue_resp.status_code == 200

        # 3. Check calibration metrics updated
        cal_resp = client.get("/api/v1/alerts/calibration")
        assert cal_resp.status_code == 200
    finally:
        app.dependency_overrides.clear()

