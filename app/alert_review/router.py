"""
FastAPI Router for AI Code-Scanning Alert Review Service.

Endpoints:
- POST /api/v1/alerts/review-sarif: Review all alerts in uploaded SARIF
- POST /api/v1/alerts/review-payload: Review a single normalized alert or webhook payload
- POST /api/v1/alerts/feedback: Record human AppSec ground truth for calibration
- GET  /api/v1/alerts/calibration: Retrieve calibration accuracy and Brier score metrics
- GET  /api/v1/alerts/health: Status check
"""

import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel

from .models_alert import (
    TriageReport,
    HumanTriageFeedback,
    CalibrationMetrics,
    DeterminationType,
)
from .service import AlertReviewService
from .calibration import CalibrationStore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["AI Code Scanning Alert Review"])

# Shared singleton service instance
_alert_service: Optional[AlertReviewService] = None


def get_alert_service() -> AlertReviewService:
    """Dependency provider for AlertReviewService."""
    global _alert_service
    if _alert_service is None:
        _alert_service = AlertReviewService()
    return _alert_service


class SarifReviewRequest(BaseModel):
    """Request payload for reviewing a SARIF file."""
    repo: str
    commit_sha: str
    ref: Optional[str] = None
    sarif: Dict[str, Any]


class AlertFeedbackRequest(BaseModel):
    """Request payload for human AppSec calibration feedback."""
    alert_id: str
    repo: str
    human_verdict: DeterminationType
    human_notes: Optional[str] = None
    reviewer_id: Optional[str] = None


@router.get("/health", summary="Health check for Alert Review Service")
async def health_check():
    return {
        "status": "healthy",
        "service": "AI Code-Scanning Alert Review Service",
        "stages": [
            "1. Alert Collector & Normalizer",
            "2. Code Context Builder",
            "3. AI Investigator",
            "4. Evidence Verifier & Reviewer",
            "5. Determination & Confidence Engine",
            "6. Report Generator & Calibration"
        ]
    }


@router.post("/review-sarif", response_model=List[TriageReport], summary="Review all alerts in a SARIF file")
async def review_sarif(
    request: SarifReviewRequest,
    service: AlertReviewService = Depends(get_alert_service)
):
    """
    Ingest a SARIF v2.1.0 document (e.g. from CodeQL) and review each finding.
    Returns full triage reports with evidence and calibrated confidence scores.
    """
    try:
        reports = await service.review_sarif_file(
            sarif_data=request.sarif,
            repo=request.repo,
            commit_sha=request.commit_sha,
            ref=request.ref
        )
        return reports
    except Exception as e:
        logger.error(f"Error reviewing SARIF file: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/review-webhook", response_model=Optional[TriageReport], summary="Review alert from webhook payload")
async def review_webhook(
    payload: Dict[str, Any],
    service: AlertReviewService = Depends(get_alert_service)
):
    """
    Directly review an incoming GitHub code_scanning_alert webhook payload.
    """
    try:
        report = await service.review_webhook_payload(payload)
        if not report:
            return None
        return report
    except Exception as e:
        logger.error(f"Error reviewing webhook payload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback", summary="Submit human AppSec outcome for calibration")
async def submit_feedback(
    feedback: AlertFeedbackRequest,
    service: AlertReviewService = Depends(get_alert_service)
):
    """
    Record a human AppSec engineer's final verdict to calibrate the AI confidence engine.
    """
    success = await service.record_human_outcome(
        alert_id=feedback.alert_id,
        repo=feedback.repo,
        verdict=feedback.human_verdict,
        notes=feedback.human_notes,
        reviewer_id=feedback.reviewer_id
    )
    return {"success": success, "message": "Feedback recorded for calibration"}


@router.get("/calibration", response_model=CalibrationMetrics, summary="Get calibration accuracy metrics")
async def get_calibration_stats(
    service: AlertReviewService = Depends(get_alert_service)
):
    """
    Get accuracy, Brier score, and calibration bucket statistics across all retained human outcomes.
    """
    return service.get_calibration_metrics()
