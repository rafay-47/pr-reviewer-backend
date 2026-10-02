"""
Storage, AppSec Review, and Calibration Module.

Retains triage reports and human-reviewed outcomes for continuous evaluation
and confidence score calibration:
- Records AI triage assessments (predictions, confidence scores, evidence)
- Ingests human AppSec engineer triage decisions (from GitHub alert closures or dashboard)
- Calculates calibration metrics: Brier score, Expected Calibration Error (ECE),
  precision/recall curves, and confidence bucket calibration tables
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from .models_alert import (
    TriageReport,
    HumanTriageFeedback,
    CalibrationMetrics,
    DeterminationType,
)

logger = logging.getLogger(__name__)


class CalibrationStore:
    """Manages retention of triage reports and calibration against human ground truth."""

    def __init__(self, db_client=None):
        """
        Args:
            db_client: Optional Supabase or database client. If None, uses in-memory store.
        """
        self.db_client = db_client
        self._in_memory_reports: Dict[str, TriageReport] = {}
        self._in_memory_feedback: Dict[str, HumanTriageFeedback] = {}

    async def save_triage_report(self, report: TriageReport) -> str:
        """Store triage report in database or memory."""
        self._in_memory_reports[report.alert_id] = report

        if self.db_client:
            try:
                row = {
                    "alert_id": report.alert_id,
                    "repo": report.repo,
                    "commit_sha": report.commit_sha,
                    "rule_id": report.rule_id,
                    "determination": report.determination.value,
                    "confidence_score": report.confidence.score,
                    "confidence_level": report.confidence.qualitative_level,
                    "recommendation": report.recommendation.value,
                    "appsec_decision": report.appsec_decision,
                    "is_stale": report.is_stale,
                    "pr_comment_id": report.pr_comment_id,
                    "developer_feedback": report.developer_feedback,
                    "developer_questions": report.developer_questions,
                    "missing_evidence": report.missing_evidence,
                    "executive_summary": report.executive_summary,
                    "markdown_report": report.markdown_report,
                    "created_at": report.created_at,
                    "agent_version": report.agent_version,
                }
                self.db_client.table("alert_reviews").upsert(row).execute()
            except Exception as e:
                logger.warning(f"Could not persist alert_review to database: {e}")

        return report.alert_id

    def get_report(self, alert_id: str) -> Optional[TriageReport]:
        """Get a triage report by alert ID."""
        if alert_id in self._in_memory_reports:
            return self._in_memory_reports[alert_id]
        for aid, rep in self._in_memory_reports.items():
            if aid.endswith(f"#{alert_id}") or aid == alert_id:
                return rep
        return None

    def get_reports(self, status: Optional[str] = None, limit: int = 50) -> List[TriageReport]:
        """Get triage reports optionally filtered by decision status or determination."""
        reports = list(self._in_memory_reports.values())
        if status:
            st = status.upper()
            reports = [
                r for r in reports
                if (r.appsec_decision and r.appsec_decision.upper() == st)
                or (r.determination and r.determination.value.upper() == st)
                or (st == "PENDING" and (not r.appsec_decision or r.appsec_decision.upper() == "PENDING"))
            ]
        return reports[:limit]

    async def update_report(self, report: TriageReport) -> bool:
        """Update an existing triage report."""
        self._in_memory_reports[report.alert_id] = report
        if self.db_client:
            try:
                row = {
                    "alert_id": report.alert_id,
                    "repo": report.repo,
                    "commit_sha": report.commit_sha,
                    "rule_id": report.rule_id,
                    "determination": report.determination.value,
                    "confidence_score": report.confidence.score,
                    "confidence_level": report.confidence.qualitative_level,
                    "recommendation": report.recommendation.value,
                    "appsec_decision": report.appsec_decision,
                    "is_stale": report.is_stale,
                    "pr_comment_id": report.pr_comment_id,
                    "developer_feedback": report.developer_feedback,
                    "developer_questions": report.developer_questions,
                    "missing_evidence": report.missing_evidence,
                    "executive_summary": report.executive_summary,
                    "markdown_report": report.markdown_report,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                self.db_client.table("alert_reviews").upsert(row).execute()
            except Exception as e:
                logger.warning(f"Could not update alert_review in database: {e}")
        return True

    async def record_human_outcome(self, feedback: HumanTriageFeedback) -> bool:
        """
        Record a human AppSec engineer's final verdict on an alert.
        Triggered when an engineer closes/dismisses an alert in GitHub or UI.
        """
        self._in_memory_feedback[feedback.alert_id] = feedback

        if self.db_client:
            try:
                row = {
                    "alert_id": feedback.alert_id,
                    "repo": feedback.repo,
                    "human_verdict": feedback.human_verdict.value,
                    "human_notes": feedback.human_notes,
                    "reviewer_id": feedback.reviewer_id,
                    "created_at": feedback.created_at,
                }
                self.db_client.table("alert_human_outcomes").upsert(row).execute()
            except Exception as e:
                logger.warning(f"Could not persist alert_human_outcomes: {e}")

        return True

    def calculate_metrics(self) -> CalibrationMetrics:
        """
        Calculate calibration metrics comparing AI determinations and confidence scores
        against retained human outcomes.
        """
        # Find all alert IDs that have both an AI report and human feedback
        common_ids = set(self._in_memory_reports.keys()).intersection(self._in_memory_feedback.keys())
        total = len(common_ids)

        if total == 0:
            return CalibrationMetrics(
                total_reviewed_by_human=0,
                true_positive_agreement_count=0,
                false_positive_agreement_count=0,
                overall_accuracy=0.0,
                brier_score=0.0,
                precision=0.0,
                recall=0.0,
                confidence_bucket_stats={}
            )

        tp_agreements = 0
        fp_agreements = 0
        correct_count = 0

        # For Brier Score & Precision/Recall calculations (treating TRUE_POSITIVE as positive class)
        squared_errors = []
        true_positives = 0
        false_positives = 0
        false_negatives = 0

        # Buckets: 0.0-0.6, 0.6-0.8, 0.8-1.0
        buckets = {
            "low (0.0-0.6)": {"count": 0, "correct": 0, "sum_conf": 0.0},
            "medium (0.6-0.85)": {"count": 0, "correct": 0, "sum_conf": 0.0},
            "high (0.85-1.0)": {"count": 0, "correct": 0, "sum_conf": 0.0},
        }

        for aid in common_ids:
            report = self._in_memory_reports[aid]
            human = self._in_memory_feedback[aid]

            ai_det = report.determination
            human_det = human.human_verdict
            conf = report.confidence.score

            is_correct = (ai_det == human_det)
            if is_correct:
                correct_count += 1
                if ai_det == DeterminationType.TRUE_POSITIVE:
                    tp_agreements += 1
                elif ai_det == DeterminationType.FALSE_POSITIVE:
                    fp_agreements += 1

            # Precision / Recall stats
            if ai_det == DeterminationType.TRUE_POSITIVE:
                if human_det == DeterminationType.TRUE_POSITIVE:
                    true_positives += 1
                else:
                    false_positives += 1
            else:
                if human_det == DeterminationType.TRUE_POSITIVE:
                    false_negatives += 1

            # Brier Score calculation:
            # Let target y = 1 if human says TRUE_POSITIVE, else 0
            y = 1.0 if human_det == DeterminationType.TRUE_POSITIVE else 0.0
            p = conf if ai_det == DeterminationType.TRUE_POSITIVE else (1.0 - conf)
            squared_errors.append((p - y) ** 2)

            # Bucket attribution
            if conf < 0.60:
                b_key = "low (0.0-0.6)"
            elif conf < 0.85:
                b_key = "medium (0.6-0.85)"
            else:
                b_key = "high (0.85-1.0)"

            buckets[b_key]["count"] += 1
            buckets[b_key]["sum_conf"] += conf
            if is_correct:
                buckets[b_key]["correct"] += 1

        accuracy = correct_count / total
        brier = sum(squared_errors) / total if squared_errors else 0.0

        precision = (true_positives / (true_positives + false_positives)) if (true_positives + false_positives) > 0 else 0.0
        recall = (true_positives / (true_positives + false_negatives)) if (true_positives + false_negatives) > 0 else 0.0

        # Format bucket statistics
        bucket_stats = {}
        for b_name, data in buckets.items():
            cnt = data["count"]
            acc = (data["correct"] / cnt) if cnt > 0 else 0.0
            avg_c = (data["sum_conf"] / cnt) if cnt > 0 else 0.0
            bucket_stats[b_name] = {
                "count": cnt,
                "accuracy": round(acc, 3),
                "avg_confidence": round(avg_c, 3),
                "calibration_gap": round(abs(avg_c - acc), 3)
            }

        return CalibrationMetrics(
            total_reviewed_by_human=total,
            true_positive_agreement_count=tp_agreements,
            false_positive_agreement_count=fp_agreements,
            overall_accuracy=round(accuracy, 3),
            brier_score=round(brier, 4),
            precision=round(precision, 3),
            recall=round(recall, 3),
            confidence_bucket_stats=bucket_stats
        )
