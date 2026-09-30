"""
AI Alert Review Service Orchestrator.

Coordinates the end-to-end 6-stage alert review pipeline:
1. Alert Collector & Normalizer
2. Code Context Builder
3. AI Investigator
4. Evidence Verifier & Reviewer
5. Determination & Confidence Engine
6. Report Generator & Storage / Calibration
"""

import logging
from typing import Dict, Any, Optional, List, Callable

from .models_alert import (
    NormalizedAlert,
    AlertCodeContext,
    InvestigatorAssessment,
    VerificationReport,
    DeterminationType,
    ConfidenceScore,
    TriageReport,
    HumanTriageFeedback,
    CalibrationMetrics,
)
from .alert_collector import parse_github_alert_webhook, parse_sarif, fetch_alert_from_github_api
from .context_builder import CodeContextBuilder
from .investigator import AIInvestigator
from .verifier import EvidenceVerifier
from .confidence_engine import ConfidenceEngine
from .report_generator import ReportGenerator
from .calibration import CalibrationStore
from .llm_bridge import default_llm_caller

logger = logging.getLogger(__name__)


class AlertReviewService:
    """End-to-end service executing the 6-stage static alert review pipeline."""

    def __init__(
        self,
        llm_caller: Optional[Callable] = None,
        local_repo_path: Optional[str] = None,
        github_token: Optional[str] = None,
        db_client=None,
        auto_dismiss_false_positives: bool = False,
        min_dismiss_confidence: float = 0.90
    ):
        """
        Args:
            llm_caller: Async callable (system_prompt: str, user_prompt: str) -> str. Defaults to default_llm_caller.
            local_repo_path: Root of local repository checkout if available
            github_token: GitHub token for API calls
            db_client: Database client for report persistence
            auto_dismiss_false_positives: Whether to dismiss verified FPs via GitHub API
            min_dismiss_confidence: Minimum confidence threshold to trigger auto-dismissal
        """
        self.llm_caller = llm_caller or default_llm_caller
        self.github_token = github_token
        self.auto_dismiss_false_positives = auto_dismiss_false_positives
        self.min_dismiss_confidence = min_dismiss_confidence

        # Initialize all 6 pipeline stages
        self.context_builder = CodeContextBuilder(
            local_repo_path=local_repo_path,
            github_token=github_token
        )
        self.investigator = AIInvestigator(llm_caller=self.llm_caller)
        self.verifier = EvidenceVerifier(llm_caller=self.llm_caller)
        self.confidence_engine = ConfidenceEngine()
        self.report_generator = ReportGenerator()
        self.calibration_store = CalibrationStore(db_client=db_client)

    async def review_normalized_alert(self, alert: NormalizedAlert) -> TriageReport:
        """
        Execute the 6-stage review on an already normalized alert.
        
        Args:
            alert: NormalizedAlert instance.
            
        Returns:
            TriageReport instance.
        """
        logger.info(f"Starting AI Alert Review for {alert.alert_id} ({alert.rule_id})")

        # Stage 2: Code Context Builder
        logger.debug(f"[Stage 2] Building code context for {alert.alert_id}")
        context: AlertCodeContext = await self.context_builder.build_context(alert)

        # Stage 3: AI Investigator
        logger.debug(f"[Stage 3] Running AI Investigator for {alert.alert_id}")
        assessment: InvestigatorAssessment = await self.investigator.investigate(alert, context)

        # Stage 4: Evidence Verifier & Reviewer
        logger.debug(f"[Stage 4] Running Adversarial Verifier for {alert.alert_id}")
        verification: VerificationReport = await self.verifier.verify(alert, context, assessment)

        # Stage 5: Determination & Confidence Engine
        logger.debug(f"[Stage 5] Evaluating Determination and Confidence for {alert.alert_id}")
        determination, confidence = self.confidence_engine.calculate_determination_and_confidence(
            alert=alert,
            context=context,
            investigator=assessment,
            verifier=verification
        )

        # Stage 6: Report Generator
        logger.debug(f"[Stage 6] Generating Triage Report for {alert.alert_id}")
        report: TriageReport = self.report_generator.generate_report(
            alert=alert,
            context=context,
            investigator=assessment,
            verifier=verification,
            determination=determination,
            confidence=confidence
        )

        # Storage & Persistence
        await self.calibration_store.save_triage_report(report)

        # Optional Auto-Dismissal via GitHub API
        if (
            self.auto_dismiss_false_positives
            and determination == DeterminationType.FALSE_POSITIVE
            and confidence.score >= self.min_dismiss_confidence
            and self.github_token
            and "#" in alert.alert_id
        ):
            try:
                repo_part, alert_num_str = alert.alert_id.split("#", 1)
                owner, repo_name = repo_part.split("/", 1)
                if alert_num_str.isdigit():
                    alert_number = int(alert_num_str)
                    await self.report_generator.dismiss_github_alert(
                        owner=owner,
                        repo=repo_name,
                        alert_number=alert_number,
                        github_token=self.github_token,
                        reason="false positive",
                        comment=f"AI Alert Review: Validated False Positive ({confidence.score:.0%} confidence)."
                    )
            except Exception as e:
                logger.warning(f"Auto-dismissal failed for {alert.alert_id}: {e}")

        logger.info(
            f"Completed AI Alert Review for {alert.alert_id}: "
            f"Verdict={determination.value}, Confidence={confidence.score:.0%} ({confidence.qualitative_level})"
        )
        return report

    async def review_webhook_payload(self, payload: Dict[str, Any]) -> Optional[TriageReport]:
        """
        Stage 1 + Full Pipeline: Review alert from a GitHub webhook event.
        """
        alert = parse_github_alert_webhook(payload)
        if not alert:
            return None
        return await self.review_normalized_alert(alert)

    async def review_sarif_file(
        self,
        sarif_data: Dict[str, Any],
        repo: str,
        commit_sha: str,
        ref: Optional[str] = None
    ) -> List[TriageReport]:
        """
        Stage 1 + Full Pipeline: Review all alerts in a SARIF file.
        """
        alerts = parse_sarif(sarif_data, repo=repo, commit_sha=commit_sha, ref=ref)
        reports = []
        for alert in alerts:
            rep = await self.review_normalized_alert(alert)
            reports.append(rep)
        return reports

    async def record_human_outcome(
        self,
        alert_id: str,
        repo: str,
        verdict: DeterminationType,
        notes: Optional[str] = None,
        reviewer_id: Optional[str] = None
    ) -> bool:
        """
        Record a human AppSec engineer's ground-truth review for calibration.
        """
        feedback = HumanTriageFeedback(
            alert_id=alert_id,
            repo=repo,
            human_verdict=verdict,
            human_notes=notes,
            reviewer_id=reviewer_id
        )
        return await self.calibration_store.record_human_outcome(feedback)

    def get_calibration_metrics(self) -> CalibrationMetrics:
        """
        Retrieve calibration and accuracy statistics against retained human outcomes.
        """
        return self.calibration_store.calculate_metrics()
