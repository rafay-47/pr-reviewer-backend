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
        self._normalized_alert_cache: Dict[str, NormalizedAlert] = {}

    async def review_normalized_alert(
        self,
        alert: NormalizedAlert,
        developer_feedback: Optional[str] = None,
        is_stale: bool = False,
        appsec_decision: str = "PENDING",
        pr_comment_id: Optional[int] = None
    ) -> TriageReport:
        """
        Execute the 6-stage review on an already normalized alert.
        
        Args:
            alert: NormalizedAlert instance.
            developer_feedback: Optional developer explanation or response to previous questions.
            is_stale: Whether the commit being reviewed has been superseded by newer commits.
            appsec_decision: Status of human AppSec decision ('PENDING', 'APPROVED', 'DENIED').
            pr_comment_id: GitHub PR comment ID for in-place updates.
            
        Returns:
            TriageReport instance.
        """
        logger.info(f"Starting AI Alert Review for {alert.alert_id} ({alert.rule_id}) [Feedback: {bool(developer_feedback)}]")
        self._normalized_alert_cache[alert.alert_id] = alert

        # Stage 2: Code Context Builder
        logger.debug(f"[Stage 2] Building code context for {alert.alert_id}")
        context: AlertCodeContext = await self.context_builder.build_context(alert)

        # Stage 3: AI Investigator (evaluates scanner claim + developer feedback if provided)
        logger.debug(f"[Stage 3] Running AI Investigator for {alert.alert_id}")
        assessment: InvestigatorAssessment = await self.investigator.investigate(
            alert=alert,
            context=context,
            developer_feedback=developer_feedback
        )

        # Stage 4: Evidence Verifier & Reviewer (scrutinizes investigator and developer claims)
        logger.debug(f"[Stage 4] Running Adversarial Verifier for {alert.alert_id}")
        verification: VerificationReport = await self.verifier.verify(
            alert=alert,
            context=context,
            assessment=assessment,
            developer_feedback=developer_feedback
        )

        # Stage 5: Determination & Confidence Engine
        logger.debug(f"[Stage 5] Evaluating Determination and Confidence for {alert.alert_id}")
        determination, confidence = self.confidence_engine.calculate_determination_and_confidence(
            alert=alert,
            context=context,
            investigator=assessment,
            verifier=verification
        )

        # Stage 6: Report Generator (assembles structured single-card PR format)
        logger.debug(f"[Stage 6] Generating Triage Report for {alert.alert_id}")
        report: TriageReport = self.report_generator.generate_report(
            alert=alert,
            context=context,
            investigator=assessment,
            verifier=verification,
            determination=determination,
            confidence=confidence,
            developer_feedback=developer_feedback,
            is_stale=is_stale,
            appsec_decision=appsec_decision,
            pr_comment_id=pr_comment_id
        )

        # Storage & Persistence
        await self.calibration_store.save_triage_report(report)

        logger.info(
            f"Completed AI Alert Review for {alert.alert_id}: "
            f"Verdict={determination.value}, Confidence={confidence.score:.0%} ({confidence.qualitative_level}) - AppSec Final Authority Preserved"
        )
        return report

    async def reassess_with_developer_response(
        self,
        alert_id: str,
        developer_response: str,
        pr_comment_id: Optional[int] = None,
        cached_alert: Optional[NormalizedAlert] = None
    ) -> TriageReport:
        """
        Re-evaluate an alert when the developer supplies evidence or answers in the PR thread.
        
        Args:
            alert_id: Unique alert ID (e.g. 'org/repo#42').
            developer_response: Plaintext reply from developer.
            pr_comment_id: ID of the PR comment to update.
            cached_alert: Optional pre-normalized alert object.
            
        Returns:
            Updated TriageReport.
        """
        alert = cached_alert or self._normalized_alert_cache.get(alert_id)
        if not alert:
            raise ValueError(f"No alert data found for {alert_id} to perform reassessment.")

        return await self.review_normalized_alert(
            alert=alert,
            developer_feedback=developer_response,
            pr_comment_id=pr_comment_id
        )

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

    async def record_appsec_decision(
        self,
        repo: str,
        alert_id: str,
        decision: str,
        reason: Optional[str] = None,
        reviewer: Optional[str] = None,
        pr_number: Optional[int] = None,
        github_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Record and execute an official AppSec engineer dismissal approval or denial.
        AppSec engineers hold exclusive dismissal authority.
        """
        if "/" in repo:
            owner, repo_name = repo.split("/", 1)
        else:
            owner, repo_name = "", repo

        alert_num_str = alert_id.split("#")[-1]
        alert_number = int(alert_num_str) if alert_num_str.isdigit() else 0

        from .github_app_service import GitHubAppAlertHandler
        handler = GitHubAppAlertHandler(service=self)
        token = github_token or self.github_token

        return await handler.apply_appsec_decision(
            owner=owner,
            repo=repo_name,
            alert_number=alert_number,
            decision=decision,
            reason=reason,
            reviewer=reviewer,
            pr_number=pr_number,
            token=token
        )

    def get_alert_queue(self, status: Optional[str] = None, limit: int = 50) -> List[TriageReport]:
        """
        Retrieve queue of alerts for AppSec review.
        """
        return self.calibration_store.get_reports(status=status, limit=limit)

    def get_calibration_metrics(self) -> CalibrationMetrics:
        """
        Retrieve calibration and accuracy statistics against retained human outcomes.
        """
        return self.calibration_store.calculate_metrics()
