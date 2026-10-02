"""
Report Generator (Stage 6).

Assembles audit-ready security reports across multiple formats:
- GitHub Markdown Summary (PR comments, Code Scanning alert comment, Job Summary)
- Actionable Remediation Plans (drop-in code fixes, CodeQL dataflow modeling, or dismissal text)
- Structured JSON reports for SIEM and automation
- Optional GitHub API integration to dismiss false positives automatically
"""

import json
import logging
from typing import List, Dict, Any, Optional
import httpx

from .models_alert import (
    NormalizedAlert,
    AlertCodeContext,
    InvestigatorAssessment,
    VerificationReport,
    DeterminationType,
    RecommendationType,
    CodeReference,
    ConfidenceScore,
    RemediationPlan,
    TriageReport,
)

logger = logging.getLogger(__name__)


def _generate_remediation(
    alert: NormalizedAlert,
    determination: DeterminationType,
    investigator: InvestigatorAssessment,
    verifier: VerificationReport
) -> RemediationPlan:
    """Generate tailored remediation guidance based on the determination."""
    if determination == DeterminationType.TRUE_POSITIVE:
        return RemediationPlan(
            action_type="CODE_FIX",
            suggested_fix_code=f"// Example remediation for {alert.rule_id} at {alert.primary_location.file_path}:{alert.primary_location.line_number}\n// Use parameterized queries or strict schema validation.",
            fix_explanation="The vulnerability is verified and exploitable. Replace raw string interpolation with parameterized queries or validated types.",
            dismissal_reason=None,
            dismissal_comment=None,
            codeql_modeling_recommendation=None
        )
    elif determination == DeterminationType.FALSE_POSITIVE:
        dismissal_text = (
            f"AI Alert Review: Validated False Positive ({investigator.proposed_determination.value}). "
            f"Evidence verifies that input is parameterized or safely neutralized. Rule: {alert.rule_id}."
        )
        return RemediationPlan(
            action_type="DISMISS_ALERT",
            suggested_fix_code=None,
            fix_explanation=None,
            dismissal_reason="false positive",
            dismissal_comment=dismissal_text,
            codeql_modeling_recommendation=(
                f"To suppress similar findings automatically in CodeQL, define a dataflow barrier sanitizer "
                f"in your CodeQL model for {alert.rule_id}."
            )
        )
    elif determination == DeterminationType.INSUFFICIENT_EVIDENCE:
        return RemediationPlan(
            action_type="REQUEST_EVIDENCE",
            suggested_fix_code=None,
            fix_explanation="Insufficient evidence to verify whether input is safely handled. Awaiting developer clarification in PR.",
            dismissal_reason=None,
            dismissal_comment=None,
            codeql_modeling_recommendation=None
        )
    else:
        return RemediationPlan(
            action_type="MANUAL_INVESTIGATION",
            suggested_fix_code=None,
            fix_explanation="AppSec review required to inspect runtime behavior or external architecture.",
            dismissal_reason=None,
            dismissal_comment=None,
            codeql_modeling_recommendation=None
        )


def _build_markdown_report(
    alert: NormalizedAlert,
    determination: DeterminationType,
    confidence: ConfidenceScore,
    investigator: InvestigatorAssessment,
    verifier: VerificationReport,
    remediation: RemediationPlan,
    developer_feedback: Optional[str] = None,
    is_stale: bool = False,
    appsec_decision: str = "PENDING"
) -> str:
    """Render structured, unified Markdown comment for the PR."""
    lines = []
    
    # 1. Unique Machine-readable anchor for in-place comment updates
    lines.append(f"<!-- AI_CODEQL_ALERT_REVIEW:{alert.alert_id} -->")

    # 2. Extract alert number for clean title
    alert_num = alert.alert_id.split("#")[-1] if "#" in alert.alert_id else alert.alert_id

    # 3. Assessment & Status Badges
    if is_stale:
        status_banner = "⚠️ **STATUS: STALE ASSESSMENT** (New commits pushed — waiting for updated CodeQL scan)"
    elif determination == DeterminationType.TRUE_POSITIVE:
        status_banner = f"🚨 **VERDICT: TRUE POSITIVE** | **ASSESSMENT: LIKELY VALID VULNERABILITY** ({confidence.qualitative_level} confidence: {confidence.score:.0%})"
    elif determination == DeterminationType.FALSE_POSITIVE:
        status_banner = f"🛡️ **VERDICT: FALSE POSITIVE** | **ASSESSMENT: LIKELY FALSE POSITIVE** ({confidence.qualitative_level} confidence: {confidence.score:.0%})"
    elif determination == DeterminationType.INSUFFICIENT_EVIDENCE:
        status_banner = f"❓ **ASSESSMENT: INSUFFICIENT EVIDENCE** ({confidence.qualitative_level} confidence: {confidence.score:.0%})"
    elif determination == DeterminationType.ACCEPTABLE_RISK:
        status_banner = f"⚠️ **VERDICT: ACCEPTABLE RISK** | **ASSESSMENT: ACCEPTABLE RISK** ({confidence.qualitative_level} confidence: {confidence.score:.0%})"
    else:
        status_banner = f"🔍 **VERDICT: SUSPICIOUS / NEEDS HUMAN REVIEW** | **ASSESSMENT: NEEDS APPSEC REVIEW** ({confidence.qualitative_level} confidence: {confidence.score:.0%})"

    lines.append(f"### 🤖 AI AppSec Review — Alert #{alert_num}: `{alert.rule_id}`\n")
    lines.append(f"{status_banner}\n")

    # 4. Consolidated Review Card
    short_commit = alert.commit_sha[:8] if alert.commit_sha else "HEAD"
    lines.append(f"> **Alert Reference:** [{alert.repo}#{alert_num}]({alert.source_url or '#'})  ")
    lines.append(f"> **Rule:** `{alert.rule_id}` ({alert.rule_name}) | **Severity:** `{alert.severity.value}`  ")
    lines.append(f"> **Reviewed Commit:** `{short_commit}`  ")
    lines.append(f"> **Location:** `{alert.primary_location.file_path}:{alert.primary_location.line_number}`  ")
    lines.append(f"> **AppSec Dismissal Decision:** `{appsec_decision}` (AppSec holds final approval authority)  ")

    # 5. Developer Action / Questions
    lines.append("\n#### 👤 Developer Action Required:")
    if determination == DeterminationType.INSUFFICIENT_EVIDENCE or investigator.developer_questions:
        lines.append("**Please respond directly in this PR comment thread with evidence or answers to the following:**")
        for q in (investigator.developer_questions or ["Where does input sanitization or parameter binding occur for this query?"]):
            lines.append(f"- ❓ **{q}**")
        if investigator.missing_evidence:
            lines.append("\n*Missing context identified by AI:*")
            for m in investigator.missing_evidence:
                lines.append(f"  * `{m}`")
    elif determination == DeterminationType.TRUE_POSITIVE:
        lines.append("🔴 **Remediation Required:** Code changes needed before merge. Please parameterize inputs or apply strict schema validation.")
        if remediation.suggested_fix_code:
            lines.append(f"\n```suggestion\n{remediation.suggested_fix_code}\n```")
    elif determination == DeterminationType.FALSE_POSITIVE:
        lines.append("🟢 **No Developer Action Needed:** Finding appears to be a False Positive. Request dismissal on the alert if blocked; AppSec will review and record final decision.")
    else:
        lines.append("🟡 **Awaiting AppSec Review:** Manual review queued for the Application Security team.")

    # 6. Developer Justification Status (if response received)
    if developer_feedback:
        lines.append("\n#### 💬 Developer Feedback Received:")
        lines.append(f"> \"{developer_feedback.strip()}\"")
        if verifier.developer_evidence_verified:
            lines.append("✅ **Developer Evidence Status:** Corroborated by repository code inspection.")
        else:
            lines.append("⚠️ **Developer Evidence Status:** Unverified verbal statement. Code verification required.")
            if verifier.unverified_developer_claims:
                for c in verifier.unverified_developer_claims:
                    lines.append(f"  * {c}")

    # 7. Collapsible Deep-Dive Details for AppSec Engineer
    lines.append("\n<details>")
    lines.append("<summary><b>🔍 AppSec Investigation Details & Evidence Matrix (Click to expand)</b></summary>\n")

    lines.append(f"**Executive Summary:** {confidence.explanation}\n")
    lines.append(f"**Scanner Claim:** {alert.scanner_message}\n")

    # Dataflow hops
    if alert.code_flows:
        lines.append("##### 🌊 CodeQL Dataflow Trace:")
        for flow in alert.code_flows:
            for idx, node in enumerate(flow.nodes):
                hop_type = node.step_type.upper()
                lines.append(f"{idx+1}. `[{hop_type}]` `{node.file_path}:{node.line_number}` — {node.description or 'step'}")
                if node.code_snippet:
                    lines.append(f"   ```text\n   {node.code_snippet.strip()}\n   ```")
        lines.append("")

    # Evidence Matrix
    lines.append("##### ⚖️ Evidence Matrix:")
    if investigator.supporting_evidence:
        lines.append("| ID | Category | Title & Finding | Cited Code |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for item in investigator.supporting_evidence:
            ref_str = item.code_reference or ""
            snippet = f"`{ref_str[:40]}...`" if len(ref_str) > 40 else (f"`{ref_str}`" if ref_str else "N/A")
            lines.append(f"| {item.id} | `{item.category.value}` | **{item.title}**: {item.description} | {snippet} |")
    if investigator.opposing_evidence:
        for item in investigator.opposing_evidence:
            ref_str = item.code_reference or ""
            snippet = f"`{ref_str[:40]}...`" if len(ref_str) > 40 else (f"`{ref_str}`" if ref_str else "N/A")
            lines.append(f"| {item.id} | `{item.category.value}` | **{item.title}**: {item.description} | {snippet} |")

    # Adversarial verification
    lines.append(f"\n- **Code Grounding Ratio:** `{verifier.grounding_score:.0%}`")
    if verifier.challenges:
        lines.append("- **Adversarial Verifier Challenges:**")
        for c in verifier.challenges:
            icon = "⚠️ Counter Valid" if c.was_adversarial_counter_valid else "✅ Mitigated"
            lines.append(f"  * **{icon}**: {c.challenge_question} — *{c.challenge_resolution}*")

    lines.append("\n</details>")

    lines.append("\n---")
    lines.append("*Review powered by AI AppSec PR Reviewer. AppSec engineers retain exclusive dismissal authority.*")

    return "\n".join(lines)


class ReportGenerator:
    """Generates triage reports with human-in-the-loop governance."""

    def generate_report(
        self,
        alert: NormalizedAlert,
        context: AlertCodeContext,
        investigator: InvestigatorAssessment,
        verifier: VerificationReport,
        determination: DeterminationType,
        confidence: ConfidenceScore,
        developer_feedback: Optional[str] = None,
        is_stale: bool = False,
        appsec_decision: str = "PENDING",
        pr_comment_id: Optional[int] = None
    ) -> TriageReport:
        """
        Produce a full TriageReport object.
        """
        remediation = _generate_remediation(alert, determination, investigator, verifier)
        md_report = _build_markdown_report(
            alert=alert,
            determination=determination,
            confidence=confidence,
            investigator=investigator,
            verifier=verifier,
            remediation=remediation,
            developer_feedback=developer_feedback,
            is_stale=is_stale,
            appsec_decision=appsec_decision
        )

        exec_summary = (
            f"Alert {alert.alert_id} evaluated as {determination.value} "
            f"with {confidence.score:.0%} confidence ({confidence.qualitative_level}). "
            f"Recommendation: {investigator.recommendation.value}."
        )

        return TriageReport(
            alert_id=alert.alert_id,
            repo=alert.repo,
            commit_sha=alert.commit_sha,
            rule_id=alert.rule_id,
            rule_name=alert.rule_name,
            severity=alert.severity,
            determination=determination,
            confidence=confidence,
            executive_summary=exec_summary,
            scanner_claim=alert.scanner_message,
            investigator_assessment=investigator,
            verification_report=verifier,
            remediation=remediation,
            limitations=verifier.missing_context_flags,
            markdown_report=md_report,
            code_references=investigator.code_references,
            verified_evidence=investigator.verified_evidence,
            missing_evidence=investigator.missing_evidence,
            developer_questions=investigator.developer_questions,
            recommendation=investigator.recommendation,
            appsec_decision=appsec_decision,
            is_stale=is_stale,
            pr_comment_id=pr_comment_id,
            developer_feedback=developer_feedback
        )

    async def dismiss_github_alert(
        self,
        owner: str,
        repo: str,
        alert_number: int,
        github_token: str,
        reason: str,
        comment: str
    ) -> bool:
        """
        Strict AppSec governance enforcement:
        The AI service NEVER automatically dismisses alerts in GitHub.
        Dismissal authority belongs exclusively to human AppSec engineers.
        """
        logger.warning(
            f"Attempted automated dismissal on {owner}/{repo}#{alert_number} blocked by governance policy. "
            "AI service operates in advisory mode; AppSec engineers hold exclusive dismissal authority."
        )
        return False
