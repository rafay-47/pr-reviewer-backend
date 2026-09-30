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
            suggested_fix_code=f"// Example remediation for {alert.rule_id} at {alert.primary_location.file_path}:{alert.primary_location.line_number}\n// Use parameterized inputs or validate against a strict schema.",
            fix_explanation="The vulnerability is exploitable. Replace the vulnerable direct interpolation/execution with parameterized interfaces.",
            dismissal_reason=None,
            dismissal_comment=None,
            codeql_modeling_recommendation=None
        )
    elif determination == DeterminationType.FALSE_POSITIVE:
        dismissal_text = (
            f"AI Alert Review: Validated as False Positive ({investigator.proposed_determination.value}). "
            f"Evidence shows taint is neutralized or unreachable. Rule: {alert.rule_id}."
        )
        return RemediationPlan(
            action_type="DISMISS_ALERT",
            suggested_fix_code=None,
            fix_explanation=None,
            dismissal_reason="false positive",
            dismissal_comment=dismissal_text,
            codeql_modeling_recommendation=(
                f"To suppress similar findings automatically in CodeQL, define a dataflow barrier sanitizer "
                f"in your CodeQL model or query suite for {alert.rule_id}."
            )
        )
    else:
        return RemediationPlan(
            action_type="MANUAL_INVESTIGATION",
            suggested_fix_code=None,
            fix_explanation="Manual investigation required by AppSec team to inspect runtime behavior or external dependencies.",
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
    remediation: RemediationPlan
) -> str:
    """Render rich Markdown report for GitHub."""
    # Banner
    if determination == DeterminationType.TRUE_POSITIVE:
        badge = f"🚨 **VERDICT: TRUE POSITIVE** (Confidence: {confidence.score:.0%} - {confidence.qualitative_level})"
    elif determination == DeterminationType.FALSE_POSITIVE:
        badge = f"🛡️ **VERDICT: FALSE POSITIVE** (Confidence: {confidence.score:.0%} - {confidence.qualitative_level})"
    elif determination == DeterminationType.ACCEPTABLE_RISK:
        badge = f"⚠️ **VERDICT: ACCEPTABLE RISK** (Confidence: {confidence.score:.0%} - {confidence.qualitative_level})"
    else:
        badge = f"🔍 **VERDICT: SUSPICIOUS / NEEDS HUMAN REVIEW** (Confidence: {confidence.score:.0%} - {confidence.qualitative_level})"

    lines = []
    lines.append(f"## 🤖 AI Code Scanning Alert Review")
    lines.append(f"\n{badge}\n")
    lines.append(f"**Alert ID:** `{alert.alert_id}` | **Rule:** `{alert.rule_id}` ({alert.rule_name}) | **Severity:** `{alert.severity.value}`")
    if alert.cwe_ids:
        lines.append(f"**CWE References:** {', '.join(alert.cwe_ids)}")
    lines.append(f"**Location:** `{alert.primary_location.file_path}:{alert.primary_location.line_number}`")

    lines.append(f"\n### 📋 Executive Summary")
    lines.append(confidence.explanation)

    lines.append(f"\n### 🎯 Scanner Claim")
    lines.append(f"> {alert.scanner_message}")

    # Evidence Matrix
    lines.append(f"\n### ⚖️ Evidence Matrix")

    lines.append(f"\n#### Supporting Evidence (Indicating True Positive)")
    if investigator.supporting_evidence:
        lines.append("| ID | Category | Title | Code Reference |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for item in investigator.supporting_evidence:
            ref_snippet = f"`{item.code_reference[:45]}...`" if item.code_reference else "N/A"
            lines.append(f"| {item.id} | `{item.category.value}` | **{item.title}**: {item.description} | {ref_snippet} |")
    else:
        lines.append("_No substantial supporting evidence found._")

    lines.append(f"\n#### Opposing Evidence (Indicating False Positive / Mitigation)")
    if investigator.opposing_evidence:
        lines.append("| ID | Category | Title | Code Reference |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for item in investigator.opposing_evidence:
            ref_snippet = f"`{item.code_reference[:45]}...`" if item.code_reference else "N/A"
            lines.append(f"| {item.id} | `{item.category.value}` | **{item.title}**: {item.description} | {ref_snippet} |")
    else:
        lines.append("_No substantial opposing evidence found._")

    # Verification & Adversarial Challenges
    lines.append(f"\n### 🔬 Adversarial Verification & Grounding")
    lines.append(f"- **Grounding Score:** `{verifier.grounding_score:.0%}` (code references verified in source files)")
    if verifier.ungrounded_claims:
        lines.append(f"- ⚠️ **Ungrounded Citations:** {len(verifier.ungrounded_claims)} claims failed strict source verification.")
    
    if verifier.challenges:
        lines.append(f"\n<details><summary><b>Adversarial Challenges ({len(verifier.challenges)})</b></summary>\n")
        for c in verifier.challenges:
            status_icon = "⚠️ Bypass Found" if c.was_adversarial_counter_valid else "✅ Defended"
            lines.append(f"- **{status_icon}**: {c.challenge_question}")
            lines.append(f"  * *Counter-argument:* {c.counter_argument}")
            lines.append(f"  * *Resolution:* {c.challenge_resolution}\n")
        lines.append("</details>")

    # Limitations & Unknowns
    if verifier.missing_context_flags:
        lines.append(f"\n### ⚠️ Limitations & Unverified Assumptions")
        for flag in verifier.missing_context_flags:
            lines.append(f"- {flag}")

    # Actionable Remediation
    lines.append(f"\n### 💡 Recommended Action")
    if remediation.action_type == "DISMISS_ALERT":
        lines.append(f"**Recommended GitHub Action:** Dismiss alert as **False Positive**.")
        lines.append(f"```text\n{remediation.dismissal_comment}\n```")
        if remediation.codeql_modeling_recommendation:
            lines.append(f"\n> **CodeQL Modeling Tip:** {remediation.codeql_modeling_recommendation}")
    elif remediation.action_type == "CODE_FIX":
        lines.append(f"**Recommended GitHub Action:** Require code modification before merging.")
        if remediation.suggested_fix_code:
            lines.append(f"\n```suggestion\n{remediation.suggested_fix_code}\n```")
    else:
        lines.append(f"**Recommended GitHub Action:** Escalate to Application Security Engineer for manual triage.")

    lines.append("\n---\n*Report generated by AI Alert Review Service (CodeQL Triage Engine).*")
    return "\n".join(lines)


class ReportGenerator:
    """Generates triage reports and handles automated GitHub alert updates."""

    def generate_report(
        self,
        alert: NormalizedAlert,
        context: AlertCodeContext,
        investigator: InvestigatorAssessment,
        verifier: VerificationReport,
        determination: DeterminationType,
        confidence: ConfidenceScore
    ) -> TriageReport:
        """
        Produce a full TriageReport object.
        """
        remediation = _generate_remediation(alert, determination, investigator, verifier)
        md_report = _build_markdown_report(alert, determination, confidence, investigator, verifier, remediation)

        exec_summary = (
            f"Alert {alert.alert_id} evaluated as {determination.value} "
            f"with {confidence.score:.0%} confidence ({confidence.qualitative_level})."
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
            markdown_report=md_report
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
        Call GitHub API PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}
        to dismiss a false positive finding.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        payload = {
            "state": "dismissed",
            "dismissed_reason": reason,
            "dismissed_comment": comment[:280]  # GitHub comment limit
        }

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.patch(url, headers=headers, json=payload)
                if resp.status_code in (200, 204):
                    logger.info(f"Successfully dismissed GitHub alert {owner}/{repo}#{alert_number}")
                    return True
                else:
                    logger.warning(f"Failed to dismiss GitHub alert: {resp.status_code} - {resp.text}")
                    return False
        except Exception as e:
            logger.error(f"Error dismissing GitHub alert: {e}")
            return False
