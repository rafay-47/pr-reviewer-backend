"""
GitHub App Handler for Code Scanning Alerts & Delegated Dismissal Requests.

Enables 100% automated AI Alert Review via GitHub App (zero YAML workflows required):
1. Ingests GitHub App webhook events for `code_scanning_alert`:
   - New alerts created by CodeQL (`action: created`, `reopened_by_user`)
   - Alert dismissal requests submitted by developers (`action: closed_by_user`)
2. Uses GitHub App installation tokens to fetch code context at the analyzed commit
3. Executes the 6-stage AI Alert Review pipeline
4. Publishes outcomes back to GitHub:
   - Creates GitHub Check Runs on the commit (no workflow files required)
   - Posts comments to associated Pull Requests
   - Automatically executes or validates alert dismissal requests via GitHub API
   - Retains human and AI outcomes for continuous calibration
"""

import logging
import re
from typing import Dict, Any, Optional, List, Tuple
import httpx

from ..config import Settings, get_settings
from ..github_app_auth import get_installation_token, get_installation_for_repo
from .models_alert import (
    NormalizedAlert,
    AlertCodeContext,
    DeterminationType,
    TriageReport,
    HumanTriageFeedback,
    AlertSeverity,
)
from .alert_collector import parse_github_alert_webhook
from .context_builder import CodeContextBuilder
from .service import AlertReviewService

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"


class GitHubAppAlertHandler:
    """Handles GitHub App webhook events and API integrations for Code Scanning alerts."""

    def __init__(self, service: Optional[AlertReviewService] = None, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.service = service or AlertReviewService()

    async def get_token_for_payload(self, payload: Dict[str, Any]) -> Optional[str]:
        """Obtain GitHub App installation access token from webhook payload."""
        installation_id = payload.get("installation", {}).get("id")
        if not installation_id:
            repo_full = payload.get("repository", {}).get("full_name")
            if repo_full and "/" in repo_full:
                owner, repo = repo_full.split("/", 1)
                try:
                    installation_id = await get_installation_for_repo(owner, repo, self.settings)
                except Exception as e:
                    logger.warning(f"Could not find installation for {repo_full}: {e}")

        if not installation_id:
            logger.warning("No GitHub App installation ID available in payload or database")
            return None

        try:
            token, _ = await get_installation_token(int(installation_id), self.settings)
            return token
        except Exception as e:
            logger.error(f"Failed to generate GitHub App installation token for {installation_id}: {e}")
            return None

    async def find_associated_pull_request(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
        ref: Optional[str],
        token: str
    ) -> Optional[int]:
        """Determine PR number from ref or commit SHA."""
        if ref and "refs/pull/" in ref:
            m = re.search(r"refs/pull/(\d+)", ref)
            if m:
                return int(m.group(1))

        # Query GitHub API for PRs associated with this commit
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits/{commit_sha}/pulls"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    prs = resp.json()
                    if prs and len(prs) > 0:
                        return prs[0].get("number")
        except Exception as e:
            logger.warning(f"Could not resolve PR for commit {commit_sha}: {e}")

        return None

    async def create_check_run(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
        report: TriageReport,
        token: str
    ) -> Optional[Dict[str, Any]]:
        """
        Create a GitHub Check Run on the analyzed commit.
        Provides native GitHub UI integration without any GitHub Action workflows.
        """
        # Determine Check Run conclusion
        if report.determination == DeterminationType.FALSE_POSITIVE:
            conclusion = "success"
            title = f"🛡️ False Positive Validated ({report.confidence.score:.0%} confidence)"
        elif report.determination == DeterminationType.TRUE_POSITIVE:
            conclusion = "action_required"
            title = f"🚨 Valid Security Finding: {report.rule_id} ({report.confidence.score:.0%} confidence)"
        elif report.determination == DeterminationType.ACCEPTABLE_RISK:
            conclusion = "neutral"
            title = f"⚠️ Acceptable Risk ({report.confidence.score:.0%} confidence)"
        else:
            conclusion = "neutral"
            title = f"🔍 Needs Human Review ({report.confidence.score:.0%} confidence)"

        check_run_payload = {
            "name": f"AI CodeQL Review: {report.rule_id}",
            "head_sha": commit_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": title[:255],
                "summary": report.executive_summary[:65000],
                "text": report.markdown_report[:65000]
            }
        }

        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/check-runs"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(url, headers=headers, json=check_run_payload)
                if resp.status_code in (200, 201):
                    logger.info(f"Created GitHub Check Run for {owner}/{repo}@{commit_sha}")
                    return resp.json()
                else:
                    logger.warning(f"Failed to create Check Run: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"Error creating GitHub Check Run: {e}")

        return None

    async def post_pull_request_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        report: TriageReport,
        token: str
    ) -> bool:
        """Post the review markdown report as a comment on the PR."""
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        payload = {"body": report.markdown_report}

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                return resp.status_code in (200, 201)
        except Exception as e:
            logger.error(f"Error posting PR comment for #{pr_number}: {e}")
            return False

    async def process_webhook_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for GitHub App `code_scanning_alert` events:
        - When CodeQL publishes alerts (action: created, reopened)
        - When a developer submits a dismissal request for an alert (action: closed_by_user)
        """
        action = payload.get("action")
        repo_data = payload.get("repository", {})
        repo_full = repo_data.get("full_name") or ""
        if "/" not in repo_full:
            return {"status": "ignored", "reason": "Missing repository name"}

        owner, repo_name = repo_full.split("/", 1)
        alert_data = payload.get("alert", {})
        alert_number = alert_data.get("number")

        logger.info(f"GitHub App received code_scanning_alert event: {action} on {repo_full}#{alert_number}")

        # Resolve GitHub App installation token
        token = await self.get_token_for_payload(payload)
        if token:
            # Wire installation token into context builder so it fetches real code at commit
            self.service.context_builder.github_token = token
            self.service.github_token = token

        # =========================================================================
        # Case A: Developer Submits a Dismissal Request (action: closed_by_user)
        # =========================================================================
        if action in ("closed_by_user", "dismissed"):
            dismissed_reason = alert_data.get("dismissed_reason") or "false positive"
            dismissed_comment = alert_data.get("dismissed_comment") or ""
            dismissed_by = alert_data.get("dismissed_by", {}).get("login", "developer")

            logger.info(
                f"Dismissal request submitted for {repo_full}#{alert_number} by {dismissed_by} "
                f"Reason: '{dismissed_reason}' - Comment: '{dismissed_comment}'"
            )

            # 1. Parse alert into NormalizedAlert
            normalized = parse_github_alert_webhook(payload)
            if not normalized:
                # Force normalization even if closed_by_user
                payload_mock = dict(payload)
                payload_mock["action"] = "created"
                normalized = parse_github_alert_webhook(payload_mock)

            if not normalized:
                return {"status": "error", "reason": "Could not normalize alert data for dismissal review"}

            # 2. Execute 6-stage AI Review to validate developer's dismissal claim
            report: TriageReport = await self.service.review_normalized_alert(normalized)

            # 3. Check if human dismissal matches AI determination
            human_verdict = (
                DeterminationType.FALSE_POSITIVE if "false" in dismissed_reason.lower()
                else DeterminationType.ACCEPTABLE_RISK if "won't" in dismissed_reason.lower() or "wont" in dismissed_reason.lower()
                else DeterminationType.TRUE_POSITIVE
            )

            # Record human calibration outcome
            await self.service.record_human_outcome(
                alert_id=normalized.alert_id,
                repo=repo_full,
                verdict=human_verdict,
                notes=f"User {dismissed_by} submitted dismissal: {dismissed_reason} ({dismissed_comment})",
                reviewer_id=dismissed_by
            )

            # 4. Publish Check Run evaluating the dismissal request
            if token and normalized.commit_sha:
                await self.create_check_run(owner, repo_name, normalized.commit_sha, report, token)

            # 5. Check if dismissal is dangerous (e.g. human marked False Positive, but AI found valid True Positive)
            is_disputed = (human_verdict == DeterminationType.FALSE_POSITIVE and report.determination == DeterminationType.TRUE_POSITIVE)
            if is_disputed and token:
                logger.warning(f"⚠️ DISPUTED DISMISSAL on {repo_full}#{alert_number}! Developer dismissed valid True Positive!")
                pr_number = await self.find_associated_pull_request(owner, repo_name, normalized.commit_sha, normalized.ref, token)
                if pr_number:
                    warning_body = (
                        f"### ⚠️ Security Alert Dismissal Disputed by AI AppSec Reviewer\n\n"
                        f"User **@{dismissed_by}** requested dismissal of alert **#{alert_number}** as `{dismissed_reason}`.\n\n"
                        f"However, the AI Alert Review Service determined this finding is a **TRUE POSITIVE** "
                        f"with **{report.confidence.score:.0%} confidence**.\n\n"
                        f"**Reason:** {report.confidence.explanation}\n\n"
                        f"Please review the finding carefully before proceeding."
                    )
                    await self.post_pull_request_comment(
                        owner=owner,
                        repo=repo_name,
                        pr_number=pr_number,
                        report=TriageReport(
                            **{**report.model_dump(), "markdown_report": warning_body}
                        ),
                        token=token
                    )

            return {
                "status": "processed",
                "event_type": "dismissal_request_review",
                "alert_id": normalized.alert_id,
                "human_dismissal_reason": dismissed_reason,
                "ai_determination": report.determination.value,
                "confidence": report.confidence.score,
                "dismissal_validated": (report.determination == DeterminationType.FALSE_POSITIVE)
            }

        # =========================================================================
        # Case B: CodeQL Publishes New Scanning Alert (action: created / reopened)
        # =========================================================================
        elif action in ("created", "reopened_by_user", "appeared_in_branch", "reopened"):
            normalized = parse_github_alert_webhook(payload)
            if not normalized:
                return {"status": "ignored", "reason": f"Unhandled alert action: {action}"}

            report: TriageReport = await self.service.review_normalized_alert(normalized)

            # Publish Check Run on the commit (native GitHub App UI without YAML)
            if token and normalized.commit_sha:
                await self.create_check_run(owner, repo_name, normalized.commit_sha, report, token)

            # If associated with a PR, post PR comment
            if token:
                pr_num = await self.find_associated_pull_request(owner, repo_name, normalized.commit_sha, normalized.ref, token)
                if pr_num:
                    await self.post_pull_request_comment(owner, repo_name, pr_num, report, token)

            return {
                "status": "processed",
                "event_type": "new_alert_triage",
                "alert_id": normalized.alert_id,
                "determination": report.determination.value,
                "confidence": report.confidence.score,
                "report": report.model_dump()
            }

        else:
            logger.info(f"Ignoring code_scanning_alert action: {action}")
            return {"status": "ignored", "reason": f"Action {action} not processed"}
