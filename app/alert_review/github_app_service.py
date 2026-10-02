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

    async def post_or_update_pull_request_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        report: TriageReport,
        token: str
    ) -> Optional[int]:
        """
        Post or update a single consolidated review comment per finding on the PR.
        Searches for existing comment with marker `<!-- AI_CODEQL_ALERT_REVIEW:{alert_id} -->`.
        If found: updates in-place via PATCH.
        If not found: creates new comment via POST.
        Returns the comment ID.
        """
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        marker = f"<!-- AI_CODEQL_ALERT_REVIEW:{report.alert_id} -->"

        existing_comment_id = None
        list_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{pr_number}/comments"

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(list_url, headers=headers, params={"per_page": 100})
                if resp.status_code == 200:
                    comments = resp.json()
                    for c in comments:
                        body_text = c.get("body") or ""
                        if marker in body_text:
                            existing_comment_id = c.get("id")
                            break
        except Exception as e:
            logger.warning(f"Error checking existing comments on PR #{pr_number}: {e}")

        payload = {"body": report.markdown_report}

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                if existing_comment_id:
                    update_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/comments/{existing_comment_id}"
                    resp = await client.patch(update_url, headers=headers, json=payload)
                    if resp.status_code in (200, 201):
                        logger.info(f"Updated PR comment #{existing_comment_id} for {report.alert_id} in-place.")
                        report.pr_comment_id = existing_comment_id
                        return existing_comment_id
                else:
                    create_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{pr_number}/comments"
                    resp = await client.post(create_url, headers=headers, json=payload)
                    if resp.status_code in (200, 201):
                        cid = resp.json().get("id")
                        logger.info(f"Created new PR comment #{cid} for {report.alert_id}.")
                        report.pr_comment_id = cid
                        return cid
        except Exception as e:
            logger.error(f"Error creating/updating PR comment for #{pr_number}: {e}")

        return None

    async def post_pull_request_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        report: TriageReport,
        token: str
    ) -> bool:
        """Backwards compatible method posting or updating PR comment."""
        cid = await self.post_or_update_pull_request_comment(owner, repo, pr_number, report, token)
        return cid is not None

    async def execute_appsec_dismissal(
        self,
        owner: str,
        repo: str,
        alert_number: int,
        token: str,
        reason: str = "false positive",
        comment: str = "Dismissal approved by AppSec engineer"
    ) -> bool:
        """
        Execute alert dismissal on GitHub Code Scanning API on behalf of AppSec approval.
        """
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        payload = {
            "state": "dismissed",
            "dismissed_reason": reason,
            "dismissed_comment": comment[:280]
        }
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.patch(url, headers=headers, json=payload)
                if resp.status_code in (200, 201):
                    logger.info(f"Successfully dismissed GitHub alert {owner}/{repo}#{alert_number} via AppSec approval.")
                    return True
                else:
                    logger.warning(f"Failed to dismiss alert {owner}/{repo}#{alert_number} on GitHub API: {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.error(f"Error executing GitHub alert dismissal: {e}")
        return False

    async def execute_appsec_reopen(
        self,
        owner: str,
        repo: str,
        alert_number: int,
        token: str,
        comment: str = "Alert dismissal denied by AppSec engineer"
    ) -> bool:
        """
        Ensure alert remains or reopens on GitHub Code Scanning API when AppSec denies dismissal.
        """
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        payload = {
            "state": "open"
        }
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.patch(url, headers=headers, json=payload)
                if resp.status_code in (200, 201):
                    logger.info(f"Successfully marked GitHub alert {owner}/{repo}#{alert_number} as open.")
                    return True
                else:
                    logger.warning(f"GitHub alert {owner}/{repo}#{alert_number} status response: {resp.status_code}")
        except Exception as e:
            logger.error(f"Error reopening GitHub alert: {e}")
        return False

    async def apply_appsec_decision(
        self,
        owner: str,
        repo: str,
        alert_number: int,
        decision: str,
        reason: Optional[str] = None,
        reviewer: Optional[str] = "appsec_engineer",
        pr_number: Optional[int] = None,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        AppSec engineers hold exclusive dismissal authority.
        This method applies an AppSec engineer's final approval or denial:
        1. Updates GitHub Code Scanning alert state via GitHub API.
        2. Updates the consolidated PR comment in-place with the AppSec decision.
        3. Records human outcome in CalibrationStore for continuous model calibration.
        """
        target_alert_id = f"{owner}/{repo}#{alert_number}"
        report = self.service.calibration_store.get_report(target_alert_id)
        if not report:
            report = self.service.calibration_store.get_report(str(alert_number))

        is_approved = decision.strip().lower() in ("approve", "approved", "dismiss")
        reviewer_name = reviewer or "appsec_engineer"

        decision_text = f"APPROVED by @{reviewer_name}" if is_approved else f"DENIED by @{reviewer_name}"
        if reason:
            decision_text += f": {reason.strip()}"

        github_alert_updated = False
        pr_comment_updated = False

        # 1. Update GitHub Code Scanning Alert via API if token is provided
        if token:
            if is_approved:
                dismiss_reason = "false positive"
                if reason and ("wont" in reason.lower() or "won't" in reason.lower() or "risk" in reason.lower()):
                    dismiss_reason = "won't fix"
                github_alert_updated = await self.execute_appsec_dismissal(
                    owner=owner,
                    repo=repo,
                    alert_number=alert_number,
                    token=token,
                    reason=dismiss_reason,
                    comment=f"Approved by AppSec @{reviewer_name}: {reason or 'Dismissal approved'}"
                )
            else:
                github_alert_updated = await self.execute_appsec_reopen(
                    owner=owner,
                    repo=repo,
                    alert_number=alert_number,
                    token=token,
                    comment=f"Denied by AppSec @{reviewer_name}: {reason or 'Dismissal denied'}"
                )

        # 2. Update TriageReport if present
        if report:
            report.appsec_decision = decision_text
            # Update the AppSec Decision line in markdown_report
            if report.markdown_report:
                badge = "✅" if is_approved else "❌"
                new_line = f"> **AppSec Dismissal Decision:** {badge} `{decision_text}`  "
                if "> **AppSec Dismissal Decision:**" in report.markdown_report:
                    report.markdown_report = re.sub(
                        r"> \*\*AppSec Dismissal Decision:\*\* .*",
                        new_line,
                        report.markdown_report
                    )
                else:
                    report.markdown_report += f"\n\n{new_line}\n"

            await self.service.calibration_store.update_report(report)

            # 3. Update PR comment in-place if PR number and token available
            if pr_number and token:
                cid = await self.post_or_update_pull_request_comment(
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    report=report,
                    token=token
                )
                pr_comment_updated = cid is not None

        # 4. Record human outcome for calibration
        human_verdict = DeterminationType.FALSE_POSITIVE if is_approved else DeterminationType.TRUE_POSITIVE
        await self.service.record_human_outcome(
            alert_id=target_alert_id,
            repo=f"{owner}/{repo}",
            verdict=human_verdict,
            notes=f"AppSec Decision: {decision_text}",
            reviewer_id=reviewer_name
        )

        return {
            "status": "success",
            "alert_id": target_alert_id,
            "decision": "approved" if is_approved else "denied",
            "decision_text": decision_text,
            "github_alert_updated": github_alert_updated,
            "pr_comment_updated": pr_comment_updated,
            "report_found": report is not None
        }

    async def handle_appsec_command(
        self,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle `/appsec approve` or `/appsec deny` commands posted by AppSec engineers in PR comments.
        Syntax:
          /appsec approve [alert_id] [optional reason]
          /appsec deny [alert_id] [optional reason]
        """
        comment = payload.get("comment", {})
        body = comment.get("body", "").strip()
        author = comment.get("user", {}).get("login", "appsec_reviewer")

        issue = payload.get("issue") or payload.get("pull_request") or {}
        pr_number = issue.get("number")
        if not pr_number:
            return {"status": "ignored", "reason": "Not a pull request"}

        repo_data = payload.get("repository", {})
        repo_full = repo_data.get("full_name") or ""
        if "/" not in repo_full:
            return {"status": "ignored", "reason": "Invalid repository"}

        owner, repo_name = repo_full.split("/", 1)
        token = await self.get_token_for_payload(payload)

        # Parse command tokens: e.g. ["/appsec", "approve", "#42", "reason text..."]
        parts = body.split(None, 2)
        if len(parts) < 2:
            return {
                "status": "error",
                "reason": "Usage: /appsec approve [alert_number] [reason] OR /appsec deny [alert_number] [reason]"
            }

        subaction = parts[1].lower()
        if subaction not in ("approve", "approved", "deny", "denied", "reject"):
            return {
                "status": "error",
                "reason": f"Unknown AppSec action '{subaction}'. Must be 'approve' or 'deny'."
            }

        rest = parts[2].strip() if len(parts) > 2 else ""

        # Check if first word of rest is an alert number (e.g. #42, 42, alert-42)
        alert_number = None
        reason = rest
        if rest:
            m = re.match(r"^(?:#|alert-?)?(\d+)(?:\s+(.*))?$", rest, re.IGNORECASE)
            if m:
                alert_number = int(m.group(1))
                reason = m.group(2) or ""

        # If alert_number wasn't provided, find alert from existing PR comments
        if not alert_number and token:
            list_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/issues/{pr_number}/comments"
            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28"
            }
            try:
                async with httpx.AsyncClient(timeout=20.0) as client:
                    resp = await client.get(list_url, headers=headers, params={"per_page": 100})
                    if resp.status_code == 200:
                        for c in resp.json():
                            c_body = c.get("body") or ""
                            if "<!-- AI_CODEQL_ALERT_REVIEW:" in c_body:
                                m = re.search(r"<!-- AI_CODEQL_ALERT_REVIEW:(.*?) -->", c_body)
                                if m:
                                    aid = m.group(1)
                                    num_str = aid.split("#")[-1]
                                    if num_str.isdigit():
                                        alert_number = int(num_str)
                                        break
            except Exception as e:
                logger.warning(f"Error resolving alert number for PR #{pr_number}: {e}")

        if not alert_number:
            return {
                "status": "error",
                "reason": f"Could not determine target CodeQL alert for PR #{pr_number}. Please specify alert number: e.g. `/appsec {subaction} #42`"
            }

        # Apply AppSec Decision
        res = await self.apply_appsec_decision(
            owner=owner,
            repo=repo_name,
            alert_number=alert_number,
            decision=subaction,
            reason=reason,
            reviewer=author,
            pr_number=pr_number,
            token=token
        )

        # Post reply acknowledgment in PR thread
        if token and pr_number:
            badge = "✅ APPROVED" if "approve" in subaction else "❌ DENIED"
            ack_msg = (
                f"@{author} AppSec dismissal decision recorded: **{badge}** for Alert **#{alert_number}**.\n\n"
                f"- **Reviewer:** @{author}\n"
                f"- **Outcome:** `{res.get('decision_text')}`\n"
                f"- **GitHub Alert Status:** {'Updated via GitHub API' if res.get('github_alert_updated') else 'Recorded'}\n"
                f"- **PR Review Summary:** Updated in-place."
            )
            create_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/issues/{pr_number}/comments"
            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28"
            }
            try:
                async with httpx.AsyncClient(timeout=20.0) as client:
                    await client.post(create_url, headers=headers, json={"body": ack_msg})
            except Exception as e:
                logger.warning(f"Failed to post acknowledgment comment: {e}")

        return res

    async def handle_developer_comment(
        self,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle developer responses in PR comments to AI alert questions.
        Evaluates the developer's justification and triggers an AI reassessment,
        then updates the original bot comment in-place.
        """
        action = payload.get("action")
        if action != "created":
            return {"status": "ignored", "reason": "Not a created comment"}

        comment = payload.get("comment", {})
        body = comment.get("body", "")
        author = comment.get("user", {}).get("login", "")
        is_bot = comment.get("user", {}).get("type") == "Bot"

        if is_bot or not body.strip():
            return {"status": "ignored", "reason": "Ignoring bot or empty comment"}

        issue = payload.get("issue") or payload.get("pull_request") or {}
        pr_number = issue.get("number")
        if not pr_number:
            return {"status": "ignored", "reason": "Not a pull request comment"}

        repo_data = payload.get("repository", {})
        repo_full = repo_data.get("full_name") or ""
        if "/" not in repo_full:
            return {"status": "ignored", "reason": "Invalid repository"}

        owner, repo_name = repo_full.split("/", 1)
        token = await self.get_token_for_payload(payload)
        if not token:
            return {"status": "error", "reason": "No token available"}

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        # 1. Fetch comments on PR to identify which alert is being discussed
        list_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/issues/{pr_number}/comments"
        matching_bot_comment = None
        target_alert_id = None

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(list_url, headers=headers, params={"per_page": 100})
                if resp.status_code == 200:
                    comments = resp.json()
                    bot_comments = []
                    for c in comments:
                        c_body = c.get("body") or ""
                        if "<!-- AI_CODEQL_ALERT_REVIEW:" in c_body:
                            m = re.search(r"<!-- AI_CODEQL_ALERT_REVIEW:(.*?) -->", c_body)
                            if m:
                                bot_comments.append((m.group(1), c))

                    # If developer specifically mentioned an alert number like #42 or finding 42
                    for aid, c in bot_comments:
                        alert_num = aid.split("#")[-1]
                        if f"#{alert_num}" in body or f"alert {alert_num}" in body.lower() or f"finding {alert_num}" in body.lower():
                            matching_bot_comment = c
                            target_alert_id = aid
                            break

                    # If no explicit mention but there's only 1 alert review on the PR
                    if not target_alert_id and len(bot_comments) == 1:
                        target_alert_id, matching_bot_comment = bot_comments[0]
                    # Or if developer replied to the bot comment
                    elif not target_alert_id and bot_comments:
                        target_alert_id, matching_bot_comment = bot_comments[-1]
        except Exception as e:
            logger.error(f"Error matching alert for developer comment: {e}")

        if not target_alert_id:
            logger.info(f"No matching CodeQL alert review comment found on PR #{pr_number} for developer comment.")
            return {"status": "ignored", "reason": "No matching alert found on PR"}

        logger.info(f"Developer @{author} replied to Alert {target_alert_id}: {body[:80]}")

        # 2. Reassess finding using developer's reply
        try:
            cached_alert = self.service._normalized_alert_cache.get(target_alert_id)
            if not cached_alert:
                alert_num_str = target_alert_id.split("#")[-1]
                if alert_num_str.isdigit():
                    from .alert_collector import fetch_alert_from_github_api
                    cached_alert = await fetch_alert_from_github_api(owner, repo_name, int(alert_num_str), token)

            if not cached_alert:
                return {"status": "error", "reason": f"Could not find or fetch alert data for {target_alert_id}"}

            bot_cid = matching_bot_comment.get("id") if matching_bot_comment else None
            updated_report: TriageReport = await self.service.reassess_with_developer_response(
                alert_id=target_alert_id,
                developer_response=f"Developer @{author} says: {body}",
                pr_comment_id=bot_cid,
                cached_alert=cached_alert
            )

            # 3. Update the single bot comment in-place on the PR
            await self.post_or_update_pull_request_comment(
                owner=owner,
                repo=repo_name,
                pr_number=pr_number,
                report=updated_report,
                token=token
            )

            return {
                "status": "processed",
                "event_type": "developer_evidence_reassessment",
                "alert_id": target_alert_id,
                "determination": updated_report.determination.value,
                "recommendation": updated_report.recommendation.value,
                "confidence": updated_report.confidence.score
            }
        except Exception as e:
            logger.error(f"Failed to reassess alert {target_alert_id} on developer response: {e}")
            return {"status": "error", "reason": str(e)}

    async def handle_pull_request_synchronize(
        self,
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        When new commits are pushed to a PR, mark all active alert reviews as stale.
        This prevents AppSec from approving dismissals based on outdated code.
        """
        repo_data = payload.get("repository", {})
        repo_full = repo_data.get("full_name") or ""
        if "/" not in repo_full:
            return {"status": "ignored", "reason": "Missing repository"}

        owner, repo_name = repo_full.split("/", 1)
        pr_data = payload.get("pull_request", {})
        pr_number = pr_data.get("number")
        new_head_sha = pr_data.get("head", {}).get("sha") or payload.get("after") or "HEAD"

        token = await self.get_token_for_payload(payload)
        if not token or not pr_number:
            return {"status": "ignored", "reason": "No token or PR number"}

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        # Find existing alert review comments on PR
        list_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/issues/{pr_number}/comments"
        updated_count = 0
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(list_url, headers=headers, params={"per_page": 100})
                if resp.status_code == 200:
                    comments = resp.json()
                    for c in comments:
                        c_body = c.get("body") or ""
                        cid = c.get("id")
                        if "<!-- AI_CODEQL_ALERT_REVIEW:" in c_body and "STATUS: STALE ASSESSMENT" not in c_body:
                            stale_banner = (
                                f"\n\n> ⚠️ **STATUS: STALE ASSESSMENT (Commit Outdated)**: "
                                f"New commit `{new_head_sha[:8]}` was pushed. "
                                f"Previous evaluation invalidated. Waiting for updated CodeQL scan results...\n\n"
                            )
                            # Prepend stale notice
                            new_body = re.sub(
                                r"(<!-- AI_CODEQL_ALERT_REVIEW:.*? -->)",
                                r"\1" + stale_banner,
                                c_body
                            )
                            update_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/issues/comments/{cid}"
                            patch_resp = await client.patch(update_url, headers=headers, json={"body": new_body})
                            if patch_resp.status_code in (200, 201):
                                updated_count += 1
        except Exception as e:
            logger.warning(f"Error marking alert reviews as stale on PR #{pr_number}: {e}")

        return {
            "status": "processed",
            "event_type": "pull_request_synchronize_stale_invalidation",
            "pr_number": pr_number,
            "stale_comments_updated": updated_count
        }

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

    async def process_check_run_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle completed CodeQL Check Runs on PRs.
        When CodeQL runs on a pull request, GitHub executes a check run (e.g. 'Code scanning results / CodeQL').
        This method acts as a resilient trigger if GitHub's code_scanning_alert webhook is delayed or restricted to the default branch.
        """
        action = payload.get("action")
        if action != "completed":
            return {"status": "ignored", "reason": f"Check run action '{action}' not completed"}

        check_run = payload.get("check_run", {})
        check_name = check_run.get("name", "")

        # Ignore our own AI Alert Review check runs to prevent recursion
        if check_name.startswith("AI CodeQL Review:") or check_name.startswith("AI Alert Review:"):
            return {"status": "ignored", "reason": "Ignoring AI Alert Review self-check run"}

        # Only process CodeQL / Code scanning check runs
        if not ("code scanning" in check_name.lower() or "codeql" in check_name.lower()):
            return {"status": "ignored", "reason": f"Check run '{check_name}' is not a CodeQL scan"}

        repo_data = payload.get("repository", {})
        repo_full = repo_data.get("full_name") or ""
        if "/" not in repo_full:
            return {"status": "ignored", "reason": "Missing repository name"}

        owner, repo_name = repo_full.split("/", 1)
        commit_sha = check_run.get("head_sha")
        if not commit_sha:
            return {"status": "ignored", "reason": "Missing commit SHA in check_run"}

        token = await self.get_token_for_payload(payload)
        if not token:
            logger.warning(f"Could not get GitHub App token for {repo_full}")
            return {"status": "error", "reason": "Could not obtain GitHub App token"}

        self.service.context_builder.github_token = token
        self.service.github_token = token

        # Fetch code scanning alerts for this commit / PR
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        alerts_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/code-scanning/alerts"
        alerts = []
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(alerts_url, headers=headers, params={"commit_sha": commit_sha})
                if resp.status_code == 200:
                    alerts = resp.json()
        except Exception as e:
            logger.error(f"Error fetching code scanning alerts for {repo_full}@{commit_sha}: {e}")

        # If empty, try fetching by PR ref
        if not alerts:
            prs = check_run.get("pull_requests", [])
            for pr in prs:
                pr_num = pr.get("number")
                if pr_num:
                    try:
                        async with httpx.AsyncClient(timeout=20.0) as client:
                            resp = await client.get(alerts_url, headers=headers, params={"ref": f"refs/pull/{pr_num}/head"})
                            if resp.status_code == 200 and resp.json():
                                alerts.extend(resp.json())
                    except Exception as e:
                        logger.warning(f"Error fetching alerts for PR #{pr_num}: {e}")

        if not alerts:
            logger.info(f"No code scanning alerts returned by API for {repo_full}@{commit_sha}")
            return {"status": "processed", "alerts_reviewed": 0, "message": "No alerts found for commit"}

        reviewed_reports = []
        for alert_item in alerts:
            synthetic_payload = {
                "action": "created",
                "alert": alert_item,
                "repository": repo_data,
                "installation": payload.get("installation", {})
            }
            if "most_recent_instance" not in alert_item:
                alert_item["most_recent_instance"] = {
                    "commit_sha": commit_sha,
                    "location": {
                        "path": alert_item.get("rule", {}).get("description", "source.js"),
                        "start_line": 1
                    }
                }
            res = await self.process_webhook_event(synthetic_payload)
            reviewed_reports.append(res)

        return {
            "status": "processed",
            "event_type": "check_run_codeql_triage",
            "alerts_reviewed": len(reviewed_reports),
            "results": reviewed_reports
        }
