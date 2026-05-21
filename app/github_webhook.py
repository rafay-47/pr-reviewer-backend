"""
GitHub App Webhook Handler.

Receives webhook events from GitHub App and automatically triggers PR reviews.
Supports:
- pull_request.opened
- pull_request.synchronize
- pull_request.reopened
- issue_comment commands (/review, /ignore, /help)
"""

import logging
import hmac
import hashlib
import re
from typing import Optional, Dict, Any, List
from datetime import datetime

import httpx
from fastapi import Request, HTTPException

from .config import Settings, get_settings
from .github_app_auth import get_installation_token, get_installation_for_repo
from .database import get_repo_config, get_supabase_client
from .models import RepoPolicy

logger = logging.getLogger(__name__)


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """
    Verify GitHub webhook signature.
    
    GitHub sends the signature in the X-Hub-Signature-256 header.
    It's computed as HMAC-SHA256 of the payload using the webhook secret.
    
    Args:
        payload: Raw request body bytes
        signature: Signature from X-Hub-Signature-256 header (format: "sha256=<hash>")
        secret: Webhook secret configured in GitHub App
        
    Returns:
        True if signature is valid, False otherwise
    """
    logger.debug(f"Verifying webhook signature, secret length: {len(secret) if secret else 0}")
    
    if not signature or not signature.startswith("sha256="):
        logger.warning(f"Invalid signature format: {signature[:20] if signature else 'None'}...")
        return False
    
    if not secret:
        logger.error("Webhook secret is empty or None")
        return False
    
    expected_mac = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    result = hmac.compare_digest(signature[7:], expected_mac)
    if not result:
        logger.warning(f"Signature mismatch. Got: {signature[7:20]}..., Expected: {expected_mac[:20]}...")
    
    return result


async def fetch_pr_diff_from_github(
    owner: str,
    repo: str,
    pr_number: int,
    installation_id: int,
    settings: Optional[Settings] = None
) -> str:
    """
    Fetch the diff for a pull request from GitHub API.
    
    Args:
        owner: Repository owner
        repo: Repository name
        pr_number: PR number
        installation_id: GitHub App installation ID
        settings: Application settings
        
    Returns:
        PR diff as text
        
    Raises:
        HTTPException: If unable to fetch diff
    """
    if settings is None:
        settings = get_settings()
    
    # Get installation token
    token, _ = await get_installation_token(installation_id, settings)
    
    async with httpx.AsyncClient() as client:
        # Fetch the PR diff
        response = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3.diff",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0
        )
        
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="Pull request not found")
        
        response.raise_for_status()
        
        # The response body is the diff when using v3.diff accept header
        return response.text


def extract_line_mapping_from_diff(diff_text: str) -> Dict[str, List[int]]:
    """
    Extract file -> list of new line numbers from a git diff.
    
    This is used to validate that line numbers from LLM actually exist in the diff.
    GitHub requires line numbers to be valid positions in the PR diff.
    
    Returns:
        Dict mapping file_path -> list of line numbers in the "new" version
    """
    line_mapping: Dict[str, List[int]] = {}
    current_file = None
    current_new_line = 0
    
    for line in diff_text.split('\n'):
        # Detect new file in diff
        file_match = re.match(r'diff --git a/(.+?) b/(.+)$', line)
        if file_match:
            current_file = file_match.group(2)
            if current_file not in line_mapping:
                line_mapping[current_file] = []
            current_new_line = 0
            continue
        
        # Detect hunk header @@ -X,Y +Z,W @@
        hunk_match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
        if hunk_match and current_file:
            current_new_line = int(hunk_match.group(1))
            continue
        
        # Track new lines (+, not +++)
        if line.startswith('+') and not line.startswith('+++'):
            if current_file:
                line_mapping[current_file].append(current_new_line)
            current_new_line += 1
        elif line.startswith('-') and not line.startswith('---'):
            # Deleted line - don't increment
            continue
        elif line and not line.startswith('\\'):
            # Context line
            current_new_line += 1
    
    return line_mapping


def find_closest_line(file_lines: List[int], target_line: int) -> Optional[int]:
    """Find the closest line number to the target in the file's new lines."""
    if not file_lines:
        return None
    
    # Exact match
    if target_line in file_lines:
        return target_line
    
    # Find closest
    closest = min(file_lines, key=lambda x: abs(x - target_line))
    
    # Only return if within 5 lines (to avoid wildly incorrect matches)
    if abs(closest - target_line) <= 5:
        return closest
    
    return None


async def post_pr_comment(
    owner: str,
    repo: str,
    pr_number: int,
    body: str,
    installation_id: int,
    settings: Optional[Settings] = None
) -> Dict[str, Any]:
    """
    Post a comment to a pull request.
    
    Args:
        owner: Repository owner
        repo: Repository name
        pr_number: PR number
        body: Comment body (markdown)
        installation_id: GitHub App installation ID
        settings: Application settings
        
    Returns:
        GitHub API response
    """
    if settings is None:
        settings = get_settings()
    
    # Get installation token
    token, _ = await get_installation_token(installation_id, settings)
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"body": body},
            timeout=30.0
        )
        
        response.raise_for_status()
        return response.json()


async def update_pr_merge_status(
    owner: str,
    repo: str,
    commit_sha: str,
    installation_id: int,
    state: str,
    description: str,
    settings: Optional[Settings] = None,
    context: str = "ai-appsec/high-vuln-gate",
    target_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Publish a commit status used by branch protection to gate PR merges.

    States: error, failure, pending, success.
    """
    if settings is None:
        settings = get_settings()

    if not commit_sha:
        raise ValueError("Missing commit_sha for status update")

    token, _ = await get_installation_token(installation_id, settings)
    payload: Dict[str, Any] = {
        "state": state,
        "description": description[:140],
        "context": context,
    }
    if target_url:
        payload["target_url"] = target_url

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/statuses/{commit_sha}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json=payload,
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()


async def post_inline_comment(
    owner: str,
    repo: str,
    pr_number: int,
    body: str,
    commit_id: str,
    path: str,
    line: int,
    side: str = "RIGHT",
    installation_id: int = None,
    settings: Optional[Settings] = None,
    suggestion: Optional[str] = None
) -> Dict[str, Any]:
    """
    Post an inline line-level comment to a pull request.
    
    Args:
        owner: Repository owner
        repo: Repository name
        pr_number: PR number
        body: Comment body (markdown)
        commit_id: The SHA of the commit to comment on
        path: The file path being commented on
        line: The line number to comment on
        side: "RIGHT" for new code, "LEFT" for deleted code
        installation_id: GitHub App installation ID
        settings: Application settings
        suggestion: Optional code suggestion block
        
    Returns:
        GitHub API response
    """
    if settings is None:
        settings = get_settings()
    
    # Get installation token
    token, _ = await get_installation_token(installation_id, settings)
    
    # Build comment body with optional suggestion
    comment_body = body
    if suggestion:
        comment_body += f"\n\n```suggestion:{path}\n{suggestion}\n```"
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={
                "body": comment_body,
                "commit_id": commit_id,
                "path": path,
                "line": line,
                "side": side
            },
            timeout=30.0
        )
        
        response.raise_for_status()
        return response.json()


async def get_pull_request_details(
    owner: str,
    repo: str,
    pr_number: int,
    installation_id: int,
    settings: Optional[Settings] = None
) -> Dict[str, Any]:
    """
    Get pull request details including commit SHA.
    
    Args:
        owner: Repository owner
        repo: Repository name
        pr_number: PR number
        installation_id: GitHub App installation ID
        settings: Application settings
        
    Returns:
        PR details including head SHA
    """
    if settings is None:
        settings = get_settings()
    
    token, _ = await get_installation_token(installation_id, settings)
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0
        )
        
        response.raise_for_status()
        return response.json()


async def post_inline_comments_for_findings(
    owner: str,
    repo: str,
    pr_number: int,
    findings: List[Dict[str, Any]],
    commit_id: str,
    installation_id: int,
    settings: Optional[Settings] = None
) -> List[Dict[str, Any]]:
    """
    Post inline line-level comments for all findings.
    
    Args:
        owner: Repository owner
        repo: Repository name
        pr_number: PR number
        findings: List of finding dicts with file_path, line_range, etc.
        commit_id: The SHA of the commit
        installation_id: GitHub App installation ID
        settings: Application settings
        
    Returns:
        List of GitHub API responses
    """
    results = []
    
    for finding in findings:
        file_path = finding.get("file_path", finding.get("file"))
        line_range = finding.get("line_range", "0")
        
        # Parse line number from line_range (e.g., "5-10" -> 5)
        try:
            if "-" in str(line_range):
                line = int(str(line_range).split("-")[0])
            elif "," in str(line_range):
                line = int(str(line_range).split(",")[0])
            else:
                line = int(line_range) if line_range else 1
        except (ValueError, TypeError):
            line = 1
        
        # Build comment body
        risk_label = str(finding.get("risk", "MEDIUM")).upper()
        fingerprint = finding.get("fingerprint", "")
        
        body = f"""**[{risk_label}] Security Finding: {finding.get('title', 'Issue')}**

{finding.get('description', '')}

**Impact:** {finding.get('impact', 'Unknown impact')}

**Recommendation:** {finding.get('recommendation', 'Fix the issue')}

---
*AI AppSec PR Reviewer* (fingerprint: `{fingerprint}`)

To dismiss: `/ignore {fingerprint}`"""
        
        # Get suggestion if available
        suggestion = finding.get("example_fix")
        
        try:
            result = await post_inline_comment(
                owner=owner,
                repo=repo,
                pr_number=pr_number,
                body=body,
                commit_id=commit_id,
                path=file_path,
                line=line,
                side="RIGHT",
                installation_id=installation_id,
                settings=settings,
                suggestion=suggestion
            )
            results.append(result)
            logger.info(f"Posted inline comment on {file_path}:{line}")
        except Exception as e:
            logger.error(f"Failed to post inline comment on {file_path}:{e}")
    
    return results


async def post_pr_review_with_suggestions(
    owner: str,
    repo: str,
    pr_number: int,
    findings: List[Dict[str, Any]],
    commit_sha: str,
    installation_id: int,
    settings: Optional[Settings] = None,
    enforcement_mode: str = "advisory",
    diff_text: str = "",
    summary: str = "",
    resolved_findings: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Post a PR review with inline comments and code suggestions.
    
    Uses GitHub's Pull Request Reviews API to group all findings together
    with optional code suggestions that can be committed in one click.
    
    Args:
        owner: Repository owner
        repo: Repository name
        pr_number: PR number
        findings: List of finding dicts with line info and suggested fixes
        commit_sha: The SHA of the commit to review
        installation_id: GitHub App installation ID
        settings: Application settings
        enforcement_mode: "enforce" or "advisory" - determines if REQUEST_CHANGES or COMMENT
        diff_text: The actual diff text to validate line numbers
        
    Returns:
        GitHub API response for the created review
    """
    if settings is None:
        settings = get_settings()
    
    resolved_findings = resolved_findings or []
    
    # Extract line mapping from diff to validate line numbers
    line_mapping = extract_line_mapping_from_diff(diff_text) if diff_text else {}
    logger.info(f"Extracted line mapping for {len(line_mapping)} files from diff")
    
    token, _ = await get_installation_token(installation_id, settings)
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    inline_comments = []
    summary_findings = []
    
    for finding in findings:
        file_path = finding.get("file_path", finding.get("file"))
        llm_line = finding.get("line_start") or finding.get("line")
        
        if not file_path:
            summary_findings.append(finding)
            continue
        
        # Validate and correct line number from diff
        line = None
        if llm_line:
            if line_mapping.get(file_path):
                file_lines = line_mapping[file_path]
                line = find_closest_line(file_lines, int(llm_line))
                if line:
                    logger.info(f"Validated line {line} for {file_path} (LLM suggested {llm_line})")
                else:
                    # Fall back to LLM's line number anyway
                    logger.warning(f"Could not find close line for {file_path}:{llm_line}, using LLM's line")
                    line = int(llm_line)
            else:
                # No line mapping for this file, use LLM's line
                line = int(llm_line)
        
        # If we still don't have a line, add to summary
        if not line:
            summary_findings.append(finding)
            continue
        
        body = _build_inline_comment_body(finding)
        
        comment = {
            "path": file_path,
            "line": int(line),
            "side": "RIGHT",
            "body": body
        }
        
        # Handle multi-line suggestions - validate end line too
        line_end = finding.get("line_end")
        if line_end and line_mapping.get(file_path):
            end_line = find_closest_line(line_mapping[file_path], int(line_end))
            if end_line and end_line != line:
                comment["start_line"] = int(line)
                comment["start_side"] = "RIGHT"
                comment["line"] = int(end_line)
        
        inline_comments.append(comment)
    
    # Determine review event type
    high_findings = [f for f in findings if str(f.get("risk", "")).upper() == "HIGH" or str(f.get("severity", "")).upper() == "HIGH"]
    if enforcement_mode == "enforce" and high_findings:
        event = "REQUEST_CHANGES"
    else:
        event = "COMMENT"
    
    # Build review body
    review_body = _build_pr_review_body(findings, summary_findings, resolved_findings, summary)
    
    # If no inline comments, just post a regular comment
    if not inline_comments:
        logger.info("No inline comments to post, using regular comment")
        await post_pr_comment(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            body=review_body,
            installation_id=installation_id,
            settings=settings
        )
        return {"id": "comment-only", "body": review_body}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
                headers=headers,
                json={
                    "commit_id": commit_sha,
                    "body": review_body,
                    "event": event,
                    "comments": inline_comments
                },
                timeout=60.0
            )
            
            if response.status_code == 422:
                # Fallback: post as separate comments if review API fails
                logger.warning(f"PR review API returned 422, falling back to individual comments: {response.text}")
                
                # Post inline comments one by one
                for comment in inline_comments:
                    try:
                        await client.post(
                            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments",
                            headers=headers,
                            json={
                                "commit_id": commit_sha,
                                "path": comment["path"],
                                "line": comment["line"],
                                "side": comment.get("side", "RIGHT"),
                                "body": comment["body"]
                            },
                            timeout=30.0
                        )
                    except Exception as e:
                        logger.error(f"Failed to post inline comment: {e}")
                
                # Also post summary as issue comment
                await post_pr_comment(
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    body=review_body,
                    installation_id=installation_id,
                    settings=settings
                )
                
                return {"id": "fallback-comments", "status": "posted as comments"}
            
            response.raise_for_status()
            result = response.json()
            logger.info(f"Posted PR review #{result.get('id')} to PR #{pr_number} with {len(inline_comments)} inline comments")
            return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to post PR review: {e.response.status_code} - {e.response.text}")
        # Fallback: post as regular comment
        await post_pr_comment(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            body=review_body,
            installation_id=installation_id,
            settings=settings
        )
        return {"id": "fallback", "status": "posted as comment", "error": str(e)}


def _build_inline_comment_body(finding: Dict[str, Any]) -> str:
    """Build an inline review comment for a specific line."""
    severity = finding.get("severity") or finding.get("risk") or "MEDIUM"
    severity_str = _normalize_severity(severity)
    title = finding.get("title", "Security Issue")

    file_path = finding.get("file_path", finding.get("file", "unknown"))
    line_start = finding.get("line_start") or finding.get("line", "")
    line_end = finding.get("line_end", "")
    line_range = f"{line_start}-{line_end}" if line_start and line_end else str(line_start) if line_start else ""
    is_new = finding.get("is_new", True)
    status_text = "New" if is_new else "Still present"

    lines = [
        f"**Severity: {severity_str}** — {title}",
        "",
    ]

    if file_path and file_path != "unknown":
        lines.append(f"**File:** `{file_path}` line {line_range} — {status_text}")
        lines.append("")

    description = finding.get("description") or finding.get("issue") or ""
    if description:
        lines.append(description)
        lines.append("")

    impact = finding.get("impact") or finding.get("impact_description")
    if impact:
        lines.append(f"**Impact:** {impact}")
        lines.append("")

    recommendation = finding.get("recommendation")
    if recommendation:
        lines.append(f"**Fix:** {recommendation}")
        lines.append("")

    evidence = finding.get("evidence") or finding.get("code_snippet")
    if evidence:
        lines.append("```")
        lines.append(evidence)
        lines.append("```")
        lines.append("")

    example_fix = finding.get("example_fix") or finding.get("suggested_fix")
    if example_fix:
        lines.append("```")
        lines.append(example_fix)
        lines.append("```")
        lines.append("")

    refs = []
    if finding.get("cwe"):
        refs.append(f"CWE-{finding['cwe']}")
    if finding.get("owasp"):
        refs.append(f"OWASP: {finding['owasp']}")
    if refs:
        lines.append(f"**Refs:** {' | '.join(refs)}")
        lines.append("")

    confidence = finding.get("confidence")
    if confidence:
        confidence_str = _normalize_confidence(confidence)
        lines.append(f"**Confidence:** {confidence_str}")
        lines.append("")

    fingerprint = finding.get("fingerprint")
    if fingerprint:
        lines.append(f"*Dismiss: `/ignore {fingerprint}`*")

    return "\n".join(lines)


def _normalize_severity(value) -> str:
    """Normalize severity/risk value to string."""
    if hasattr(value, 'value'):  # Enum
        return str(value.value).upper()
    return str(value).upper().split(".")[-1]  # Handle "RISKLEVEL.MEDIUM"


def _normalize_confidence(value) -> str:
    """Normalize confidence value to readable string."""
    if hasattr(value, 'value'):  # Enum
        return str(value.value).upper()
    return str(value).upper().split(".")[-1]  # Handle "CONFIDENCELEVEL.HIGH"


def _build_pr_review_body(
    all_findings: List[Dict],
    summary_findings: List[Dict],
    resolved_findings: List[Dict] = None,
    summary: str = ""
) -> str:
    """Build the PR review summary comment."""
    resolved_findings = resolved_findings or []

    high = [f for f in all_findings if _normalize_severity(f.get("severity", f.get("risk", ""))) == "HIGH"]
    med = [f for f in all_findings if _normalize_severity(f.get("severity", f.get("risk", ""))) == "MEDIUM"]
    low = [f for f in all_findings if _normalize_severity(f.get("severity", f.get("risk", ""))) == "LOW"]

    lines = [
        "## Security Review",
        "",
    ]

    if summary:
        lines.append(summary)
        lines.append("")

    if resolved_findings:
        lines.append(f"**{len(resolved_findings)} previous finding(s) resolved in this PR.**")
        lines.append("")
        for rf in resolved_findings:
            risk_label = _normalize_severity(rf.get("risk", ""))
            title = rf.get("title", "Unknown issue")
            file_path = rf.get("file_path", rf.get("file", "unknown"))
            line_range = rf.get("line_range", "")
            location = f"{file_path}:{line_range}" if line_range else file_path
            lines.append(f"- ~~[{risk_label}] {title}~~ — `{location}`")
        lines.append("")
        lines.append("---")
        lines.append("")

    if all_findings:
        lines.append(f"**{len(all_findings)} finding(s):** {len(high)} high, {len(med)} medium, {len(low)} low")
        lines.append("")

        for f in all_findings:
            risk_str = _normalize_severity(f.get("severity", f.get("risk", "")))
            title = f.get("title", "Security Issue")
            file_path = f.get("file_path", f.get("file", "unknown"))
            line_start = f.get("line_start") or f.get("line", "")
            line_end = f.get("line_end", "")
            line_range = f"{line_start}-{line_end}" if line_start and line_end else str(line_start) if line_start else ""
            location = f"{file_path}:{line_range}" if line_range else file_path
            is_new = f.get("is_new", True)
            status_text = "New" if is_new else "Still present"

            lines.append(f"- **[{risk_str}]** {title} — `{location}` — {status_text}")

        lines.append("")

    if summary_findings:
        lines.append("**Additional findings (no line location):**")
        lines.append("")
        for f in summary_findings:
            file_path = f.get("file_path", f.get("file", "unknown"))
            lines.append(f"- **{f.get('title', 'Issue')}** — `{file_path}`")
        lines.append("")

    if not all_findings and not summary_findings and not resolved_findings:
        lines.append("No security issues found in this change set.")
        lines.append("")

    lines.append("---")
    lines.append("*AppSec PR Reviewer — validate findings before applying changes.*")

    return "\n".join(lines)


async def post_pr_approval(
    owner: str,
    repo: str,
    pr_number: int,
    commit_sha: str,
    installation_id: int,
    settings: Optional[Settings] = None
) -> Dict[str, Any]:
    """
    Post an approving review for a clean PR (no security issues).
    
    Args:
        owner: Repository owner
        repo: Repository name
        pr_number: PR number
        commit_sha: The SHA of the commit
        installation_id: GitHub App installation ID
        settings: Application settings
        
    Returns:
        GitHub API response
    """
    if settings is None:
        settings = get_settings()
    
    token, _ = await get_installation_token(installation_id, settings)
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    review_body = """## Security Review Complete

No security vulnerabilities found in this PR.

---
*AI AppSec PR Reviewer*"""
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
            headers=headers,
            json={
                "commit_id": commit_sha,
                "body": review_body,
                "event": "APPROVE"
            },
            timeout=30.0
        )
        
        response.raise_for_status()
        return response.json()


async def resolve_org_from_installation(installation_id: int) -> Optional[str]:
    """
    Find organization ID from GitHub App installation ID.
    
    This queries the database to find which organization has this installation.
    
    Args:
        installation_id: GitHub App installation ID
        
    Returns:
        Organization ID or None if not found
    """
    try:
        client = get_supabase_client()
        result = client.table("github_app_installations").select("org_id").eq(
            "installation_id", installation_id
        ).maybe_single().execute()
        
        if result and result.data:
            return result.data.get("org_id")
        
        logger.warning(f"No organization found for installation {installation_id}")
        return None
        
    except Exception as e:
        logger.error(f"Failed to resolve org from installation {installation_id}: {e}")
        return None


def detect_language(repo_name: str) -> str:
    """
    Detect programming language from repository name or fetch from GitHub.
    
    For now, returns a default. Could be enhanced to check repo languages.
    
    Args:
        repo_name: Full repository name (owner/repo)
        
    Returns:
        Language string for LLM
    """
    # Simple detection based on common patterns
    # This could be enhanced by fetching languages from GitHub API
    repo_lower = repo_name.lower()
    
    if any(ext in repo_lower for ext in ["node", "express", "react", "vue", "angular"]):
        return "nodejs"
    elif any(ext in repo_lower for ext in ["django", "flask", "fastapi", "python"]):
        return "python"
    elif any(ext in repo_lower for ext in ["go", "golang"]):
        return "go"
    elif any(ext in repo_lower for ext in ["ruby", "rails"]):
        return "ruby"
    elif any(ext in repo_lower for ext in ["java", "spring"]):
        return "java"
    elif any(ext in repo_lower for ext in ["php", "laravel"]):
        return "php"
    
    return "nodejs"  # Default


async def get_repo_policy_from_db(org_id: str, repo_name: str) -> Optional[RepoPolicy]:
    """
    Get repository policy from database.
    
    Args:
        org_id: Organization ID
        repo_name: Repository name
        
    Returns:
        RepoPolicy or None
    """
    try:
        config = await get_repo_config(org_id, repo_name)
        if config and config.get("policy"):
            return RepoPolicy(**config["policy"])
        return None
    except Exception as e:
        logger.warning(f"Failed to get policy for {repo_name}: {e}")
        return None


async def record_webhook_event(
    event_type: str,
    action: str,
    repo_name: str,
    pr_number: int,
    org_id: Optional[str],
    installation_id: int,
    status: str,
    error_message: Optional[str] = None,
    review_id: Optional[str] = None
) -> None:
    """
    Record webhook event in database for logging/debugging.
    
    Args:
        event_type: Type of event (e.g., "pull_request")
        action: Action (e.g., "opened", "synchronize")
        repo_name: Repository name
        pr_number: PR number
        org_id: Organization ID
        installation_id: GitHub App installation ID
        status: Processing status ("received", "processing", "completed", "error")
        error_message: Error message if status is "error"
        review_id: Review ID if review was created
    """
    try:
        client = get_supabase_client()
        client.table("github_webhook_events").insert({
            "event_type": event_type,
            "action": action,
            "repo_name": repo_name,
            "pr_number": pr_number,
            "org_id": org_id,
            "installation_id": installation_id,
            "status": status,
            "error_message": error_message,
            "review_id": review_id,
            "created_at": datetime.utcnow().isoformat(),
        }).execute()
    except Exception as e:
        logger.error(f"Failed to record webhook event: {e}")


async def process_pull_request_webhook(
    payload: Dict[str, Any],
    settings: Settings
) -> Dict[str, Any]:
    """
    Process a pull_request webhook event.
    
    This is the main logic that:
    1. Extracts PR information
    2. Fetches the diff
    3. Loads repository policy
    4. Triggers security review
    5. Posts findings to GitHub
    
    Args:
        payload: Webhook payload
        settings: Application settings
        
    Returns:
        Processing result
    """
    # Extract repository info
    repository = payload.get("repository", {})
    repo_full_name = repository.get("full_name")
    
    if not repo_full_name:
        raise ValueError("Missing repository information in webhook payload")
    
    # Extract PR info
    pr_data = payload.get("pull_request", {})
    pr_number = pr_data.get("number")
    pr_title = pr_data.get("title")
    pr_author = pr_data.get("user", {}).get("login")
    pr_head_sha = pr_data.get("head", {}).get("sha")
    
    if not pr_number:
        raise ValueError("Missing PR number in webhook payload")
    
    # Extract installation ID
    installation = payload.get("installation", {})
    installation_id = installation.get("id")
    
    if not installation_id:
        raise ValueError("Missing installation ID in webhook payload")
    
    # Resolve organization from installation
    org_id = await resolve_org_from_installation(installation_id)
    
    if not org_id:
        logger.warning(f"Could not resolve organization for installation {installation_id}")
        return {
            "status": "skipped",
            "reason": "Organization not found for this installation",
            "repo": repo_full_name,
            "pr_number": pr_number
        }
    
    # Record event received
    await record_webhook_event(
        event_type="pull_request",
        action=payload.get("action", "unknown"),
        repo_name=repo_full_name,
        pr_number=pr_number,
        org_id=org_id,
        installation_id=installation_id,
        status="processing"
    )
    
    # If a repo config exists and is explicitly disabled, skip review.
    # Otherwise allow reviews for all repos under the installation.
    try:
        repo_config = await get_repo_config(org_id, repo_full_name)
        if repo_config and not repo_config.get("enabled", True):
            logger.info(f"Repository {repo_full_name} is disabled, skipping review")
            return {
                "status": "skipped",
                "reason": "Repository is disabled",
                "repo": repo_full_name,
                "pr_number": pr_number
            }
    except Exception as e:
        logger.error(f"Failed to check repo config: {e}")
        # Continue anyway, will use defaults
    
    # Parse owner/repo
    parts = repo_full_name.split("/")
    if len(parts) != 2:
        raise ValueError(f"Invalid repository name format: {repo_full_name}")
    owner, repo = parts

    # Mark check as pending as soon as we start processing.
    if pr_head_sha:
        try:
            await update_pr_merge_status(
                owner=owner,
                repo=repo,
                commit_sha=pr_head_sha,
                installation_id=installation_id,
                state="pending",
                description="AI AppSec security review in progress",
                settings=settings,
            )
        except Exception as e:
            logger.warning(f"Failed to publish pending merge-gate status: {e}")
    
    # Fetch PR diff
    try:
        diff = await fetch_pr_diff_from_github(
            owner, repo, pr_number, installation_id, settings
        )
    except Exception as e:
        logger.error(f"Failed to fetch PR diff: {e}")
        await record_webhook_event(
            event_type="pull_request",
            action=payload.get("action", "unknown"),
            repo_name=repo_full_name,
            pr_number=pr_number,
            org_id=org_id,
            installation_id=installation_id,
            status="error",
            error_message=f"Failed to fetch diff: {str(e)}"
        )
        raise
    
    # Get repository policy
    policy = await get_repo_policy_from_db(org_id, repo_full_name)
    
    # Detect language
    language = detect_language(repo_full_name)
    
    # Import review service here to avoid circular imports
    from .review_service import ReviewService, ReviewContext
    from .tenants import TenantContext
    
    # Create review context
    context = ReviewContext(
        org_id=org_id,
        org_name=None,  # Will be resolved by service
        repo=repo_full_name,
        pr_number=pr_number,
        diff=diff,
        language=language,
        framework="express",  # Default, could be enhanced
        policy=policy,
        pr_title=pr_title,
        pr_author=pr_author
    )
    
    # Create tenant context for database persistence
    tenant = TenantContext(
        org_id=org_id,
        org_name=None,
        user_id=None,  # Webhook doesn't have a user context
        token_scopes=["admin:policy", "read:metrics", "write:findings"]  # Grant necessary scopes
    )
    
    # Perform review with tenant context for persistence
    service = ReviewService(settings)
    result = await service.review_pr(context, tenant)

    # Publish a required status check result for branch protection.
    if pr_head_sha:
        try:
            should_block = bool(result.response.should_block) if (result.success and result.response) else False
            high_count = 0
            if result.response and result.response.findings:
                high_count = sum(
                    1
                    for finding in result.response.findings
                    if _normalize_severity(getattr(finding, "risk", "")) == "HIGH"
                )

            if not result.success:
                await update_pr_merge_status(
                    owner=owner,
                    repo=repo,
                    commit_sha=pr_head_sha,
                    installation_id=installation_id,
                    state="error",
                    description="AI AppSec review failed",
                    settings=settings,
                )
            # Temporary hard gate: always fail merge when HIGH findings exist,
            # regardless of repository policy mode.
            elif high_count > 0:
                await update_pr_merge_status(
                    owner=owner,
                    repo=repo,
                    commit_sha=pr_head_sha,
                    installation_id=installation_id,
                    state="failure",
                    description=f"Blocked: {high_count} HIGH vulnerability findings",
                    settings=settings,
                )
            else:
                await update_pr_merge_status(
                    owner=owner,
                    repo=repo,
                    commit_sha=pr_head_sha,
                    installation_id=installation_id,
                    state="success",
                    description="No HIGH vulnerabilities found",
                    settings=settings,
                )
        except Exception as e:
            logger.warning(f"Failed to publish final merge-gate status: {e}")
    
    # Post review to GitHub if successful
    if result.should_post_comment:
        try:
            # Get PR details including commit SHA for inline comments
            pr_details = await get_pull_request_details(
                owner=owner,
                repo=repo,
                pr_number=pr_number,
                installation_id=installation_id,
                settings=settings
            )
            commit_sha = pr_details.get("head", {}).get("sha")
            
            findings_list = []
            if result.response.findings:
                findings_list = [f.model_dump() for f in result.response.findings]
            
            # Determine enforcement mode from policy
            enforcement_mode = "advisory"
            if policy and hasattr(policy, 'mode'):
                enforcement_mode = str(policy.mode.value) if hasattr(policy.mode, 'value') else str(policy.mode)
            
            # Post PR review with inline comments and suggestions
            if findings_list and commit_sha:
                # Get summary and resolved findings from result
                review_summary = ""
                resolved_findings_list = []
                if result.response:
                    review_summary = result.response.summary or ""
                    resolved_findings_list = result.response.resolved_findings or []
                
                review_result = await post_pr_review_with_suggestions(
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    findings=findings_list,
                    commit_sha=commit_sha,
                    installation_id=installation_id,
                    settings=settings,
                    enforcement_mode=enforcement_mode,
                    diff_text=diff,
                    summary=review_summary,
                    resolved_findings=resolved_findings_list
                )
                logger.info(f"Posted PR review to PR #{pr_number} with {len(findings_list)} findings")
            elif commit_sha:
                # No findings - post an approving review
                await post_pr_approval(
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    installation_id=installation_id,
                    settings=settings
                )
                logger.info(f"Posted approval to clean PR #{pr_number}")
            else:
                logger.warning(f"No commit SHA found for PR #{pr_number}")
                
        except Exception as e:
            logger.error(f"Failed to post PR review: {e}")
            # Don't fail the webhook if posting fails
    
    # Record completion
    await record_webhook_event(
        event_type="pull_request",
        action=payload.get("action", "unknown"),
        repo_name=repo_full_name,
        pr_number=pr_number,
        org_id=org_id,
        installation_id=installation_id,
        status="completed" if result.success else "error",
        error_message=result.error_message if not result.success else None,
        review_id=result.review_id
    )
    
    return {
        "status": "success" if result.success else "error",
        "repo": repo_full_name,
        "pr_number": pr_number,
        "review_id": result.review_id,
        "findings_count": len(result.response.findings) if result.response.findings else 0,
        "should_block": result.response.should_block if result.success else False
    }


# ============================================================================
# Installation Event Handlers
# ============================================================================

async def process_installation_created(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle installation.created webhook event.
    
    This is called when a user installs the GitHub App on their account or organization.
    We need to wait for them to link it to their organization via the API.
    
    Args:
        payload: Webhook payload
        
    Returns:
        Processing result
    """
    installation = payload.get("installation", {})
    installation_id = installation.get("id")
    account = installation.get("account", {})
    
    if not installation_id:
        raise ValueError("Missing installation ID in payload")
    
    logger.info(
        f"GitHub App installed: installation_id={installation_id}, "
        f"account={account.get('login')} ({account.get('type')})"
    )
    
    # We don't link to org here - the user must do that via API
    # Just log that we received the installation
    return {
        "status": "logged",
        "installation_id": installation_id,
        "account": account.get("login"),
        "message": "Installation recorded. Awaiting organization link."
    }


async def process_installation_deleted(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle installation.deleted webhook event.
    
    This is called when a user uninstalls the GitHub App.
    We should clean up the installation record.
    
    Args:
        payload: Webhook payload
        
    Returns:
        Processing result
    """
    installation = payload.get("installation", {})
    installation_id = installation.get("id")
    
    if not installation_id:
        raise ValueError("Missing installation ID in payload")
    
    # Try to find and deactivate the installation
    try:
        client = get_supabase_client()
        result = client.table("github_app_installations").update({
            "is_active": False,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("installation_id", installation_id).execute()
        
        if result.data:
            logger.info(f"Deactivated GitHub App installation {installation_id}")
        else:
            logger.warning(f"Installation {installation_id} not found for deactivation")
            
    except Exception as e:
        logger.error(f"Failed to deactivate installation {installation_id}: {e}")
    
    return {
        "status": "deactivated",
        "installation_id": installation_id,
        "message": "Installation deactivated"
    }


async def process_installation_suspend(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle installation.suspend webhook event.
    
    This is called when GitHub suspends the App installation.
    
    Args:
        payload: Webhook payload
        
    Returns:
        Processing result
    """
    installation = payload.get("installation", {})
    installation_id = installation.get("id")
    sender = payload.get("sender", {})
    
    if not installation_id:
        raise ValueError("Missing installation ID in payload")
    
    try:
        client = get_supabase_client()
        result = client.table("github_app_installations").update({
            "is_active": False,
            "suspended_at": datetime.utcnow().isoformat(),
            "suspended_by": sender.get("login", "github"),
            "updated_at": datetime.utcnow().isoformat()
        }).eq("installation_id", installation_id).execute()
        
        if result.data:
            logger.info(f"Suspended GitHub App installation {installation_id}")
        else:
            logger.warning(f"Installation {installation_id} not found for suspension")
            
    except Exception as e:
        logger.error(f"Failed to suspend installation {installation_id}: {e}")
    
    return {
        "status": "suspended",
        "installation_id": installation_id,
        "suspended_by": sender.get("login", "github"),
        "message": "Installation suspended"
    }


async def store_github_app_installation(
    org_id: str,
    installation_id: int,
    account_login: str,
    account_type: str,
    account_id: int,
    repository_selection: str = "all",
    permissions: Optional[Dict] = None,
    events: Optional[List] = None
) -> Dict[str, Any]:
    """
    Store or update GitHub App installation information.
    
    This is called via API when a user links their GitHub App installation
    to their organization.
    
    Args:
        org_id: Organization ID
        installation_id: GitHub App installation ID
        account_login: GitHub account login (user or org name)
        account_type: 'User' or 'Organization'
        account_id: GitHub account ID
        repository_selection: 'all' or 'selected'
        permissions: Granted permissions dict
        events: Subscribed events list
        
    Returns:
        Stored installation record
    """
    try:
        client = get_supabase_client()
        
        # Use the upsert function from migration
        result = client.rpc(
            "upsert_github_app_installation",
            {
                "p_org_id": org_id,
                "p_installation_id": installation_id,
                "p_account_login": account_login,
                "p_account_type": account_type,
                "p_account_id": account_id,
                "p_repository_selection": repository_selection,
                "p_permissions": permissions or {},
                "p_events": events or []
            }
        ).execute()
        
        logger.info(
            f"Linked GitHub App installation {installation_id} to organization {org_id}"
        )
        
        return {
            "success": True,
            "installation_id": installation_id,
            "org_id": org_id,
            "account_login": account_login,
            "message": "Installation linked successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to store installation {installation_id}: {e}")
        raise


async def get_installation_for_org(org_id: str) -> Optional[Dict[str, Any]]:
    """
    Get GitHub App installation for an organization.
    
    Args:
        org_id: Organization ID
        
    Returns:
        Installation record or None
    """
    try:
        client = get_supabase_client()
        result = client.table("github_app_installations").select("*").eq(
            "org_id", org_id
        ).eq("is_active", True).maybe_single().execute()
        
        return result.data if result.data else None
        
    except Exception as e:
        logger.error(f"Failed to get installation for org {org_id}: {e}")
        return None


