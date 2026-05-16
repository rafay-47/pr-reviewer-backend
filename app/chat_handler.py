"""
Chat handler for AI interactions in PR comments.

Handles slash commands like /aiappsec explain, fix, why, ask.
"""

import logging
from typing import Optional, Tuple

import httpx

from .database import get_findings_for_pr, get_finding_by_id

logger = logging.getLogger(__name__)

# Timeout for LLM calls
CHAT_TIMEOUT_SECONDS = 60


async def handle_chat_command(
    org_id: str,
    repo_name: str,
    pr_number: int,
    command: str,
    finding_number: Optional[int] = None,
    question: Optional[str] = None,
    llm_provider: str = "claude",
    api_key: str = "",
    model: str = "claude-sonnet-4-20250514",
) -> Tuple[str, Optional[str]]:
    """
    Handle a chat command and return the response.
    
    Args:
        org_id: Organization ID
        repo_name: Repository name (org/repo)
        pr_number: Pull request number
        command: Command type (explain, fix, why, ask)
        finding_number: 1-indexed finding number for explain/fix/why
        question: Question text for 'ask' command
        llm_provider: LLM provider
        api_key: API key
        model: Model name
        
    Returns:
        Tuple of (response_markdown, finding_title)
    """
    # Get findings for this PR
    findings = await get_findings_for_pr(org_id, repo_name, pr_number)
    
    if command in ["explain", "fix", "why"]:
        if not finding_number:
            return "Please specify a finding number. Example: `/aiappsec explain 1`", None
        
        if finding_number < 1 or finding_number > len(findings):
            return f"Finding #{finding_number} not found. This PR has {len(findings)} findings.", None
        
        finding = findings[finding_number - 1]
        
        if command == "explain":
            return await _explain_finding(finding, llm_provider, api_key, model)
        elif command == "fix":
            return await _suggest_fix(finding, llm_provider, api_key, model)
        elif command == "why":
            return await _explain_why(finding, llm_provider, api_key, model)
    
    elif command == "ask":
        if not question:
            return "Please provide a question. Example: `/aiappsec ask Is this SQL injection exploitable?`", None
        
        return await _answer_question(question, findings, repo_name, llm_provider, api_key, model)
    
    return f"Unknown command: {command}", None


async def _explain_finding(
    finding: dict,
    llm_provider: str,
    api_key: str,
    model: str
) -> Tuple[str, Optional[str]]:
    """Generate a deep explanation of a finding."""
    
    prompt = f"""You are a senior application security engineer explaining a security finding to a developer.

Finding Details:
- Title: {finding.get('title', 'Unknown')}
- Risk Level: {finding.get('risk', 'Unknown')}
- Confidence: {finding.get('confidence', 'Unknown')}
- File: {finding.get('file_path', 'Unknown')}:{finding.get('line_range', '')}
- Description: {finding.get('description', '')}
- Impact: {finding.get('impact', '')}
- Evidence: {finding.get('evidence', '')}
- CWE: {finding.get('cwe', '')}
- OWASP: {finding.get('owasp', '')}

Please provide a comprehensive explanation that includes:
1. **What is happening**: A clear explanation of the vulnerability
2. **Why it's dangerous**: Real-world attack scenarios
3. **How to verify**: Steps to confirm if this is exploitable
4. **Common misconceptions**: Address why developers might think this is safe
5. **Defense in depth**: Multiple layers of protection

Format your response in markdown suitable for a GitHub PR comment."""

    response = await _call_llm(prompt, llm_provider, api_key, model)
    
    title = finding.get('title', 'Unknown Finding')
    header = f"## Deep Dive: {title}\n\n"
    
    return header + response, title


async def _suggest_fix(
    finding: dict,
    llm_provider: str,
    api_key: str,
    model: str
) -> Tuple[str, Optional[str]]:
    """Generate a code fix suggestion for a finding."""
    
    prompt = f"""You are a senior application security engineer providing a code fix for a security finding.

Finding Details:
- Title: {finding.get('title', 'Unknown')}
- Risk Level: {finding.get('risk', 'Unknown')}
- File: {finding.get('file_path', 'Unknown')}:{finding.get('line_range', '')}
- Description: {finding.get('description', '')}
- Current Code (Evidence): 
```
{finding.get('evidence', 'No code provided')}
```
- Recommendation: {finding.get('recommendation', '')}
- Example Fix from Review: {finding.get('example_fix', 'Not provided')}

Please provide:
1. **The Fix**: The exact code changes needed (show before/after)
2. **Explanation**: Why this fix works
3. **Testing**: How to test that the fix is correct
4. **Edge Cases**: Any edge cases to consider

Format your response in markdown with proper code blocks suitable for a GitHub PR comment.
Use the appropriate language syntax highlighting for the code blocks."""

    response = await _call_llm(prompt, llm_provider, api_key, model)
    
    title = finding.get('title', 'Unknown Finding')
    header = f"## Suggested Fix: {title}\n\n"
    
    return header + response, title


async def _explain_why(
    finding: dict,
    llm_provider: str,
    api_key: str,
    model: str
) -> Tuple[str, Optional[str]]:
    """Explain why a finding matters and its business impact."""
    
    prompt = f"""You are a senior application security engineer explaining why a security finding matters to business stakeholders and developers.

Finding Details:
- Title: {finding.get('title', 'Unknown')}
- Risk Level: {finding.get('risk', 'Unknown')}
- Impact: {finding.get('impact', '')}
- CWE: {finding.get('cwe', '')}
- OWASP: {finding.get('owasp', '')}

Please explain:
1. **Business Impact**: How could this affect the business? (data breach, compliance, reputation)
2. **Real-World Examples**: Notable breaches caused by similar vulnerabilities
3. **Compliance**: Relevant regulations (GDPR, PCI-DSS, SOC2, etc.)
4. **Risk Quantification**: Help them understand the severity
5. **Priority**: Why this should be fixed now vs later

Make it compelling but not alarmist. Format in markdown for a GitHub PR comment."""

    response = await _call_llm(prompt, llm_provider, api_key, model)
    
    title = finding.get('title', 'Unknown Finding')
    header = f"## Why This Matters: {title}\n\n"
    
    return header + response, title


async def _answer_question(
    question: str,
    findings: list,
    repo_name: str,
    llm_provider: str,
    api_key: str,
    model: str
) -> Tuple[str, Optional[str]]:
    """Answer a general security question about the PR."""
    
    # Build context from findings
    findings_context = ""
    if findings:
        findings_context = "Current findings in this PR:\n"
        for i, f in enumerate(findings, 1):
            findings_context += f"\n{i}. [{f.get('risk', 'UNKNOWN')}] {f.get('title', 'Unknown')}\n"
            findings_context += f"   File: {f.get('file_path', 'Unknown')}\n"
            findings_context += f"   Description: {f.get('description', '')[:200]}...\n"
    else:
        findings_context = "No security findings in this PR.\n"
    
    prompt = f"""You are a senior application security engineer answering a question about a pull request.

Repository: {repo_name}

{findings_context}

Developer's Question:
{question}

Please provide a helpful, accurate answer. If the question relates to one of the findings, reference it by number.
If you're not sure about something, say so. Format your response in markdown for a GitHub PR comment."""

    response = await _call_llm(prompt, llm_provider, api_key, model)
    
    header = f"## Security Q&A\n\n**Question:** {question}\n\n**Answer:**\n\n"
    
    return header + response, None


async def _call_llm(
    prompt: str,
    llm_provider: str,
    api_key: str,
    model: str
) -> str:
    """Call the LLM and return the response text."""
    
    system_prompt = "You are a helpful senior application security engineer. Provide clear, actionable guidance."
    
    try:
        if llm_provider.lower() == "claude":
            return await _call_claude(system_prompt, prompt, api_key, model)
        elif llm_provider.lower() == "openai":
            return await _call_openai(system_prompt, prompt, api_key, model)
        elif llm_provider.lower() == "gemini":
            return await _call_gemini(system_prompt, prompt, api_key, model)
        elif llm_provider.lower() == "groq":
            return await _call_groq(system_prompt, prompt, api_key, model)
        else:
            return f"Unsupported LLM provider: {llm_provider}"
    except Exception as e:
        logger.error(f"LLM call failed: {type(e).__name__}: {e}")
        return f"Sorry, I encountered an error processing your request. Please try again."


async def _call_claude(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    """Call Claude API."""
    async with httpx.AsyncClient(timeout=CHAT_TIMEOUT_SECONDS) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 2048,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}]
            }
        )
        response.raise_for_status()
        data = response.json()
        content = data.get("content", [])
        return content[0].get("text", "") if content else ""


async def _call_openai(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    """Call OpenAI API."""
    async with httpx.AsyncClient(timeout=CHAT_TIMEOUT_SECONDS) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "max_tokens": 2048,
                "temperature": 0.3,
            }
        )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices", [])
        return choices[0].get("message", {}).get("content", "") if choices else ""


async def _call_gemini(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    """Call Gemini API."""
    async with httpx.AsyncClient(timeout=CHAT_TIMEOUT_SECONDS) as client:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        response = await client.post(
            url,
            headers={"Content-Type": "application/json"},
            params={"key": api_key},
            json={
                "contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}],
                "generationConfig": {"temperature": 0.3, "maxOutputTokens": 2048}
            }
        )
        response.raise_for_status()
        data = response.json()
        candidates = data.get("candidates", [])
        if candidates:
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            return parts[0].get("text", "") if parts else ""
        return ""


async def _call_groq(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    """Call Groq API."""
    async with httpx.AsyncClient(timeout=CHAT_TIMEOUT_SECONDS) as client:
        response = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "max_tokens": 2048,
                "temperature": 0.3,
            }
        )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices", [])
        return choices[0].get("message", {}).get("content", "") if choices else ""


def parse_slash_command(comment_body: str) -> Optional[dict]:
    """
    Parse a slash command from a PR comment.
    
    Examples:
        /aiappsec explain 1
        /aiappsec fix 2
        /aiappsec why 1
        /aiappsec ask Is this exploitable?
    
    Returns:
        Dict with 'command', 'finding_number', 'question' or None if not a command
    """
    if not comment_body.strip().startswith("/aiappsec"):
        return None
    
    parts = comment_body.strip().split(maxsplit=2)
    
    if len(parts) < 2:
        return {"command": "help", "finding_number": None, "question": None}
    
    command = parts[1].lower()
    
    if command in ["explain", "fix", "why"]:
        finding_number = None
        if len(parts) >= 3:
            try:
                finding_number = int(parts[2])
            except ValueError:
                pass
        return {"command": command, "finding_number": finding_number, "question": None}
    
    elif command == "ask":
        question = parts[2] if len(parts) >= 3 else None
        return {"command": "ask", "finding_number": None, "question": question}
    
    elif command == "help":
        return {"command": "help", "finding_number": None, "question": None}
    
    return None


def generate_help_message() -> str:
    """Generate help message for slash commands."""
    return """## AI Security Assistant Commands

Use these commands to interact with the AI security reviewer:

| Command | Description | Example |
|---------|-------------|---------|
| `/aiappsec explain <n>` | Get detailed explanation of finding #n | `/aiappsec explain 1` |
| `/aiappsec fix <n>` | Get suggested code fix for finding #n | `/aiappsec fix 1` |
| `/aiappsec why <n>` | Understand why finding #n matters | `/aiappsec why 1` |
| `/aiappsec ask <question>` | Ask any security question | `/aiappsec ask Is this SQL injection exploitable?` |
| `/aiappsec help` | Show this help message | `/aiappsec help` |

---
*AI AppSec PR Reviewer*"""
