"""
LLM Client for security analysis.

Provides integration with Claude (Anthropic), OpenAI, Google Gemini, and Groq APIs
to perform AI-powered security reviews of code changes.

Features:
- Diff pre-processing with ignore patterns
- Chunking for Groq's smaller context window
- Parallel analysis + synthesis pass
- Retry + fallback for rate limits
"""

import asyncio
import json
import logging
import os
import re
from typing import Optional, List, Dict, Any

import httpx

from .models import ReviewResponse, SecurityFinding, RiskLevel, ConfidenceLevel, RepoPolicy, PolicyMode
from .diff_parser import ParsedDiff, parse_diff, build_review_context
from .security_rules import build_security_hints

logger = logging.getLogger(__name__)

# LLM configuration
LLM_TIMEOUT_SECONDS = 45  # Timeout for LLM API calls
LLM_MAX_RETRIES = 3  # Number of retries for transient errors
LLM_RETRY_DELAY_SECONDS = 2  # Base delay between retries (exponential backoff)

# Token limits per provider
GROQ_TOKEN_LIMIT = 6000  # Conservative for llama-3.3-70b
CLAUDE_TOKEN_LIMIT = 150000
OPENAI_TOKEN_LIMIT = 120000
GEMINI_TOKEN_LIMIT = 100000

# Ignore patterns for files to skip during analysis
IGNORE_PATTERNS = [
    r"package-lock\.json",
    r"yarn\.lock",
    r"poetry\.lock",
    r"\.min\.(js|css)$",
    r"^dist/",
    r"^build/",
    r"migrations/.*\.sql$",
    r"__snapshots__/",
    r"\.generated\.",
    r"vendor/",
    r"node_modules/",
    r"\.git/",
    r"\.(png|jpg|jpeg|gif|svg|ico)$",
    r"\.lock$",
    r"\.sum$",
    r"go\.mod",
    r"go\.sum",
    r"Cargo\.lock",
    r"requirements\.txt",
]


def filter_diff_files(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter and prioritize files in a diff for security analysis.
    
    Args:
        files: List of file dicts with 'filename', 'patch', 'status', etc.
        
    Returns:
        Filtered and prioritized list of files
    """
    filtered = []
    for f in files:
        filename = f.get("filename", "")
        
        # Skip if matches ignore patterns
        if any(re.search(p, filename) for p in IGNORE_PATTERNS):
            logger.info(f"Skipping ignored file: {filename}")
            continue
            
        # Skip files with no changes
        patch = f.get("patch", "")
        if not patch or len(patch.strip()) == 0:
            continue
            
        filtered.append(f)
    
    # Prioritize high-risk files first
    def priority(f: Dict) -> int:
        filename = f.get("filename", "")
        patch_size = len(f.get("patch", ""))
        
        # Highest priority: auth, payment, crypto, secrets related
        if any(k in filename.lower() for k in ["auth", "login", "payment", "crypto", "secret", "password", "token", "session"]):
            return 3
        # High priority: large changes
        if patch_size > 2000:
            return 2
        # Medium priority: medium changes  
        if patch_size > 500:
            return 1
        return 0
    
    return sorted(filtered, key=priority, reverse=True)


def chunk_diff_files(files: List[Dict[str, Any]], max_tokens: int = GROQ_TOKEN_LIMIT) -> List[List[Dict[str, Any]]]:
    """
    Chunk files into groups that fit within token limit.
    
    Args:
        files: List of filtered file dicts
        max_tokens: Maximum tokens per chunk (default: Groq limit)
        
    Returns:
        List of file chunks
    """
    chunks = []
    current_chunk = []
    current_tokens = 0
    
    for f in files:
        patch = f.get("patch", "")
        # Rough token estimate: ~4 chars per token
        file_tokens = len(patch) // 4
        
        # If file is huge on its own, truncate it
        if file_tokens > max_tokens * 0.8:
            f = dict(f)
            f["patch"] = patch[:int(max_tokens * 0.8 * 4)] + "\n... [truncated - file too large]"
            file_tokens = int(max_tokens * 0.8)
            logger.warning(f"Truncated large file: {f.get('filename')}")
        
        # Check if adding this file would exceed limit
        if current_tokens + file_tokens > max_tokens:
            if current_chunk:
                chunks.append(current_chunk)
            current_chunk = [f]
            current_tokens = file_tokens
        else:
            current_chunk.append(f)
            current_tokens += file_tokens
    
    # Add final chunk
    if current_chunk:
        chunks.append(current_chunk)
    
    logger.info(f"Chunked {len(files)} files into {len(chunks)} chunks")
    return chunks


def _build_chunk_diff_text(files: List[Dict[str, Any]]) -> str:
    """Build diff text from a chunk of files."""
    parts = []
    for f in files:
        filename = f.get("filename", "unknown")
        patch = f.get("patch", "")
        status = f.get("status", "modified")
        parts.append(f"### {filename} ({status})\n```diff\n{patch}\n```")
    return "\n\n".join(parts)


class LLMError(Exception):
    """Exception raised for LLM-related errors."""
    
    def __init__(self, message: str, error_type: str, is_retryable: bool = False):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.is_retryable = is_retryable


def _is_retryable_status(status_code: int) -> bool:
    """Check if HTTP status code should trigger a retry."""
    return status_code == 429 or status_code >= 500


async def _retry_with_backoff(
    func,
    max_retries: int = LLM_MAX_RETRIES,
    base_delay: float = LLM_RETRY_DELAY_SECONDS
) -> str:
    """
    Retry an async function with exponential backoff.
    
    Retries on 429 (rate limit) and 5xx (server errors).
    """
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            return await func()
        except httpx.HTTPStatusError as e:
            last_exception = e
            if _is_retryable_status(e.response.status_code) and attempt < max_retries:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    f"LLM API returned {e.response.status_code}, "
                    f"retrying in {delay}s (attempt {attempt + 1}/{max_retries + 1})"
                )
                await asyncio.sleep(delay)
            else:
                raise LLMError(
                    f"LLM API error: {e.response.status_code}",
                    error_type="api_error" if e.response.status_code < 500 else "server_error",
                    is_retryable=_is_retryable_status(e.response.status_code)
                )
        except httpx.TimeoutException as e:
            last_exception = e
            if attempt < max_retries:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    f"LLM API timeout, retrying in {delay}s (attempt {attempt + 1}/{max_retries + 1})"
                )
                await asyncio.sleep(delay)
            else:
                raise LLMError(
                    "LLM API request timed out",
                    error_type="timeout",
                    is_retryable=True
                )
        except httpx.RequestError as e:
            last_exception = e
            if attempt < max_retries:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    f"LLM API connection error, retrying in {delay}s (attempt {attempt + 1}/{max_retries + 1})"
                )
                await asyncio.sleep(delay)
            else:
                raise LLMError(
                    f"LLM API connection failed: {str(e)}",
                    error_type="connection_error",
                    is_retryable=True
                )
    
    # Should not reach here, but just in case
    raise LLMError(
        f"LLM API failed after {max_retries + 1} attempts",
        error_type="max_retries_exceeded",
        is_retryable=False
    )


async def _retry_groq_with_fallback(
    func,
    provider: str,
    max_retries: int = 5,
    base_delay: float = 2.0
) -> str:
    """
    Enhanced retry logic specifically for Groq with fallback.
    
    Groq's free/low tier hits rate limits often - this handles that with
    exponential backoff and extended retries.
    """
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            return await func()
        except httpx.HTTPStatusError as e:
            last_exception = e
            # Groq rate limit (429) - retry with longer delays
            if e.response.status_code == 429:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    f"Groq rate limit hit, retrying in {delay}s (attempt {attempt + 1}/{max_retries})"
                )
                await asyncio.sleep(delay)
            elif e.response.status_code >= 500:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    f"Groq server error {e.response.status_code}, retrying in {delay}s"
                )
                await asyncio.sleep(delay)
            else:
                raise LLMError(
                    f"LLM API error: {e.response.status_code}",
                    error_type="api_error",
                    is_retryable=False
                )
        except httpx.TimeoutException as e:
            last_exception = e
            delay = base_delay * (2 ** attempt)
            logger.warning(f"LLM timeout, retrying in {delay}s (attempt {attempt + 1})")
            await asyncio.sleep(delay)
        except Exception as e:
            last_exception = e
            if "rate_limit" in str(e).lower() or "429" in str(e):
                delay = base_delay * (2 ** attempt)
                logger.warning(f"Rate limit error, retrying in {delay}s")
                await asyncio.sleep(delay)
            else:
                raise
    
    raise LLMError(
        f"Groq failed after {max_retries} attempts: {last_exception}",
        error_type="rate_limit_exceeded",
        is_retryable=False
    )


async def _analyze_chunk_parallel(
    diff_text: str,
    language: str,
    framework: str,
    llm_provider: str,
    api_key: str,
    model: str,
    pr_context: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Analyze a chunk of diff text using the LLM.
    Used for parallel chunk analysis.
    """
    security_hints = build_security_hints(language, framework)
    
    user_prompt = f"""Review the following Git diff for security vulnerabilities in a {language} / {framework} application.

Only consider vulnerabilities introduced or modified in this diff. Focus on real, exploitable issues.

{f"Security context: {security_hints}" if security_hints else ""}

```diff
{diff_text}
```

Analyze this diff and respond with JSON containing your security findings."""

    async def make_call():
        if llm_provider.lower() == "claude":
            return await _call_claude(SYSTEM_PROMPT, user_prompt, api_key, model)
        elif llm_provider.lower() == "openai":
            return await _call_openai(SYSTEM_PROMPT, user_prompt, api_key, model)
        elif llm_provider.lower() == "gemini":
            return await _call_gemini(SYSTEM_PROMPT, user_prompt, api_key, model)
        elif llm_provider.lower() == "groq":
            return await _call_groq(SYSTEM_PROMPT, user_prompt, api_key, model)
        else:
            raise ValueError(f"Unsupported LLM provider: {llm_provider}")

    # Use enhanced retry for Groq
    if llm_provider.lower() == "groq":
        response_text = await _retry_groq_with_fallback(make_call, llm_provider)
    else:
        response_text = await _retry_with_backoff(make_call)
    
    return {"response": response_text, "provider": llm_provider}


async def _synthesize_findings(
    findings: List[Dict],
    language: str,
    framework: str,
    llm_provider: str,
    api_key: str,
    model: str
) -> List[Dict]:
    """
    Synthesis pass to deduplicate and prioritize findings from multiple chunks.
    Only called when there are multiple chunks.
    """
    if not findings:
        return []
    
    findings_json = json.dumps(findings[:20])  # Limit for synthesis
    
    synthesis_prompt = f"""You are a Senior AppSec Engineer. Review the following security findings from a PR review that was split into multiple chunks.

Your task is to:
1. Remove duplicate findings (same file, similar issue)
2. Keep the finding with more complete details
3. Merge findings about the same vulnerability
4. Prioritize by severity

Findings JSON:
{findings_json}

Return a JSON array of unique, deduplicated findings with this format:
{{"findings": [{{"title": str, "risk": "HIGH|MEDIUM|LOW", "confidence": "HIGH|MEDIUM|LOW", "file": str, "line_range": str, "evidence": str, "description": str, "impact": str, "recommendation": str, "example_fix": str, "owasp": str, "cwe": str}}]}}"""

    async def make_call():
        if llm_provider.lower() == "claude":
            return await _call_claude(SYSTEM_PROMPT, synthesis_prompt, api_key, model)
        elif llm_provider.lower() == "openai":
            return await _call_openai(SYSTEM_PROMPT, synthesis_prompt, api_key, model)
        elif llm_provider.lower() == "gemini":
            return await _call_gemini(SYSTEM_PROMPT, synthesis_prompt, api_key, model)
        elif llm_provider.lower() == "groq":
            return await _call_groq(SYSTEM_PROMPT, synthesis_prompt, api_key, model)
    
    try:
        if llm_provider.lower() == "groq":
            response_text = await _retry_groq_with_fallback(make_call, llm_provider, max_retries=3)
        else:
            response_text = await _retry_with_backoff(make_call, max_retries=2)
        
        data = json.loads(response_text)
        synthesized = data.get("findings", [])
        logger.info(f"Synthesized {len(findings)} findings into {len(synthesized)} unique findings")
        return synthesized
    except Exception as e:
        logger.warning(f"Synthesis failed, returning original findings: {e}")
        return findings

# System prompt for the Senior AppSec Engineer persona
SYSTEM_PROMPT = """You are a Senior Application Security Engineer. You review code changes in pull requests and identify real security vulnerabilities with extremely low false positives.

Focus on these categories:
- Injection (SQL, NoSQL, OS command, LDAP, template)
- Authentication flaws
- Broken or missing authorization checks (including IDOR and broken access control)
- Hardcoded secrets, credentials, API keys and tokens
- Insecure use of cryptography or random values
- SSRF, path traversal and unsafe file handling
- Insecure deserialization
- Sensitive data exposure (logging or responses)
- Insecure session management

You are reviewing only the code changes in the diff, not the whole repository. Only report issues that are plausibly exploitable in a realistic scenario.

CONFIDENCE LEVELS - Be honest about your certainty:
- HIGH: You are certain this is a real vulnerability with clear evidence in the diff
- MEDIUM: Likely a vulnerability, but depends on context not visible in the diff
- LOW: Possible issue but needs more context to confirm
- NEEDS_REVIEW: Suspicious pattern that requires manual human review (use this for uncertain cases instead of making false positive findings)

For uncertain findings, mark them as NEEDS_REVIEW rather than reporting them as confirmed vulnerabilities.

CRITICAL: For each finding, you MUST provide a concrete suggested_fix that can be committed directly. The suggested_fix must:
- Be valid, runnable code as a drop-in replacement
- Preserve exact indentation from the original code (use same number of spaces/tabs)
- Fix ONLY the specific vulnerability - no unrelated changes
- Be 1-5 lines maximum
- Use the same variable/function names as the original code

If you cannot confidently provide a fix, set suggested_fix to null but still provide the best recommendation possible.

For each issue, you must return structured data with:
- title
- risk (HIGH, MEDIUM, or LOW)
- confidence (HIGH, MEDIUM, LOW, or NEEDS_REVIEW)
- evidence (exact 1-3 lines from the diff that demonstrate the issue - copy the actual code)
- file (the file path being changed)
- line_start (the starting line number in the new version of the file)
- line_end (the ending line number, same as line_start for single-line changes)
- description (what is wrong)
- impact (what an attacker can do)
- recommendation (how to fix)
- suggested_fix (the exact code to replace the vulnerable lines - CRITICAL for GitHub suggestions)
- original_code (the exact vulnerable lines from the diff for reference)
- owasp (best matching OWASP Top 10 2021 category or empty string)
- cwe (best matching CWE ID or empty string)

If no clear issues are found, return an empty findings list and a summary that states: "No clear security vulnerabilities identified in this change."

IMPORTANT: Respond ONLY with valid JSON in this exact format:
{
  "summary": "Brief summary of findings",
  "findings": [
    {
      "title": "...",
      "risk": "HIGH|MEDIUM|LOW",
      "confidence": "HIGH|MEDIUM|LOW|NEEDS_REVIEW",
      "evidence": "actual code line(s) from the diff",
      "file": "src/auth/login.py",
      "line_start": 42,
      "line_end": 45,
      "original_code": "query = f'SELECT * FROM users WHERE id = {user_id}'",
      "suggested_fix": "query = 'SELECT * FROM users WHERE id = %s'\\ncursor.execute(query, (user_id,))",
      "description": "...",
      "impact": "...",
      "recommendation": "...",
      "owasp": "A03:2021 – Injection",
      "cwe": "CWE-89"
    }
  ]
}"""


def _build_user_prompt(diff_text: str, language: str, framework: str) -> str:
    """Build the user prompt for the LLM."""
    security_hints = build_security_hints(language, framework)
    
    prompt = f"""Review the following Git diff for security vulnerabilities in a {language} / {framework} application.

Only consider vulnerabilities introduced or modified in this diff. Focus on real, exploitable issues.

{f"Security context: {security_hints}" if security_hints else ""}

```diff
{diff_text}
```

Analyze this diff and respond with JSON containing your security findings."""
    
    return prompt


async def _call_claude(
    system_prompt: str,
    user_prompt: str,
    api_key: str,
    model: str = "claude-sonnet-4-20250514"
) -> str:
    """Call Claude API and return the response text."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 4096,
                "system": system_prompt,
                "messages": [
                    {"role": "user", "content": user_prompt}
                ]
            }
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract text from Claude's response
        content = data.get("content", [])
        if content and len(content) > 0:
            return content[0].get("text", "")
        return ""


async def _call_openai(
    system_prompt: str,
    user_prompt: str,
    api_key: str,
    model: str = "gpt-4o"
) -> str:
    """Call OpenAI API and return the response text."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
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
                "max_tokens": 4096,
                "temperature": 0.1,  # Low temperature for consistent analysis
            }
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract text from OpenAI's response
        choices = data.get("choices", [])
        if choices and len(choices) > 0:
            return choices[0].get("message", {}).get("content", "")
        return ""


async def _call_gemini(
    system_prompt: str,
    user_prompt: str,
    api_key: str,
    model: str = "gemini-2.0-flash"
) -> str:
    """Call Google Gemini API and return the response text."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
        # Gemini API endpoint
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        
        response = await client.post(
            url,
            headers={
                "Content-Type": "application/json",
            },
            params={
                "key": api_key
            },
            json={
                "contents": [
                    {
                        "parts": [
                            {"text": f"{system_prompt}\n\n{user_prompt}"}
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": 4096,
                    "responseMimeType": "application/json"
                },
                "safetySettings": [
                    {
                        "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                        "threshold": "BLOCK_NONE"
                    },
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "threshold": "BLOCK_NONE"
                    },
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_NONE"
                    },
                    {
                        "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        "threshold": "BLOCK_NONE"
                    }
                ]
            }
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract text from Gemini's response
        candidates = data.get("candidates", [])
        if candidates and len(candidates) > 0:
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            if parts and len(parts) > 0:
                return parts[0].get("text", "")
        return ""


async def _call_groq(
    system_prompt: str,
    user_prompt: str,
    api_key: str,
    model: str = "llama-3.3-70b-versatile"
) -> str:
    """Call Groq API and return the response text.
    
    Groq provides fast inference for open-source models like Llama and Mixtral.
    API is OpenAI-compatible.
    """
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
        request_body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "max_tokens": 4096,
            "temperature": 0.1,  # Low temperature for consistent analysis
        }
        
        # Only add json_object mode for models that support it
        # Llama and Mixtral models support it, but some others may not
        json_supported_models = [
            "llama", "mixtral", "gemma"
        ]
        if any(m in model.lower() for m in json_supported_models):
            request_body["response_format"] = {"type": "json_object"}
        
        logger.info(f"Groq request - model: {model}")
        
        response = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=request_body
        )
        response.raise_for_status()
        data = response.json()
        
        logger.debug(f"Groq raw response keys: {data.keys()}")
        
        # Extract text from Groq's response (OpenAI-compatible format)
        choices = data.get("choices", [])
        if choices and len(choices) > 0:
            message = choices[0].get("message", {})
            content = message.get("content", "")
            if not content:
                logger.warning(f"Groq returned empty content. Full response: {data}")
            else:
                logger.info(f"Groq response received: {len(content)} chars")
            return content
        
        logger.warning(f"Groq returned no choices. Full response: {data}")
        return ""


def _parse_llm_response(response_text: str) -> tuple[str, list[dict]]:
    """
    Parse the LLM response to extract findings.
    
    Returns:
        Tuple of (summary, findings_list)
    """
    # Handle empty response
    if not response_text or not response_text.strip():
        logger.error("LLM response is empty")
        return "Unable to parse security review results - empty response from LLM.", []
    
    logger.debug(f"Parsing LLM response: {response_text[:200]}...")
    
    # Try to parse as direct JSON first (for JSON mode responses)
    try:
        data = json.loads(response_text.strip())
        summary = data.get("summary", "Security review completed.")
        findings = data.get("findings", [])
        logger.info(f"Successfully parsed JSON response: {len(findings)} findings")
        return summary, findings
    except json.JSONDecodeError:
        pass  # Not direct JSON, try extracting from text
    
    # Try to extract JSON from markdown code blocks
    json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response_text)
    if json_match:
        json_str = json_match.group(1)
    else:
        # Try to find JSON object directly in text
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            json_str = json_match.group(0)
        else:
            logger.warning(f"Could not find JSON in LLM response. Response: {response_text[:500]}")
            return "Unable to parse security review results.", []
    
    try:
        data = json.loads(json_str)
        summary = data.get("summary", "Security review completed.")
        findings = data.get("findings", [])
        logger.info(f"Successfully parsed JSON from text: {len(findings)} findings")
        return summary, findings
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM JSON response: {e}. Raw text: {json_str[:500]}")
        return "Unable to parse security review results.", []


def _normalize_risk(risk: str) -> RiskLevel:
    """Normalize risk level string to RiskLevel enum."""
    # Handle enum-style strings like "RISKLEVEL.MEDIUM" or "RiskLevel.HIGH"
    risk_clean = risk.upper().strip()
    if "." in risk_clean:
        risk_clean = risk_clean.split(".")[-1]
    
    if risk_clean in ("HIGH", "CRITICAL", "SEVERE"):
        return RiskLevel.HIGH
    elif risk_clean in ("MEDIUM", "MODERATE"):
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


def _normalize_confidence(confidence: str) -> ConfidenceLevel:
    """Normalize confidence level string to ConfidenceLevel enum."""
    # Handle enum-style strings like "CONFIDENCELEVEL.MEDIUM" or "ConfidenceLevel.HIGH"
    conf_clean = confidence.upper().strip()
    if "." in conf_clean:
        conf_clean = conf_clean.split(".")[-1]
    
    if conf_clean in ("HIGH", "CERTAIN", "CONFIRMED"):
        return ConfidenceLevel.HIGH
    elif conf_clean in ("MEDIUM", "MODERATE", "LIKELY"):
        return ConfidenceLevel.MEDIUM
    elif conf_clean in ("LOW", "POSSIBLE", "UNCERTAIN"):
        return ConfidenceLevel.LOW
    elif conf_clean in ("NEEDS_REVIEW", "NEEDS-REVIEW", "MANUAL_REVIEW", "REVIEW"):
        return ConfidenceLevel.NEEDS_REVIEW
    else:
        return ConfidenceLevel.MEDIUM  # Default to medium if unknown


def _compute_findings_hash(findings: list[SecurityFinding]) -> str:
    """Compute a hash of findings for deduplication."""
    import hashlib
    
    # Create a stable string representation of findings
    finding_strs = []
    for f in findings:
        finding_strs.append(f"{f.file_path}:{f.line_range}:{f.title}:{f.risk.value}")
    
    combined = "|".join(sorted(finding_strs))
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def _compute_finding_fingerprint(finding: SecurityFinding) -> str:
    """
    Compute a unique fingerprint for a finding for deduplication across runs.
    
    Fingerprint = hash(file + risk) 
    This is intentionally simple to ensure stable matching across commits.
    Different issues in the same file will be grouped by risk level.
    """
    import hashlib
    
    fingerprint_str = f"{finding.file_path}|{finding.risk.value}"
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


def _apply_deduplication(
    findings: list[SecurityFinding],
    previous_fingerprints: list[str]
) -> tuple[list[SecurityFinding], int, int]:
    """
    Apply deduplication logic to findings based on previous fingerprints.
    
    Args:
        findings: List of findings from current run
        previous_fingerprints: Fingerprints from previous run
        
    Returns:
        Tuple of (findings_with_fingerprints, new_count, still_present_count)
    """
    previous_set = set(previous_fingerprints)
    new_count = 0
    still_present_count = 0
    
    for finding in findings:
        fingerprint = _compute_finding_fingerprint(finding)
        finding.fingerprint = fingerprint
        
        if fingerprint in previous_set:
            finding.is_new = False
            still_present_count += 1
        else:
            finding.is_new = True
            new_count += 1
    
    return findings, new_count, still_present_count


def _filter_by_policy(
    findings: list[SecurityFinding],
    policy: Optional[RepoPolicy]
) -> tuple[list[SecurityFinding], list[SecurityFinding], bool]:
    """
    Filter findings based on repository policy.
    
    Returns:
        Tuple of (filtered_findings, needs_review_findings, was_filtered)
    """
    if not policy:
        # No policy - return all findings that aren't NEEDS_REVIEW
        confirmed = [f for f in findings if f.confidence != ConfidenceLevel.NEEDS_REVIEW]
        needs_review = [f for f in findings if f.confidence == ConfidenceLevel.NEEDS_REVIEW]
        return confirmed, needs_review, False
    
    filtered = []
    needs_review = []
    was_filtered = False
    
    # Risk level order for comparison
    risk_order = {RiskLevel.HIGH: 3, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 1}
    confidence_order = {
        ConfidenceLevel.HIGH: 4,
        ConfidenceLevel.MEDIUM: 3,
        ConfidenceLevel.LOW: 2,
        ConfidenceLevel.NEEDS_REVIEW: 1
    }
    
    min_risk_val = risk_order.get(policy.min_risk, 1)
    min_conf_val = confidence_order.get(policy.min_confidence, 1)
    
    for finding in findings:
        # Always separate NEEDS_REVIEW findings
        if finding.confidence == ConfidenceLevel.NEEDS_REVIEW:
            needs_review.append(finding)
            continue
        
        # Check if file is in blocklist
        file_blocked = False
        for pattern in policy.blocklist:
            if pattern.endswith('/'):
                # Directory pattern
                if finding.file_path.startswith(pattern) or f"/{pattern}" in finding.file_path:
                    file_blocked = True
                    break
            elif '*' in pattern:
                # Glob pattern - simple check
                import fnmatch
                if fnmatch.fnmatch(finding.file_path, pattern) or fnmatch.fnmatch(finding.file_path, f"**/{pattern}"):
                    file_blocked = True
                    break
            else:
                # Exact match or path contains
                if pattern in finding.file_path:
                    file_blocked = True
                    break
        
        if file_blocked:
            was_filtered = True
            continue
        
        # Check risk level
        finding_risk_val = risk_order.get(finding.risk, 1)
        if finding_risk_val < min_risk_val:
            was_filtered = True
            continue
        
        # Check confidence level
        finding_conf_val = confidence_order.get(finding.confidence, 2)
        if finding_conf_val < min_conf_val:
            was_filtered = True
            continue
        
        filtered.append(finding)
    
    # Apply max_findings limit
    if len(filtered) > policy.max_findings:
        was_filtered = True
        # Keep highest risk findings
        filtered = sorted(filtered, key=lambda f: (risk_order.get(f.risk, 1), confidence_order.get(f.confidence, 1)), reverse=True)
        filtered = filtered[:policy.max_findings]
    
    return filtered, needs_review, was_filtered


def _build_findings_markdown(
    summary: str,
    findings: list[SecurityFinding],
    needs_review: list[SecurityFinding] = None,
    filtered_by_policy: bool = False,
    total_before_filter: int = 0,
    new_findings_count: int = 0,
    still_present_count: int = 0,
    fingerprints: list[str] = None,
    resolved_findings: list[dict] = None,
    resolved_findings_count: int = 0
) -> str:
    """Build a markdown comment for a PR security review."""
    needs_review = needs_review or []
    fingerprints = fingerprints or []
    resolved_findings = resolved_findings or []

    all_fingerprints = fingerprints or [f.fingerprint for f in findings if f.fingerprint]
    all_fingerprints.extend([f.fingerprint for f in needs_review if f.fingerprint])
    fingerprints_json = json.dumps(all_fingerprints)

    high_findings = [f for f in findings if f.risk == RiskLevel.HIGH]
    medium_findings = [f for f in findings if f.risk == RiskLevel.MEDIUM]
    low_findings = [f for f in findings if f.risk == RiskLevel.LOW]

    lines = [
        "## Security Review",
        "",
        "<!-- AI_APPSEC_REVIEW -->",
        f"<!-- FINGERPRINTS:{fingerprints_json}-->",
        "",
    ]

    if summary:
        lines.append(summary)
        lines.append("")

    if resolved_findings_count > 0 or resolved_findings:
        count = resolved_findings_count or len(resolved_findings)
        lines.append(f"**{count} previous finding(s) resolved in this PR.**")
        lines.append("")
        if resolved_findings:
            for rf in resolved_findings:
                title = rf.get("title", "Unknown issue")
                risk = rf.get("risk", "UNKNOWN")
                file_path = rf.get("file_path", rf.get("file", "unknown"))
                line_range = rf.get("line_range", "")
                location = f"{file_path}:{line_range}" if line_range else file_path
                lines.append(f"- ~~[{risk}] {title}~~ — `{location}`")
        lines.append("")
        lines.append("---")
        lines.append("")

    if not findings and not needs_review:
        lines.append("No security issues found in this change set.")
        lines.append("")
        lines.append("---")
        lines.append("*AppSec PR Reviewer — validate findings before applying changes.*")
        return "\n".join(lines)

    if findings:
        lines.append(f"**{len(findings)} finding(s):** {len(high_findings)} high, {len(medium_findings)} medium, {len(low_findings)} low")
        lines.append("")

        for i, finding in enumerate(findings, 1):
            location = f"{finding.file_path}:{finding.line_range}"
            status_text = "New" if finding.is_new else "Still present"
            lines.append(f"**{i}. [{finding.risk.value}]** {finding.title} — `{location}` — {status_text}")
            lines.append("")
            lines.append(f"**Confidence:** {finding.confidence.value}")
            lines.append("")
            lines.append(finding.description)
            lines.append("")

            if finding.impact:
                lines.append(f"**Impact:** {finding.impact}")
                lines.append("")

            if finding.recommendation:
                lines.append(f"**Fix:** {finding.recommendation}")
                lines.append("")

            if finding.evidence:
                lines.append("```")
                lines.append(finding.evidence)
                lines.append("```")
                lines.append("")

            if finding.example_fix:
                lines.append("```")
                lines.append(finding.example_fix)
                lines.append("```")
                lines.append("")

            refs = []
            if finding.owasp:
                refs.append(f"OWASP: {finding.owasp}")
            if finding.cwe:
                refs.append(finding.cwe)
            if refs:
                lines.append(f"**Refs:** {' | '.join(refs)}")
                lines.append("")

            lines.append("---")
            lines.append("")

    if needs_review:
        lines.append("**Items requiring manual review:**")
        lines.append("")
        for i, finding in enumerate(needs_review, 1):
            location = f"{finding.file_path}:{finding.line_range}"
            lines.append(f"- {finding.title} — `{location}`")
        lines.append("")

    lines.append("---")
    lines.append("*AppSec PR Reviewer — validate findings before applying changes.*")
    return "\n".join(lines)


def attach_review_identity(markdown: str, review_id: str) -> str:
    """Attach review identity metadata to the markdown comment."""
    if not markdown or not review_id:
        return markdown

    identity_line = f"**Review ID:** `{review_id}`"
    marker = "<!-- AI_APPSEC_REVIEW -->"

    if identity_line in markdown:
        return markdown

    if marker in markdown:
        return markdown.replace(marker, f"{marker}\n{identity_line}", 1)

    return f"{identity_line}\n\n{markdown}"

def regenerate_markdown_with_resolved(
    result: "ReviewResponse",
    resolved_findings: list[dict],
    resolved_findings_count: int = 0
) -> str:
    """
    Regenerate the findings markdown with resolved findings information.
    
    This is called after the review is complete and resolved findings have been
    detected by comparing with the previous review.
    
    Args:
        result: The ReviewResponse from analyze_diff
        resolved_findings: List of resolved finding details
        resolved_findings_count: Number of resolved findings
        
    Returns:
        Updated markdown string with resolved findings section
    """
    return _build_findings_markdown(
        summary=result.summary,
        findings=result.findings or [],
        needs_review=result.needs_manual_review or [],
        filtered_by_policy=result.filtered_by_policy,
        total_before_filter=result.total_findings_before_filter,
        new_findings_count=result.new_findings_count,
        still_present_count=result.still_present_count,
        fingerprints=result.fingerprints or [],
        resolved_findings=resolved_findings,
        resolved_findings_count=resolved_findings_count
    )


def _build_error_markdown(error_type: str, details: str) -> str:
    """Build a clean markdown error message for review failures."""
    error_messages = {
        "timeout": "The security review request timed out.",
        "api_error": "The review provider returned an error.",
        "server_error": "The review service is temporarily unavailable.",
        "connection_error": "Could not connect to the review service.",
        "max_retries_exceeded": "The review failed after multiple retry attempts.",
        "internal_error": "An unexpected error occurred.",
    }

    message = error_messages.get(error_type, "The security review could not be completed.")

    return f"""## Security Review Report

<!-- AI_APPSEC_REVIEW -->

**{message}**

**Error Type:** `{error_type}`

---

**Recommended next steps:**
- Please retry by pushing a new commit or re-running the workflow
- If the problem persists, check the service status and configuration
- Contact your administrator if issues continue

---
_Generated by AppSec PR Reviewer_"""

async def analyze_diff(
    diff_text: str,
    language: str = "nodejs",
    framework: str = "express",
    llm_provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    policy: Optional[RepoPolicy] = None,
    previous_fingerprints: Optional[list[str]] = None,
) -> ReviewResponse:
    """
    Analyze a git diff for security vulnerabilities.
    
    Uses:
    - Diff pre-processing with ignore patterns
    - Chunking for Groq's smaller context window
    - Parallel analysis + synthesis pass
    - Enhanced retry for Groq rate limits
    
    Args:
        diff_text: The raw git diff text
        language: Programming language (nodejs, python, java, etc.)
        framework: Web framework (express, fastapi, spring, etc.)
        llm_provider: LLM provider ("claude", "openai", "gemini", or "groq"), defaults to env var
        api_key: API key for the LLM provider, defaults to env var
        model: Model name to use, defaults based on provider
        policy: Optional repository policy to apply for filtering
        previous_fingerprints: Fingerprints from previous run for deduplication
        
    Returns:
        ReviewResponse with findings and markdown
    """
    previous_fingerprints = previous_fingerprints or []
    
    # Get configuration from environment if not provided
    llm_provider = llm_provider or os.getenv("LLM_PROVIDER", "claude")
    api_key = api_key or os.getenv("LLM_API_KEY")
    
    if not api_key:
        raise ValueError("LLM_API_KEY environment variable is required")
    
    # Set default model based on provider
    if not model:
        if llm_provider.lower() == "claude":
            model = "claude-sonnet-4-20250514"
        elif llm_provider.lower() == "gemini":
            model = "gemini-2.0-flash"
        elif llm_provider.lower() == "groq":
            model = "llama-3.3-70b-versatile"
        else:
            model = "gpt-4o"
    
    # Determine token limit based on provider
    if llm_provider.lower() == "groq":
        max_tokens = GROQ_TOKEN_LIMIT
    elif llm_provider.lower() == "gemini":
        max_tokens = GEMINI_TOKEN_LIMIT
    elif llm_provider.lower() == "openai":
        max_tokens = OPENAI_TOKEN_LIMIT
    else:
        max_tokens = CLAUDE_TOKEN_LIMIT
    
    # Handle empty diff
    if not diff_text or not diff_text.strip():
        return ReviewResponse(
            summary="No code changes to review.",
            findings=[],
            findings_markdown=_build_findings_markdown("No code changes to review.", []),
            total_findings_before_filter=0,
            filtered_by_policy=False,
            needs_manual_review=[],
            findings_hash=None
        )
    
    # Parse diff into files
    try:
        parsed_diff = parse_diff(diff_text)
        files = []
        for file_patch in parsed_diff.files:
            # Determine status
            if file_patch.is_new_file:
                status = "added"
            elif file_patch.is_deleted:
                status = "deleted"
            else:
                status = "modified"
            
            # Get patch content from hunks
            patch_content = ""
            for hunk in file_patch.hunks:
                patch_content += f"@@ -{hunk.old_start},{hunk.old_count} +{hunk.new_start},{hunk.new_count} @@\n"
                patch_content += hunk.content + "\n"
            
            # Count additions from added_lines
            additions = len(file_patch.added_lines)
            
            files.append({
                "filename": file_patch.path,
                "patch": patch_content,
                "status": status,
                "additions": additions,
                "deletions": 0
            })
        logger.info(f"Parsed diff into {len(files)} files")
    except Exception as e:
        logger.warning(f"Failed to parse diff into files, treating as single chunk: {e}")
        files = [{"filename": "unknown", "patch": diff_text, "status": "modified", "additions": 0, "deletions": 0}]
    
    # Filter and prioritize files
    filtered_files = filter_diff_files(files)
    logger.info(f"Filtered to {len(filtered_files)} relevant files")
    
    if not filtered_files:
        return ReviewResponse(
            summary="No relevant code changes to review (all files ignored).",
            findings=[],
            findings_markdown=_build_findings_markdown("No relevant code changes to review.", []),
            total_findings_before_filter=0,
            filtered_by_policy=False,
            needs_manual_review=[],
            findings_hash=None
        )
    
    # Chunk files
    file_chunks = chunk_diff_files(filtered_files, max_tokens)
    logger.info(f"Chunked into {len(file_chunks)} chunks for {llm_provider}")
    
    try:
        all_findings_data = []
        
        if len(file_chunks) == 1:
            # Single chunk - use original approach
            diff_text_chunk = _build_chunk_diff_text(file_chunks[0])
            user_prompt = _build_user_prompt(diff_text_chunk, language, framework)
            
            async def make_llm_call():
                if llm_provider.lower() == "claude":
                    return await _call_claude(SYSTEM_PROMPT, user_prompt, api_key, model)
                elif llm_provider.lower() == "openai":
                    return await _call_openai(SYSTEM_PROMPT, user_prompt, api_key, model)
                elif llm_provider.lower() == "gemini":
                    return await _call_gemini(SYSTEM_PROMPT, user_prompt, api_key, model)
                elif llm_provider.lower() == "groq":
                    return await _call_groq(SYSTEM_PROMPT, user_prompt, api_key, model)
                else:
                    raise ValueError(f"Unsupported LLM provider")
            
            if llm_provider.lower() == "groq":
                response_text = await _retry_groq_with_fallback(make_llm_call, llm_provider)
            else:
                response_text = await _retry_with_backoff(make_llm_call)
            
            summary, findings_data = _parse_llm_response(response_text)
            all_findings_data.extend(findings_data)
        else:
            # Multiple chunks - parallel analysis
            logger.info(f"Running parallel analysis on {len(file_chunks)} chunks")
            summary = "Multiple chunks analyzed"
            
            async def analyze_single_chunk(chunk_idx: int, chunk_files: list) -> list:
                diff_text_chunk = _build_chunk_diff_text(chunk_files)
                user_prompt = _build_user_prompt(diff_text_chunk, language, framework)
                
                async def make_llm_call():
                    if llm_provider.lower() == "claude":
                        return await _call_claude(SYSTEM_PROMPT, user_prompt, api_key, model)
                    elif llm_provider.lower() == "openai":
                        return await _call_openai(SYSTEM_PROMPT, user_prompt, api_key, model)
                    elif llm_provider.lower() == "gemini":
                        return await _call_gemini(SYSTEM_PROMPT, user_prompt, api_key, model)
                    elif llm_provider.lower() == "groq":
                        return await _call_groq(SYSTEM_PROMPT, user_prompt, api_key, model)
                
                try:
                    if llm_provider.lower() == "groq":
                        response_text = await _retry_groq_with_fallback(make_llm_call, llm_provider, max_retries=3)
                    else:
                        response_text = await _retry_with_backoff(make_llm_call, max_retries=2)
                    
                    _, findings_data = _parse_llm_response(response_text)
                    return findings_data
                except Exception as e:
                    logger.error(f"Chunk {chunk_idx} failed: {e}")
                    return []
            
            # Run all chunks in parallel
            tasks = [analyze_single_chunk(i, chunk) for i, chunk in enumerate(file_chunks)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect results
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Chunk analysis failed: {result}")
                    continue
                if isinstance(result, list):
                    all_findings_data.extend(result)
            
            logger.info(f"Total findings from all chunks: {len(all_findings_data)}")
            
            # Synthesis pass if multiple chunks
            if len(file_chunks) > 1 and all_findings_data:
                logger.info("Running synthesis pass to deduplicate findings")
                synthesized = await _synthesize_findings(
                    all_findings_data, language, framework, llm_provider, api_key, model
                )
                if synthesized:
                    all_findings_data = synthesized
        
        # Ensure summary is set
        if 'summary' not in locals():
            summary = f"Reviewed {len(files)} files, found {len(all_findings_data)} potential issues"
        
        logger.info(f"Total raw findings from all chunks: {len(all_findings_data)}")
        
        # Convert to SecurityFinding objects
        findings = []
        logger.info(f"Processing {len(all_findings_data)} raw findings from LLM")
        
        for i, f in enumerate(all_findings_data):
            logger.debug(f"Raw finding {i+1}: {f}")
            try:
                # Parse line numbers
                line_start = f.get("line_start")
                line_end = f.get("line_end")
                
                # If line_start/line_end not provided, try to parse from line_range
                if not line_start:
                    line_range = f.get("line_range", "0")
                    try:
                        if "-" in str(line_range):
                            parts = str(line_range).split("-")
                            line_start = int(parts[0])
                            line_end = int(parts[1]) if len(parts) > 1 else line_start
                        else:
                            line_start = int(line_range) if line_range else 1
                            line_end = line_start
                    except (ValueError, TypeError):
                        line_start = 1
                        line_end = 1
                
                finding = SecurityFinding(
                    title=f.get("title", "Unknown Issue"),
                    risk=_normalize_risk(f.get("risk", "MEDIUM")),
                    confidence=_normalize_confidence(f.get("confidence", "MEDIUM")),
                    file_path=f.get("file", "unknown"),  # LLM returns "file", model uses "file_path"
                    line_range=str(f.get("line_range", f"{line_start}-{line_end}")),
                    line_start=line_start,
                    line_end=line_end,
                    original_code=f.get("original_code") or None,
                    suggested_fix=f.get("suggested_fix") or f.get("example_fix") or None,
                    evidence=f.get("evidence", ""),
                    description=f.get("description", "No description provided"),
                    impact=f.get("impact", "No impact assessment provided"),
                    recommendation=f.get("recommendation", "No recommendation provided"),
                    example_fix=f.get("example_fix") or f.get("suggested_fix") or None,
                    owasp=f.get("owasp") or None,
                    cwe=f.get("cwe") or None,
                    status="open",  # Default status for new findings
                )
                findings.append(finding)
                logger.info(f"Successfully parsed finding: {finding.title} ({finding.risk.value}, confidence: {finding.confidence.value})")
            except Exception as e:
                logger.error(f"Failed to parse finding {i+1}: {e}. Raw data: {f}")
                continue
        
        # Sort by risk level (HIGH first), then by confidence
        risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2}
        conf_order = {ConfidenceLevel.HIGH: 0, ConfidenceLevel.MEDIUM: 1, ConfidenceLevel.LOW: 2, ConfidenceLevel.NEEDS_REVIEW: 3}
        findings.sort(key=lambda x: (risk_order.get(x.risk, 3), conf_order.get(x.confidence, 3)))
        
        total_before_filter = len(findings)
        
        # Apply policy filtering if provided
        filtered_findings, needs_review, was_filtered = _filter_by_policy(findings, policy)
        
        # Apply deduplication based on previous fingerprints
        filtered_findings, new_count, still_present_count = _apply_deduplication(
            filtered_findings, previous_fingerprints
        )
        
        # Also apply deduplication to needs_review findings
        needs_review, nr_new, nr_still = _apply_deduplication(needs_review, previous_fingerprints)
        
        # Collect all fingerprints for this run
        all_fingerprints = [f.fingerprint for f in filtered_findings if f.fingerprint]
        all_fingerprints.extend([f.fingerprint for f in needs_review if f.fingerprint])
        
        # Build markdown with all info
        markdown = _build_findings_markdown(
            summary,
            filtered_findings,
            needs_review=needs_review,
            filtered_by_policy=was_filtered,
            total_before_filter=total_before_filter,
            new_findings_count=new_count,
            still_present_count=still_present_count,
            fingerprints=all_fingerprints
        )
        
        # Compute findings hash for deduplication
        findings_hash = _compute_findings_hash(filtered_findings) if filtered_findings else None
        
        # Determine if PR should be blocked using fail_on and min_confidence
        should_block = False
        if policy and policy.mode == PolicyMode.ENFORCE and filtered_findings:
            risk_order = {RiskLevel.HIGH: 3, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 1}
            confidence_order = {
                ConfidenceLevel.HIGH: 4,
                ConfidenceLevel.MEDIUM: 3,
                ConfidenceLevel.LOW: 2,
                ConfidenceLevel.NEEDS_REVIEW: 1
            }
            
            # Use fail_on for the risk threshold (default to HIGH)
            fail_on_risk_val = risk_order.get(policy.fail_on, 3)
            # Use min_confidence for confidence threshold
            min_conf_val = confidence_order.get(policy.min_confidence, 1)
            
            # Block if any finding meets BOTH thresholds:
            # - risk >= fail_on
            # - confidence >= min_confidence
            for finding in filtered_findings:
                finding_risk_val = risk_order.get(finding.risk, 1)
                finding_conf_val = confidence_order.get(finding.confidence, 2)
                
                if finding_risk_val >= fail_on_risk_val and finding_conf_val >= min_conf_val:
                    should_block = True
                    logger.info(
                        f"Gate triggered: {finding.title} (risk={finding.risk.value} >= {policy.fail_on.value}, "
                        f"confidence={finding.confidence.value} >= {policy.min_confidence.value})"
                    )
                    break
        
        return ReviewResponse(
            summary=summary,
            findings=filtered_findings,
            findings_markdown=markdown,
            total_findings_before_filter=total_before_filter,
            filtered_by_policy=was_filtered,
            needs_manual_review=needs_review,
            findings_hash=findings_hash,
            should_block=should_block,
            fingerprints=all_fingerprints,
            new_findings_count=new_count,
            still_present_count=still_present_count
        )
        
    except LLMError as e:
        logger.error(f"LLM error: {e.error_type} - {e.message}")
        error_markdown = _build_error_markdown(e.error_type, e.message)
        return ReviewResponse(
            summary=f"AI review failed: {e.error_type}",
            findings=[],
            findings_markdown=error_markdown,
            total_findings_before_filter=0,
            filtered_by_policy=False,
            needs_manual_review=[],
            findings_hash=None,
            should_block=False
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"LLM API error: {e.response.status_code}")
        error_markdown = _build_error_markdown("api_error", f"HTTP {e.response.status_code}")
        return ReviewResponse(
            summary=f"AI review failed: HTTP {e.response.status_code}",
            findings=[],
            findings_markdown=error_markdown,
            total_findings_before_filter=0,
            filtered_by_policy=False,
            needs_manual_review=[],
            findings_hash=None,
            should_block=False
        )
    except Exception as e:
        logger.error(f"Unexpected error during security analysis: {type(e).__name__}")
        error_markdown = _build_error_markdown("internal_error", "An unexpected error occurred")
        return ReviewResponse(
            summary="AI review failed: internal_error",
            findings=[],
            findings_markdown=error_markdown,
            total_findings_before_filter=0,
            filtered_by_policy=False,
            needs_manual_review=[],
            findings_hash=None,
            should_block=False
        )


