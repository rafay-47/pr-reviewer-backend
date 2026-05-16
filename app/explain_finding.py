"""
SAST Finding Explanation Module.

Provides AI-powered explanations for security findings from external
SAST tools like Fortify, Semgrep, CodeQL, and others.
"""

import json
import logging
import re
from typing import Optional

import httpx

from .models import (
    ExplainFindingRequest, ExplainFindingResponse,
    RiskLevel, ConfidenceLevel
)

logger = logging.getLogger(__name__)

# Timeout for LLM calls
LLM_TIMEOUT_SECONDS = 45

# System prompt for explaining SAST findings
EXPLAIN_SYSTEM_PROMPT = """You are an expert Application Security Engineer who helps developers understand security findings from SAST (Static Application Security Testing) tools.

Your role is to:
1. Explain the security finding in plain, non-jargon English that any developer can understand
2. Explain WHY this is a security risk (the real-world impact)
3. Provide clear, actionable remediation steps
4. Show example code for the fix when applicable

When explaining findings, be:
- Clear and concise
- Developer-friendly (assume they're smart but may not be security experts)
- Practical (focus on real risks, not theoretical ones)
- Helpful (give them everything they need to fix it)

You will receive findings from various SAST tools including:
- Fortify (HP/Micro Focus)
- Semgrep
- CodeQL (GitHub)
- Snyk
- Checkmarx
- SonarQube
- Bandit (Python)
- ESLint security plugins
- And others

Respond ONLY with valid JSON in this exact format:
{
  "explanation": "Plain English explanation of what this finding means",
  "risk_justification": "Why this is a security risk and what an attacker could do",
  "remediation": "Step-by-step guidance on how to fix this issue",
  "example_fix": "Example code showing the secure implementation (or null if not applicable)",
  "severity": "HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "references": ["List of relevant references (OWASP, CWE, documentation links)"]
}"""


def _build_explain_prompt(request: ExplainFindingRequest) -> str:
    """Build the user prompt for explaining a SAST finding."""
    prompt_parts = [
        f"Please explain the following security finding from {request.tool}:",
        "",
        "**Finding:**",
        request.finding_text,
        "",
    ]
    
    if request.rule_id:
        prompt_parts.extend([
            f"**Rule ID:** {request.rule_id}",
            "",
        ])
    
    if request.file_path:
        prompt_parts.extend([
            f"**File:** {request.file_path}",
            "",
        ])
    
    if request.code_snippet:
        prompt_parts.extend([
            f"**Code ({request.language}):**",
            "```",
            request.code_snippet,
            "```",
            "",
        ])
    
    prompt_parts.extend([
        "Explain this finding in plain English and provide remediation guidance.",
        "Respond with JSON only."
    ])
    
    return "\n".join(prompt_parts)


async def _call_llm(
    system_prompt: str,
    user_prompt: str,
    llm_provider: str,
    api_key: str,
    model: str
) -> str:
    """Call the LLM API and return the response text."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
        if llm_provider.lower() == "claude":
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
            
        elif llm_provider.lower() == "openai":
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
                    "temperature": 0.1,
                }
            )
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            return choices[0].get("message", {}).get("content", "") if choices else ""
            
        elif llm_provider.lower() == "gemini":
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            response = await client.post(
                url,
                headers={"Content-Type": "application/json"},
                params={"key": api_key},
                json={
                    "contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}],
                    "generationConfig": {
                        "temperature": 0.1,
                        "maxOutputTokens": 2048,
                        "responseMimeType": "application/json"
                    }
                }
            )
            response.raise_for_status()
            data = response.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                return parts[0].get("text", "") if parts else ""
            return ""
            
        elif llm_provider.lower() == "groq":
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
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"}
                }
            )
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            return choices[0].get("message", {}).get("content", "") if choices else ""
        
        else:
            raise ValueError(f"Unsupported LLM provider: {llm_provider}")


def _parse_response(response_text: str) -> dict:
    """Parse the LLM response to extract explanation data."""
    if not response_text:
        return {}
    
    # Try direct JSON parse
    try:
        return json.loads(response_text.strip())
    except json.JSONDecodeError:
        pass
    
    # Try extracting from markdown code block
    json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response_text)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass
    
    # Try finding raw JSON object
    json_match = re.search(r'\{[\s\S]*\}', response_text)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass
    
    logger.error(f"Failed to parse LLM response: {response_text[:500]}")
    return {}


def _normalize_severity(severity: str) -> RiskLevel:
    """Normalize severity string to RiskLevel enum."""
    severity_upper = severity.upper().strip()
    if severity_upper in ("HIGH", "CRITICAL", "SEVERE"):
        return RiskLevel.HIGH
    elif severity_upper in ("MEDIUM", "MODERATE"):
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


def _normalize_confidence(confidence: str) -> ConfidenceLevel:
    """Normalize confidence string to ConfidenceLevel enum."""
    conf_upper = confidence.upper().strip()
    if conf_upper in ("HIGH", "CERTAIN"):
        return ConfidenceLevel.HIGH
    elif conf_upper in ("MEDIUM", "MODERATE"):
        return ConfidenceLevel.MEDIUM
    else:
        return ConfidenceLevel.LOW


async def explain_sast_finding(
    request: ExplainFindingRequest,
    llm_provider: str,
    api_key: str,
    model: str,
) -> ExplainFindingResponse:
    """
    Explain a SAST finding in plain English.
    
    Args:
        request: The explain finding request
        llm_provider: LLM provider to use
        api_key: API key for the LLM
        model: Model name to use
        
    Returns:
        ExplainFindingResponse with explanation and remediation
    """
    # Build the prompt
    user_prompt = _build_explain_prompt(request)
    
    logger.info(f"Explaining {request.tool} finding: {request.rule_id or 'no rule id'}")
    
    # Call LLM
    response_text = await _call_llm(
        system_prompt=EXPLAIN_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        llm_provider=llm_provider,
        api_key=api_key,
        model=model
    )
    
    # Parse response
    data = _parse_response(response_text)
    
    if not data:
        # Return a default response if parsing failed
        return ExplainFindingResponse(
            explanation="Unable to parse the security finding. Please try again or contact support.",
            risk_justification="Could not determine risk level.",
            remediation="Please review the original finding and consult security documentation.",
            example_fix=None,
            severity=RiskLevel.MEDIUM,
            confidence=ConfidenceLevel.LOW,
            references=[],
            tool=request.tool,
            original_rule_id=request.rule_id
        )
    
    return ExplainFindingResponse(
        explanation=data.get("explanation", "No explanation provided"),
        risk_justification=data.get("risk_justification", "No risk justification provided"),
        remediation=data.get("remediation", "No remediation guidance provided"),
        example_fix=data.get("example_fix"),
        severity=_normalize_severity(data.get("severity", "MEDIUM")),
        confidence=_normalize_confidence(data.get("confidence", "MEDIUM")),
        references=data.get("references", []),
        tool=request.tool,
        original_rule_id=request.rule_id
    )
