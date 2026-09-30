"""
AI Investigator (Stage 3).

Reviews the static scanner's specific claim using a structured AppSec investigation protocol:
- Evaluates source untrustedness and reachability
- Traces taint propagation along CodeQL flow hops
- Analyzes sink exploitability and parameterization
- Identifies framework defenses, sanitizers, and encodings
- Generates structured, balanced Supporting and Opposing Evidence
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional

from .models_alert import (
    NormalizedAlert,
    AlertCodeContext,
    InvestigatorAssessment,
    EvidenceItem,
    EvidenceCategory,
    EvidenceDirection,
    DeterminationType,
)

logger = logging.getLogger(__name__)

INVESTIGATOR_SYSTEM_PROMPT = """You are a Principal Application Security Engineer and CodeQL Triage Specialist.
Your job is to rigorously investigate a static code-scanning alert to determine whether the finding is a TRUE POSITIVE (valid security vulnerability) or a FALSE POSITIVE (safe or mitigated code).

INVESTIGATION PROTOCOL:
1. Scanner Claim: Understand exactly what the static scanner (CodeQL) claims is vulnerable.
2. Source Validity: Can an external untrusted user or attacker control the data entering at the source?
3. Taint Propagation: Does the taint actually flow unbroken to the sink? Look for:
   - Type conversions (e.g. parseInt, Number, UUID validation, float)
   - Schema / input validation (e.g. Zod, Joi, Pydantic, regex)
   - String escaping / encoding / sanitization
   - Broken dataflow where values are overwritten or reassigned
4. Sink Exploitability: Is the sink truly vulnerable in the manner used? Look for:
   - Parameterized queries (? or $1 placeholders)
   - ORM abstractions that auto-parameterize
   - Safe API options or flag settings
5. Defenses & Mitigations: Are there ambient defenses or framework protections preventing exploitation?

EVIDENCE REQUIREMENTS:
You MUST produce TWO structured lists of evidence:
- supporting_evidence: Specific facts and exact code citations that support the scanner's claim (reasons why it is a True Positive).
- opposing_evidence: Specific facts and exact code citations that refute the scanner's claim (reasons why it is a False Positive / mitigated).

Every evidence item must cite REAL lines and code from the provided context. Do NOT invent functions, files, or variables.

OUTPUT FORMAT:
You must respond ONLY with valid JSON matching this schema:
{
  "claim_summary": "Summary of the scanner's claim",
  "source_analysis": "Analysis of source untrustedness",
  "propagation_analysis": "Analysis of taint path hops",
  "sink_analysis": "Analysis of sink exploitability",
  "defenses_analysis": "Analysis of sanitizers and framework defenses",
  "proposed_determination": "TRUE_POSITIVE" | "FALSE_POSITIVE" | "NEEDS_REVIEW",
  "preliminary_confidence": 0.85,
  "supporting_evidence": [
    {
      "id": "sup-1",
      "category": "SOURCE_VALIDITY" | "TAINT_PROPAGATION" | "SINK_EXPLOITABILITY" | "REACHABILITY",
      "title": "Short title",
      "description": "Explanation",
      "code_reference": "exact code lines",
      "file_path": "path/to/file",
      "line_numbers": [42],
      "weight": 2.0
    }
  ],
  "opposing_evidence": [
    {
      "id": "opp-1",
      "category": "SANITIZATION_DEFENSE" | "SINK_EXPLOITABILITY" | "ENVIRONMENT_DEFENSE" | "TAINT_PROPAGATION",
      "title": "Short title",
      "description": "Explanation",
      "code_reference": "exact code lines",
      "file_path": "path/to/file",
      "line_numbers": [50],
      "weight": 2.5
    }
  ],
  "reasoning": "Comprehensive explanation of why the proposed determination was reached"
}
"""


def _format_context_for_prompt(alert: NormalizedAlert, context: AlertCodeContext) -> str:
    """Format alert metadata and extracted code slices into prompt text."""
    parts = []
    parts.append(f"# SCANNER ALERT DETAILS")
    parts.append(f"- Tool: {alert.tool_name} {alert.tool_version or ''}")
    parts.append(f"- Rule ID: {alert.rule_id}")
    parts.append(f"- Rule Name: {alert.rule_name}")
    parts.append(f"- Severity: {alert.severity.value}")
    parts.append(f"- CWEs: {', '.join(alert.cwe_ids) if alert.cwe_ids else 'None specified'}")
    parts.append(f"- Description: {alert.rule_description}")
    parts.append(f"- Scanner Message: {alert.scanner_message}")
    parts.append(f"- Primary Location: {alert.primary_location.file_path}:{alert.primary_location.line_number}")

    parts.append("\n# CODEQL DATAFLOW PATH (SOURCE -> STEPS -> SINK)")
    for path in alert.code_flows:
        parts.append(f"## Path: {path.path_id}")
        for idx, node in enumerate(path.nodes):
            step_type = node.step_type.upper()
            parts.append(f"[{idx+1}] ({step_type}) {node.file_path}:{node.line_number} - {node.description or ''}")
            if node.code_snippet:
                parts.append(f"    Code: {node.code_snippet.strip()}")

    parts.append("\n# REPOSITORY ENVIRONMENT CONTEXT")
    parts.append(f"- Detected Frameworks: {', '.join(context.detected_frameworks) or 'None'}")
    parts.append(f"- Detected Database/ORMs: {', '.join([f for f in context.detected_frameworks if f in ('prisma', 'sqlalchemy', 'typeorm', 'knex', 'mongoose')]) or 'None'}")
    parts.append(f"- Detected Security Middlewares: {', '.join(context.detected_middleware) or 'None'}")
    parts.append(f"- Key Imports: {', '.join(context.imported_modules[:15]) or 'None'}")

    parts.append("\n# RELEVANT CODE SLICES AT ANALYZED COMMIT")

    if context.source_slices:
        parts.append("## Source Slices:")
        for s in context.source_slices:
            parts.append(f"### File: {s.file_path} (Lines {s.start_line}-{s.end_line}) [{s.enclosing_symbol or 'global'}]")
            parts.append("```\n" + s.content + "\n```")

    if context.path_slices:
        parts.append("## Intermediary Propagation Slices:")
        for s in context.path_slices:
            parts.append(f"### File: {s.file_path} (Lines {s.start_line}-{s.end_line}) [{s.enclosing_symbol or 'global'}]")
            parts.append("```\n" + s.content + "\n```")

    if context.sink_slices:
        parts.append("## Sink Execution Slices:")
        for s in context.sink_slices:
            parts.append(f"### File: {s.file_path} (Lines {s.start_line}-{s.end_line}) [{s.enclosing_symbol or 'global'}]")
            parts.append("```\n" + s.content + "\n```")

    return "\n".join(parts)


def _clean_json_response(raw_text: str) -> Dict[str, Any]:
    """Extract and parse JSON object from LLM response text."""
    text = raw_text.strip()
    # Strip markdown code blocks
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        # Fallback regex extraction of outer JSON object
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        raise ValueError(f"Failed to parse investigator JSON response: {e}\nRaw output: {raw_text[:300]}")


class AIInvestigator:
    """Investigator agent for analyzing scanner claims and compiling bidirectional evidence."""

    def __init__(self, llm_caller):
        """
        Args:
            llm_caller: Async callable `(system_prompt: str, user_prompt: str) -> str`.
        """
        self.llm_caller = llm_caller

    async def investigate(
        self,
        alert: NormalizedAlert,
        context: AlertCodeContext
    ) -> InvestigatorAssessment:
        """
        Run security claim investigation on the alert and context.
        
        Args:
            alert: NormalizedAlert instance.
            context: AlertCodeContext bundle.
            
        Returns:
            InvestigatorAssessment instance.
        """
        user_prompt = _format_context_for_prompt(alert, context)
        raw_response = await self.llm_caller(INVESTIGATOR_SYSTEM_PROMPT, user_prompt)
        parsed = _clean_json_response(raw_response)

        # Parse supporting evidence items
        supporting_items = []
        for idx, item in enumerate(parsed.get("supporting_evidence", [])):
            cat = item.get("category", "SINK_EXPLOITABILITY")
            try:
                cat_enum = EvidenceCategory(cat)
            except ValueError:
                cat_enum = EvidenceCategory.SINK_EXPLOITABILITY

            supporting_items.append(EvidenceItem(
                id=item.get("id") or f"sup_{idx+1}",
                category=cat_enum,
                direction=EvidenceDirection.SUPPORTING,
                title=item.get("title", "Supporting Evidence"),
                description=item.get("description", ""),
                code_reference=item.get("code_reference"),
                file_path=item.get("file_path"),
                line_numbers=item.get("line_numbers"),
                weight=float(item.get("weight", 1.0))
            ))

        # Parse opposing evidence items
        opposing_items = []
        for idx, item in enumerate(parsed.get("opposing_evidence", [])):
            cat = item.get("category", "SANITIZATION_DEFENSE")
            try:
                cat_enum = EvidenceCategory(cat)
            except ValueError:
                cat_enum = EvidenceCategory.SANITIZATION_DEFENSE

            opposing_items.append(EvidenceItem(
                id=item.get("id") or f"opp_{idx+1}",
                category=cat_enum,
                direction=EvidenceDirection.OPPOSING,
                title=item.get("title", "Opposing Evidence"),
                description=item.get("description", ""),
                code_reference=item.get("code_reference"),
                file_path=item.get("file_path"),
                line_numbers=item.get("line_numbers"),
                weight=float(item.get("weight", 1.0))
            ))

        # Determination mapping
        det_raw = parsed.get("proposed_determination", "NEEDS_REVIEW").upper()
        if "TRUE" in det_raw or "TP" in det_raw:
            det = DeterminationType.TRUE_POSITIVE
        elif "FALSE" in det_raw or "FP" in det_raw:
            det = DeterminationType.FALSE_POSITIVE
        elif "ACCEPTABLE" in det_raw:
            det = DeterminationType.ACCEPTABLE_RISK
        else:
            det = DeterminationType.NEEDS_REVIEW

        conf = float(parsed.get("preliminary_confidence", 0.7))
        conf = max(0.0, min(1.0, conf))

        return InvestigatorAssessment(
            alert_id=alert.alert_id,
            proposed_determination=det,
            claim_summary=parsed.get("claim_summary", alert.scanner_message),
            supporting_evidence=supporting_items,
            opposing_evidence=opposing_items,
            reasoning=parsed.get("reasoning", ""),
            source_analysis=parsed.get("source_analysis", ""),
            propagation_analysis=parsed.get("propagation_analysis", ""),
            sink_analysis=parsed.get("sink_analysis", ""),
            defenses_analysis=parsed.get("defenses_analysis", ""),
            preliminary_confidence=conf
        )
