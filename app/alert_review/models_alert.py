"""
Pydantic Models for AI Code-Scanning Alert Review Service.

Defines all data models across the 6 pipeline stages:
1. Alert Collector & Normalizer
2. Code Context Builder
3. AI Investigator
4. Evidence Verifier & Reviewer
5. Determination & Confidence Engine
6. Report Generator
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class DeterminationType(str, Enum):
    """Final determination of the alert validity."""
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    ACCEPTABLE_RISK = "ACCEPTABLE_RISK"


class AlertSeverity(str, Enum):
    """Standardized alert severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOTE = "NOTE"
    WARNING = "WARNING"
    ERROR = "ERROR"


class EvidenceCategory(str, Enum):
    """Categorization for structured evidence items."""
    SOURCE_VALIDITY = "SOURCE_VALIDITY"
    TAINT_PROPAGATION = "TAINT_PROPAGATION"
    SINK_EXPLOITABILITY = "SINK_EXPLOITABILITY"
    SANITIZATION_DEFENSE = "SANITIZATION_DEFENSE"
    ENVIRONMENT_DEFENSE = "ENVIRONMENT_DEFENSE"
    REACHABILITY = "REACHABILITY"


class EvidenceDirection(str, Enum):
    """Direction of evidence relative to the scanner finding."""
    SUPPORTING = "SUPPORTING"  # Supports scanner claim (indicates TRUE POSITIVE)
    OPPOSING = "OPPOSING"      # Refutes scanner claim (indicates FALSE POSITIVE or safe)


# ==========================================
# 1. Alert Collector & Normalizer Models
# ==========================================

class CodeFlowNode(BaseModel):
    """A single node/step in a CodeQL dataflow or taint tracking path."""
    file_path: str = Field(..., description="Relative file path")
    line_number: int = Field(..., description="Line number in source file")
    column: Optional[int] = Field(default=None, description="Column number")
    end_line: Optional[int] = Field(default=None, description="Ending line number if range")
    end_column: Optional[int] = Field(default=None, description="Ending column number")
    code_snippet: Optional[str] = Field(default=None, description="Snippet or symbol at step")
    function_name: Optional[str] = Field(default=None, description="Enclosing function name")
    description: Optional[str] = Field(default=None, description="Step description (e.g. 'read parameter')")
    step_type: str = Field(default="step", description="Node type: 'source', 'step', or 'sink'")


class CodeFlowPath(BaseModel):
    """A dataflow path from source to sink."""
    path_id: str = Field(default="flow_1", description="Identifier for this path")
    nodes: List[CodeFlowNode] = Field(default_factory=list, description="Ordered path hops")


class NormalizedAlert(BaseModel):
    """Normalized schema for static analysis alerts from any scanner."""
    alert_id: str = Field(..., description="Unique alert ID (e.g. repo#alert_num)")
    repo: str = Field(..., description="Full repo slug (org/repo)")
    commit_sha: str = Field(..., description="Analyzed commit SHA")
    ref: Optional[str] = Field(default=None, description="Branch or PR ref")
    tool_name: str = Field(default="CodeQL", description="Scanner name")
    tool_version: Optional[str] = Field(default=None, description="Scanner version")
    rule_id: str = Field(..., description="Scanner rule ID (e.g. 'js/sql-injection')")
    rule_name: str = Field(..., description="Readable rule name")
    rule_description: str = Field(..., description="Formal vulnerability description")
    severity: AlertSeverity = Field(default=AlertSeverity.HIGH)
    cwe_ids: List[str] = Field(default_factory=list, description="Associated CWEs")
    primary_location: CodeFlowNode = Field(..., description="Primary issue location")
    code_flows: List[CodeFlowPath] = Field(default_factory=list, description="Taint tracking paths")
    scanner_message: str = Field(..., description="Scanner finding message")
    source_url: Optional[str] = Field(default=None, description="Link to alert in GitHub")
    raw_scanner_output: Optional[Dict[str, Any]] = Field(default=None, description="Original raw payload")


# ==========================================
# 2. Code Context Builder Models
# ==========================================

class CodeContextSnippet(BaseModel):
    """Enriched source snippet for a specific location."""
    file_path: str
    start_line: int
    end_line: int
    content: str
    enclosing_symbol: Optional[str] = None
    role: str = Field(default="context", description="Role: 'source', 'path_step', 'sink', 'sanitizer'")


class AlertCodeContext(BaseModel):
    """Enriched code context bundle around the alert at the analyzed commit."""
    alert_id: str
    commit_sha: str
    source_slices: List[CodeContextSnippet] = Field(default_factory=list)
    path_slices: List[CodeContextSnippet] = Field(default_factory=list)
    sink_slices: List[CodeContextSnippet] = Field(default_factory=list)
    related_files: List[str] = Field(default_factory=list)
    imported_modules: List[str] = Field(default_factory=list)
    detected_frameworks: List[str] = Field(default_factory=list)
    detected_middleware: List[str] = Field(default_factory=list)
    context_token_estimate: int = Field(default=0)


# ==========================================
# 3. AI Investigator Models
# ==========================================

class EvidenceItem(BaseModel):
    """Granular piece of evidence for or against alert validity."""
    id: str = Field(..., description="Unique evidence ID")
    category: EvidenceCategory
    direction: EvidenceDirection
    title: str
    description: str
    code_reference: Optional[str] = Field(default=None, description="Exact code snippet cited")
    file_path: Optional[str] = None
    line_numbers: Optional[List[int]] = None
    weight: float = Field(default=1.0, ge=0.5, le=5.0, description="Significance weight")


class InvestigatorAssessment(BaseModel):
    """Output from the AI Investigator reviewing the scanner's claim."""
    alert_id: str
    proposed_determination: DeterminationType
    claim_summary: str
    supporting_evidence: List[EvidenceItem] = Field(default_factory=list)
    opposing_evidence: List[EvidenceItem] = Field(default_factory=list)
    reasoning: str
    source_analysis: str
    propagation_analysis: str
    sink_analysis: str
    defenses_analysis: str
    preliminary_confidence: float = Field(ge=0.0, le=1.0)


# ==========================================
# 4. Evidence Verifier & Reviewer Models
# ==========================================

class ChallengeItem(BaseModel):
    """Adversarial check challenging the investigator's reasoning."""
    id: str
    target_evidence_id: Optional[str] = None
    challenge_question: str
    counter_argument: str
    challenged_assumption: str
    challenge_resolution: str
    was_adversarial_counter_valid: bool


class VerificationReport(BaseModel):
    """Output from the adversarial verifier reviewing the investigator."""
    alert_id: str
    grounding_score: float = Field(ge=0.0, le=1.0, description="Fraction of references grounded in real code")
    ungrounded_claims: List[str] = Field(default_factory=list)
    challenges: List[ChallengeItem] = Field(default_factory=list)
    consensus_with_investigator: bool
    suggested_determination: DeterminationType
    missing_context_flags: List[str] = Field(default_factory=list)
    verifier_notes: str


# ==========================================
# 5. Determination & Confidence Engine Models
# ==========================================

class ConfidenceScore(BaseModel):
    """Calibrated confidence evaluation."""
    score: float = Field(ge=0.0, le=1.0, description="Calculated confidence 0.0 to 1.0")
    qualitative_level: str = Field(description="HIGH, MEDIUM, or LOW")
    grounding_factor: float
    flow_completeness_factor: float
    consensus_factor: float
    assumption_penalty: float
    explanation: str


class RemediationPlan(BaseModel):
    """Actionable remediation guidance."""
    action_type: str = Field(description="CODE_FIX, DISMISS_ALERT, ADD_SANITIZER, MANUAL_INVESTIGATION")
    suggested_fix_code: Optional[str] = None
    fix_explanation: Optional[str] = None
    dismissal_reason: Optional[str] = None  # 'false positive' or 'won't fix'
    dismissal_comment: Optional[str] = None
    codeql_modeling_recommendation: Optional[str] = None


# ==========================================
# 6. Report Generator & Storage Models
# ==========================================

class TriageReport(BaseModel):
    """Complete AppSec triage report."""
    alert_id: str
    repo: str
    commit_sha: str
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    determination: DeterminationType
    confidence: ConfidenceScore
    executive_summary: str
    scanner_claim: str
    investigator_assessment: InvestigatorAssessment
    verification_report: VerificationReport
    remediation: RemediationPlan
    limitations: List[str] = Field(default_factory=list)
    markdown_report: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent_version: str = Field(default="1.0.0-alert-review")


class HumanTriageFeedback(BaseModel):
    """Human AppSec engineer outcome for calibration."""
    alert_id: str
    repo: str
    human_verdict: DeterminationType
    human_notes: Optional[str] = None
    reviewer_id: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CalibrationMetrics(BaseModel):
    """Calibration statistics over historical triage runs."""
    total_reviewed_by_human: int
    true_positive_agreement_count: int
    false_positive_agreement_count: int
    overall_accuracy: float
    brier_score: float = Field(description="Mean squared error between confidence score and ground truth (lower is better)")
    precision: float
    recall: float
    confidence_bucket_stats: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
