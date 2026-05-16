"""
Pydantic models for request/response validation.

Defines the data structures for the /review-pr endpoint.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Security risk severity levels."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class PolicyMode(str, Enum):
    """Policy enforcement mode."""
    ADVISORY = "advisory"  # Always pass, just comment
    ENFORCE = "enforce"    # Fail PR when high risk exists


class ConfidenceLevel(str, Enum):
    """Confidence levels for findings."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEEDS_REVIEW = "NEEDS_REVIEW"  # Uncertain - requires manual verification


class FindingStatus(str, Enum):
    """Finding lifecycle status."""
    OPEN = "open"                      # Active issue that needs fixing
    RESOLVED = "resolved"              # Fixed in code
    ACCEPTED_RISK = "accepted_risk"    # Won't fix, documented acceptance
    FALSE_POSITIVE = "false_positive"  # Not a real issue
    WONT_FIX = "wont_fix"              # Known limitation, won't address


class ResolutionMethod(str, Enum):
    """How a finding was resolved."""
    AUTOMATIC = "automatic"    # Code was removed/changed
    MANUAL = "manual"          # User manually marked it
    CLEAN_PR = "clean_pr"      # PR passed with 0 findings


class RepoPolicy(BaseModel):
    """
    Repository-level security policy configuration.
    
    Can be provided in the request or loaded from .aiappsec.yml in the repo.
    """
    mode: PolicyMode = Field(
        default=PolicyMode.ADVISORY,
        description="Enforcement mode: 'advisory' (comment only) or 'enforce' (fail PR on high risk)"
    )
    fail_on: RiskLevel = Field(
        default=RiskLevel.HIGH,
        description="Risk level threshold for failing PR in enforce mode (HIGH or MEDIUM)"
    )
    max_findings: int = Field(
        default=10,
        description="Maximum number of findings to report",
        ge=1,
        le=50
    )
    min_risk: RiskLevel = Field(
        default=RiskLevel.LOW,
        description="Minimum risk level to report"
    )
    min_confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.LOW,
        description="Minimum confidence level to report (also used for gate)"
    )
    blocklist: list[str] = Field(
        default_factory=list,
        description="Path patterns to exclude from review (e.g., 'test/', '*.spec.js')"
    )
    rules: dict[str, bool] = Field(
        default_factory=lambda: {
            "injection": True,
            "secrets": True,
            "auth": True,
            "ssrf": True,
            "crypto": True,
            "deserialization": True,
        },
        description="Enable/disable specific vulnerability categories"
    )


class ReviewRequest(BaseModel):
    """
    Request model for the /review-pr endpoint.
    
    Contains all the information needed to perform a security review
    of a pull request's code changes.
    """
    repo: str = Field(
        ...,
        description="Repository identifier in 'org/reponame' format",
        examples=["myorg/myapp"]
    )
    pr_number: int = Field(
        ...,
        description="Pull request number",
        ge=1,
        examples=[123]
    )
    language: str = Field(
        default="nodejs",
        description="Primary programming language of the codebase",
        examples=["nodejs", "python", "java"]
    )
    framework: str = Field(
        default="express",
        description="Web framework used in the codebase",
        examples=["express", "fastapi", "spring"]
    )
    diff: str = Field(
        ...,
        description="Git diff text containing the code changes to review",
        min_length=1
    )
    policy: Optional[RepoPolicy] = Field(
        default=None,
        description="Optional repository policy to apply"
    )
    # Previous findings fingerprints for deduplication
    previous_fingerprints: list[str] = Field(
        default_factory=list,
        description="Fingerprints from previous review run for deduplication"
    )
    # HMAC signature for request authentication
    signature: Optional[str] = Field(
        default=None,
        description="HMAC-SHA256 signature of the request body"
    )
    timestamp: Optional[int] = Field(
        default=None,
        description="Unix timestamp when the request was signed"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "repo": "myorg/myapp",
                    "pr_number": 42,
                    "language": "nodejs",
                    "framework": "express",
                    "diff": "diff --git a/src/app.js b/src/app.js\n...",
                    "policy": {
                        "max_findings": 5,
                        "min_risk": "MEDIUM",
                        "blocklist": ["test/", "*.spec.js"]
                    }
                }
            ]
        }
    }


class SecurityFinding(BaseModel):
    """
    Represents a single security vulnerability finding.
    
    Contains all the details a developer needs to understand
    and fix the security issue.
    """
    title: str = Field(
        ...,
        description="Brief title describing the vulnerability",
        examples=["Possible SQL injection in user lookup"]
    )
    risk: RiskLevel = Field(
        ...,
        description="Severity level of the vulnerability"
    )
    confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.MEDIUM,
        description="How confident we are this is a real vulnerability"
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Path to the file containing the vulnerability",
        examples=["src/controllers/userController.js"]
    )
    line_range: Optional[str] = Field(
        default=None,
        description="Line numbers where the vulnerability exists",
        examples=["45-60", "23"]
    )
    line_start: Optional[int] = Field(
        default=None,
        description="Starting line number in the new version of the file"
    )
    line_end: Optional[int] = Field(
        default=None,
        description="Ending line number in the new version of the file"
    )
    original_code: Optional[str] = Field(
        default=None,
        description="Original vulnerable code from the diff for reference"
    )
    suggested_fix: Optional[str] = Field(
        default=None,
        description="Code suggestion for GitHub one-click fix"
    )
    evidence: Optional[str] = Field(
        default=None,
        description="Exact diff snippet line(s) showing the vulnerability",
        examples=["const query = `SELECT * FROM users WHERE id = ${userId}`"]
    )
    description: Optional[str] = Field(
        default=None,
        description="Detailed explanation of what is wrong"
    )
    impact: Optional[str] = Field(
        default=None,
        description="What an attacker could do by exploiting this vulnerability"
    )
    recommendation: Optional[str] = Field(
        default=None,
        description="How to fix the vulnerability"
    )
    example_fix: Optional[str] = Field(
        default=None,
        description="Example code showing the secure implementation"
    )
    owasp: Optional[str] = Field(
        default=None,
        description="Matching OWASP Top 10 category",
        examples=["A03:2021 Injection"]
    )
    cwe: Optional[str] = Field(
        default=None,
        description="Matching CWE identifier",
        examples=["CWE-89"]
    )
    # Fingerprint for deduplication across runs
    fingerprint: Optional[str] = Field(
        default=None,
        description="Unique fingerprint for deduplication: hash(file_path + title + risk + line_range)"
    )
    # Track if this finding existed in previous run
    is_new: bool = Field(
        default=True,
        description="Whether this is a new finding or still present from previous run"
    )
    # Status for tracking finding lifecycle
    status: str = Field(
        default="open",
        description="Finding status: open, resolved, false_positive, accepted_risk"
    )
    # Additional fields from database
    id: Optional[str] = Field(
        default=None,
        description="Unique identifier for the finding (set by database)"
    )
    category: Optional[str] = Field(
        default=None,
        description="Vulnerability category (e.g., injection, auth, secrets)"
    )
    resolution_method: Optional[str] = Field(
        default=None,
        description="How the finding was resolved: automatic, manual, clean_pr"
    )
    resolved_at: Optional[str] = Field(
        default=None,
        description="ISO timestamp when the finding was resolved"
    )
    resolved_by_user_id: Optional[str] = Field(
        default=None,
        description="User ID who resolved the finding"
    )
    resolved_reason: Optional[str] = Field(
        default=None,
        description="Reason for resolution"
    )
    resolved_notes: Optional[str] = Field(
        default=None,
        description="Additional notes about the resolution"
    )
    created_at: Optional[str] = Field(
        default=None,
        description="ISO timestamp when the finding was created"
    )


class ReviewResponse(BaseModel):
    """
    Response model for the /review-pr endpoint.
    
    Contains the complete security review results including
    structured findings and a formatted markdown comment.
    """
    summary: str = Field(
        ...,
        description="Brief summary of the security review results",
        examples=["Found 1 high and 1 medium risk issue in this PR."]
    )
    findings: list[SecurityFinding] = Field(
        default_factory=list,
        description="List of security vulnerabilities found"
    )
    findings_markdown: str = Field(
        ...,
        description="Markdown-formatted review comment for posting on the PR"
    )
    # Metadata about filtering applied
    total_findings_before_filter: int = Field(
        default=0,
        description="Total findings found before policy filters were applied"
    )
    filtered_by_policy: bool = Field(
        default=False,
        description="Whether any findings were filtered by policy"
    )
    needs_manual_review: list[SecurityFinding] = Field(
        default_factory=list,
        description="Findings marked as needing manual review (low confidence)"
    )
    # For deduplication - unique hash of findings
    findings_hash: Optional[str] = Field(
        default=None,
        description="Hash of findings for deduplication"
    )
    # Enforcement mode result
    should_block: bool = Field(
        default=False,
        description="Whether the PR should be blocked (enforce mode with high risk findings)"
    )
    # Enforcement mode availability
    enforcement_available: bool = Field(
        default=True,
        description="Whether enforcement mode is available for this organization"
    )
    enforcement_downgraded: bool = Field(
        default=False,
        description="Whether enforcement mode was downgraded to advisory due to plan limits"
    )
    # All fingerprints from this run (for passing to next run)
    fingerprints: list[str] = Field(
        default_factory=list,
        description="All finding fingerprints from this run for deduplication"
    )
    # Count of new vs still-present findings
    new_findings_count: int = Field(
        default=0,
        description="Number of new findings in this run"
    )
    still_present_count: int = Field(
        default=0,
        description="Number of findings still present from previous run"
    )
    # Count of resolved findings from previous run
    resolved_findings_count: int = Field(
        default=0,
        description="Number of findings resolved since previous run"
    )
    # Detailed resolved findings information
    resolved_findings: list[dict] = Field(
        default_factory=list,
        description="Findings that were present in previous run but resolved now"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "summary": "Found 1 high risk issue in this PR.",
                    "findings": [
                        {
                            "title": "Possible SQL injection in user lookup",
                            "risk": "HIGH",
                            "confidence": "HIGH",
                            "evidence": "const query = `SELECT * FROM users WHERE id = ${userId}`",
                            "file": "src/controllers/userController.js",
                            "line_range": "45-60",
                            "description": "User input is concatenated directly into SQL query.",
                            "impact": "Attacker can execute arbitrary SQL queries.",
                            "recommendation": "Use parameterized queries.",
                            "example_fix": "db.query('SELECT * FROM users WHERE id = ?', [userId])",
                            "owasp": "A03:2021 Injection",
                            "cwe": "CWE-89"
                        }
                    ],
                    "findings_markdown": "### 🔒 AI Security Review\n\n**Summary:** Found 1 high risk issue.\n\n...",
                    "total_findings_before_filter": 2,
                    "filtered_by_policy": True
                }
            ]
        }
    }


class ErrorResponse(BaseModel):
    """Standard error response model."""
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(default=None, description="Error code for programmatic handling")


# ============================================================================
# Explain Finding Models (for SAST integration)
# ============================================================================

class ExplainFindingRequest(BaseModel):
    """
    Request model for the /explain-finding endpoint.
    
    Used to get plain English explanations of findings from external
    SAST tools like Fortify, Semgrep, or CodeQL.
    """
    tool: str = Field(
        ...,
        description="Name of the SAST tool (e.g., 'fortify', 'semgrep', 'codeql', 'snyk')",
        examples=["fortify", "semgrep", "codeql"]
    )
    finding_text: str = Field(
        ...,
        description="Raw finding text/output from the SAST tool",
        min_length=1
    )
    code_snippet: Optional[str] = Field(
        default=None,
        description="Code snippet where the finding was detected"
    )
    file_path: Optional[str] = Field(
        default=None,
        description="Path to the file containing the finding"
    )
    language: str = Field(
        default="unknown",
        description="Programming language of the code",
        examples=["javascript", "python", "java"]
    )
    # Optional context
    rule_id: Optional[str] = Field(
        default=None,
        description="Rule ID from the SAST tool",
        examples=["java.lang.security.audit.sqli", "CWE-89"]
    )


class ExplainFindingResponse(BaseModel):
    """
    Response model for the /explain-finding endpoint.
    
    Provides plain English explanation, remediation guidance,
    and risk justification for SAST findings.
    """
    explanation: str = Field(
        ...,
        description="Plain English explanation of what the finding means"
    )
    risk_justification: str = Field(
        ...,
        description="Why this is a security risk and its potential impact"
    )
    remediation: str = Field(
        ...,
        description="Step-by-step guidance on how to fix the issue"
    )
    example_fix: Optional[str] = Field(
        default=None,
        description="Example code showing the secure implementation"
    )
    severity: RiskLevel = Field(
        ...,
        description="Assessed severity level"
    )
    confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.MEDIUM,
        description="Confidence in this assessment"
    )
    references: list[str] = Field(
        default_factory=list,
        description="Relevant references (OWASP, CWE, documentation links)"
    )
    # Metadata
    tool: str = Field(
        ...,
        description="The SAST tool that generated the original finding"
    )
    original_rule_id: Optional[str] = Field(
        default=None,
        description="Original rule ID from the tool"
    )


# ============================================================================
# Metrics Models
# ============================================================================

class ReviewMetrics(BaseModel):
    """Metrics for a single review."""
    repo: str
    pr_number: int
    review_time_ms: int
    findings_count: int
    high_count: int
    medium_count: int
    low_count: int
    needs_review_count: int
    success: bool
    error_type: Optional[str] = None
    timestamp: str


class AggregatedMetrics(BaseModel):
    """Aggregated metrics for the service."""
    total_prs_reviewed: int = Field(default=0, description="Total PRs reviewed")
    total_findings: int = Field(default=0, description="Total findings across all reviews")
    findings_by_category: dict[str, int] = Field(
        default_factory=dict,
        description="Findings count by category (injection, secrets, etc.)"
    )
    findings_by_risk: dict[str, int] = Field(
        default_factory=lambda: {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        description="Findings count by risk level"
    )
    avg_review_time_ms: float = Field(default=0, description="Average review time in milliseconds")
    success_rate: float = Field(default=0, description="Percentage of successful reviews")
    total_success: int = Field(default=0, description="Total successful reviews")
    total_failure: int = Field(default=0, description="Total failed reviews")
    uptime_seconds: int = Field(default=0, description="Service uptime in seconds")


# ============================================================================
# Sprint 3: Multi-Tenant & Token Models
# ============================================================================

class TokenScope(str, Enum):
    """Available token scopes."""
    REVIEW_PR = "review:pr"
    EXPLAIN_FINDING = "explain:finding"
    ADMIN_POLICY = "admin:policy"
    ADMIN_TOKENS = "admin:tokens"
    READ_METRICS = "read:metrics"
    FEEDBACK = "feedback:write"
    ALL = "*"


class TokenType(str, Enum):
    """Simplified token types for better UX.
    
    Only CI/CD tokens are supported - they are exclusively for GitHub Actions.
    Frontend/dashboard access uses Supabase JWT only.
    """
    CICD = "cicd"
    CUSTOM = "custom"  # Legacy support - treated same as cicd


class TokenCreateRequest(BaseModel):
    """Request to create a new API token.
    
    Only CI/CD tokens can be created - they are exclusively for GitHub Actions.
    Frontend/dashboard uses Supabase JWT authentication.
    """
    name: str = Field(..., description="Human-readable name for the token", min_length=1, max_length=100)
    token_type: Optional[TokenType] = Field(
        default=TokenType.CICD,
        description="Token type - only 'cicd' is supported. CI/CD tokens are for GitHub Actions only."
    )
    scopes: Optional[list[str]] = Field(
        default=None,
        description="[Deprecated] List of permission scopes. Use token_type instead."
    )
    expires_in_days: Optional[int] = Field(
        default=None,
        description="Number of days until token expires (null = never)",
        ge=1,
        le=365
    )


class TokenCreateResponse(BaseModel):
    """Response after creating a new API token."""
    token: str = Field(..., description="The API token - SAVE THIS, it won't be shown again!")
    id: str = Field(..., description="Token ID for management")
    name: str = Field(..., description="Token name")
    prefix: str = Field(..., description="Token prefix for identification")
    token_type: TokenType = Field(..., description="Token type")
    scopes: list[str] = Field(..., description="Token scopes")
    expires_at: Optional[str] = Field(default=None, description="Expiration timestamp")
    created_at: str = Field(..., description="Creation timestamp")


class TokenInfo(BaseModel):
    """Token information (without the actual token)."""
    id: str
    name: str
    prefix: str
    token_type: TokenType = Field(default=TokenType.CUSTOM, description="Token type")
    scopes: list[str]
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    last_used_at: Optional[str] = None
    created_at: str


class CicdTokenResponse(BaseModel):
    """Response for CI/CD token endpoint."""
    id: str
    name: str
    prefix: str
    token_type: TokenType
    scopes: list[str]
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    last_used_at: Optional[str] = None
    created_at: str
    # Note: The actual token is only returned once during creation
    has_token: bool = Field(..., description="Whether this org has a CI/CD token configured")


class RegenerateCicdTokenResponse(BaseModel):
    """Response after regenerating CI/CD token."""
    token: str = Field(..., description="The new CI/CD token - SAVE THIS, it won't be shown again!")
    id: str
    name: str
    prefix: str
    token_type: TokenType
    scopes: list[str]
    created_at: str


class TokenTypeInfo(BaseModel):
    """Information about a token type."""
    id: TokenType
    name: str
    description: str
    scopes: list[str]
    auto_generate: bool
    recommended_use: str


class TokenTypesResponse(BaseModel):
    """Response listing available token types."""
    token_types: list[TokenTypeInfo] = Field(..., description="Available token types with their details")


class TokenListResponse(BaseModel):
    """List of API tokens."""
    tokens: list[TokenInfo] = Field(default_factory=list)
    total: int = Field(default=0)


class SwitchOrgResponse(BaseModel):
    """Response after switching organization.
    
    Used for JWT-based organization switching. No API token is returned
    since frontend uses JWT for authentication.
    """
    success: bool = Field(..., description="Whether the switch was successful")
    org_id: str = Field(..., description="Organization ID")
    org_name: str = Field(..., description="Organization name")
    org_slug: str = Field(..., description="Organization slug")
    role: str = Field(..., description="User's role in the organization")


# ============================================================================
# Sprint 3: Dashboard Models
# ============================================================================

class DashboardStatsResponse(BaseModel):
    """Dashboard statistics response."""
    total_reviews: int = Field(default=0, description="Total PRs reviewed")
    total_findings: int = Field(default=0, description="Total findings")
    high_findings: int = Field(default=0, description="High severity findings")
    medium_findings: int = Field(default=0, description="Medium severity findings")
    low_findings: int = Field(default=0, description="Low severity findings")
    avg_review_time_ms: float = Field(default=0, description="Average review time")
    success_rate: float = Field(default=0, description="Review success rate %")
    blocked_count: int = Field(default=0, description="PRs blocked by policy")
    resolved_findings: int = Field(default=0, description="Total resolved findings")
    period_days: int = Field(default=30, description="Stats period in days")


class CategoryStats(BaseModel):
    """Finding category statistics."""
    category: str
    count: int


class CategoryStatsResponse(BaseModel):
    """Category statistics response."""
    categories: list[CategoryStats] = Field(default_factory=list)
    period_days: int = Field(default=30)


class RepoRisk(BaseModel):
    """Repository risk information."""
    repo_name: str
    review_count: int
    total_findings: int
    high_findings: int
    risk_score: float


class RepoRiskResponse(BaseModel):
    """Top risky repositories response."""
    repos: list[RepoRisk] = Field(default_factory=list)
    period_days: int = Field(default=30)


class TrendDataPoint(BaseModel):
    """Single data point for trend chart."""
    date: str
    review_count: int
    findings_count: int
    high_count: int


class TrendDataResponse(BaseModel):
    """Trend data response."""
    data: list[TrendDataPoint] = Field(default_factory=list)
    period_days: int = Field(default=30)


# ============================================================================
# Sprint 3: Feedback Models
# ============================================================================

class FeedbackLabel(str, Enum):
    """Feedback labels for findings."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class FeedbackRequest(BaseModel):
    """Request to submit feedback on a finding."""
    fingerprint: str = Field(..., description="Finding fingerprint")
    label: FeedbackLabel = Field(..., description="Feedback label")
    finding_id: Optional[str] = Field(default=None, description="Finding ID if known")
    repo_name: Optional[str] = Field(default=None, description="Repository name")
    comment: Optional[str] = Field(default=None, description="Optional comment", max_length=1000)
    github_user: Optional[str] = Field(default=None, description="GitHub username if from PR comment")


class FeedbackResponse(BaseModel):
    """Response after submitting feedback."""
    id: str = Field(..., description="Feedback ID")
    fingerprint: str
    label: str
    created_at: str
    suppression_created: bool = Field(
        default=False,
        description="Whether a suppression rule was auto-created"
    )


class FeedbackStats(BaseModel):
    """Feedback statistics."""
    true_positive: int = 0
    false_positive: int = 0
    accepted_risk: int = 0
    total: int = 0


# ============================================================================
# Sprint 3: Chat Models
# ============================================================================

class ChatCommand(str, Enum):
    """Available chat commands."""
    EXPLAIN = "explain"
    FIX = "fix"
    WHY = "why"
    ASK = "ask"


class ChatRequest(BaseModel):
    """Request for AI chat in PR."""
    repo_name: str = Field(..., description="Repository name (org/repo)")
    pr_number: int = Field(..., description="Pull request number")
    command: ChatCommand = Field(..., description="Chat command")
    finding_number: Optional[int] = Field(
        default=None,
        description="Finding number (1-indexed) for explain/fix/why commands"
    )
    question: Optional[str] = Field(
        default=None,
        description="Question for 'ask' command",
        max_length=1000
    )
    github_user: Optional[str] = Field(default=None, description="GitHub username")


class ChatResponse(BaseModel):
    """Response from AI chat."""
    response: str = Field(..., description="AI response (markdown)")
    command: str = Field(..., description="Command that was executed")
    finding_title: Optional[str] = Field(default=None, description="Related finding title")


# ============================================================================
# Sprint 3: Repository Config Models
# ============================================================================

class RepoConfigRequest(BaseModel):
    """Request to create/update repository configuration."""
    repo_name: str = Field(..., description="Repository name (org/repo)")
    policy: Optional[RepoPolicy] = Field(default=None, description="Security policy")
    enabled: bool = Field(default=True, description="Whether reviews are enabled")


class RepoConfigResponse(BaseModel):
    """Repository configuration response."""
    id: str
    repo_name: str
    policy: dict
    enabled: bool
    created_at: str
    updated_at: str
    source: Optional[str] = Field(default="manual", description="Repository source: github or manual")
    github_repo_id: Optional[str] = Field(default=None, description="GitHub repository ID if imported from GitHub")


class RepoConfigListResponse(BaseModel):
    """List of repository configurations."""
    configs: list[RepoConfigResponse] = Field(default_factory=list)
    total: int = Field(default=0)


# ============================================================================
# Sprint 3: Suppression Rule Models
# ============================================================================

class SuppressionRuleRequest(BaseModel):
    """Request to create a suppression rule."""
    reason: str = Field(..., description="Reason for suppression", min_length=1, max_length=500)
    fingerprint: Optional[str] = Field(default=None, description="Exact fingerprint to match")
    title_pattern: Optional[str] = Field(default=None, description="Regex pattern for title")
    file_pattern: Optional[str] = Field(default=None, description="Glob pattern for file path")
    category: Optional[str] = Field(default=None, description="Category to suppress")
    expires_in_days: Optional[int] = Field(default=None, description="Days until expiration", ge=1, le=365)


class SuppressionRuleResponse(BaseModel):
    """Suppression rule response."""
    id: str
    fingerprint: Optional[str] = None
    title_pattern: Optional[str] = None
    file_pattern: Optional[str] = None
    category: Optional[str] = None
    reason: str
    is_active: bool
    expires_at: Optional[str] = None
    created_at: str


class SuppressionRuleListResponse(BaseModel):
    """List of suppression rules."""
    rules: list[SuppressionRuleResponse] = Field(default_factory=list)
    total: int = Field(default=0)


# ============================================================================
# GitHub Integration Models
# ============================================================================

class GitHubRepoInfo(BaseModel):
    """GitHub repository information."""
    id: int = Field(..., description="GitHub repo ID")
    name: str = Field(..., description="Repository name")
    full_name: str = Field(..., description="Full name (owner/repo)")
    owner: str = Field(..., description="Repository owner")
    private: bool = Field(..., description="Is private repository")
    description: Optional[str] = Field(default=None, description="Repository description")
    default_branch: str = Field(default="main", description="Default branch")
    html_url: str = Field(..., description="GitHub URL")
    can_push: bool = Field(default=False, description="User can push to repo")
    can_admin: bool = Field(default=False, description="User has admin access")
    # Import status (added when checking against repo_configs)
    imported: bool = Field(default=False, description="Already imported to AI AppSec")
    workflow_installed: bool = Field(default=False, description="Security workflow installed")


class GitHubReposResponse(BaseModel):
    """List of GitHub repositories."""
    repos: list[GitHubRepoInfo] = Field(default_factory=list)
    total: int = Field(default=0)
    github_user: Optional[str] = Field(default=None, description="Authenticated GitHub user")


class GitHubImportRequest(BaseModel):
    """Request to import GitHub repos."""
    repos: list[str] = Field(
        ..., 
        description="List of repo full names to import (owner/repo)",
        min_length=1,
        max_length=50
    )
    default_policy: Optional[RepoPolicy] = Field(
        default=None,
        description="Default policy for imported repos"
    )


class GitHubImportResult(BaseModel):
    """Result of importing a single repo."""
    repo_name: str
    success: bool
    error: Optional[str] = None
    config_id: Optional[str] = None


class GitHubImportResponse(BaseModel):
    """Response from bulk repo import."""
    results: list[GitHubImportResult] = Field(default_factory=list)
    total_imported: int = Field(default=0)
    total_failed: int = Field(default=0)


class WorkflowStatusResponse(BaseModel):
    """Workflow installation status."""
    installed: bool = Field(..., description="Is workflow installed")
    path: str = Field(..., description="Workflow file path")
    sha: Optional[str] = Field(default=None, description="File SHA if exists")
    version: Optional[str] = Field(default=None, description="Workflow version")


class WorkflowInstallRequest(BaseModel):
    """Request to install workflow in a repo."""
    repos: list[str] = Field(
        ...,
        description="List of repo full names (owner/repo)",
        min_length=1,
        max_length=20
    )


class WorkflowInstallResult(BaseModel):
    """Result of installing workflow in a single repo."""
    repo_name: str
    success: bool
    action: str = Field(..., description="Action taken: created, updated, failed")
    error: Optional[str] = None
    commit_sha: Optional[str] = None


class WorkflowInstallResponse(BaseModel):
    """Response from bulk workflow installation."""
    results: list[WorkflowInstallResult] = Field(default_factory=list)
    total_success: int = Field(default=0)
    total_failed: int = Field(default=0)


class QuickSetupRequest(BaseModel):
    """Request for one-step org + token setup."""
    org_name: str = Field(..., description="Organization name", min_length=1, max_length=100)
    org_slug: Optional[str] = Field(default=None, description="Organization slug (auto-generated if not provided)")
    token_name: str = Field(default="GitHub Actions Token", description="API token name")


class QuickSetupResponse(BaseModel):
    """Response from quick setup."""
    org_id: str = Field(..., description="Organization ID")
    org_name: str = Field(..., description="Organization name")
    org_slug: str = Field(..., description="Organization slug")
    api_token: str = Field(..., description="API token - SAVE THIS!")
    token_prefix: str = Field(..., description="Token prefix for identification")
    # Instructions for GitHub Actions
    secrets_to_add: dict = Field(
        default_factory=dict,
        description="Secrets to add to GitHub repos"
    )


class CreateOrgRequest(BaseModel):
    """Request for creating an organization."""
    org_name: str = Field(..., description="Organization name", min_length=1, max_length=100)
    org_slug: Optional[str] = Field(default=None, description="Organization slug (auto-generated if not provided)")


class CreateOrgResponse(BaseModel):
    """Response from organization creation."""
    org_id: str = Field(..., description="Organization ID")
    org_name: str = Field(..., description="Organization name")
    org_slug: str = Field(..., description="Organization slug")
    api_token: str = Field(..., description="Bootstrap API token - SAVE THIS!")
    token_prefix: str = Field(..., description="Token prefix for identification")

class CreateInvitationRequest(BaseModel):
    """Request to invite a user to an organization."""
    email: str = Field(..., description="Email address of user to invite", min_length=3)
    role: str = Field(default="member", description="Role to assign (admin or member)")
    expires_in_days: int = Field(default=7, description="Days until invitation expires", ge=1, le=30)


class InvitationResponse(BaseModel):
    """Response with invitation details."""
    id: str = Field(..., description="Invitation ID")
    email: str = Field(..., description="Invited email address")
    role: str = Field(..., description="Role to be assigned")
    invite_token: str = Field(..., description="Invitation token")
    invite_url: str = Field(..., description="Full invitation URL")
    expires_at: str = Field(..., description="Expiration timestamp")
    created_at: str = Field(..., description="Creation timestamp")


class AcceptInvitationRequest(BaseModel):
    """Request to accept an invitation."""
    invite_token: str = Field(..., description="Invitation token from email/link", min_length=32)


class AcceptInvitationResponse(BaseModel):
    """Response after accepting invitation."""
    org_id: str = Field(..., description="Organization ID")
    org_name: str = Field(..., description="Organization name")
    org_slug: str = Field(..., description="Organization slug")
    role: str = Field(..., description="Your role in the organization")
    message: str = Field(default="Successfully joined organization")


# ============================================================================
# Finding Resolution Models
# ============================================================================

class ResolveFindingRequest(BaseModel):
    """Request to resolve a finding manually."""
    finding_id: str = Field(..., description="UUID of the finding to resolve")
    status: FindingStatus = Field(..., description="New status for the finding")
    reason: Optional[str] = Field(default=None, description="Short reason for resolution")
    notes: Optional[str] = Field(default=None, description="Detailed notes about resolution")


class BulkResolveFindingsRequest(BaseModel):
    """Request to bulk resolve multiple findings."""
    finding_ids: list[str] = Field(..., description="List of finding UUIDs", min_length=1)
    status: FindingStatus = Field(..., description="New status for all findings")
    reason: Optional[str] = Field(default=None, description="Short reason for resolution")
    notes: Optional[str] = Field(default=None, description="Detailed notes about resolution")


class ReopenFindingRequest(BaseModel):
    """Request to reopen a resolved finding."""
    finding_id: str = Field(..., description="UUID of the finding to reopen")
    reason: Optional[str] = Field(default=None, description="Reason for reopening")


class ResolutionResponse(BaseModel):
    """Response after resolving finding(s)."""
    success: bool = Field(..., description="Whether the operation succeeded")
    count: int = Field(default=1, description="Number of findings affected")
    message: str = Field(..., description="Human-readable result message")


class FindingStatusHistory(BaseModel):
    """Finding status change history entry."""
    id: str
    old_status: str
    new_status: str
    changed_by_user_id: Optional[str] = None
    change_method: str
    reason: Optional[str] = None
    notes: Optional[str] = None
    created_at: str



class PendingInvitation(BaseModel):
    """Pending invitation details."""
    id: str = Field(..., description="Invitation ID")
    email: str = Field(..., description="Invited email")
    role: str = Field(..., description="Role")
    invite_token: str = Field(..., description="Invitation token")
    invited_by_email: str = Field(..., description="Who sent the invitation")
    expires_at: str = Field(..., description="Expiration timestamp")
    created_at: str = Field(..., description="Creation timestamp")


class InvitationListResponse(BaseModel):
    """List of pending invitations."""
    invitations: list[PendingInvitation] = Field(default_factory=list)
    total: int = Field(default=0)


# ============================================================================
# Pricing & Subscription Models
# ============================================================================

class PlanFeatures(BaseModel):
    """Features available in a pricing plan."""
    advisory_mode: bool = Field(default=True, description="Advisory mode (comment only)")
    enforcement_mode: bool = Field(default=False, description="Enforcement mode (block PRs)")
    dashboard: bool = Field(default=False, description="Dashboard access")
    audit_logs: bool = Field(default=False, description="Audit logs access")
    sso: bool = Field(default=False, description="SSO/SAML integration")
    policy_as_code: bool = Field(default=False, description="Policy as code support")
    siem_integration: bool = Field(default=False, description="SIEM integration")
    custom_rules: bool = Field(default=False, description="Custom security rules")
    priority_support: bool = Field(default=False, description="Priority email support")
    dedicated_support: bool = Field(default=False, description="Dedicated support manager")


class PlanLimits(BaseModel):
    """Usage limits for a pricing plan."""
    max_repos: int = Field(default=1, description="Max repositories (-1 = unlimited)")
    max_prs_per_month: int = Field(default=30, description="Max PRs per month (-1 = unlimited)")
    max_team_members: int = Field(default=1, description="Max team members (-1 = unlimited)")


class PricingPlan(BaseModel):
    """Pricing plan details."""
    id: str = Field(..., description="Plan ID (free, team, enterprise)")
    name: str = Field(..., description="Plan display name")
    description: Optional[str] = Field(default=None, description="Plan description")
    price_monthly_cents: int = Field(default=0, description="Monthly price in cents")
    price_yearly_cents: int = Field(default=0, description="Yearly price in cents")
    limits: PlanLimits = Field(default_factory=PlanLimits)
    features: PlanFeatures = Field(default_factory=PlanFeatures)
    is_popular: bool = Field(default=False, description="Is this the popular/recommended plan")


class PricingPlansResponse(BaseModel):
    """List of all pricing plans."""
    plans: list[PricingPlan] = Field(default_factory=list)


class UsageStatus(BaseModel):
    """Current usage status for an organization."""
    within_limits: bool = Field(..., description="Whether org is within plan limits")
    
    repos_used: int = Field(default=0, description="Repositories currently in use")
    repos_limit: int = Field(default=1, description="Repository limit (-1 = unlimited)")
    repos_remaining: int = Field(default=1, description="Remaining repos available")
    
    prs_used: int = Field(default=0, description="PRs reviewed this month")
    prs_limit: int = Field(default=30, description="Monthly PR limit (-1 = unlimited)")
    prs_remaining: int = Field(default=30, description="Remaining PRs this month")
    
    members_used: int = Field(default=1, description="Current team members")
    members_limit: int = Field(default=1, description="Team member limit (-1 = unlimited)")
    members_remaining: int = Field(default=0, description="Remaining member slots")
    
    plan_id: str = Field(default="free", description="Current plan ID")
    plan_name: str = Field(default="Free", description="Current plan name")
    
    period_start: Optional[str] = Field(default=None, description="Current billing period start")
    period_end: Optional[str] = Field(default=None, description="Current billing period end")


class SubscriptionResponse(BaseModel):
    """Subscription details for an organization."""
    id: str = Field(..., description="Subscription ID")
    org_id: str = Field(..., description="Organization ID")
    plan_id: str = Field(..., description="Current plan ID")
    plan_name: str = Field(..., description="Current plan name")
    status: str = Field(default="active", description="Subscription status")
    billing_cycle: str = Field(default="monthly", description="Billing cycle")
    current_period_start: Optional[str] = Field(default=None, description="Period start")
    current_period_end: Optional[str] = Field(default=None, description="Period end")
    trial_end: Optional[str] = Field(default=None, description="Trial end date")
    usage: UsageStatus = Field(..., description="Current usage status")
    features: PlanFeatures = Field(..., description="Available features")


class UpgradePlanRequest(BaseModel):
    """Request to upgrade/change subscription plan."""
    plan_id: str = Field(..., description="Target plan ID")
    billing_cycle: str = Field(default="monthly", description="Billing cycle (monthly/yearly)")


class UpgradePlanResponse(BaseModel):
    """Response after plan upgrade."""
    success: bool = Field(..., description="Whether upgrade succeeded")
    subscription: SubscriptionResponse = Field(..., description="Updated subscription")
    message: str = Field(..., description="Result message")
    checkout_url: Optional[str] = Field(default=None, description="URL for payment (if needed)")