"""
Comprehensive Automated Test Suite for AI Code-Scanning Alert Review Service.

Tests all 6 pipeline stages:
1. Alert Collector & Normalizer (GitHub Webhooks + CodeQL SARIF 2.1.0)
2. Code Context Builder (Source/Sink extraction, imports, framework detection)
3. AI Investigator (Structured claim investigation, supporting/opposing evidence)
4. Evidence Verifier & Reviewer (Programmatic grounding check, adversarial challenges)
5. Determination & Confidence Engine (Calibrated confidence, bypasses, evidence criteria)
6. Report Generator & Calibration (Markdown, remediation plans, Brier score metrics)
End-to-End Service Pipeline Execution
"""

import pytest
import json
from unittest.mock import AsyncMock

from app.alert_review.models_alert import (
    NormalizedAlert,
    AlertSeverity,
    CodeFlowNode,
    CodeFlowPath,
    DeterminationType,
    EvidenceCategory,
    EvidenceDirection,
    EvidenceItem,
    InvestigatorAssessment,
    VerificationReport,
    ChallengeItem,
    ConfidenceScore,
    TriageReport,
    HumanTriageFeedback,
    AlertCodeContext,
    CodeContextSnippet,
)
from app.alert_review.alert_collector import (
    parse_github_alert_webhook,
    parse_sarif,
    _extract_cwe_from_tags,
)
from app.alert_review.context_builder import (
    CodeContextBuilder,
    _extract_enclosing_block,
    _analyze_imports_and_env,
)
from app.alert_review.investigator import AIInvestigator
from app.alert_review.verifier import EvidenceVerifier, _check_evidence_grounding
from app.alert_review.confidence_engine import ConfidenceEngine
from app.alert_review.report_generator import ReportGenerator
from app.alert_review.calibration import CalibrationStore
from app.alert_review.service import AlertReviewService


# Sample Webhook Payload
SAMPLE_WEBHOOK_PAYLOAD = {
    "action": "created",
    "repository": {"full_name": "acme-corp/payment-service"},
    "alert": {
        "number": 42,
        "html_url": "https://github.com/acme-corp/payment-service/security/code-scanning/42",
        "rule": {
            "id": "js/sql-injection",
            "name": "SQL query built from user-controlled sources",
            "security_severity_level": "high",
            "description": "Building a SQL query from user input without sanitization can lead to SQL injection.",
            "tags": ["security", "external/cwe/cwe-089"]
        },
        "tool": {"name": "CodeQL", "version": "2.16.0"},
        "most_recent_instance": {
            "commit_sha": "abc123def456",
            "ref": "refs/heads/main",
            "location": {
                "path": "src/controllers/userController.js",
                "start_line": 25,
                "start_column": 12,
                "end_line": 25,
                "end_column": 45
            },
            "message": {"text": "User input from req.params.id flows directly into database query"}
        }
    }
}

# Sample CodeQL SARIF 2.1.0 with complete dataflow threadFlow (Source -> Hop -> Sink)
SAMPLE_SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "version": "2.16.0",
                    "rules": [
                        {
                            "id": "js/sql-injection",
                            "name": "SQL query built from user-controlled sources",
                            "shortDescription": {"text": "SQL query built from user-controlled sources"},
                            "fullDescription": {"text": "Building a SQL query directly from untrusted input leads to SQL Injection."},
                            "properties": {
                                "security-severity": "8.5",
                                "tags": ["security", "external/cwe/cwe-089"]
                            }
                        }
                    ]
                }
            },
            "results": [
                {
                    "ruleId": "js/sql-injection",
                    "message": {"text": "This SQL query depends on a user-provided value."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/routes/users.js"},
                                "region": {
                                    "startLine": 45,
                                    "startColumn": 5,
                                    "endLine": 45,
                                    "endColumn": 50,
                                    "snippet": {"text": "const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);"}
                                }
                            }
                        }
                    ],
                    "codeFlows": [
                        {
                            "threadFlows": [
                                {
                                    "locations": [
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "src/routes/users.js"},
                                                    "region": {"startLine": 20, "startColumn": 5, "snippet": {"text": "const userId = req.query.id;"}}
                                                },
                                                "message": {"text": "Source: user-provided query parameter"}
                                            }
                                        },
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "src/routes/users.js"},
                                                    "region": {"startLine": 35, "startColumn": 5, "snippet": {"text": "const sanitized = sanitizeId(userId);"}}
                                                },
                                                "message": {"text": "Step: passed to helper"}
                                            }
                                        },
                                        {
                                            "location": {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "src/routes/users.js"},
                                                    "region": {"startLine": 45, "startColumn": 5, "snippet": {"text": "db.query(`SELECT * FROM users WHERE id = ${userId}`);"}}
                                                },
                                                "message": {"text": "Sink: raw SQL query"}
                                            }
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    ]
}

SAMPLE_SOURCE_CODE = """
import express from 'express';
import { db } from '../database';
import helmet from 'helmet';

const router = express.Router();

router.get('/user/:id', async (req, res) => {
    const userId = req.query.id;
    
    // Check user ID
    if (!userId) {
        return res.status(400).send('Missing ID');
    }
    
    const parsedId = parseInt(userId, 10);
    if (isNaN(parsedId)) {
        return res.status(400).send('Invalid ID format');
    }

    const query = `SELECT * FROM users WHERE id = ${parsedId}`;
    const result = await db.query(query);
    return res.json(result);
});

export default router;
"""


# =========================================================================
# Stage 1 Tests: Alert Collector & Normalizer
# =========================================================================

def test_parse_github_alert_webhook():
    alert = parse_github_alert_webhook(SAMPLE_WEBHOOK_PAYLOAD)
    assert alert is not None
    assert alert.alert_id == "acme-corp/payment-service#42"
    assert alert.repo == "acme-corp/payment-service"
    assert alert.rule_id == "js/sql-injection"
    assert alert.severity == AlertSeverity.HIGH
    assert "CWE-89" in alert.cwe_ids
    assert alert.primary_location.file_path == "src/controllers/userController.js"
    assert alert.primary_location.line_number == 25
    assert len(alert.code_flows) >= 1


def test_parse_sarif():
    alerts = parse_sarif(SAMPLE_SARIF, repo="acme-corp/payment-service", commit_sha="abc123def456")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "js/sql-injection"
    assert alert.severity == AlertSeverity.HIGH
    assert "CWE-89" in alert.cwe_ids
    assert len(alert.code_flows) == 1
    
    flow = alert.code_flows[0]
    assert len(flow.nodes) == 3
    assert flow.nodes[0].step_type == "source"
    assert flow.nodes[1].step_type == "step"
    assert flow.nodes[2].step_type == "sink"
    assert flow.nodes[0].line_number == 20
    assert flow.nodes[2].line_number == 45


def test_cwe_extraction_from_tags():
    tags = ["security", "external/cwe/cwe-089", "external/cwe/cwe-079", "cwe-918"]
    cwes = _extract_cwe_from_tags(tags)
    assert "CWE-89" in cwes
    assert "CWE-79" in cwes
    assert "CWE-918" in cwes


# =========================================================================
# Stage 2 Tests: Code Context Builder
# =========================================================================

@pytest.mark.asyncio
async def test_code_context_builder():
    async def mock_file_reader(path: str, commit: str):
        return SAMPLE_SOURCE_CODE

    builder = CodeContextBuilder(file_reader_override=mock_file_reader)
    alerts = parse_sarif(SAMPLE_SARIF, repo="acme-corp/payment-service", commit_sha="abc123def456")
    context = await builder.build_context(alerts[0])

    assert context.alert_id == alerts[0].alert_id
    assert "express" in context.detected_frameworks
    assert "helmet" in context.detected_middleware
    assert len(context.source_slices) >= 1
    assert len(context.sink_slices) >= 1
    assert context.context_token_estimate > 0


def test_import_and_framework_detection():
    imports, frameworks, dbs, middlewares = _analyze_imports_and_env(SAMPLE_SOURCE_CODE)
    assert "express" in frameworks
    assert "helmet" in middlewares
    assert "express" in imports


# =========================================================================
# Stage 3 Tests: AI Investigator
# =========================================================================

@pytest.mark.asyncio
async def test_ai_investigator():
    mock_llm_response = json.dumps({
        "claim_summary": "CodeQL claims req.query.id is concatenated into SQL query.",
        "source_analysis": "req.query.id is user-controlled via HTTP query parameter.",
        "propagation_analysis": "Passed to parseInt, which coerces to numeric value.",
        "sink_analysis": "Query is formatted using parsedId which is guaranteed to be integer.",
        "defenses_analysis": "parseInt sanitizes non-numeric injection payloads.",
        "proposed_determination": "FALSE_POSITIVE",
        "preliminary_confidence": 0.92,
        "supporting_evidence": [
            {
                "id": "sup-1",
                "category": "SOURCE_VALIDITY",
                "title": "User-controlled input",
                "description": "Source is req.query.id",
                "code_reference": "const userId = req.query.id;",
                "file_path": "src/routes/users.js",
                "line_numbers": [20],
                "weight": 2.0
            }
        ],
        "opposing_evidence": [
            {
                "id": "opp-1",
                "category": "SANITIZATION_DEFENSE",
                "title": "Numeric cast prevents injection",
                "description": "Input is validated and parsed using parseInt with NaN check",
                "code_reference": "const parsedId = parseInt(userId, 10);",
                "file_path": "src/routes/users.js",
                "line_numbers": [16],
                "weight": 3.0
            }
        ],
        "reasoning": "Although the scanner traced taint to db.query, parseInt guarantees string injection is impossible."
    })

    async def mock_caller(sys, user):
        return mock_llm_response

    investigator = AIInvestigator(mock_caller)
    alerts = parse_sarif(SAMPLE_SARIF, repo="acme-corp/payment-service", commit_sha="abc123def456")
    
    async def mock_reader(p, c):
        return SAMPLE_SOURCE_CODE

    builder = CodeContextBuilder(file_reader_override=mock_reader)
    context = await builder.build_context(alerts[0])

    assessment = await investigator.investigate(alerts[0], context)
    assert assessment.proposed_determination == DeterminationType.FALSE_POSITIVE
    assert assessment.preliminary_confidence == 0.92
    assert len(assessment.supporting_evidence) == 1
    assert len(assessment.opposing_evidence) == 1
    assert assessment.opposing_evidence[0].category == EvidenceCategory.SANITIZATION_DEFENSE


# =========================================================================
# Stage 4 Tests: Evidence Verifier & Grounding
# =========================================================================

@pytest.mark.asyncio
async def test_evidence_verifier_grounding_check():
    alerts = parse_sarif(SAMPLE_SARIF, repo="acme-corp/payment-service", commit_sha="abc123def456")
    
    async def mock_reader(p, c):
        return SAMPLE_SOURCE_CODE

    builder = CodeContextBuilder(file_reader_override=mock_reader)
    context = await builder.build_context(alerts[0])

    # Assessment with real code citation
    grounded_assessment = InvestigatorAssessment(
        alert_id=alerts[0].alert_id,
        proposed_determination=DeterminationType.FALSE_POSITIVE,
        claim_summary="Test claim",
        supporting_evidence=[],
        opposing_evidence=[
            EvidenceItem(
                id="opp-1",
                category=EvidenceCategory.SANITIZATION_DEFENSE,
                direction=EvidenceDirection.OPPOSING,
                title="Integer parse",
                description="Parsed integer",
                code_reference="const parsedId = parseInt(userId, 10);",
                weight=2.0
            )
        ],
        reasoning="Test reasoning",
        source_analysis="s",
        propagation_analysis="p",
        sink_analysis="s",
        defenses_analysis="d",
        preliminary_confidence=0.9
    )

    score, ungrounded = _check_evidence_grounding(grounded_assessment, context)
    assert score == 1.0
    assert len(ungrounded) == 0

    # Assessment with hallucinated code citation
    hallucinated_assessment = InvestigatorAssessment(
        alert_id=alerts[0].alert_id,
        proposed_determination=DeterminationType.FALSE_POSITIVE,
        claim_summary="Test claim",
        supporting_evidence=[],
        opposing_evidence=[
            EvidenceItem(
                id="opp-fake",
                category=EvidenceCategory.SANITIZATION_DEFENSE,
                direction=EvidenceDirection.OPPOSING,
                title="Fake sanitizer",
                description="Sanitizer that does not exist",
                code_reference="const safe = sqlEscapeAllCharactersSafely(userId);",
                weight=2.0
            )
        ],
        reasoning="Fake reasoning",
        source_analysis="s",
        propagation_analysis="p",
        sink_analysis="s",
        defenses_analysis="d",
        preliminary_confidence=0.9
    )

    score_fake, ungrounded_fake = _check_evidence_grounding(hallucinated_assessment, context)
    assert score_fake == 0.0
    assert len(ungrounded_fake) == 1


# =========================================================================
# Stage 5 Tests: Determination & Confidence Engine
# =========================================================================

def test_confidence_engine_true_positive():
    engine = ConfidenceEngine()
    alert = parse_github_alert_webhook(SAMPLE_WEBHOOK_PAYLOAD)

    investigator = InvestigatorAssessment(
        alert_id=alert.alert_id,
        proposed_determination=DeterminationType.TRUE_POSITIVE,
        claim_summary="SQLi exists",
        supporting_evidence=[
            EvidenceItem(
                id="sup-1",
                category=EvidenceCategory.SINK_EXPLOITABILITY,
                direction=EvidenceDirection.SUPPORTING,
                title="Raw SQL",
                description="Direct string interpolation into database query",
                weight=3.0
            )
        ],
        opposing_evidence=[],
        reasoning="Taint flows straight into query",
        source_analysis="s",
        propagation_analysis="p",
        sink_analysis="s",
        defenses_analysis="none",
        preliminary_confidence=0.95
    )

    verifier = VerificationReport(
        alert_id=alert.alert_id,
        grounding_score=1.0,
        ungrounded_claims=[],
        challenges=[],
        consensus_with_investigator=True,
        suggested_determination=DeterminationType.TRUE_POSITIVE,
        missing_context_flags=[],
        verifier_notes="Verified vulnerable"
    )

    # Empty context bundle with 1 mock slice
    from app.alert_review.models_alert import AlertCodeContext, CodeContextSnippet
    context = AlertCodeContext(
        alert_id=alert.alert_id,
        commit_sha=alert.commit_sha,
        sink_slices=[CodeContextSnippet(file_path="f.js", start_line=1, end_line=5, content="db.query")]
    )

    det, conf = engine.calculate_determination_and_confidence(alert, context, investigator, verifier)
    assert det == DeterminationType.TRUE_POSITIVE
    assert conf.score >= 0.85
    assert conf.qualitative_level == "HIGH"


def test_confidence_engine_adversarial_bypass_override():
    """If investigator said False Positive, but verifier proved a bypass, override to TRUE_POSITIVE."""
    engine = ConfidenceEngine()
    alert = parse_github_alert_webhook(SAMPLE_WEBHOOK_PAYLOAD)

    investigator = InvestigatorAssessment(
        alert_id=alert.alert_id,
        proposed_determination=DeterminationType.FALSE_POSITIVE,
        claim_summary="Sanitizer handles it",
        supporting_evidence=[],
        opposing_evidence=[
            EvidenceItem(
                id="opp-1",
                category=EvidenceCategory.SANITIZATION_DEFENSE,
                direction=EvidenceDirection.OPPOSING,
                title="Regex filter",
                description="Filtered by regex",
                weight=2.0
            )
        ],
        reasoning="Sanitizer exists",
        source_analysis="s",
        propagation_analysis="p",
        sink_analysis="s",
        defenses_analysis="d",
        preliminary_confidence=0.85
    )

    verifier = VerificationReport(
        alert_id=alert.alert_id,
        grounding_score=1.0,
        ungrounded_claims=[],
        challenges=[
            ChallengeItem(
                id="chal-1",
                challenge_question="Can regex be bypassed?",
                counter_argument="Regex lacks anchors, bypass confirmed via CRLF injection",
                challenged_assumption="Complete escaping",
                challenge_resolution="Bypass verified",
                was_adversarial_counter_valid=True
            )
        ],
        consensus_with_investigator=False,
        suggested_determination=DeterminationType.TRUE_POSITIVE,
        missing_context_flags=[],
        verifier_notes="Bypass found"
    )

    from app.alert_review.models_alert import AlertCodeContext, CodeContextSnippet
    context = AlertCodeContext(
        alert_id=alert.alert_id,
        commit_sha=alert.commit_sha,
        sink_slices=[CodeContextSnippet(file_path="f.js", start_line=1, end_line=5, content="db.query")]
    )

    det, conf = engine.calculate_determination_and_confidence(alert, context, investigator, verifier)
    assert det == DeterminationType.TRUE_POSITIVE


def test_confidence_engine_low_grounding_downgrades_to_needs_review():
    engine = ConfidenceEngine()
    alert = parse_github_alert_webhook(SAMPLE_WEBHOOK_PAYLOAD)

    investigator = InvestigatorAssessment(
        alert_id=alert.alert_id,
        proposed_determination=DeterminationType.TRUE_POSITIVE,
        claim_summary="SQLi exists",
        supporting_evidence=[],
        opposing_evidence=[],
        reasoning="Claims vulnerability",
        source_analysis="s",
        propagation_analysis="p",
        sink_analysis="s",
        defenses_analysis="none",
        preliminary_confidence=0.9
    )

    verifier = VerificationReport(
        alert_id=alert.alert_id,
        grounding_score=0.40,  # Low grounding
        ungrounded_claims=["Cited function db.escape_badly does not exist"],
        challenges=[],
        consensus_with_investigator=True,
        suggested_determination=DeterminationType.TRUE_POSITIVE,
        missing_context_flags=["Source file truncated"],
        verifier_notes="Ungrounded citations"
    )

    from app.alert_review.models_alert import AlertCodeContext
    context = AlertCodeContext(alert_id=alert.alert_id, commit_sha=alert.commit_sha)

    det, conf = engine.calculate_determination_and_confidence(alert, context, investigator, verifier)
    assert det == DeterminationType.NEEDS_REVIEW
    assert "Grounding score too low" in conf.explanation


# =========================================================================
# Stage 6 & Calibration Tests: Report Generator & Store
# =========================================================================

def test_report_generator_markdown_formatting():
    gen = ReportGenerator()
    alert = parse_github_alert_webhook(SAMPLE_WEBHOOK_PAYLOAD)

    from app.alert_review.models_alert import AlertCodeContext
    context = AlertCodeContext(alert_id=alert.alert_id, commit_sha=alert.commit_sha)

    investigator = InvestigatorAssessment(
        alert_id=alert.alert_id,
        proposed_determination=DeterminationType.FALSE_POSITIVE,
        claim_summary="CodeQL flagged param in query",
        supporting_evidence=[
            EvidenceItem(
                id="sup-1",
                category=EvidenceCategory.SOURCE_VALIDITY,
                direction=EvidenceDirection.SUPPORTING,
                title="Input parameter",
                description="Query parameter from user",
                code_reference="req.params.id",
                weight=1.5
            )
        ],
        opposing_evidence=[
            EvidenceItem(
                id="opp-1",
                category=EvidenceCategory.SANITIZATION_DEFENSE,
                direction=EvidenceDirection.OPPOSING,
                title="Validated integer",
                description="Cast using parseInt",
                code_reference="parseInt(id, 10)",
                weight=3.0
            )
        ],
        reasoning="Integer validation eliminates SQL injection.",
        source_analysis="s",
        propagation_analysis="p",
        sink_analysis="s",
        defenses_analysis="d",
        preliminary_confidence=0.95
    )

    verifier = VerificationReport(
        alert_id=alert.alert_id,
        grounding_score=1.0,
        ungrounded_claims=[],
        challenges=[],
        consensus_with_investigator=True,
        suggested_determination=DeterminationType.FALSE_POSITIVE,
        missing_context_flags=[],
        verifier_notes="Verified safe."
    )

    confidence = ConfidenceScore(
        score=0.94,
        qualitative_level="HIGH",
        grounding_factor=1.0,
        flow_completeness_factor=1.0,
        consensus_factor=1.0,
        assumption_penalty=0.0,
        explanation="Full consensus on False Positive."
    )

    report = gen.generate_report(
        alert=alert,
        context=context,
        investigator=investigator,
        verifier=verifier,
        determination=DeterminationType.FALSE_POSITIVE,
        confidence=confidence
    )

    assert report.determination == DeterminationType.FALSE_POSITIVE
    assert "🛡️ **VERDICT: FALSE POSITIVE**" in report.markdown_report
    assert "Evidence Matrix" in report.markdown_report
    assert "req.params.id" in report.markdown_report
    assert report.remediation.action_type == "DISMISS_ALERT"
    assert report.remediation.dismissal_reason == "false positive"


@pytest.mark.asyncio
async def test_calibration_store_and_metrics():
    store = CalibrationStore()
    alert = parse_github_alert_webhook(SAMPLE_WEBHOOK_PAYLOAD)

    report = TriageReport(
        alert_id=alert.alert_id,
        repo=alert.repo,
        commit_sha=alert.commit_sha,
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        severity=alert.severity,
        determination=DeterminationType.FALSE_POSITIVE,
        confidence=ConfidenceScore(
            score=0.92,
            qualitative_level="HIGH",
            grounding_factor=1.0,
            flow_completeness_factor=1.0,
            consensus_factor=1.0,
            assumption_penalty=0.0,
            explanation="Safe"
        ),
        executive_summary="False Positive confirmed",
        scanner_claim=alert.scanner_message,
        investigator_assessment=InvestigatorAssessment(
            alert_id=alert.alert_id,
            proposed_determination=DeterminationType.FALSE_POSITIVE,
            claim_summary="c",
            reasoning="r",
            source_analysis="s",
            propagation_analysis="p",
            sink_analysis="s",
            defenses_analysis="d",
            preliminary_confidence=0.9
        ),
        verification_report=VerificationReport(
            alert_id=alert.alert_id,
            grounding_score=1.0,
            consensus_with_investigator=True,
            suggested_determination=DeterminationType.FALSE_POSITIVE,
            verifier_notes="v"
        ),
        remediation=ReportGenerator().generate_report(
            alert,
            AlertCodeContext(alert_id=alert.alert_id, commit_sha="1"),
            InvestigatorAssessment(
                alert_id=alert.alert_id,
                proposed_determination=DeterminationType.FALSE_POSITIVE,
                claim_summary="c",
                reasoning="r",
                source_analysis="s",
                propagation_analysis="p",
                sink_analysis="s",
                defenses_analysis="d",
                preliminary_confidence=0.9
            ),
            VerificationReport(
                alert_id=alert.alert_id,
                grounding_score=1.0,
                consensus_with_investigator=True,
                suggested_determination=DeterminationType.FALSE_POSITIVE,
                verifier_notes="v"
            ),
            DeterminationType.FALSE_POSITIVE,
            ConfidenceScore(
                score=0.92,
                qualitative_level="HIGH",
                grounding_factor=1.0,
                flow_completeness_factor=1.0,
                consensus_factor=1.0,
                assumption_penalty=0.0,
                explanation="Safe"
            )
        ).remediation,
        markdown_report="markdown"
    )

    await store.save_triage_report(report)

    # Record human AppSec outcome agreeing with AI (Human says False Positive)
    feedback = HumanTriageFeedback(
        alert_id=alert.alert_id,
        repo=alert.repo,
        human_verdict=DeterminationType.FALSE_POSITIVE,
        human_notes="Confirmed false positive during triage."
    )
    await store.record_human_outcome(feedback)

    metrics = store.calculate_metrics()
    assert metrics.total_reviewed_by_human == 1
    assert metrics.false_positive_agreement_count == 1
    assert metrics.overall_accuracy == 1.0
    assert metrics.brier_score < 0.05  # Highly calibrated


# =========================================================================
# End-to-End Service Pipeline Test
# =========================================================================

@pytest.mark.asyncio
async def test_end_to_end_alert_review_service():
    mock_inv_response = json.dumps({
        "claim_summary": "CodeQL flagged user input query",
        "source_analysis": "req.query.id enters via HTTP",
        "propagation_analysis": "Passed to db.query without sanitization",
        "sink_analysis": "Raw string concatenation in SQL statement",
        "defenses_analysis": "No sanitizers found",
        "proposed_determination": "TRUE_POSITIVE",
        "preliminary_confidence": 0.95,
        "supporting_evidence": [
            {
                "id": "sup-1",
                "category": "SINK_EXPLOITABILITY",
                "title": "Unsanitized SQL concatenation",
                "description": "Vulnerable sink",
                "code_reference": "SELECT * FROM users WHERE id = ${userId}",
                "weight": 3.0
            }
        ],
        "opposing_evidence": [],
        "reasoning": "Classic SQL Injection"
    })

    mock_ver_response = json.dumps({
        "grounding_score": 1.0,
        "ungrounded_claims": [],
        "consensus_with_investigator": True,
        "suggested_determination": "TRUE_POSITIVE",
        "challenges": [],
        "missing_context_flags": [],
        "verifier_notes": "All claims verified against source."
    })

    call_count = 0
    async def mock_llm_caller(sys, user):
        nonlocal call_count
        call_count += 1
        if "Principal Application Security Engineer" in sys:
            return mock_inv_response
        else:
            return mock_ver_response

    service = AlertReviewService(llm_caller=mock_llm_caller)
    
    # Inject file reader override into context builder
    async def mock_reader(path, commit):
        return "const query = `SELECT * FROM users WHERE id = ${userId}`;\nawait db.query(query);"
    service.context_builder.file_reader_override = mock_reader

    # Run complete review on SARIF
    reports = await service.review_sarif_file(
        sarif_data=SAMPLE_SARIF,
        repo="acme-corp/payment-service",
        commit_sha="abc123def456"
    )

    assert len(reports) == 1
    triage = reports[0]
    assert triage.determination == DeterminationType.TRUE_POSITIVE
    assert triage.confidence.score >= 0.85
    assert triage.confidence.qualitative_level == "HIGH"
    assert "🚨 **VERDICT: TRUE POSITIVE**" in triage.markdown_report
    assert triage.remediation.action_type == "CODE_FIX"
    assert call_count == 2  # Stage 3 (Investigator) + Stage 4 (Verifier)
