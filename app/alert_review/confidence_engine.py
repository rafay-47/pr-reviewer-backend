"""
Determination & Confidence Engine (Stage 5).

Applies deterministic AppSec evidence criteria and computes calibrated confidence scores:
- Enforces strict evidence requirements for TRUE_POSITIVE and FALSE_POSITIVE
- Adjudicates consensus between Investigator and Verifier
- Calculates evidence-based confidence using grounding, path completeness, consensus, and penalties
"""

import logging
from typing import List, Dict, Any, Optional

from .models_alert import (
    NormalizedAlert,
    AlertCodeContext,
    InvestigatorAssessment,
    VerificationReport,
    DeterminationType,
    ConfidenceScore,
    EvidenceCategory,
)

logger = logging.getLogger(__name__)


class ConfidenceEngine:
    """Calculates evidence-based determinations and calibrated confidence scores."""

    def __init__(
        self,
        weight_grounding: float = 0.35,
        weight_flow: float = 0.25,
        weight_consensus: float = 0.30,
        weight_evidence: float = 0.10,
        penalty_per_assumption: float = 0.05,
        max_assumption_penalty: float = 0.20,
    ):
        self.w_grounding = weight_grounding
        self.w_flow = weight_flow
        self.w_consensus = weight_consensus
        self.w_evidence = weight_evidence
        self.penalty_per_assumption = penalty_per_assumption
        self.max_assumption_penalty = max_assumption_penalty

    def calculate_determination_and_confidence(
        self,
        alert: NormalizedAlert,
        context: AlertCodeContext,
        investigator: InvestigatorAssessment,
        verifier: VerificationReport
    ) -> tuple[DeterminationType, ConfidenceScore]:
        """
        Adjudicate evidence and compute final calibrated confidence score.
        
        Args:
            alert: NormalizedAlert instance.
            context: AlertCodeContext bundle.
            investigator: Investigator assessment.
            verifier: Adversarial verification report.
            
        Returns:
            (final_determination, confidence_score)
        """
        # 1. Flow completeness factor
        total_hops = sum(len(f.nodes) for f in alert.code_flows)
        if total_hops == 0:
            total_hops = 1
        available_slices = len(context.source_slices) + len(context.path_slices) + len(context.sink_slices)
        flow_completeness_factor = min(1.0, available_slices / max(1, total_hops))

        # 2. Grounding factor
        grounding_factor = max(0.0, min(1.0, verifier.grounding_score))

        # 3. Consensus factor
        consensus = (investigator.proposed_determination == verifier.suggested_determination)
        consensus_factor = 1.0 if consensus else 0.45

        # 4. Evidence weight balance
        total_sup_weight = sum(item.weight for item in investigator.supporting_evidence)
        total_opp_weight = sum(item.weight for item in investigator.opposing_evidence)
        total_ev_weight = total_sup_weight + total_opp_weight

        if total_ev_weight > 0:
            dominant_ratio = max(total_sup_weight, total_opp_weight) / total_ev_weight
            evidence_factor = min(1.0, dominant_ratio)
        else:
            evidence_factor = 0.5

        # 5. Assumption penalty
        num_assumptions = len(verifier.missing_context_flags)
        assumption_penalty = min(self.max_assumption_penalty, num_assumptions * self.penalty_per_assumption)

        # 6. Check for valid adversarial bypasses
        has_successful_bypass = any(
            c.was_adversarial_counter_valid for c in verifier.challenges
            if "bypass" in c.counter_argument.lower() or "bypass" in c.challenge_resolution.lower()
        )

        # 7. Adjudicate Determination
        final_det = DeterminationType.NEEDS_REVIEW
        determination_reason = ""

        # Case A: Low grounding -> Cannot trust AI reasoning
        if grounding_factor < 0.60:
            final_det = DeterminationType.NEEDS_REVIEW
            determination_reason = f"Grounding score too low ({grounding_factor:.2f}). Evidence cites unverified code."

        # Case B: Adversarial verifier proved a bypass against a proposed False Positive
        elif investigator.proposed_determination == DeterminationType.FALSE_POSITIVE and has_successful_bypass:
            final_det = DeterminationType.TRUE_POSITIVE
            determination_reason = "Investigator proposed False Positive, but adversarial verifier proved a bypass against the sanitizer."

        # Case C: Consensus reached
        elif consensus:
            final_det = investigator.proposed_determination
            determination_reason = f"Full consensus between Investigator and Verifier on {final_det.value}."

        # Case D: Disagreement between Investigator and Verifier
        else:
            # If one is TRUE_POSITIVE and one is FALSE_POSITIVE without clear bypass, flag for human AppSec review
            final_det = DeterminationType.NEEDS_REVIEW
            determination_reason = (
                f"Disagreement: Investigator proposed {investigator.proposed_determination.value}, "
                f"Verifier suggested {verifier.suggested_determination.value}."
            )

        # 8. Compute Raw Score
        raw_score = (
            (self.w_grounding * grounding_factor) +
            (self.w_flow * flow_completeness_factor) +
            (self.w_consensus * consensus_factor) +
            (self.w_evidence * evidence_factor) -
            assumption_penalty
        )

        # Clamp between 0.15 and 0.98 (leave margin for human certainty)
        final_score = round(max(0.15, min(0.98, raw_score)), 3)

        # Qualitative Level
        if final_score >= 0.85:
            level = "HIGH"
        elif final_score >= 0.65:
            level = "MEDIUM"
        else:
            level = "LOW"

        explanation = (
            f"{determination_reason} Confidence: {final_score:.0%} ({level}). "
            f"Grounding: {grounding_factor:.0%}, Path Completeness: {flow_completeness_factor:.0%}, "
            f"Consensus: {'Yes' if consensus else 'No'}."
        )

        score_obj = ConfidenceScore(
            score=final_score,
            qualitative_level=level,
            grounding_factor=grounding_factor,
            flow_completeness_factor=flow_completeness_factor,
            consensus_factor=consensus_factor,
            assumption_penalty=assumption_penalty,
            explanation=explanation
        )

        return final_det, score_obj
