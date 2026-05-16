"""
Metrics tracking for the AI AppSec PR Reviewer.

Provides in-memory metrics collection and aggregation for
monitoring service usage and performance.
"""

import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

from .models import AggregatedMetrics, SecurityFinding

logger = logging.getLogger(__name__)


class MetricsTracker:
    """In-memory metrics tracker for the service."""
    
    def __init__(self):
        self._start_time = time.time()
        self._total_reviews = 0
        self._successful_reviews = 0
        self._failed_reviews = 0
        self._total_findings = 0
        self._findings_by_risk: dict[str, int] = defaultdict(int)
        self._findings_by_category: dict[str, int] = defaultdict(int)
        self._total_review_time_ms = 0
        self._reviews: list[dict] = []  # Store last N reviews for debugging
        self._max_stored_reviews = 100
    
    def record_review(
        self,
        repo: str,
        pr_number: int,
        review_time_ms: int,
        findings: list[SecurityFinding],
        success: bool,
        error_type: Optional[str] = None
    ) -> None:
        """Record metrics for a single review."""
        self._total_reviews += 1
        self._total_review_time_ms += review_time_ms
        
        if success:
            self._successful_reviews += 1
        else:
            self._failed_reviews += 1
        
        # Count findings
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for finding in findings:
            self._total_findings += 1
            self._findings_by_risk[finding.risk.value] += 1
            
            if finding.risk.value == "HIGH":
                high_count += 1
            elif finding.risk.value == "MEDIUM":
                medium_count += 1
            else:
                low_count += 1
            
            # Categorize by OWASP or CWE
            if finding.owasp:
                # Extract category from OWASP (e.g., "A03:2021 Injection" -> "injection")
                category = finding.owasp.split()[-1].lower() if finding.owasp else "other"
                self._findings_by_category[category] += 1
            elif finding.cwe:
                self._findings_by_category["cwe_" + finding.cwe.replace("CWE-", "")] += 1
            else:
                self._findings_by_category["uncategorized"] += 1
        
        # Store review record (for debugging, keep last N)
        review_record = {
            "repo": repo,
            "pr_number": pr_number,
            "review_time_ms": review_time_ms,
            "findings_count": len(findings),
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "success": success,
            "error_type": error_type,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self._reviews.append(review_record)
        if len(self._reviews) > self._max_stored_reviews:
            self._reviews.pop(0)
        
        # Log structured metrics
        logger.info(
            f"METRIC: review repo={repo} pr={pr_number} "
            f"time_ms={review_time_ms} findings={len(findings)} "
            f"high={high_count} medium={medium_count} low={low_count} "
            f"success={success}"
        )
    
    def get_aggregated_metrics(self) -> AggregatedMetrics:
        """Get aggregated metrics for the service."""
        avg_time = (
            self._total_review_time_ms / self._total_reviews
            if self._total_reviews > 0 else 0
        )
        
        success_rate = (
            (self._successful_reviews / self._total_reviews * 100)
            if self._total_reviews > 0 else 0
        )
        
        uptime_seconds = int(time.time() - self._start_time)
        
        return AggregatedMetrics(
            total_prs_reviewed=self._total_reviews,
            total_findings=self._total_findings,
            findings_by_category=dict(self._findings_by_category),
            findings_by_risk=dict(self._findings_by_risk) or {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            avg_review_time_ms=round(avg_time, 2),
            success_rate=round(success_rate, 2),
            total_success=self._successful_reviews,
            total_failure=self._failed_reviews,
            uptime_seconds=uptime_seconds
        )
    
    def get_recent_reviews(self, limit: int = 10) -> list[dict]:
        """Get the most recent reviews for debugging."""
        return self._reviews[-limit:]


# Global metrics tracker instance
_metrics_tracker: Optional[MetricsTracker] = None


def get_metrics_tracker() -> MetricsTracker:
    """Get or create the global metrics tracker."""
    global _metrics_tracker
    if _metrics_tracker is None:
        _metrics_tracker = MetricsTracker()
    return _metrics_tracker
