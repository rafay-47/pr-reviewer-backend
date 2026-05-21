"""
Subscription and pricing management for the AI AppSec PR Reviewer.

Handles plan limits, feature gating, and usage tracking for
enterprise pricing tiers.
"""

import logging
import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, date, timedelta
from enum import Enum
from typing import Optional, Any

from fastapi import HTTPException
from .security import add_request_timing

logger = logging.getLogger(__name__)


class PlanTier(str, Enum):
    """Available pricing tiers."""
    FREE = "free"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, Enum):
    """Subscription status."""
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    TRIALING = "trialing"


@dataclass
class PlanLimits:
    """Plan limits and feature flags."""
    plan_id: str
    plan_name: str
    
    # Limits (-1 = unlimited)
    max_repos: int
    max_prs_per_month: int
    max_team_members: int
    
    # Features
    feature_advisory_mode: bool
    feature_enforcement_mode: bool
    feature_dashboard: bool
    feature_audit_logs: bool
    feature_sso: bool
    feature_policy_as_code: bool
    feature_siem_integration: bool
    feature_custom_rules: bool
    feature_priority_support: bool
    feature_dedicated_support: bool
    
    # Pricing
    price_monthly_cents: int
    price_yearly_cents: int
    
    def is_unlimited(self, limit_name: str) -> bool:
        """Check if a limit is unlimited."""
        value = getattr(self, limit_name, 0)
        return value == -1


@dataclass
class UsageStatus:
    """Current usage status for an organization."""
    within_limits: bool
    
    repos_used: int
    repos_limit: int
    repos_remaining: int
    
    prs_used: int
    prs_limit: int
    prs_remaining: int
    
    members_used: int
    members_limit: int
    members_remaining: int
    
    plan_id: str
    plan_name: str
    
    def get_limit_message(self) -> Optional[str]:
        """Get a message if any limit is exceeded."""
        messages = []
        
        if self.repos_limit != -1 and self.repos_used >= self.repos_limit:
            messages.append(f"Repository limit reached ({self.repos_used}/{self.repos_limit})")
        
        if self.prs_limit != -1 and self.prs_used >= self.prs_limit:
            messages.append(f"Monthly PR review limit reached ({self.prs_used}/{self.prs_limit})")
        
        if self.members_limit != -1 and self.members_used >= self.members_limit:
            messages.append(f"Team member limit reached ({self.members_used}/{self.members_limit})")
        
        return "; ".join(messages) if messages else None


PLAN_CACHE_TTL_SECONDS = 60
USAGE_CACHE_TTL_SECONDS = 45
PLAN_DETAILS_CACHE_TTL_SECONDS = 300
_org_plan_cache: dict[str, tuple[PlanLimits, datetime]] = {}
_usage_status_cache: dict[str, tuple[UsageStatus, datetime]] = {}
_plan_details_cache: dict[str, tuple[PlanLimits, datetime]] = {}
_org_plan_fetch_locks: dict[str, asyncio.Lock] = {}
_usage_fetch_locks: dict[str, asyncio.Lock] = {}
_plan_details_fetch_locks: dict[str, asyncio.Lock] = {}


async def _execute_query(query):
    """Run blocking Supabase query execution off the event loop."""
    return await asyncio.to_thread(query.execute)


def _parse_date_like(value: Any) -> Optional[date]:
    """Parse DB date/timestamp values into a date."""
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()

    text = str(value).strip()
    if not text:
        return None

    # Handle common Postgres/Supabase timestamp formats.
    text = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).date()
    except Exception:
        pass
    try:
        return date.fromisoformat(text[:10])
    except Exception:
        return None


def _default_period_for(today: date) -> tuple[date, date]:
    """Return default calendar-month period boundaries."""
    period_start = today.replace(day=1)
    if period_start.month == 12:
        next_month = period_start.replace(year=period_start.year + 1, month=1)
    else:
        next_month = period_start.replace(month=period_start.month + 1)
    period_end = next_month - timedelta(days=1)
    return period_start, period_end


async def _resolve_billing_period(
    org_id: str,
    today: date,
) -> tuple[date, date]:
    """Resolve active billing period from subscription, fallback to month."""
    from .database import get_supabase_client

    period_start, period_end = _default_period_for(today)
    try:
        client = get_supabase_client()
        result = await _execute_query(
            client.table("subscriptions")
            .select("current_period_start, current_period_end")
            .eq("org_id", org_id)
            .maybe_single()
        )
        if result and result.data:
            start = _parse_date_like(result.data.get("current_period_start"))
            end = _parse_date_like(result.data.get("current_period_end"))
            if start and end:
                return start, end
    except Exception as e:
        logger.warning(f"Failed to resolve billing period from subscriptions for org {org_id}: {e}")
    return period_start, period_end


def _get_cached_plan(org_id: str) -> Optional[PlanLimits]:
    cached = _org_plan_cache.get(org_id)
    if not cached:
        return None

    plan, expires_at = cached
    if datetime.utcnow() >= expires_at:
        _org_plan_cache.pop(org_id, None)
        return None
    return plan


def _set_cached_plan(org_id: str, plan: PlanLimits) -> None:
    _org_plan_cache[org_id] = (
        plan,
        datetime.utcnow() + timedelta(seconds=PLAN_CACHE_TTL_SECONDS),
    )


def _get_cached_usage(org_id: str) -> Optional[UsageStatus]:
    cached = _usage_status_cache.get(org_id)
    if not cached:
        return None

    usage, expires_at = cached
    if datetime.utcnow() >= expires_at:
        _usage_status_cache.pop(org_id, None)
        return None
    return usage


def _set_cached_usage(org_id: str, usage: UsageStatus) -> None:
    _usage_status_cache[org_id] = (
        usage,
        datetime.utcnow() + timedelta(seconds=USAGE_CACHE_TTL_SECONDS),
    )


def _get_cached_plan_details(plan_id: str) -> Optional[PlanLimits]:
    cached = _plan_details_cache.get(plan_id)
    if not cached:
        return None

    plan, expires_at = cached
    if datetime.utcnow() >= expires_at:
        _plan_details_cache.pop(plan_id, None)
        return None
    return plan


def _set_cached_plan_details(plan_id: str, plan: PlanLimits) -> None:
    _plan_details_cache[plan_id] = (
        plan,
        datetime.utcnow() + timedelta(seconds=PLAN_DETAILS_CACHE_TTL_SECONDS),
    )


# Default plan limits (used when DB is not available)
DEFAULT_PLANS: dict[str, PlanLimits] = {
    "free": PlanLimits(
        plan_id="free",
        plan_name="Free",
        max_repos=1,
        max_prs_per_month=30,
        max_team_members=1,
        feature_advisory_mode=True,
        feature_enforcement_mode=False,
        feature_dashboard=True,
        feature_audit_logs=False,
        feature_sso=False,
        feature_policy_as_code=False,
        feature_siem_integration=False,
        feature_custom_rules=False,
        feature_priority_support=False,
        feature_dedicated_support=False,
        price_monthly_cents=0,
        price_yearly_cents=0,
    ),
    "team": PlanLimits(
        plan_id="team",
        plan_name="Team",
        max_repos=10,
        max_prs_per_month=500,
        max_team_members=10,
        feature_advisory_mode=True,
        feature_enforcement_mode=True,
        feature_dashboard=True,
        feature_audit_logs=False,
        feature_sso=False,
        feature_policy_as_code=False,
        feature_siem_integration=False,
        feature_custom_rules=False,
        feature_priority_support=True,
        feature_dedicated_support=False,
        price_monthly_cents=4900,
        price_yearly_cents=49900,
    ),
    "enterprise": PlanLimits(
        plan_id="enterprise",
        plan_name="Enterprise",
        max_repos=-1,  # Unlimited
        max_prs_per_month=-1,  # Unlimited
        max_team_members=-1,  # Unlimited
        feature_advisory_mode=True,
        feature_enforcement_mode=True,
        feature_dashboard=True,
        feature_audit_logs=True,
        feature_sso=True,
        feature_policy_as_code=True,
        feature_siem_integration=True,
        feature_custom_rules=True,
        feature_priority_support=True,
        feature_dedicated_support=True,
        price_monthly_cents=0,  # Custom pricing
        price_yearly_cents=0,
    ),
}


async def get_plan_limits(plan_id: str) -> PlanLimits:
    """Get plan limits from database or defaults."""
    from .database import get_supabase_client

    cached = _get_cached_plan_details(plan_id)
    if cached:
        return cached
    
    lock = _plan_details_fetch_locks.setdefault(plan_id, asyncio.Lock())
    async with lock:
        cached_after_lock = _get_cached_plan_details(plan_id)
        if cached_after_lock:
            return cached_after_lock

        try:
            client = get_supabase_client()
            result = await _execute_query(
                client.table("pricing_plans").select("*").eq("id", plan_id).maybe_single()
            )
        
            if result and result.data:
                data = result.data
                plan = PlanLimits(
                    plan_id=data["id"],
                    plan_name=data["name"],
                    max_repos=data.get("max_repos", 1),
                    max_prs_per_month=data.get("max_prs_per_month", 30),
                    max_team_members=data.get("max_team_members", 1),
                    feature_advisory_mode=data.get("feature_advisory_mode", True),
                    feature_enforcement_mode=data.get("feature_enforcement_mode", False),
                    feature_dashboard=data.get("feature_dashboard", True),
                    feature_audit_logs=data.get("feature_audit_logs", False),
                    feature_sso=data.get("feature_sso", False),
                    feature_policy_as_code=data.get("feature_policy_as_code", False),
                    feature_siem_integration=data.get("feature_siem_integration", False),
                    feature_custom_rules=data.get("feature_custom_rules", False),
                    feature_priority_support=data.get("feature_priority_support", False),
                    feature_dedicated_support=data.get("feature_dedicated_support", False),
                    price_monthly_cents=data.get("price_monthly_cents", 0),
                    price_yearly_cents=data.get("price_yearly_cents", 0),
                )
                _set_cached_plan_details(plan_id, plan)
                return plan
        except Exception as e:
            logger.warning(f"Failed to fetch plan from DB, using defaults: {e}")

    fallback_plan = DEFAULT_PLANS.get(plan_id, DEFAULT_PLANS["free"])
    _set_cached_plan_details(plan_id, fallback_plan)
    return fallback_plan


async def get_organization_plan(org_id: str) -> PlanLimits:
    """Get the plan limits for an organization."""
    plan_start = time.perf_counter()
    cached_plan = _get_cached_plan(org_id)
    if cached_plan:
        elapsed_ms = (time.perf_counter() - plan_start) * 1000
        logger.info(f"[timing][subscriptions/get_organization_plan] cache_hit=true total_ms={elapsed_ms:.2f} org_id={org_id}")
        add_request_timing("subscriptions.get_organization_plan", elapsed_ms)
        return cached_plan

    lock = _org_plan_fetch_locks.setdefault(org_id, asyncio.Lock())
    async with lock:
        cached_after_lock = _get_cached_plan(org_id)
        if cached_after_lock:
            elapsed_ms = (time.perf_counter() - plan_start) * 1000
            logger.info(f"[timing][subscriptions/get_organization_plan] cache_hit=after_lock total_ms={elapsed_ms:.2f} org_id={org_id}")
            add_request_timing("subscriptions.get_organization_plan", elapsed_ms)
            return cached_after_lock

        from .database import get_supabase_client

        try:
            client = get_supabase_client()

            # Get org's plan_id
            org_query_start = time.perf_counter()
            result = await _execute_query(
                client.table("organizations").select("plan_id").eq("id", org_id).maybe_single()
            )
            org_query_ms = (time.perf_counter() - org_query_start) * 1000
            logger.info(f"[timing][subscriptions/get_organization_plan] org_plan_query_ms={org_query_ms:.2f} org_id={org_id}")

            if result and result.data:
                plan_id = result.data.get("plan_id", "free")
                limits_start = time.perf_counter()
                plan = await get_plan_limits(plan_id)
                limits_ms = (time.perf_counter() - limits_start) * 1000
                _set_cached_plan(org_id, plan)
                elapsed_ms = (time.perf_counter() - plan_start) * 1000
                logger.info(
                    f"[timing][subscriptions/get_organization_plan] cache_hit=false plan_limits_ms={limits_ms:.2f} total_ms={elapsed_ms:.2f} org_id={org_id} plan_id={plan_id}"
                )
                add_request_timing("subscriptions.get_organization_plan", elapsed_ms)
                return plan
        except Exception as e:
            logger.warning(f"Failed to fetch org plan: {e}")
    
    fallback = DEFAULT_PLANS["free"]
    _set_cached_plan(org_id, fallback)
    elapsed_ms = (time.perf_counter() - plan_start) * 1000
    logger.info(f"[timing][subscriptions/get_organization_plan] fallback=true total_ms={elapsed_ms:.2f} org_id={org_id}")
    add_request_timing("subscriptions.get_organization_plan", elapsed_ms)
    return fallback


async def get_usage_status(org_id: str, use_cache: bool = True) -> UsageStatus:
    """Get current usage status for an organization."""
    usage_start = time.perf_counter()
    if use_cache:
        cached_usage = _get_cached_usage(org_id)
        if cached_usage:
            elapsed_ms = (time.perf_counter() - usage_start) * 1000
            logger.info(f"[timing][subscriptions/get_usage_status] cache_hit=true total_ms={elapsed_ms:.2f} org_id={org_id}")
            add_request_timing("subscriptions.get_usage_status", elapsed_ms)
            return cached_usage

    lock = _usage_fetch_locks.setdefault(org_id, asyncio.Lock())
    async with lock:
        if use_cache:
            cached_after_lock = _get_cached_usage(org_id)
            if cached_after_lock:
                elapsed_ms = (time.perf_counter() - usage_start) * 1000
                logger.info(f"[timing][subscriptions/get_usage_status] cache_hit=after_lock total_ms={elapsed_ms:.2f} org_id={org_id}")
                add_request_timing("subscriptions.get_usage_status", elapsed_ms)
                return cached_after_lock

        from .database import get_supabase_client

        try:
            client = get_supabase_client()
            plan = await get_organization_plan(org_id)
            today = date.today()
            period_start, period_end = await _resolve_billing_period(org_id, today)

            usage_query = (
                client.table("usage_records")
                .select("prs_reviewed")
                .eq("org_id", org_id)
                .lte("period_start", today.isoformat())
                .gte("period_end", today.isoformat())
                .order("period_start", desc=True)
                .order("created_at", desc=True)
                .limit(1)
            )
            repos_query = (
                client.table("repo_configs")
                .select("id", count="exact")
                .eq("org_id", org_id)
                .eq("enabled", True)
            )
            members_query = (
                client.table("org_members")
                .select("id", count="exact")
                .eq("org_id", org_id)
            )
            exact_period_usage_query = (
                client.table("usage_records")
                .select("prs_reviewed")
                .eq("org_id", org_id)
                .eq("period_start", period_start.isoformat())
                .eq("period_end", period_end.isoformat())
                .order("created_at", desc=True)
                .limit(1)
            )

            usage_result, repos_result, members_result, exact_usage_result = await asyncio.gather(
                _execute_query(usage_query),
                _execute_query(repos_query),
                _execute_query(members_query),
                _execute_query(exact_period_usage_query),
            )

            usage_rows = (exact_usage_result.data if exact_usage_result and exact_usage_result.data else None) or (
                usage_result.data if usage_result and usage_result.data else []
            )
            prs_used = int(usage_rows[0].get("prs_reviewed") or 0) if usage_rows else 0
            repos_used = int(repos_result.count or 0) if repos_result else 0
            members_used = int(members_result.count or 0) if members_result else 0

            repos_limit = plan.max_repos
            prs_limit = plan.max_prs_per_month
            members_limit = plan.max_team_members

            within_limits = True
            if repos_limit != -1 and repos_used >= repos_limit:
                within_limits = False
            if prs_limit != -1 and prs_used >= prs_limit:
                within_limits = False
            if members_limit != -1 and members_used >= members_limit:
                within_limits = False

            usage_status = UsageStatus(
                within_limits=within_limits,
                repos_used=repos_used,
                repos_limit=repos_limit,
                repos_remaining=-1 if repos_limit == -1 else max(0, repos_limit - repos_used),
                prs_used=prs_used,
                prs_limit=prs_limit,
                prs_remaining=-1 if prs_limit == -1 else max(0, prs_limit - prs_used),
                members_used=members_used,
                members_limit=members_limit,
                members_remaining=-1 if members_limit == -1 else max(0, members_limit - members_used),
                plan_id=plan.plan_id,
                plan_name=plan.plan_name,
            )
            _set_cached_usage(org_id, usage_status)
            elapsed_ms = (time.perf_counter() - usage_start) * 1000
            logger.info(
                "[timing][subscriptions/get_usage_status] cache_hit=false total_ms=%.2f org_id=%s period=%s..%s prs_used=%s",
                elapsed_ms,
                org_id,
                period_start.isoformat(),
                period_end.isoformat(),
                prs_used,
            )
            add_request_timing("subscriptions.get_usage_status", elapsed_ms)
            return usage_status
        except Exception as e:
            logger.warning(f"Failed to get usage status via direct table reads: {e}")
    
    # Return default free tier usage (assume at limit)
    fallback_usage = UsageStatus(
        within_limits=True,
        repos_used=0,
        repos_limit=1,
        repos_remaining=1,
        prs_used=0,
        prs_limit=30,
        prs_remaining=30,
        members_used=1,
        members_limit=1,
        members_remaining=0,
        plan_id="free",
        plan_name="Free",
    )
    _set_cached_usage(org_id, fallback_usage)
    elapsed_ms = (time.perf_counter() - usage_start) * 1000
    logger.info(f"[timing][subscriptions/get_usage_status] fallback=true total_ms={elapsed_ms:.2f} org_id={org_id}")
    add_request_timing("subscriptions.get_usage_status", elapsed_ms)
    return fallback_usage


async def check_can_add_repo(org_id: str) -> tuple[bool, Optional[str]]:
    """Repository count limits are intentionally not enforced."""
    return True, None


async def check_can_review_pr(org_id: str) -> tuple[bool, Optional[str]]:
    """Check if organization can perform another PR review this month."""
    usage = await get_usage_status(org_id, use_cache=False)
    
    if usage.prs_limit == -1:  # Unlimited
        return True, None
    
    if usage.prs_used >= usage.prs_limit:
        return False, f"Monthly PR review limit reached ({usage.prs_used}/{usage.prs_limit}). Upgrade your plan for more reviews."
    
    return True, None


async def check_can_add_member(org_id: str) -> tuple[bool, Optional[str]]:
    """Check if organization can add another team member."""
    usage = await get_usage_status(org_id, use_cache=False)
    
    if usage.members_limit == -1:  # Unlimited
        return True, None
    
    if usage.members_used >= usage.members_limit:
        return False, f"Team member limit reached ({usage.members_used}/{usage.members_limit}). Upgrade your plan to add more members."
    
    return True, None


async def check_feature_access(org_id: str, feature: str) -> tuple[bool, Optional[str]]:
    """Check if organization has access to a specific feature."""
    plan = await get_organization_plan(org_id)
    
    feature_attr = f"feature_{feature}"
    has_feature = getattr(plan, feature_attr, False)
    
    if not has_feature:
        return False, f"The '{feature.replace('_', ' ')}' feature is not available on the {plan.plan_name} plan. Upgrade to access this feature."
    
    return True, None


async def increment_pr_usage(org_id: str) -> bool:
    """Increment PR review usage for the current month.

    Returns:
        True when usage increment succeeds, False otherwise.
    """
    from .database import get_supabase_client

    try:
        client = get_supabase_client()
        today = date.today()
        period_start, period_end = await _resolve_billing_period(org_id, today)

        existing = await _execute_query(
            client.table("usage_records")
            .select("id, prs_reviewed")
            .eq("org_id", org_id)
            .eq("period_start", period_start.isoformat())
            .eq("period_end", period_end.isoformat())
            .order("created_at", desc=False)
            .limit(1)
        )

        if not existing or not existing.data:
            # Backward compatibility: support previously stored rows where period
            # boundaries may differ but still include today's date.
            existing = await _execute_query(
                client.table("usage_records")
                .select("id, prs_reviewed")
                .eq("org_id", org_id)
                .lte("period_start", today.isoformat())
                .gte("period_end", today.isoformat())
                .order("period_start", desc=True)
                .order("created_at", desc=True)
                .limit(1)
            )

        now_iso = datetime.utcnow().isoformat()
        rows = existing.data if existing and existing.data else []
        if rows:
            record = rows[0]
            current_count = int(record.get("prs_reviewed") or 0)
            await _execute_query(
                client.table("usage_records")
                .update(
                    {
                        "prs_reviewed": current_count + 1,
                        "updated_at": now_iso,
                    }
                )
                .eq("id", record["id"])
            )
        else:
            await _execute_query(
                client.table("usage_records").insert(
                    {
                        "org_id": org_id,
                        "period_start": period_start.isoformat(),
                        "period_end": period_end.isoformat(),
                        "repos_count": 0,
                        "prs_reviewed": 1,
                        "findings_count": 0,
                        "team_members_count": 0,
                        "updated_at": now_iso,
                    }
                )
            )

        _usage_status_cache.pop(org_id, None)
        logger.info(
            "Incremented PR usage via usage_records path for org %s period %s..%s",
            org_id,
            period_start.isoformat(),
            period_end.isoformat(),
        )
        return True
    except Exception as error:
        logger.error(f"Failed to increment PR usage for org {org_id}: {error}")
        return False


async def get_all_plans() -> list[dict]:
    """Get all available pricing plans."""
    from .database import get_supabase_client
    
    try:
        client = get_supabase_client()
        result = await _execute_query(
            client.table("pricing_plans").select("*").eq("is_active", True).order("display_order")
        )
        
        if result and result.data:
            return result.data
    except Exception as e:
        logger.warning(f"Failed to fetch plans from DB: {e}")
    
    # Return default plans
    return [
        {
            "id": "free",
            "name": "Free",
            "description": "Perfect for individual developers and small projects",
            "price_monthly_cents": 0,
            "price_yearly_cents": 0,
            "max_repos": 1,
            "max_prs_per_month": 30,
            "max_team_members": 1,
            "feature_advisory_mode": True,
            "feature_enforcement_mode": False,
            "feature_dashboard": True,
            "feature_audit_logs": False,
            "feature_sso": False,
            "feature_policy_as_code": False,
            "feature_siem_integration": False,
            "feature_custom_rules": False,
            "feature_priority_support": False,
            "feature_dedicated_support": False,
        },
        {
            "id": "team",
            "name": "Team",
            "description": "For growing teams that need security enforcement",
            "price_monthly_cents": 4900,
            "price_yearly_cents": 49900,
            "max_repos": 10,
            "max_prs_per_month": 500,
            "max_team_members": 10,
            "feature_advisory_mode": True,
            "feature_enforcement_mode": True,
            "feature_dashboard": True,
            "feature_audit_logs": False,
            "feature_sso": False,
            "feature_policy_as_code": False,
            "feature_siem_integration": False,
            "feature_custom_rules": False,
            "feature_priority_support": True,
            "feature_dedicated_support": False,
        },
        {
            "id": "enterprise",
            "name": "Enterprise",
            "description": "For organizations requiring compliance and advanced security",
            "price_monthly_cents": 0,
            "price_yearly_cents": 0,
            "max_repos": -1,
            "max_prs_per_month": -1,
            "max_team_members": -1,
            "feature_advisory_mode": True,
            "feature_enforcement_mode": True,
            "feature_dashboard": True,
            "feature_audit_logs": True,
            "feature_sso": True,
            "feature_policy_as_code": True,
            "feature_siem_integration": True,
            "feature_custom_rules": True,
            "feature_priority_support": True,
            "feature_dedicated_support": True,
        },
    ]


async def get_subscription(org_id: str) -> Optional[dict]:
    """Get subscription details for an organization."""
    from .database import get_supabase_client
    
    try:
        client = get_supabase_client()
        result = await _execute_query(
            client.table("subscriptions").select(
                "*, pricing_plans(*)"
            ).eq("org_id", org_id).maybe_single()
        )
        
        if result and result.data:
            return result.data
    except Exception as e:
        logger.warning(f"Failed to get subscription: {e}")
    
    return None


async def update_subscription_plan(
    org_id: str, 
    plan_id: str, 
    billing_cycle: str = "monthly",
    stripe_subscription_id: Optional[str] = None,
    status: str = "active"
) -> dict:
    """Update an organization's subscription plan."""
    from .database import get_supabase_client
    
    client = get_supabase_client()
    
    # Update organization's plan
    await _execute_query(
        client.table("organizations").update({
            "plan_id": plan_id,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("id", org_id)
    )
    
    # Update or create subscription
    now = datetime.utcnow()
    subscription_data = {
        "org_id": org_id,
        "plan_id": plan_id,
        "status": status,
        "billing_cycle": billing_cycle,
        "current_period_start": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    
    if stripe_subscription_id:
        subscription_data["stripe_subscription_id"] = stripe_subscription_id
    
    result = await _execute_query(
        client.table("subscriptions").upsert(
            subscription_data,
            on_conflict="org_id"
        )
    )

    _org_plan_cache.pop(org_id, None)
    _usage_status_cache.pop(org_id, None)
    
    return result.data[0] if result.data else {}


def require_feature(feature: str):
    """
    Dependency factory for requiring a specific feature.
    Use as: Depends(require_feature("enforcement_mode"))
    
    Note: This function returns a dependency that should be used with FastAPI's Depends.
    The actual dependency injection happens in the route where it's used.
    """
    # Import here to avoid circular imports at module load time
    from fastapi import Depends, Request
    from .config import Settings, get_settings
    
    async def check_feature_dependency(
        request: Request,
        settings: Settings = Depends(get_settings)
    ):
        # Reuse JWT dashboard tenant resolution to avoid CI/CD-only token checks.
        from .main import require_tenant_context_flexible

        tenant = await require_tenant_context_flexible(request=request, settings=settings)

        can_access, message = await check_feature_access(tenant.org_id, feature)
        if not can_access:
            raise HTTPException(status_code=403, detail=message)
        return True
    return check_feature_dependency


def require_within_limits():
    """
    Dependency for checking if org is within usage limits.
    """
    async def check_limits(org_id: str):
        usage = await get_usage_status(org_id)
        if not usage.within_limits:
            message = usage.get_limit_message() or "Usage limits exceeded"
            raise HTTPException(status_code=403, detail=message)
        return usage
    return check_limits
