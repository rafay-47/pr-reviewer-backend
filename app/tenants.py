"""
Multi-tenant support for the AI AppSec PR Reviewer.

Handles tenant resolution from headers, tokens, and provides
tenant-scoped access to resources.
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from fastapi import HTTPException, Request

from .database import (
    get_organization_by_id,
    get_repo_config,
    validate_api_token,
    get_active_suppressions,
)
from .audit_log import get_audit_logger, AuditEventType, AuditEvent
from .security import get_request_id, get_client_identifier, get_user_agent
from .security import add_request_timing

logger = logging.getLogger(__name__)


@dataclass
class TenantContext:
    """Context for the current tenant/organization."""
    org_id: str
    org_name: Optional[str] = None
    org_slug: Optional[str] = None
    token_id: Optional[str] = None
    token_scopes: list[str] = None
    user_id: Optional[str] = None
    user_role: Optional[str] = None  # User's role in the organization (owner, admin, member)
    user_email: Optional[str] = None  # User's email address
    
    def __post_init__(self):
        if self.token_scopes is None:
            self.token_scopes = []
    
    def has_scope(self, scope: str) -> bool:
        """Check if the tenant context has a specific scope."""
        # Wildcard scope grants all permissions
        if "*" in self.token_scopes:
            return True
        return scope in self.token_scopes
    
    def require_scope(self, scope: str) -> None:
        """Require a specific scope, raise 403 if not present."""
        if not self.has_scope(scope):
            raise HTTPException(
                status_code=403,
                detail=f"Missing required scope: {scope}"
            )
    
    def is_admin_or_owner(self) -> bool:
        """Check if user has admin or owner role."""
        return self.user_role in ["admin", "owner"]


async def resolve_tenant_from_request(request: Request) -> TenantContext:
    """
    Resolve tenant context from the request.
    
    Priority:
    1. X-Tenant-ID header (explicit tenant selection)
    2. Token-based resolution (org_id from token)
    
    Args:
        request: The FastAPI request
        
    Returns:
        TenantContext with org_id and scopes
        
    Raises:
        HTTPException: If tenant cannot be resolved
    """
    resolve_start = time.perf_counter()
    cached_tenant = getattr(request.state, "tenant_context", None)
    if cached_tenant:
        elapsed_ms = (time.perf_counter() - resolve_start) * 1000
        logger.info(f"[timing][tenant/resolve] cache_hit=true total_ms={elapsed_ms:.2f}")
        add_request_timing("tenant.resolve", elapsed_ms)
        return cached_tenant

    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(request)
    user_agent = get_user_agent(request)
    
    # Try to get tenant from header first
    tenant_id = request.headers.get("X-Tenant-ID")
    
    # Get authorization header (required in multi-tenant token flow)
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        audit.log_auth_failure(
            request_id=request_id,
            reason="Missing bearer token",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Authorization header is required. Use 'Bearer <api_token>'."
        )

    token = auth_header.replace("Bearer ", "").strip()
    if not token or not token.startswith("aiappsec_"):
        audit.log_auth_failure(
            request_id=request_id,
            reason="Non-CI/CD token used on API-token endpoint",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="This endpoint requires a CI/CD API token (starting with 'aiappsec_')."
        )

    # Pass IP and user agent for usage tracking
    token_validate_start = time.perf_counter()
    token_data = await validate_api_token(
        token,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    token_validate_ms = (time.perf_counter() - token_validate_start) * 1000
    logger.info(f"[timing][tenant/resolve] token_validate_ms={token_validate_ms:.2f}")

    if not token_data:
        audit.log_auth_failure(
            request_id=request_id,
            reason="Invalid or expired API token",
            ip_address=ip_address,
            user_agent=user_agent,
            token_prefix=token[:16] if token else None,
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API token"
        )
    
    # Determine org_id from token and validate optional explicit header
    org_id = token_data.get("org_id")

    if tenant_id:
        if org_id != tenant_id:
            audit.log(AuditEvent(
                event_type=AuditEventType.AUTHZ_FAILURE,
                timestamp=datetime.utcnow().isoformat(),
                request_id=request_id,
                ip_address=ip_address,
                resource_type="org",
                resource_id=tenant_id,
                action="access",
                success=False,
                failure_reason="Token does not belong to the specified tenant",
            ))
            raise HTTPException(
                status_code=403,
                detail="Token does not belong to the specified tenant"
            )
        org_id = tenant_id
    
    if not org_id:
        audit.log_auth_failure(
            request_id=request_id,
            reason="Tenant ID not provided",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Unable to resolve tenant from API token"
        )
    
    # Get org details
    org_lookup_start = time.perf_counter()
    org = await get_organization_by_id(org_id)
    org_lookup_ms = (time.perf_counter() - org_lookup_start) * 1000
    logger.info(f"[timing][tenant/resolve] org_lookup_ms={org_lookup_ms:.2f}")
    if not org:
        audit.log(AuditEvent(
            event_type=AuditEventType.AUTHZ_FAILURE,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            ip_address=ip_address,
            resource_type="org",
            resource_id=org_id,
            action="access",
            success=False,
            failure_reason="Organization not found",
        ))
        raise HTTPException(
            status_code=404,
            detail=f"Organization not found: {org_id}"
        )
    
    # Build context
    scopes = token_data.get("scopes") or []
    
    tenant_context = TenantContext(
        org_id=org_id,
        org_name=org.get("name"),
        org_slug=org.get("slug"),
        token_id=token_data.get("id") if token_data else None,
        token_scopes=scopes
    )
    request.state.tenant_context = tenant_context
    elapsed_ms = (time.perf_counter() - resolve_start) * 1000
    logger.info(f"[timing][tenant/resolve] cache_hit=false total_ms={elapsed_ms:.2f}")
    add_request_timing("tenant.resolve", elapsed_ms)
    return tenant_context


async def get_tenant_repo_policy(tenant: TenantContext, repo_name: str) -> Optional[dict]:
    """
    Get repository policy for a tenant.
    
    Falls back to default policy if no specific config exists.
    
    Args:
        tenant: The tenant context
        repo_name: Repository name (e.g., "org/repo")
        
    Returns:
        Policy dict or None
    """
    config = await get_repo_config(tenant.org_id, repo_name)
    
    if config and config.get("enabled", True):
        return config.get("policy")
    
    # Return default policy if no config
    return {
        "mode": "advisory",
        "fail_on": "HIGH",
        "max_findings": 10,
        "min_risk": "LOW",
        "min_confidence": "LOW",
        "blocklist": [],
        "rules": {
            "injection": True,
            "secrets": True,
            "auth": True,
            "ssrf": True,
            "crypto": True,
            "deserialization": True
        }
    }


async def get_tenant_suppressions(tenant: TenantContext) -> list[dict]:
    """
    Get active suppression rules for a tenant.
    
    Args:
        tenant: The tenant context
        
    Returns:
        List of suppression rules
    """
    return await get_active_suppressions(tenant.org_id)


def check_suppression(
    finding: dict,
    suppressions: list[dict]
) -> bool:
    """
    Check if a finding should be suppressed.
    
    Args:
        finding: The finding dict
        suppressions: List of suppression rules
        
    Returns:
        True if the finding should be suppressed
    """
    import fnmatch
    import re
    
    fingerprint = finding.get("fingerprint", "")
    title = finding.get("title", "")
    file_path = finding.get("file_path", "")
    category = finding.get("category", "")
    
    for rule in suppressions:
        # Check fingerprint match
        if rule.get("fingerprint") and rule["fingerprint"] == fingerprint:
            logger.debug(f"Suppressing finding by fingerprint: {fingerprint}")
            return True
        
        # Check title pattern
        if rule.get("title_pattern"):
            try:
                if re.search(rule["title_pattern"], title, re.IGNORECASE):
                    logger.debug(f"Suppressing finding by title pattern: {title}")
                    return True
            except re.error:
                logger.warning(f"Invalid title pattern: {rule['title_pattern']}")
        
        # Check file pattern
        if rule.get("file_pattern") and file_path:
            if fnmatch.fnmatch(file_path, rule["file_pattern"]):
                logger.debug(f"Suppressing finding by file pattern: {file_path}")
                return True
        
        # Check category
        if rule.get("category") and rule["category"] == category:
            logger.debug(f"Suppressing finding by category: {category}")
            return True
    
    return False


class TenantMiddleware:
    """
    Middleware to resolve tenant for each request.
    
    This is an optional middleware - some routes may handle
    tenant resolution manually.
    """
    
    EXCLUDED_PATHS = {"/", "/health", "/docs", "/redoc", "/openapi.json"}
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Check if path is excluded
        path = scope.get("path", "")
        if path in self.EXCLUDED_PATHS:
            await self.app(scope, receive, send)
            return
        
        await self.app(scope, receive, send)
