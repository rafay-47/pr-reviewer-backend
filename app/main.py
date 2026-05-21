"""
AI AppSec PR Reviewer - FastAPI Application

Main entry point for the security review API service.
Exposes the /review-pr endpoint for analyzing pull request diffs.

Production-ready with:
- Configurable CORS
- Request ID tracing
- Security headers
- Audit logging
- Graceful shutdown
"""

import asyncio
import json
import hashlib
import logging
import secrets
import signal
import time
from contextlib import asynccontextmanager
from datetime import datetime, UTC
from typing import Optional, Dict, List
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .config import Settings, get_settings
from .models import (
    ReviewRequest, ReviewResponse, ErrorResponse,
    ExplainFindingRequest, ExplainFindingResponse,
    AggregatedMetrics, ReviewMetrics, SuppressionRuleRequest,
    # New models for Sprint 3
    TokenCreateRequest, TokenCreateResponse, TokenListResponse,
    TokenType, TokenTypesResponse, TokenTypeInfo, CicdTokenResponse, RegenerateCicdTokenResponse,
    FeedbackRequest, FeedbackResponse,
    DashboardStatsResponse, CategoryStatsResponse, RepoRiskResponse, TrendDataResponse,
    ChatRequest, ChatResponse,
    RepoConfigRequest, RepoConfigResponse,
    # GitHub integration models
    GitHubRepoInfo, GitHubReposResponse, GitHubImportRequest, GitHubImportResponse,
    WorkflowStatusResponse, WorkflowInstallRequest, WorkflowInstallResponse,
    QuickSetupRequest, QuickSetupResponse,
    # Organization models
    CreateOrgRequest, CreateOrgResponse,
    # Invitation models
    CreateInvitationRequest, InvitationResponse, AcceptInvitationRequest, 
    AcceptInvitationResponse, InvitationListResponse, PendingInvitation,
    # Finding resolution models
    ResolveFindingRequest, BulkResolveFindingsRequest, ReopenFindingRequest,
    ResolutionResponse, FindingStatusHistory,
    # Organization switching
    SwitchOrgResponse,
)
from .models_github_app import (
    GitHubAppInstallationRequest,
    GitHubAppInstallationResponse,
    GitHubAppInstallationInfo,
    GitHubAppInstallationsListResponse,
)
from .models_gitlab import (
    GitLabProjectInfo,
    GitLabProjectsResponse,
    GitLabImportRequest,
    GitLabImportResult,
    GitLabImportResponse,
    GitLabWebhookInstallRequest,
    GitLabWebhookInstallResult,
    GitLabWebhookInstallResponse,
    GitLabWebhookStatusResponse,
)
from .models_gitlab_app import (
    GitLabAppInstallationRequest,
    GitLabAppInstallationResponse,
    GitLabAppInstallationInfo,
    GitLabAppInstallationsListResponse,
)
from .llm_client import analyze_diff, regenerate_markdown_with_resolved, attach_review_identity
from .explain_finding import explain_sast_finding
from .metrics import MetricsTracker, get_metrics_tracker
from .security import (
    get_rate_limiter,
    get_token_rate_limiter,
    get_client_identifier,
    get_user_agent,
    validate_request_security,
    sanitize_for_logging,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    get_request_id,
    init_request_timing,
    clear_request_timing,
    get_request_timing_breakdown,
    add_request_timing,
)
from .audit_log import get_audit_logger, AuditEventType, AuditEvent
from .tenants import TenantContext, resolve_tenant_from_request, get_tenant_repo_policy, get_tenant_suppressions, check_suppression
from .auth import get_user_from_jwt, get_user_with_org, get_user_flexible, UserContext, require_org_role, require_cicd_token, require_jwt_only, require_review_pr_auth, fetch_jwks
from .subscriptions import (
    check_can_review_pr, check_can_add_repo, check_can_add_member, increment_pr_usage, check_feature_access,
    get_usage_status, get_organization_plan, require_feature
)
from .database import (
    create_api_token, list_api_tokens, revoke_api_token, rotate_api_token,
    create_review, create_findings, get_dashboard_stats, get_findings_by_category,
    get_top_risky_repos, get_review_trend, create_feedback, get_feedback_for_org,
    get_active_suppressions, create_suppression_rule, delete_suppression_rule,
    upsert_repo_config, list_repo_configs, get_repo_config,
    validate_api_token,
    # Active findings dashboard functions
    get_active_findings_stats, get_active_findings_by_category,
    get_active_findings_trend, get_top_risky_repos_active,
    # Review history and tracking functions
    get_previous_pr_review, get_previous_pr_findings, mark_findings_resolved,
    compare_pr_reviews, link_review_to_previous,
    # Finding resolution functions
    resolve_finding, bulk_resolve_findings, auto_resolve_pr_findings,
    reopen_finding, get_finding_status_history,
)

# Security scheme for Swagger UI
security_scheme = HTTPBearer(
    scheme_name="Bearer Token",
    description="Enter your API authentication token (same as API_AUTH_TOKEN)",
    auto_error=False  # Don't auto-error, we handle it manually to allow optional auth
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Graceful shutdown flag
_shutdown_event = asyncio.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    settings = get_settings()
    
    # Startup
    logger.info("Starting AI AppSec PR Reviewer API")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"LLM Provider: {settings.llm_provider}")
    logger.info(f"Model: {settings.effective_model}")
    
    # Security configuration status
    logger.info("Security Configuration:")
    logger.info(f"   - Multi-Tenant Mode: {'Enabled' if settings.multi_tenant_mode else 'Disabled (single-tenant)'}")
    logger.info(f"   - Database: {'Configured' if settings.database_configured else 'NOT CONFIGURED'}")
    logger.info(f"   - Redis: {'Configured' if settings.redis_configured else 'NOT CONFIGURED (using in-memory rate limiting)'}")
    logger.info(f"   - Bearer Auth: {'Configured' if settings.api_auth_token else 'NOT CONFIGURED'}")
    logger.info(f"   - HMAC Auth: {'Enabled' if settings.hmac_enabled else 'Disabled'}")
    logger.info(f"   - Rate Limiting: {settings.rate_limit_requests} req/{settings.rate_limit_window}s")
    logger.info(f"   - Token Rate Limiting: {settings.rate_limit_token_creation} creations/hour")
    logger.info(f"   - Max Token Lifetime: {settings.token_max_lifetime_days} days")
    logger.info(f"   - CORS Origins: {settings.cors_origins_list or 'None configured'}")
    logger.info(f"   - Security Headers: {'Enabled' if settings.enable_security_headers else 'Disabled'}")
    logger.info(f"   - Audit Logging: {'Enabled' if settings.enable_audit_logging else 'Disabled'}")
    
    # Initialize rate limiters
    get_rate_limiter(
        settings.rate_limit_requests,
        settings.rate_limit_window,
        settings.redis_url
    )
    get_token_rate_limiter(
        settings.rate_limit_token_creation,
        3600,  # 1 hour window
        settings.redis_url
    )
    
    # Initialize audit logger
    db_client = None
    if settings.database_configured:
        try:
            from .database import get_supabase_client
            db_client = get_supabase_client()
            logger.info("Database connection established")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
    
    get_audit_logger(enabled=settings.enable_audit_logging, db_client=db_client)
    
    # Initialize metrics tracker
    get_metrics_tracker()

    # Pre-warm JWKS cache so first authenticated requests don't pay cold-fetch latency.
    if settings.supabase_url:
        try:
            warmup_start = time.perf_counter()
            await fetch_jwks(settings.supabase_url)
            warmup_ms = (time.perf_counter() - warmup_start) * 1000
            logger.info(f"[timing][startup/jwks_warmup] success=true total_ms={warmup_ms:.2f}")
        except Exception as e:
            logger.warning(f"[timing][startup/jwks_warmup] success=false error={e}")
    
    # Validate configuration
    errors = settings.validate_config()
    warnings = settings.get_warnings()
    
    if errors:
        for error in errors:
            logger.error(f"Configuration error: {error}")
        if settings.is_production:
            raise RuntimeError(f"Cannot start in production with configuration errors: {errors}")
        logger.warning("Service started with configuration errors - some features may not work")
    
    for warning in warnings:
        logger.warning(f"Configuration warning: {warning}")
    
    if not errors:
        logger.info("Configuration validated successfully")
    
    yield
    
    # Graceful shutdown
    logger.info("Initiating graceful shutdown...")
    _shutdown_event.set()
    
    # Wait for in-flight requests (with timeout)
    await asyncio.sleep(min(settings.shutdown_timeout_seconds, 5))
    
    logger.info("AI AppSec PR Reviewer API shutdown complete")


# Helper function to normalize findings from database format to API format
def normalize_finding(finding: dict) -> dict:
    """
    Normalize a finding from database format to API format.
    
    Database uses 'severity', API uses 'risk' for consistency with frontend.
    Also ensures all required fields are present.
    """
    if not finding:
        return finding
    
    # Create a copy to avoid modifying the original
    normalized = dict(finding)
    
    # Map severity to risk if risk is not present
    if "risk" not in normalized and "severity" in normalized:
        normalized["risk"] = normalized["severity"]
    
    # Ensure status defaults to 'open' if not present
    if "status" not in normalized:
        normalized["status"] = "open"
    
    return normalized


def normalize_findings(findings: list) -> list:
    """Normalize a list of findings."""
    return [normalize_finding(f) for f in findings if f]


# Create FastAPI application
app = FastAPI(
    title="AI AppSec PR Reviewer",
    description="""
    **AI-Powered Security Review for Pull Requests**
    
    This API analyzes code changes in pull requests for security vulnerabilities,
    acting as a Senior Application Security Engineer.
    
    ## Features
    
    - **Injection Detection**: SQL, NoSQL, OS command, LDAP, template injections
    - **Authentication Analysis**: Broken auth, session management issues
    - **Authorization Checks**: IDOR, broken access control
    - **Secrets Detection**: Hardcoded credentials, API keys, tokens
    - **Cryptography Review**: Weak crypto, insecure random values
    - **Input Validation**: Path traversal, SSRF, unsafe file handling
    
    ## Usage
    
    Send a POST request to `/review-pr` with the PR diff and metadata.
    The API will return structured findings and a markdown comment for the PR.
    """,
    version="0.2.0",
    lifespan=lifespan,
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    }
)

# Add Request ID middleware (first, so all other middleware can use it)
app.add_middleware(RequestIDMiddleware)

# Add Security Headers middleware
settings = get_settings()
if settings.enable_security_headers:
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)

# Add CORS middleware with configurable origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "Content-Type", "Location"],
)


@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    """Log end-to-end request timing for latency debugging."""
    timing_token = init_request_timing()
    request_start = time.perf_counter()
    try:
        response = await call_next(request)
        total_ms = (time.perf_counter() - request_start) * 1000
        add_request_timing("request.total", total_ms)
        request_id = get_request_id()
        logger.info(
            f"[timing][request] method={request.method} path={request.url.path} status={response.status_code} total_ms={total_ms:.2f} request_id={request_id or 'n/a'}"
        )

        breakdown = get_request_timing_breakdown()
        if breakdown:
            rounded_breakdown = {k: round(v, 2) for k, v in sorted(breakdown.items())}
            logger.info(
                f"[timing][request_summary] method={request.method} path={request.url.path} "
                f"status={response.status_code} request_id={request_id or 'n/a'} total_ms={total_ms:.2f} "
                f"breakdown_json={json.dumps(rounded_breakdown, sort_keys=True, separators=(',', ':'))}"
            )

        return response
    finally:
        clear_request_timing(timing_token)


async def verify_auth_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    settings: Settings = Depends(get_settings)
) -> bool:
    """
    Verify the authentication token (legacy single-tenant mode).
    
    Authentication is REQUIRED. If API_AUTH_TOKEN is not configured,
    all requests will be rejected with 401.
    """
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(request)
    user_agent = get_user_agent(request)
    
    # In multi-tenant mode, this is handled by get_tenant_context
    if settings.multi_tenant_mode:
        return True
    
    # Strict auth: always require a valid token
    if not settings.api_auth_token:
        # No token configured on server - reject all requests
        logger.warning("Auth rejected: API_AUTH_TOKEN not configured on server")
        audit.log_auth_failure(
            request_id=request_id,
            reason="API_AUTH_TOKEN not configured on server",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Authentication not configured. Set API_AUTH_TOKEN environment variable."
        )
    
    if not credentials:
        logger.warning("Auth rejected: No Authorization header provided")
        audit.log_auth_failure(
            request_id=request_id,
            reason="No Authorization header provided",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Authorization header is required. Use 'Bearer <token>' format."
        )
    
    if credentials.credentials != settings.api_auth_token:
        logger.warning("Auth rejected: Invalid token provided")
        audit.log_auth_failure(
            request_id=request_id,
            reason="Invalid token provided",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token"
        )
    
    return True


async def get_tenant_context(
    request: Request,
    settings: Settings = Depends(get_settings)
) -> Optional[TenantContext]:
    """
    Get tenant context from the request.
    
    In multi-tenant mode, this resolves the tenant from headers/tokens.
    In single-tenant mode, returns None (no tenant isolation).
    """
    if not settings.multi_tenant_mode:
        return None
    
    return await resolve_tenant_from_request(request)


async def require_tenant_context(
    request: Request,
    settings: Settings = Depends(get_settings)
) -> TenantContext:
    """
    Require tenant context for app/dashboard endpoints.

    This dependency enforces JWT-based tenant resolution so frontend calls
    (dashboard, stats, findings, repos, etc.) do not require CI/CD tokens.
    """
    dependency_start = time.perf_counter()
    if not settings.multi_tenant_mode:
        raise HTTPException(
            status_code=400,
            detail="This endpoint requires multi-tenant mode to be enabled"
        )

    tenant_context = await require_tenant_context_flexible(request, settings)
    elapsed_ms = (time.perf_counter() - dependency_start) * 1000
    logger.info(f"[timing][main/require_tenant_context] total_ms={elapsed_ms:.2f}")
    add_request_timing("main.require_tenant_context", elapsed_ms)
    return tenant_context


def _jwt_scopes_for_role(role: Optional[str]) -> list[str]:
    """Return least-privilege scopes for JWT dashboard users by org role."""
    scopes = ["review:pr", "explain:finding", "read:metrics", "feedback:write"]
    if role in ["admin", "owner"]:
        scopes.extend(["admin:policy", "admin:tokens"])
    return scopes


async def require_tenant_context_flexible(
    request: Request,
    settings: Settings = Depends(get_settings)
) -> TenantContext:
    """
    Tenant context that ONLY accepts Supabase JWT tokens.
    
    This is for frontend/dashboard endpoints. API tokens (aiappsec_*)
    are explicitly rejected - they are only for CI/CD endpoints.
    
    Resolution order:
    1. X-Tenant-ID header (explicit tenant selection)
    2. Supabase JWT (lookup user's org membership)
    """
    from .database import get_user_organizations
    from .auth import verify_supabase_jwt_async
    from .audit_log import get_audit_logger
    from .security import get_request_id, get_client_identifier, get_user_agent
    
    dependency_start = time.perf_counter()
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(request)
    user_agent = get_user_agent(request)
    
    if not settings.multi_tenant_mode:
        raise HTTPException(
            status_code=400,
            detail="This endpoint requires multi-tenant mode to be enabled"
        )

    cached_tenant = getattr(request.state, "tenant_context", None)
    if cached_tenant:
        elapsed_ms = (time.perf_counter() - dependency_start) * 1000
        logger.info(f"[timing][main/require_tenant_context_flexible] cache_hit=true total_ms={elapsed_ms:.2f}")
        add_request_timing("main.require_tenant_context_flexible", elapsed_ms)
        return cached_tenant
    
    # Try to get tenant from header first
    tenant_id = request.headers.get("X-Tenant-ID")
    
    # Get authorization header
    auth_header = request.headers.get("Authorization", "")
    token = None
    
    if auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
    
    if not token:
        audit.log_auth_failure(
            request_id=request_id,
            reason="No authorization header provided",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Authorization header required"
        )
    
    # REJECT API tokens - they are only for CI/CD endpoints
    if token.startswith("aiappsec_"):
        audit.log_auth_failure(
            request_id=request_id,
            reason="API token used on dashboard endpoint - JWT required",
            ip_address=ip_address,
            user_agent=user_agent,
            token_prefix=token[:16] if token else None,
        )
        raise HTTPException(
            status_code=401,
            detail="Dashboard endpoints require Supabase JWT authentication. "
                   "API tokens are for CI/CD use only (review-pr, explain-finding). "
                   "Please log in to the dashboard."
        )
    
    # It's a Supabase JWT - verify and extract user
    try:
        verify_start = time.perf_counter()
        payload = await verify_supabase_jwt_async(token, settings)
        verify_ms = (time.perf_counter() - verify_start) * 1000
        logger.info(f"[timing][main/require_tenant_context_flexible] jwt_verify_ms={verify_ms:.2f}")
        user_id = payload.get("sub")
        user_email = payload.get("email")
        
        if not user_id:
            audit.log_auth_failure(
                request_id=request_id,
                reason="Missing user ID in JWT",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise HTTPException(status_code=401, detail="Invalid token: missing user ID")
        
        # Resolve membership via cached org list helper (includes lock-dedup + TTL cache).
        membership_start = time.perf_counter()
        user_orgs = await get_user_organizations(user_id)
        membership_ms = (time.perf_counter() - membership_start) * 1000

        if tenant_id:
            logger.info(f"[timing][main/require_tenant_context_flexible] org_members_ms={membership_ms:.2f} mode=explicit")
            selected_org = next((org for org in user_orgs if org.get("id") == tenant_id), None)
            if not selected_org:
                audit.log_auth_failure(
                    request_id=request_id,
                    reason=f"User not authorized for organization {tenant_id}",
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"You do not have access to organization {tenant_id}"
                )

            tenant_context = TenantContext(
                org_id=tenant_id,
                org_name=selected_org.get("name"),
                org_slug=selected_org.get("slug"),
                token_scopes=_jwt_scopes_for_role(selected_org.get("role", "member")),
                user_id=user_id,
                user_role=selected_org.get("role", "member"),
                user_email=user_email,
            )
            request.state.tenant_context = tenant_context
            elapsed_ms = (time.perf_counter() - dependency_start) * 1000
            logger.info(f"[timing][main/require_tenant_context_flexible] total_ms={elapsed_ms:.2f} mode=explicit")
            add_request_timing("main.require_tenant_context_flexible", elapsed_ms)
            return tenant_context

        logger.info(f"[timing][main/require_tenant_context_flexible] org_members_ms={membership_ms:.2f} mode=implicit")
        if not user_orgs:
            audit.log_auth_failure(
                request_id=request_id,
                reason="User not a member of any organization",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise HTTPException(
                status_code=403,
                detail="You must be a member of an organization to perform this action. "
                       "Please complete onboarding to create your organization."
            )

        selected_org = user_orgs[0]
        tenant_context = TenantContext(
            org_id=selected_org.get("id"),
            org_name=selected_org.get("name"),
            org_slug=selected_org.get("slug"),
            token_scopes=_jwt_scopes_for_role(selected_org.get("role", "member")),
            user_id=user_id,
            user_role=selected_org.get("role", "member"),
            user_email=user_email,
        )
        request.state.tenant_context = tenant_context
        elapsed_ms = (time.perf_counter() - dependency_start) * 1000
        logger.info(f"[timing][main/require_tenant_context_flexible] total_ms={elapsed_ms:.2f} mode=implicit")
        add_request_timing("main.require_tenant_context_flexible", elapsed_ms)
        return tenant_context
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"JWT verification failed: {type(e).__name__}: {e}")
        audit.log_auth_failure(
            request_id=request_id,
            reason="JWT verification failed",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token"
        )


def require_scope(scope: str):
    """
    Dependency factory for requiring a specific scope.
    """
    async def check_scope(
        tenant: Optional[TenantContext] = Depends(get_tenant_context)
    ):
        if tenant:
            tenant.require_scope(scope)
        return True
    return check_scope


async def get_github_token_for_tenant(tenant: TenantContext) -> str:
    """
    Get GitHub access token for a tenant from GitHub App installation.
    
    This retrieves the GitHub App installation token for use in GitHub API calls.
    
    Args:
        tenant: The authenticated tenant context
        
    Returns:
        GitHub App installation token
        
    Raises:
        HTTPException: If no GitHub App installation exists
    """
    logger.info(f"Getting GitHub App token for tenant org_id={tenant.org_id}, user_id={tenant.user_id}")
    
    try:
        # Get Supabase client to query installations
        from .database import get_supabase_client
        client = get_supabase_client()
        
        # Check for GitHub App installation linked to this org
        result = await asyncio.to_thread(
            lambda: client.table("github_app_installations").select("*").eq(
                "org_id", tenant.org_id
            ).eq("is_active", True).order("installed_at", desc=True).limit(1).execute()
        )
        
        if result.data and len(result.data) > 0:
            installation = result.data[0]
            installation_id = installation.get("installation_id")
            
            if installation_id:
                # Import here to avoid circular dependency
                from .github_app_auth import get_installation_token, InstallationNotFoundError

                try:
                    app_token, _ = await get_installation_token(installation_id)
                except InstallationNotFoundError as exc:
                    logger.warning(
                        f"GitHub installation {installation_id} became inactive for org_id={tenant.org_id}"
                    )
                    raise HTTPException(
                        status_code=409,
                        detail="GitHub App installation is no longer active. Please reinstall the GitHub App from Settings > Integrations.",
                    ) from exc

                logger.info(f"Successfully retrieved GitHub App installation token for org_id={tenant.org_id}")
                return app_token
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting GitHub App installation token for org_id={tenant.org_id}: {e}")
    
    logger.error(f"No GitHub App installation found for org_id={tenant.org_id}, user_id={tenant.user_id}")
    raise HTTPException(
        status_code=400,
        detail="GitHub App installation required. Please install the GitHub App from Settings > Integrations."
    )


async def mark_gitlab_org_integrations_inactive(
    client,
    org_id: str,
    connection_id: Optional[str] = None,
) -> None:
    """Deactivate stale GitLab connection and installation records for an org."""
    deactivated_at = datetime.now(UTC).isoformat()

    def _deactivate() -> None:
        connection_query = client.table("gitlab_connections").update({
            "is_active": False,
            "last_used_at": deactivated_at,
        }).eq("org_id", org_id).eq("is_active", True)
        if connection_id:
            connection_query = connection_query.eq("id", connection_id)
        connection_query.execute()

        client.table("gitlab_app_installations").update({
            "is_active": False,
            "updated_at": deactivated_at,
        }).eq("org_id", org_id).eq("is_active", True).execute()

    await asyncio.to_thread(_deactivate)


async def get_gitlab_token_for_tenant(tenant: TenantContext) -> str:
    """
    Get GitLab access token for a tenant from linked GitLab connection.

    Args:
        tenant: The authenticated tenant context

    Returns:
        GitLab OAuth access token

    Raises:
        HTTPException: If no active GitLab connection exists
    """
    from .database import get_supabase_client
    import httpx

    client = get_supabase_client()

    try:
        result = await asyncio.to_thread(
            lambda: client.table("gitlab_connections").select("*").eq(
                "org_id", tenant.org_id
            ).eq("is_active", True).order("connected_at", desc=True).limit(1).execute()
        )
    except Exception as e:
        logger.error(f"Failed to query GitLab connections for org {tenant.org_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to load GitLab connection")

    row = (result.data or [None])[0]
    if not row:
        raise HTTPException(
            status_code=400,
            detail="GitLab connection required. Please connect GitLab from Settings > Integrations.",
        )

    token = row.get("encrypted_access_token")
    if not token:
        await mark_gitlab_org_integrations_inactive(client, tenant.org_id, str(row.get("id")))
        raise HTTPException(
            status_code=401,
            detail="GitLab authorization has been revoked. Please reconnect GitLab from Settings > Integrations.",
        )

    # Verify the token is still valid by making a test API call
    gitlab_instance_url = row.get("gitlab_instance_url", "https://gitlab.com")
    try:
        async with httpx.AsyncClient() as http_client:
            test_response = await http_client.get(
                f"{gitlab_instance_url}/api/v4/user",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0
            )
            if test_response.status_code == 401:
                # Token is invalid/revoked - mark connection as inactive
                logger.warning(f"GitLab token for org {tenant.org_id} is invalid (401) - marking inactive")
                await mark_gitlab_org_integrations_inactive(client, tenant.org_id, str(row.get("id")))
                raise HTTPException(
                    status_code=401,
                    detail="GitLab authorization has been revoked. Please reconnect GitLab from Settings > Integrations."
                )
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            logger.warning(f"GitLab token for org {tenant.org_id} is invalid (401) - marking inactive")
            await mark_gitlab_org_integrations_inactive(client, tenant.org_id, str(row.get("id")))
            raise HTTPException(
                status_code=401,
                detail="GitLab authorization has been revoked. Please reconnect GitLab from Settings > Integrations."
            )
        raise
    except httpx.RequestError as e:
        # Network error - don't mark inactive, just raise the error
        logger.error(f"Failed to verify GitLab token: {e}")

    return token


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint - redirects to docs."""
    return {
        "service": "AI AppSec PR Reviewer",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", tags=["Health"])
async def health_check(settings: Settings = Depends(get_settings)):
    """
    Health check endpoint.
    
    Returns service status and configuration validation.
    In production, sensitive configuration details are redacted.
    """
    errors = settings.validate_config()
    
    # Base response for all environments
    response = {
        "status": "healthy" if not errors else "degraded",
        "service": "AI AppSec PR Reviewer",
        "version": "0.2.0",
    }
    
    # In production, only expose minimal information
    if settings.is_production:
        response["config_valid"] = len(errors) == 0
    else:
        # In development/staging, expose more details for debugging
        response["llm_provider"] = settings.llm_provider
        response["llm_configured"] = bool(settings.llm_api_key)
        response["security"] = {
            "bearer_auth_enabled": bool(settings.api_auth_token),
            "hmac_auth_enabled": settings.hmac_enabled,
            "rate_limiting": f"{settings.rate_limit_requests}/{settings.rate_limit_window}s",
            "max_diff_size": settings.max_diff_size,
        }
        response["config_errors"] = errors if errors else None
    
    return response


@app.post(
    "/review-pr",
    response_model=ReviewResponse,
    tags=["Security Review"],
    summary="Review a Pull Request for Security Vulnerabilities",
    responses={
        200: {
            "description": "Security review completed successfully",
            "model": ReviewResponse
        },
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        413: {"model": ErrorResponse, "description": "Request too large"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    }
)
async def review_pull_request(
    http_request: Request,
    settings: Settings = Depends(get_settings),
    user: UserContext = Depends(require_review_pr_auth),
) -> ReviewResponse:
    """
    Analyze a pull request diff for security vulnerabilities.
    
    This endpoint accepts PR metadata and a git diff, then uses an LLM
    to perform a security review acting as a Senior AppSec Engineer.
    
    **Request Body:**
    - `repo`: Repository identifier (org/reponame)
    - `pr_number`: Pull request number
    - `language`: Programming language (default: nodejs)
    - `framework`: Web framework (default: express)
    - `diff`: Git diff text containing the code changes
    - `policy`: Optional repository policy for filtering
    - `signature`: HMAC signature (if HMAC auth enabled)
    - `timestamp`: Request timestamp (if HMAC auth enabled)
    
    **Response:**
    - `summary`: Brief summary of findings
    - `findings`: List of security vulnerabilities found
    - `findings_markdown`: Markdown-formatted comment for the PR
    - `findings_hash`: Hash for deduplication
    """
    # Log incoming request details for debugging
    client_id = get_client_identifier(http_request)
    logger.info(f"[review-pr] Incoming request from {client_id}")
    logger.info(f"[review-pr] Content-Type: {http_request.headers.get('content-type')}")
    logger.info(f"[review-pr] Has Authorization: {bool(http_request.headers.get('authorization'))}")
    
    rate_limiter = get_rate_limiter()
    
    # Check rate limit
    if not rate_limiter.is_allowed(client_id):
        remaining = rate_limiter.get_remaining(client_id)
        reset_time = rate_limiter.get_reset_time(client_id)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Remaining: {remaining}. Reset in: {reset_time}s",
            headers={
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_time),
            }
        )
    
    # Read raw body for HMAC verification
    body = await http_request.body()
    logger.info(f"[review-pr] Body size: {len(body)} bytes")
    
    # With CI/CD token auth, HMAC is optional (token auth is sufficient)
    # Only require HMAC if explicitly enabled
    require_hmac = settings.hmac_enabled
    
    # Validate request security (size limits, HMAC if required)
    request_data = await validate_request_security(
        request=http_request,
        body=body,
        hmac_secret=settings.hmac_secret if require_hmac else None,
        hmac_tolerance=settings.hmac_timestamp_tolerance,
        max_request_size=settings.max_request_size,
        max_diff_size=settings.max_diff_size,
    )
    
    # Parse into ReviewRequest model
    try:
        request = ReviewRequest(**request_data)
    except Exception as e:
        logger.error(f"ReviewRequest validation failed: {type(e).__name__}: {str(e)}")
        logger.error(f"Request keys: {list(request_data.keys()) if request_data else 'None'}")
        raise HTTPException(status_code=400, detail=f"Invalid request format: {str(e)}")
    
    # Secure logging - never log full diff content
    log_data = sanitize_for_logging(request_data)
    logger.info(f"Review request: repo={log_data['repo']} PR=#{log_data['pr_number']} "
                f"lang={log_data['language']} framework={log_data['framework']} "
                f"diff_size={log_data['diff_size']} has_policy={log_data['has_policy']}")
    
    # Only log diff content if explicitly enabled (not recommended for production)
    if settings.log_diff_content:
        logger.debug(f"Diff content (first 500 chars): {request.diff[:500]}")
    
    # Validate LLM is configured
    if not settings.llm_api_key:
        logger.error("LLM API key not configured")
        raise HTTPException(
            status_code=500,
            detail="LLM API key not configured. Set LLM_API_KEY environment variable."
        )
    
    # Check scope and load policy from DB using the authenticated user's org
    # user.org_id comes from the CI/CD token
    if user.org_id:
        # Create a tenant context from the user context
        from .tenants import TenantContext
        tenant = TenantContext(
            org_id=user.org_id,
            org_name=user.org_name,
            org_slug=user.org_slug,
            token_scopes=["review:pr", "explain:finding"],
            user_id=user.user_id,
            user_role=user.role or "admin",
        )
        
        # Check usage limits before proceeding with the review
        can_review, limit_message = await check_can_review_pr(user.org_id)
        if not can_review:
            logger.warning(f"PR review blocked for org {user.org_id}: {limit_message}")
            raise HTTPException(
                status_code=403,
                detail=limit_message or "Monthly PR review limit exceeded. Please upgrade your plan."
            )
        
        # Load policy from database if not provided in request
        if not request.policy:
            db_policy = await get_tenant_repo_policy(tenant, request.repo)
            if db_policy:
                from .models import RepoPolicy
                request.policy = RepoPolicy(**db_policy)
        
        # Check if enforcement mode is available for this organization
        enforcement_available = True
        enforcement_downgraded = False
        if request.policy and request.policy.mode.value == "enforce":
            can_enforce, enforce_message = await check_feature_access(user.org_id, "enforcement_mode")
            if not can_enforce:
                # Downgrade to advisory mode
                from .models import PolicyMode
                request.policy.mode = PolicyMode.ADVISORY
                enforcement_available = False
                enforcement_downgraded = True
                logger.info(f"Downgraded to advisory mode for org {user.org_id}: {enforce_message}")
    else:
        enforcement_available = True  # Non-tenant mode has no restrictions
        enforcement_downgraded = False
        tenant = None
    
    # Track timing for metrics
    start_time = time.time()
    metrics_tracker = get_metrics_tracker()
    
    try:
        # Load suppression rules for tenant
        suppressions = []
        if tenant:
            suppressions = await get_tenant_suppressions(tenant)
        
        # Get previous findings for this PR to track changes
        previous_findings = []
        previous_fingerprints = []
        if tenant and settings.database_configured:
            try:
                previous_findings = await get_previous_pr_findings(
                    tenant.org_id, request.repo, request.pr_number
                )
                previous_fingerprints = [f.get("fingerprint", "") for f in previous_findings if f.get("fingerprint")]
                if previous_findings:
                    logger.info(f"Found {len(previous_findings)} findings from previous review of PR #{request.pr_number}")
            except Exception as e:
                logger.warning(f"Could not fetch previous findings: {e}")
        
        # Perform the security analysis with policy and deduplication
        result = await analyze_diff(
            diff_text=request.diff,
            language=request.language,
            framework=request.framework,
            llm_provider=settings.llm_provider,
            api_key=settings.llm_api_key,
            model=settings.effective_model,
            policy=request.policy,
            previous_fingerprints=previous_fingerprints or request.previous_fingerprints,
        )
        
        # Apply tenant-specific suppression rules
        if suppressions and result.findings:
            original_count = len(result.findings)
            result.findings = [
                f for f in result.findings 
                if not check_suppression(f.model_dump(), suppressions)
            ]
            suppressed_count = original_count - len(result.findings)
            if suppressed_count > 0:
                logger.info(f"Suppressed {suppressed_count} findings by tenant rules")
        
        # Normalize findings to avoid TypeError on None
        findings = result.findings or []
        needs_review = result.needs_manual_review or []

        # Calculate review time
        review_time_ms = int((time.time() - start_time) * 1000)
        
        # Record metrics (in-memory)
        metrics_tracker.record_review(
            repo=request.repo,
            pr_number=request.pr_number,
            review_time_ms=review_time_ms,
            findings=findings,
            success=True
        )
        
        # Persist to database if in multi-tenant mode
        review_record = None
        if tenant and settings.database_configured:
            try:
                # Count by severity
                def get_risk_value(finding):
                    risk = getattr(finding, "risk", None)
                    return getattr(risk, "value", risk)

                high_count = len([f for f in findings if get_risk_value(f) == "HIGH"])
                medium_count = len([f for f in findings if get_risk_value(f) == "MEDIUM"])
                low_count = len([f for f in findings if get_risk_value(f) == "LOW"])
                
                # Get previous review for linking
                previous_review = await get_previous_pr_review(
                    tenant.org_id, request.repo, request.pr_number
                )
                
                # Calculate findings comparison BEFORE creating the review
                new_findings_count = len(findings)  # Default: all are new
                resolved_findings_count = 0
                still_present_count = 0
                comparison = None
                resolved_details = []
                
                if previous_fingerprints:
                    current_fingerprints = [f.fingerprint for f in findings if f.fingerprint]
                    comparison = await compare_pr_reviews(
                        tenant.org_id, request.repo, request.pr_number,
                        current_fingerprints, previous_fingerprints
                    )
                    new_findings_count = comparison["new_count"]
                    resolved_findings_count = comparison["resolved_count"]
                    still_present_count = comparison["still_present_count"]
                
                # Calculate active findings counts (status = 'open')
                active_findings_count = len([f for f in findings if getattr(f, 'status', 'open') == 'open'])
                active_high_count = len([f for f in findings if getattr(f, 'status', 'open') == 'open' and f.risk == 'HIGH'])
                active_medium_count = len([f for f in findings if getattr(f, 'status', 'open') == 'open' and f.risk == 'MEDIUM'])
                active_low_count = len([f for f in findings if getattr(f, 'status', 'open') == 'open' and f.risk == 'LOW'])
                
                # Ensure repository config exists so dashboard repository views include
                # repos reviewed via local CLI/API flows (without GitHub/GitLab import).
                existing_repo_config = await get_repo_config(tenant.org_id, request.repo)
                if not existing_repo_config:
                    policy_dict = request.policy.model_dump() if request.policy else {}
                    await upsert_repo_config(
                        org_id=tenant.org_id,
                        repo_name=request.repo,
                        policy=policy_dict,
                        enabled=True,
                        source="manual",
                    )
                    logger.info(
                        "Auto-created repo config for org %s repo %s from /review-pr flow",
                        tenant.org_id,
                        request.repo,
                    )

                # Create review record with all counts
                review_record = await create_review(
                    org_id=tenant.org_id,
                    repo_name=request.repo,
                    pr_number=request.pr_number,
                    review_time_ms=review_time_ms,
                    findings_count=len(findings),
                    high_count=high_count,
                    medium_count=medium_count,
                    low_count=low_count,
                    needs_review_count=len(needs_review),
                    success=True,
                    should_block=result.should_block,
                    new_findings_count=new_findings_count,
                    resolved_findings_count=resolved_findings_count,
                    still_present_count=still_present_count,
                    active_findings_count=active_findings_count,
                    active_high_count=active_high_count,
                    active_medium_count=active_medium_count,
                    active_low_count=active_low_count
                )
                
                # Link to previous review
                if previous_review:
                    await link_review_to_previous(review_record["id"], previous_review["id"])
                
                # Persist both confirmed findings and "needs manual review" findings
                # so the frontend can display the full review output.
                findings_data = [f.model_dump() for f in findings]
                findings_data.extend([f.model_dump() for f in needs_review])
                if findings_data:
                    await create_findings(review_record["id"], tenant.org_id, findings_data)
                
                # Mark resolved findings and update result
                if comparison and comparison.get("resolved_fingerprints"):
                    resolved_count = await mark_findings_resolved(
                        tenant.org_id, comparison["resolved_fingerprints"]
                    )
                    logger.info(f"Marked {resolved_count} findings as resolved")
                    
                    # Update result with resolved findings info
                    result.resolved_findings_count = comparison["resolved_count"]
                    # Get details of resolved findings
                    resolved_details = [
                        {
                            "fingerprint": f.get("fingerprint"),
                            "title": f.get("title"),
                            "risk": f.get("risk"),
                            "file_path": f.get("file_path"),
                            "line_range": f.get("line_range")
                        }
                        for f in previous_findings
                        if f.get("fingerprint") in comparison["resolved_fingerprints"]
                    ]
                    result.resolved_findings = resolved_details
                    
                    # Regenerate markdown to include resolved findings
                    result.findings_markdown = regenerate_markdown_with_resolved(
                        result, resolved_details, comparison["resolved_count"]
                    )
                
                # Auto-resolve all findings if PR is clean (0 findings)
                if len(findings) == 0 and previous_fingerprints:
                    auto_resolved_count = await auto_resolve_pr_findings(
                        tenant.org_id, request.repo, request.pr_number, review_record["id"]
                    )
                    if auto_resolved_count > 0:
                        logger.info(f"Auto-resolved {auto_resolved_count} findings - PR is clean")
                        result.resolved_findings_count = auto_resolved_count
                        # Get details of all auto-resolved findings for the markdown
                        auto_resolved_details = [
                            {
                                "fingerprint": f.get("fingerprint"),
                                "title": f.get("title"),
                                "risk": f.get("risk"),
                                "file_path": f.get("file_path"),
                                "line_range": f.get("line_range")
                            }
                            for f in previous_findings
                        ]
                        result.resolved_findings = auto_resolved_details
                        # Add message to summary
                        result.summary = f"✅ PR is clean! Auto-resolved {auto_resolved_count} previous findings."
                        # Regenerate markdown with resolved findings
                        result.findings_markdown = regenerate_markdown_with_resolved(
                            result, auto_resolved_details, auto_resolved_count
                        )
                
                logger.info(f"Persisted review {review_record['id']} to database")
                
                # Increment PR usage count for billing
                try:
                    usage_incremented = await increment_pr_usage(tenant.org_id)
                    if usage_incremented:
                        logger.info(f"Incremented PR usage for org {tenant.org_id}")
                    else:
                        logger.error(f"Failed to increment PR usage for org {tenant.org_id}")
                except Exception as usage_error:
                    logger.error(f"Failed to increment PR usage: {usage_error}")
            except Exception as e:
                logger.error(f"Failed to persist review to database: {e}")
        
        # Secure logging - only log counts, not content
        logger.info(f"Review completed: {len(findings)} findings, "
                f"{len(needs_review)} needs review, "
                    f"filtered={result.filtered_by_policy}, "
                    f"new={result.new_findings_count}, still_present={result.still_present_count}, "
                    f"resolved={result.resolved_findings_count}, "
                    f"enforcement_downgraded={enforcement_downgraded}, "
                    f"time={review_time_ms}ms")
        
        # Add enforcement flags to response
        result.enforcement_available = enforcement_available
        result.enforcement_downgraded = enforcement_downgraded
        
        # If enforcement was downgraded, ensure should_block is False
        if enforcement_downgraded:
            result.should_block = False

        if review_record and review_record.get("id"):
            result.findings_markdown = attach_review_identity(result.findings_markdown, review_record["id"])
        
        return result
        
    except ValueError as e:
        review_time_ms = int((time.time() - start_time) * 1000)
        metrics_tracker.record_review(
            repo=request.repo,
            pr_number=request.pr_number,
            review_time_ms=review_time_ms,
            findings=[],
            success=False,
            error_type="validation_error"
        )
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        review_time_ms = int((time.time() - start_time) * 1000)
        metrics_tracker.record_review(
            repo=request.repo,
            pr_number=request.pr_number,
            review_time_ms=review_time_ms,
            findings=[],
            success=False,
            error_type=type(e).__name__
        )
        logger.error(f"Error during review: {type(e).__name__}: {str(e)}")
        logger.exception("Full traceback:")
        # Return a graceful error response instead of 500
        return ReviewResponse(
            summary=f"Security review encountered an error",
            findings=[],
            findings_markdown=f"""## Security Review Report

<!-- AI_APPSEC_REVIEW -->

**Status:** Review could not be completed.

{str(e)}

Please check the service configuration and try again. If the problem persists, contact the service administrator.

---
_Generated by AppSec PR Reviewer_""",
            total_findings_before_filter=0,
            filtered_by_policy=False,
            needs_manual_review=[],
            findings_hash=None
        )


@app.post(
    "/explain-finding",
    response_model=ExplainFindingResponse,
    tags=["SAST Integration"],
    summary="Explain a SAST Finding in Plain English",
    responses={
        200: {
            "description": "Finding explanation generated successfully",
            "model": ExplainFindingResponse
        },
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    }
)
async def explain_finding(
    request: ExplainFindingRequest,
    user: UserContext = Depends(require_cicd_token),
    settings: Settings = Depends(get_settings)
) -> ExplainFindingResponse:
    """
    Get a plain English explanation of a SAST finding.
    
    This endpoint takes findings from external SAST tools (Fortify, Semgrep,
    CodeQL, Snyk, etc.) and provides:
    
    - **Plain English explanation** of what the finding means
    - **Risk justification** explaining why this is a security concern
    - **Remediation guidance** with step-by-step fix instructions
    - **Example fix** showing secure code implementation
    
    This is your AI security assistant that helps developers understand
    and fix security issues faster.
    
    **Supported Tools:**
    - Fortify
    - Semgrep
    - CodeQL
    - Snyk
    - Checkmarx
    - SonarQube
    - And more...
    """
    if not settings.llm_api_key:
        logger.error("LLM API key not configured")
        raise HTTPException(
            status_code=500,
            detail="LLM API key not configured. Set LLM_API_KEY environment variable."
        )
    
    try:
        result = await explain_sast_finding(
            request=request,
            llm_provider=settings.llm_provider,
            api_key=settings.llm_api_key,
            model=settings.effective_model,
        )
        
        logger.info(f"Explained {request.tool} finding: severity={result.severity.value}")
        return result
        
    except Exception as e:
        logger.error(f"Error explaining finding: {type(e).__name__}")
        raise HTTPException(status_code=500, detail="Failed to explain finding")


@app.get(
    "/metrics",
    response_model=AggregatedMetrics,
    tags=["Metrics"],
    summary="Get Service Metrics",
    responses={
        200: {
            "description": "Metrics retrieved successfully",
            "model": AggregatedMetrics
        },
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    }
)
async def get_metrics(
    _auth: bool = Depends(verify_auth_token),
) -> AggregatedMetrics:
    """
    Get aggregated service metrics.
    
    Returns:
    - Total PRs reviewed
    - Total findings count
    - Findings by category and risk level
    - Average review time
    - Success/failure rate
    - Service uptime
    """
    metrics_tracker = get_metrics_tracker()
    return metrics_tracker.get_aggregated_metrics()


# ============================================================================
# User Authentication - Token Bootstrap (No API token required)
# ============================================================================

@app.post(
    "/api/auth/tokens",
    response_model=TokenCreateResponse,
    tags=["Authentication"],
    summary="Create API token with user authentication",
    description="""
    Create a new API token using Supabase authentication.
    
    **Authentication:** Requires a valid Supabase JWT token (obtained from user login).
    This endpoint allows users to create their first API token without needing an existing one.
    
    **Usage:**
    1. User logs in via Supabase Auth (frontend)
    2. Frontend receives JWT token
    3. Use this JWT to call this endpoint and create an API token
    4. Use the API token for subsequent API calls
    
    **Important:** The API token is only shown once! Save it securely.
    """,
    responses={
        200: {"description": "Token created successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Insufficient permissions"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    }
)
async def create_token_with_user_auth(
    http_request: Request,
    request: TokenCreateRequest,
    user: UserContext = Depends(get_user_with_org),
    settings: Settings = Depends(get_settings),
) -> TokenCreateResponse:
    """
    Create a new API token using user authentication.
    
    This endpoint allows authenticated users to create API tokens for their organization
    without needing an existing API token. Perfect for bootstrapping access.
    """
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(http_request)
    
    # Check if user has permission (admins and owners can create tokens)
    if user.role not in ["admin", "owner"]:
        audit.log_auth_failure(
            request_id=request_id,
            reason=f"Insufficient permissions: role={user.role}",
            ip_address=ip_address,
            user_agent=get_user_agent(http_request),
        )
        raise HTTPException(
            status_code=403,
            detail="Only organization admins and owners can create API tokens"
        )
    
    # Check token creation rate limit
    token_limiter = get_token_rate_limiter()
    rate_limit_key = f"token_create:{user.org_id}"
    
    if not token_limiter.is_allowed(rate_limit_key):
        audit.log_rate_limit_exceeded(
            request_id=request_id,
            ip_address=ip_address,
            limit_type="token_creation",
            limit_value=settings.rate_limit_token_creation,
        )
        remaining = token_limiter.get_remaining(rate_limit_key)
        reset_time = token_limiter.get_reset_time(rate_limit_key)
        raise HTTPException(
            status_code=429,
            detail=f"Token creation rate limit exceeded. Reset in: {reset_time}s",
            headers={
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_time),
            }
        )
    
    # Create token with security settings
    token, token_data = await create_api_token(
        org_id=user.org_id,
        name=request.name,
        scopes=request.scopes,
        created_by=user.user_id,
        expires_in_days=request.expires_in_days,
        max_lifetime_days=settings.token_max_lifetime_days,
        default_lifetime_days=settings.token_default_lifetime_days,
        allow_wildcard=not settings.is_production,  # Restrict wildcard in production
        ip_address=ip_address,
        user_agent=get_user_agent(http_request),
    )
    
    # Audit log
    audit.log_token_created(
        request_id=request_id,
        org_id=user.org_id,
        token_id=token_data["id"],
        token_prefix=token_data["prefix"],
        scopes=token_data["scopes"],
        created_by=user.user_id,
        expires_at=token_data.get("expires_at"),
        ip_address=ip_address,
    )
    
    logger.info(f"User {user.email} created API token for org {user.org_id}")
    
    return TokenCreateResponse(
        token=token,
        id=token_data["id"],
        name=token_data["name"],
        prefix=token_data["prefix"],
        token_type=token_data.get("token_type") or "cicd",
        scopes=token_data["scopes"],
        expires_at=token_data.get("expires_at"),
        created_at=token_data["created_at"]
    )


@app.post(
    "/api/auth/switch-organization",
    response_model=SwitchOrgResponse,
    tags=["Authentication"],
    summary="Switch to a different organization",
    description="""
    Switch to a different organization using JWT authentication.
    
    **Authentication:** Requires a valid Supabase JWT token.
    
    This endpoint allows users to switch between organizations they are members of.
    No API token is returned - the frontend continues to use JWT for authentication
    and sends the X-Tenant-ID header for subsequent requests.
    
    **Usage:**
    1. User is authenticated with JWT token
    2. User selects a different organization from dropdown
    3. Frontend calls this endpoint with target org_id
    4. Backend validates membership
    5. Frontend updates X-Tenant-ID header for subsequent requests
    
    **Security:** Users can only switch to organizations they are members of.
    """,
    responses={
        200: {"description": "Organization switch successful"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Not a member of the organization"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    }
)
async def switch_organization(
    http_request: Request,
    org_id: str,
    user: UserContext = Depends(get_user_from_jwt),
    settings: Settings = Depends(get_settings),
) -> SwitchOrgResponse:
    """
    Switch to a different organization using JWT authentication.
    
    Validates that the user is a member of the target organization.
    No API token is created - frontend uses JWT with X-Tenant-ID header.
    """
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(http_request)
    
    # Verify user is a member of the target organization
    from .database import get_supabase_client
    client = get_supabase_client()
    result = client.table("org_members").select(
        "role, organizations(id, name, slug)"
    ).eq("user_id", user.user_id).eq("org_id", org_id).execute()
    
    if not result.data or len(result.data) == 0:
        audit.log_auth_failure(
            request_id=request_id,
            reason=f"User not a member of organization {org_id}",
            ip_address=ip_address,
            user_agent=get_user_agent(http_request),
        )
        raise HTTPException(
            status_code=403,
            detail=f"You are not a member of organization {org_id}"
        )
    
    membership = result.data[0]
    org_data = membership.get("organizations", {})
    role = membership.get("role")
    
    # Check rate limit for organization switching (per user)
    token_limiter = get_token_rate_limiter()
    rate_limit_key = f"org_switch:{user.user_id}"
    
    if not token_limiter.is_allowed(rate_limit_key):
        audit.log_rate_limit_exceeded(
            request_id=request_id,
            ip_address=ip_address,
            limit_type="org_switch",
            limit_value=settings.rate_limit_token_creation,
        )
        remaining = token_limiter.get_remaining(rate_limit_key)
        reset_time = token_limiter.get_reset_time(rate_limit_key)
        raise HTTPException(
            status_code=429,
            detail=f"Organization switch rate limit exceeded. Reset in: {reset_time}s",
            headers={
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_time),
            }
        )
    
    logger.info(f"User {user.email} switched to organization {org_id} ({org_data.get('name')})")
    
    return SwitchOrgResponse(
        success=True,
        org_id=org_id,
        org_name=org_data.get("name", ""),
        org_slug=org_data.get("slug", ""),
        role=role
    )


# ============================================================================
# Sprint 3: Token Management Endpoints
# ============================================================================

@app.post(
    "/api/tokens",
    response_model=TokenCreateResponse,
    tags=["Token Management"],
    summary="Create a new API token",
    responses={
        200: {"description": "Token created successfully"},
        400: {"model": ErrorResponse, "description": "Invalid request"},
        403: {"model": ErrorResponse, "description": "Forbidden"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    }
)
async def create_token(
    http_request: Request,
    request: TokenCreateRequest,
    tenant: TenantContext = Depends(require_tenant_context),
    settings: Settings = Depends(get_settings),
) -> TokenCreateResponse:
    """
    Create a new API token for the organization.
    
    **Important:** The token is only shown once! Save it securely.
    
    **Available Scopes:**
    - `review:pr` - Can call /review-pr
    - `explain:finding` - Can call /explain-finding
    - `admin:policy` - Can manage repo configs
    - `admin:tokens` - Can manage tokens
    - `read:metrics` - Can read metrics and dashboard
    - `feedback:write` - Can submit feedback
    - `*` - All permissions (restricted in production)
    """
    tenant.require_scope("admin:tokens")
    
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(http_request)
    
    # Check token creation rate limit
    token_limiter = get_token_rate_limiter()
    rate_limit_key = f"token_create:{tenant.org_id}"
    
    if not token_limiter.is_allowed(rate_limit_key):
        audit.log_rate_limit_exceeded(
            request_id=request_id,
            ip_address=ip_address,
            limit_type="token_creation",
            limit_value=settings.rate_limit_token_creation,
        )
        remaining = token_limiter.get_remaining(rate_limit_key)
        reset_time = token_limiter.get_reset_time(rate_limit_key)
        raise HTTPException(
            status_code=429,
            detail=f"Token creation rate limit exceeded. Reset in: {reset_time}s",
            headers={
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_time),
            }
        )
    
    # Create token with security settings
    # Support both new token_type and legacy scopes for backward compatibility
    token, token_data = await create_api_token(
        org_id=tenant.org_id,
        name=request.name,
        scopes=request.scopes,
        token_type=request.token_type.value if request.token_type else None,
        created_by=tenant.user_id,
        expires_in_days=request.expires_in_days,
        max_lifetime_days=settings.token_max_lifetime_days,
        default_lifetime_days=settings.token_default_lifetime_days,
        allow_wildcard=not settings.is_production,  # Restrict wildcard in production
        ip_address=ip_address,
        user_agent=get_user_agent(http_request),
    )
    
    # Audit log
    audit.log_token_created(
        request_id=request_id,
        org_id=tenant.org_id,
        token_id=token_data["id"],
        token_prefix=token_data["prefix"],
        scopes=token_data["scopes"],
        created_by=tenant.user_id,
        expires_at=token_data.get("expires_at"),
        ip_address=ip_address,
    )
    
    return TokenCreateResponse(
        token=token,
        id=token_data["id"],
        name=token_data["name"],
        prefix=token_data["prefix"],
        token_type=token_data.get("token_type") or "cicd",
        scopes=token_data["scopes"],
        expires_at=token_data.get("expires_at"),
        created_at=token_data["created_at"]
    )


@app.get(
    "/api/tokens/types",
    response_model=TokenTypesResponse,
    tags=["Token Management"],
    summary="List available token types",
)
async def get_token_types() -> TokenTypesResponse:
    """
    Get information about available token types.
    
    Returns details about each token type including:
    - Name and description
    - Scopes included
    - Whether it's auto-generated
    - Recommended use cases
    """
    from .database import TOKEN_TYPES
    
    token_type_infos = []
    for type_id, type_info in TOKEN_TYPES.items():
        token_type_infos.append(TokenTypeInfo(
            id=type_id,
            name=type_info["name"],
            description=type_info["description"],
            scopes=type_info["scopes"],
            auto_generate=type_info["auto_generate"],
            recommended_use=type_info["recommended_use"],
        ))
    
    return TokenTypesResponse(token_types=token_type_infos)


@app.get(
    "/api/tokens/cicd",
    response_model=CicdTokenResponse,
    tags=["Token Management"],
    summary="Get CI/CD token",
)
async def get_cicd_token_endpoint(
    http_request: Request,
    tenant: TenantContext = Depends(require_tenant_context),
) -> CicdTokenResponse:
    """
    Get the organization's CI/CD token metadata.
    
    Note: The actual token is only shown once during creation.
    Use the regenerate endpoint to create a new token.
    """
    from .database import get_cicd_token, create_api_token
    
    token_data = await get_cicd_token(tenant.org_id)
    
    if not token_data:
        # Self-heal legacy orgs where bootstrap token generation failed.
        audit = get_audit_logger()
        request_id = get_request_id()
        ip_address = get_client_identifier(http_request)
        token, token_data = await create_api_token(
            org_id=tenant.org_id,
            name="Default CI/CD Token",
            token_type="cicd",
            created_by=tenant.user_id,
            expires_in_days=0,
            ip_address=ip_address,
            user_agent=get_user_agent(http_request),
        )
        logger.info(
            "Auto-provisioned missing CI/CD token for org %s via GET /api/tokens/cicd",
            tenant.org_id,
        )
        # Intentionally do not return plaintext token from this endpoint.
        _ = token
        audit.log_token_created(
            request_id=request_id,
            org_id=tenant.org_id,
            token_id=token_data["id"],
            token_prefix=token_data["prefix"],
            scopes=token_data["scopes"],
            created_by=tenant.user_id,
            expires_at=token_data.get("expires_at"),
            ip_address=ip_address,
        )
    
    return CicdTokenResponse(
        id=token_data["id"],
        name=token_data["name"],
        prefix=token_data["prefix"],
        token_type=token_data.get("token_type") or "cicd",
        scopes=token_data["scopes"],
        expires_at=token_data.get("expires_at"),
        revoked_at=token_data.get("revoked_at"),
        last_used_at=token_data.get("last_used_at"),
        created_at=token_data["created_at"],
        has_token=True,
    )


@app.post(
    "/api/tokens/cicd/regenerate",
    response_model=RegenerateCicdTokenResponse,
    tags=["Token Management"],
    summary="Regenerate CI/CD token",
)
async def regenerate_cicd_token_endpoint(
    http_request: Request,
    tenant: TenantContext = Depends(require_tenant_context),
) -> RegenerateCicdTokenResponse:
    """
    Regenerate the organization's CI/CD token.
    
    This will revoke the existing CI/CD token and create a new one.
    **Warning:** Any services using the old token will stop working immediately.
    
    The new token is only shown once - save it securely!
    """
    from .database import regenerate_cicd_token
    from .security import get_client_identifier
    
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(http_request)
    
    # Regenerate the CI/CD token
    token, token_data = await regenerate_cicd_token(
        org_id=tenant.org_id,
        created_by=tenant.user_id,
        ip_address=ip_address,
        user_agent=get_user_agent(http_request),
    )
    
    # Audit log
    audit.log_token_created(
        request_id=request_id,
        org_id=tenant.org_id,
        token_id=token_data["id"],
        token_prefix=token_data["prefix"],
        scopes=token_data["scopes"],
        created_by=tenant.user_id,
        expires_at=token_data.get("expires_at"),
        ip_address=ip_address,
    )
    
    return RegenerateCicdTokenResponse(
        token=token,
        id=token_data["id"],
        name=token_data["name"],
        prefix=token_data["prefix"],
        token_type=token_data.get("token_type") or "cicd",
        scopes=token_data["scopes"],
        created_at=token_data["created_at"],
    )


@app.get(
    "/api/tokens",
    response_model=TokenListResponse,
    tags=["Token Management"],
    summary="List API tokens",
)
async def list_tokens(
    tenant: TenantContext = Depends(require_tenant_context),
) -> TokenListResponse:
    """List all API tokens for the organization (metadata only, no secrets)."""
    tenant.require_scope("admin:tokens")
    
    tokens = await list_api_tokens(tenant.org_id)
    
    from .models import TokenInfo
    return TokenListResponse(
        tokens=[TokenInfo(**{**t, "token_type": (t.get("token_type") or "cicd")}) for t in tokens],
        total=len(tokens)
    )


@app.delete(
    "/api/tokens/{token_id}",
    tags=["Token Management"],
    summary="Revoke an API token",
)
async def delete_token(
    token_id: str,
    http_request: Request,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Revoke an API token. This cannot be undone."""
    tenant.require_scope("admin:tokens")
    
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(http_request)
    
    success = await revoke_api_token(token_id, tenant.org_id)
    if not success:
        raise HTTPException(status_code=404, detail="Token not found")
    
    # Audit log
    audit.log_token_revoked(
        request_id=request_id,
        org_id=tenant.org_id,
        token_id=token_id,
        revoked_by=tenant.user_id,
        ip_address=ip_address,
    )
    
    return {"status": "revoked", "token_id": token_id}


@app.post(
    "/api/tokens/{token_id}/rotate",
    response_model=TokenCreateResponse,
    tags=["Token Management"],
    summary="Rotate an API token",
)
async def rotate_token(
    token_id: str,
    http_request: Request,
    tenant: TenantContext = Depends(require_tenant_context),
) -> TokenCreateResponse:
    """
    Rotate an API token (revoke old, create new with same settings).
    
    **Important:** The new token is only shown once! Save it securely.
    """
    tenant.require_scope("admin:tokens")
    
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(http_request)
    
    result = await rotate_api_token(token_id, tenant.org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Token not found")
    
    token, token_data = result
    
    # Audit log
    audit.log_token_rotated(
        request_id=request_id,
        org_id=tenant.org_id,
        old_token_id=token_id,
        new_token_id=token_data["id"],
        new_token_prefix=token_data["prefix"],
        rotated_by=tenant.user_id,
        ip_address=ip_address,
    )
    
    return TokenCreateResponse(
        token=token,
        id=token_data["id"],
        name=token_data["name"],
        prefix=token_data["prefix"],
        scopes=token_data["scopes"],
        expires_at=token_data.get("expires_at"),
        created_at=token_data["created_at"]
    )


# ============================================================================
# Sprint 3: Dashboard Endpoints
# ============================================================================

@app.get(
    "/api/dashboard/stats",
    response_model=DashboardStatsResponse,
    tags=["Dashboard"],
    summary="Get dashboard statistics",
)
async def dashboard_stats(
    days: int = 30,
    tenant: TenantContext = Depends(require_tenant_context),
    _feature_check: bool = Depends(require_feature("dashboard")),
) -> DashboardStatsResponse:
    """Get aggregated dashboard statistics for the organization."""
    tenant.require_scope("read:metrics")

    stats_start = time.perf_counter()
    stats = await get_dashboard_stats(tenant.org_id, days)
    stats_ms = (time.perf_counter() - stats_start) * 1000
    add_request_timing("api.dashboard.stats", stats_ms)
    
    return DashboardStatsResponse(
        total_reviews=stats.get("total_reviews", 0),
        total_findings=stats.get("total_findings", 0),
        high_findings=stats.get("high_findings", 0),
        medium_findings=stats.get("medium_findings", 0),
        low_findings=stats.get("low_findings", 0),
        avg_review_time_ms=stats.get("avg_review_time_ms", 0),
        success_rate=stats.get("success_rate", 0),
        blocked_count=stats.get("blocked_count", 0),
        resolved_findings=stats.get("resolved_findings", 0),
        period_days=days
    )


@app.get(
    "/api/dashboard/findings-by-category",
    response_model=CategoryStatsResponse,
    tags=["Dashboard"],
    summary="Get findings by category",
)
async def dashboard_categories(
    days: int = 30,
    tenant: TenantContext = Depends(require_tenant_context),
    _feature_check: bool = Depends(require_feature("dashboard")),
) -> CategoryStatsResponse:
    """Get findings grouped by vulnerability category."""
    tenant.require_scope("read:metrics")

    categories_start = time.perf_counter()
    categories = await get_findings_by_category(tenant.org_id, days)
    categories_ms = (time.perf_counter() - categories_start) * 1000
    add_request_timing("api.dashboard.categories", categories_ms)
    
    from .models import CategoryStats
    return CategoryStatsResponse(
        categories=[CategoryStats(category=c["category"], count=c.get("count", 0)) for c in categories],
        period_days=days
    )


@app.get(
    "/api/dashboard/top-repos",
    response_model=RepoRiskResponse,
    tags=["Dashboard"],
    summary="Get top risky repositories",
)
async def dashboard_top_repos(
    days: int = 30,
    limit: int = 10,
    tenant: TenantContext = Depends(require_tenant_context),
    _feature_check: bool = Depends(require_feature("dashboard")),
) -> RepoRiskResponse:
    """Get repositories ranked by risk score."""
    tenant.require_scope("read:metrics")
    
    repos = await get_top_risky_repos(tenant.org_id, days, limit)
    
    from .models import RepoRisk
    return RepoRiskResponse(
        repos=[RepoRisk(
            repo_name=r["repo_name"],
            review_count=r["review_count"],
            total_findings=r["total_findings"],
            high_findings=r["high_findings"],
            risk_score=r["risk_score"]
        ) for r in repos],
        period_days=days
    )


@app.get(
    "/api/dashboard/trend",
    response_model=TrendDataResponse,
    tags=["Dashboard"],
    summary="Get review trend data",
)
async def dashboard_trend(
    days: int = 30,
    tenant: TenantContext = Depends(require_tenant_context),
    _feature_check: bool = Depends(require_feature("dashboard")),
) -> TrendDataResponse:
    """Get time-series data for trend charts."""
    tenant.require_scope("read:metrics")

    trend_start = time.perf_counter()
    trend = await get_review_trend(tenant.org_id, days)
    trend_ms = (time.perf_counter() - trend_start) * 1000
    add_request_timing("api.dashboard.trend", trend_ms)
    
    from .models import TrendDataPoint
    return TrendDataResponse(
        data=[TrendDataPoint(
            date=str(t["date"]),
            review_count=t["review_count"],
            findings_count=t["findings_count"],
            high_count=t["high_count"]
        ) for t in trend],
        period_days=days
    )


# ============================================================================
# Active Findings Dashboard Endpoints
# ============================================================================

@app.get(
    "/api/dashboard/active/stats",
    response_model=DashboardStatsResponse,
    tags=["Dashboard"],
    summary="Get active findings dashboard stats",
)
async def dashboard_active_stats(
    days: int = 30,
    tenant: TenantContext = Depends(require_tenant_context),
    _feature_check: bool = Depends(require_feature("dashboard")),
) -> DashboardStatsResponse:
    """Get dashboard stats for active findings only (status = 'open')."""
    tenant.require_scope("read:metrics")

    stats_start = time.perf_counter()
    stats = await get_active_findings_stats(tenant.org_id, days)
    stats_ms = (time.perf_counter() - stats_start) * 1000
    add_request_timing("api.dashboard.active_stats", stats_ms)
    
    return DashboardStatsResponse(
        total_reviews=stats.get("total_reviews", 0),
        total_findings=stats.get("total_findings", 0),
        high_findings=stats.get("high_findings", 0),
        medium_findings=stats.get("medium_findings", 0),
        low_findings=stats.get("low_findings", 0),
        avg_review_time_ms=stats.get("avg_review_time_ms", 0),
        success_rate=stats.get("success_rate", 0),
        blocked_count=stats.get("blocked_count", 0),
        resolved_findings=0,  # Not applicable for active findings
        period_days=days,
    )


@app.get(
    "/api/dashboard/active/findings-by-category",
    response_model=CategoryStatsResponse,
    tags=["Dashboard"],
    summary="Get active findings by category",
)
async def dashboard_active_categories(
    days: int = 30,
    tenant: TenantContext = Depends(require_tenant_context),
    _feature_check: bool = Depends(require_feature("dashboard")),
) -> CategoryStatsResponse:
    """Get active findings grouped by vulnerability category."""
    tenant.require_scope("read:metrics")

    categories_start = time.perf_counter()
    categories = await get_active_findings_by_category(tenant.org_id, days)
    categories_ms = (time.perf_counter() - categories_start) * 1000
    add_request_timing("api.dashboard.active_categories", categories_ms)
    
    from .models import CategoryStats
    return CategoryStatsResponse(
        categories=[CategoryStats(category=c["category"], count=c["count"]) for c in categories],
        period_days=days
    )


@app.get(
    "/api/dashboard/active/trend",
    response_model=TrendDataResponse,
    tags=["Dashboard"],
    summary="Get active findings trend data",
)
async def dashboard_active_trend(
    days: int = 30,
    tenant: TenantContext = Depends(require_tenant_context),
    _feature_check: bool = Depends(require_feature("dashboard")),
) -> TrendDataResponse:
    """Get active findings trend over time."""
    tenant.require_scope("read:metrics")

    trend_start = time.perf_counter()
    trend = await get_active_findings_trend(tenant.org_id, days)
    trend_ms = (time.perf_counter() - trend_start) * 1000
    add_request_timing("api.dashboard.active_trend", trend_ms)
    
    from .models import TrendDataPoint
    return TrendDataResponse(
        data=[TrendDataPoint(
            date=t["date"],
            review_count=t["review_count"],
            findings_count=t["findings_count"],
            high_count=t["high_count"]
        ) for t in trend],
        period_days=days
    )


@app.get(
    "/api/dashboard/active/top-repos",
    response_model=RepoRiskResponse,
    tags=["Dashboard"],
    summary="Get top risky repos by active findings",
)
async def dashboard_active_top_repos(
    days: int = 30,
    limit: int = 10,
    tenant: TenantContext = Depends(require_tenant_context),
    _feature_check: bool = Depends(require_feature("dashboard")),
) -> RepoRiskResponse:
    """Get top risky repositories based on active findings."""
    tenant.require_scope("read:metrics")

    repos_start = time.perf_counter()
    repos = await get_top_risky_repos_active(tenant.org_id, days, limit)
    repos_ms = (time.perf_counter() - repos_start) * 1000
    add_request_timing("api.dashboard.active_top_repos", repos_ms)
    
    from .models import RepoRisk
    return RepoRiskResponse(
        repos=[RepoRisk(
            repo_name=r["repo_name"],
            review_count=r["review_count"],
            total_findings=r["total_findings"],
            high_findings=r["high_findings"],
            risk_score=float(r["risk_score"])
        ) for r in repos],
        period_days=days
    )


# ============================================================================
# Sprint 3: Reviews & Findings List Endpoints
# ============================================================================

@app.get(
    "/api/reviews",
    tags=["Reviews"],
    summary="List recent reviews",
)
async def list_reviews(
    limit: int = 50,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Get recent reviews for the organization."""
    tenant.require_scope("read:metrics")
    
    from .database import get_recent_reviews
    reviews = await get_recent_reviews(tenant.org_id, limit)
    return {"reviews": reviews, "total": len(reviews)}


@app.get(
    "/api/findings",
    tags=["Findings"],
    summary="List recent findings",
)
async def list_findings(
    limit: int = 50,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Get recent findings for the organization."""
    tenant.require_scope("read:metrics")
    request_start = time.perf_counter()
    logger.info(
        f"[timing][api/findings] start org_id={tenant.org_id} limit={limit}"
    )
    
    from .database import get_recent_findings
    db_start = time.perf_counter()
    findings = await get_recent_findings(tenant.org_id, limit)
    db_elapsed_ms = (time.perf_counter() - db_start) * 1000
    logger.info(
        f"[timing][api/findings] db_fetch_ms={db_elapsed_ms:.2f} findings_count={len(findings)}"
    )
    
    # Normalize findings to ensure 'risk' field is present (mapped from 'severity')
    normalize_start = time.perf_counter()
    normalized_findings = normalize_findings(findings)
    normalize_elapsed_ms = (time.perf_counter() - normalize_start) * 1000
    total_elapsed_ms = (time.perf_counter() - request_start) * 1000
    logger.info(
        f"[timing][api/findings] normalize_ms={normalize_elapsed_ms:.2f} total_ms={total_elapsed_ms:.2f} total_count={len(normalized_findings)}"
    )
    add_request_timing("api.findings.list", total_elapsed_ms)
    
    return {"findings": normalized_findings, "total": len(normalized_findings)}


@app.get(
    "/api/findings/{finding_id}",
    tags=["Findings"],
    summary="Get a finding by ID",
)
async def get_finding(
    finding_id: str,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Get a single finding by ID."""
    tenant.require_scope("read:metrics")
    
    from .database import get_finding_by_id_for_org
    finding = await get_finding_by_id_for_org(finding_id, tenant.org_id)
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Normalize finding to ensure 'risk' field is present
    normalized_finding = normalize_finding(finding)
    
    return normalized_finding


# ============================================================================
# Sprint 3: Feedback Endpoints
# ============================================================================

@app.post(
    "/api/feedback",
    response_model=FeedbackResponse,
    tags=["Feedback"],
    summary="Submit feedback on a finding",
)
async def submit_feedback(
    request: FeedbackRequest,
    tenant: TenantContext = Depends(require_tenant_context),
) -> FeedbackResponse:
    """
    Submit feedback on a finding.
    
    **Labels:**
    - `true_positive` - Confirmed real vulnerability
    - `false_positive` - Not a real issue
    - `accepted_risk` - Real but accepted
    
    When marking as `false_positive`, a suppression rule is automatically
    created to prevent this finding from appearing again.
    """
    tenant.require_scope("feedback:write")
    
    feedback = await create_feedback(
        org_id=tenant.org_id,
        fingerprint=request.fingerprint,
        label=request.label.value,
        finding_id=request.finding_id,
        repo_name=request.repo_name,
        comment=request.comment,
        created_by=tenant.user_id,
        created_by_github=request.github_user
    )
    
    # Update finding status based on feedback
    status_map = {
        "true_positive": "resolved",
        "false_positive": "false_positive", 
        "accepted_risk": "accepted_risk"
    }
    new_status = status_map.get(request.label.value)
    if new_status and request.finding_id:
        await resolve_finding(
            finding_id=request.finding_id,
            org_id=tenant.org_id,
            new_status=new_status,
            user_id=tenant.user_id,
            reason=f"Feedback: {request.label.value}",
            notes=request.comment
        )
    
    # Auto-create suppression rule for false positives
    suppression_created = False
    if request.label.value == "false_positive":
        await create_suppression_rule(
            org_id=tenant.org_id,
            reason=f"Marked as false positive: {request.comment or 'No comment'}",
            fingerprint=request.fingerprint,
            expires_in_days=365,  # 1 year default
            created_by=tenant.user_id
        )
        suppression_created = True
    
    return FeedbackResponse(
        id=feedback["id"],
        fingerprint=feedback["fingerprint"],
        label=feedback["label"],
        created_at=feedback["created_at"],
        suppression_created=suppression_created
    )


@app.get(
    "/api/feedback",
    tags=["Feedback"],
    summary="List feedback for organization",
)
async def list_feedback(
    limit: int = 100,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Get recent feedback for the organization."""
    tenant.require_scope("read:metrics")
    
    feedback = await get_feedback_for_org(tenant.org_id, limit)
    return {"feedback": feedback, "total": len(feedback)}


# ============================================================================
# Finding Resolution Endpoints
# ============================================================================

@app.post(
    "/api/findings/resolve",
    response_model=ResolutionResponse,
    tags=["Findings"],
    summary="Manually resolve a finding",
)
async def resolve_finding_endpoint(
    request: ResolveFindingRequest,
    user: UserContext = Depends(get_user_with_org),
) -> ResolutionResponse:
    """
    Manually resolve a finding.
    
    **Status options:**
    - `resolved` - Fixed in code
    - `accepted_risk` - Won't fix, documented acceptance
    - `false_positive` - Not a real issue
    - `wont_fix` - Known limitation, won't address
    
    This creates an audit trail in the status history.
    """
    success = await resolve_finding(
        finding_id=request.finding_id,
        org_id=user.org_id,
        new_status=request.status.value,
        user_id=user.user_id,
        reason=request.reason,
        notes=request.notes
    )
    
    if not success:
        raise HTTPException(
            status_code=404,
            detail="Finding not found or already in this status"
        )
    
    return ResolutionResponse(
        success=True,
        count=1,
        message=f"Finding marked as {request.status.value}"
    )


@app.post(
    "/api/findings/bulk-resolve",
    response_model=ResolutionResponse,
    tags=["Findings"],
    summary="Bulk resolve multiple findings",
)
async def bulk_resolve_findings_endpoint(
    request: BulkResolveFindingsRequest,
    user: UserContext = Depends(get_user_with_org),
) -> ResolutionResponse:
    """
    Bulk resolve multiple findings at once.
    
    Useful for marking multiple false positives or accepted risks.
    """
    count = await bulk_resolve_findings(
        org_id=user.org_id,
        finding_ids=request.finding_ids,
        new_status=request.status.value,
        user_id=user.user_id,
        reason=request.reason,
        notes=request.notes
    )
    
    return ResolutionResponse(
        success=count > 0,
        count=count,
        message=f"Resolved {count} of {len(request.finding_ids)} findings"
    )


@app.post(
    "/api/findings/reopen",
    response_model=ResolutionResponse,
    tags=["Findings"],
    summary="Reopen a resolved finding",
)
async def reopen_finding_endpoint(
    request: ReopenFindingRequest,
    user: UserContext = Depends(get_user_with_org),
) -> ResolutionResponse:
    """
    Reopen a resolved finding.
    
    Useful if a finding was incorrectly marked as resolved or has reappeared.
    """
    success = await reopen_finding(
        finding_id=request.finding_id,
        org_id=user.org_id,
        user_id=user.user_id,
        reason=request.reason
    )
    
    if not success:
        raise HTTPException(
            status_code=404,
            detail="Finding not found or already open"
        )
    
    return ResolutionResponse(
        success=True,
        count=1,
        message="Finding reopened"
    )


@app.get(
    "/api/findings/{finding_id}/history",
    response_model=list[FindingStatusHistory],
    tags=["Findings"],
    summary="Get finding status history",
)
async def get_finding_history(
    finding_id: str,
    user: UserContext = Depends(get_user_with_org),
) -> list[FindingStatusHistory]:
    """
    Get the complete status change history for a finding.
    
    Shows all transitions (open → resolved, resolved → reopen, etc.)
    with timestamps and who made the change.
    """
    history = await get_finding_status_history(finding_id, user.org_id)
    return [FindingStatusHistory(**h) for h in history]



@app.get(
    "/api/feedback/stats",
    tags=["Feedback"],
    summary="Get feedback statistics",
)
async def feedback_stats(
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Get feedback statistics (true/false positive rates)."""
    tenant.require_scope("read:metrics")
    
    from .database import get_feedback_stats
    stats = await get_feedback_stats(tenant.org_id)
    return stats


# ============================================================================
# Sprint 3: Suppression Rules Endpoints
# ============================================================================

@app.get(
    "/api/suppressions",
    tags=["Suppressions"],
    summary="List active suppression rules",
)
async def list_suppressions(
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Get all active suppression rules for the organization."""
    tenant.require_scope("read:metrics")
    
    rules = await get_active_suppressions(tenant.org_id)
    
    from .models import SuppressionRuleResponse
    return {
        "rules": [SuppressionRuleResponse(**r) for r in rules],
        "total": len(rules)
    }


@app.post(
    "/api/suppressions",
    tags=["Suppressions"],
    summary="Create a suppression rule",
)
async def create_suppression(
    request: SuppressionRuleRequest,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """
    Create a new suppression rule.
    
    Suppression rules prevent findings from appearing in future reviews.
    At least one of: fingerprint, title_pattern, file_pattern, or category
    must be provided.
    """
    tenant.require_scope("admin:policy")
    
    # Validate at least one filter is provided
    if not any([request.fingerprint, request.title_pattern, request.file_pattern, request.category]):
        raise HTTPException(
            status_code=400,
            detail="At least one of fingerprint, title_pattern, file_pattern, or category is required"
        )
    
    from .models import SuppressionRuleRequest
    rule = await create_suppression_rule(
        org_id=tenant.org_id,
        reason=request.reason,
        fingerprint=request.fingerprint,
        title_pattern=request.title_pattern,
        file_pattern=request.file_pattern,
        category=request.category,
        expires_in_days=request.expires_in_days,
        created_by=tenant.user_id
    )
    
    from .models import SuppressionRuleResponse
    return SuppressionRuleResponse(**rule)


@app.delete(
    "/api/suppressions/{rule_id}",
    tags=["Suppressions"],
    summary="Delete a suppression rule",
)
async def delete_suppression(
    rule_id: str,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Deactivate a suppression rule."""
    tenant.require_scope("admin:policy")
    
    success = await delete_suppression_rule(rule_id, tenant.org_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return {"status": "deleted", "rule_id": rule_id}


# ============================================================================
# Sprint 3: Repository Config Endpoints
# ============================================================================

@app.get(
    "/api/repos",
    tags=["Repository Config"],
    summary="List repository configurations",
)
async def list_repos(
    tenant: TenantContext = Depends(require_tenant_context),
):
    """List all repository configurations for the organization."""
    tenant.require_scope("read:metrics")
    
    configs = await list_repo_configs(tenant.org_id)
    
    from .models import RepoConfigResponse
    return {
        "configs": [RepoConfigResponse(**c) for c in configs],
        "total": len(configs)
    }


@app.get(
    "/api/repos/{repo_name:path}",
    tags=["Repository Config"],
    summary="Get repository configuration",
)
async def get_repo(
    repo_name: str,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Get configuration for a specific repository."""
    tenant.require_scope("read:metrics")
    
    config = await get_repo_config(tenant.org_id, repo_name)
    if not config:
        raise HTTPException(status_code=404, detail="Repository config not found")
    
    from .models import RepoConfigResponse
    return RepoConfigResponse(**config)


@app.put(
    "/api/repos/{repo_name:path}",
    tags=["Repository Config"],
    summary="Create or update repository configuration",
)
async def update_repo(
    repo_name: str,
    request: RepoConfigRequest,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Create or update configuration for a repository."""
    tenant.require_scope("admin:policy")

    # Check repository limit only when enabling a repo that is not currently enabled
    existing_config = await get_repo_config(tenant.org_id, repo_name)
    is_currently_enabled = bool(existing_config and existing_config.get("enabled"))
    is_enabling_repo = request.enabled and not is_currently_enabled

    if is_enabling_repo:
        can_add, limit_message = await check_can_add_repo(tenant.org_id)
        if not can_add:
            logger.warning(f"Repo config blocked for org {tenant.org_id}: {limit_message}")
            raise HTTPException(
                status_code=403,
                detail=limit_message or "Repository limit reached. Upgrade your plan to add more repositories."
            )
    
    policy_dict = request.policy.model_dump() if request.policy else {}
    
    config = await upsert_repo_config(
        org_id=tenant.org_id,
        repo_name=repo_name,
        policy=policy_dict,
        enabled=request.enabled,
        source="manual",
    )
    
    from .models import RepoConfigResponse
    return RepoConfigResponse(**config)


# ============================================================================
# Sprint 3: Chat in PR Endpoints
# ============================================================================

@app.post(
    "/api/chat",
    response_model=ChatResponse,
    tags=["Chat"],
    summary="AI chat in PR",
)
async def chat_in_pr(
    request: ChatRequest,
    tenant: TenantContext = Depends(require_tenant_context),
    settings: Settings = Depends(get_settings),
) -> ChatResponse:
    """
    Handle AI chat commands from PR comments.
    
    **Commands:**
    - `explain` - Deep explanation of a finding
    - `fix` - Generate code fix for a finding
    - `why` - Explain why the finding matters
    - `ask` - General security question about the PR
    """
    tenant.require_scope("review:pr")
    
    if not settings.llm_api_key:
        raise HTTPException(status_code=500, detail="LLM not configured")
    
    from .chat_handler import handle_chat_command
    from .database import create_chat_interaction
    
    # Handle the command
    response_text, finding_title = await handle_chat_command(
        org_id=tenant.org_id,
        repo_name=request.repo_name,
        pr_number=request.pr_number,
        command=request.command.value,
        finding_number=request.finding_number,
        question=request.question,
        llm_provider=settings.llm_provider,
        api_key=settings.llm_api_key,
        model=settings.effective_model,
    )
    
    # Record the interaction
    await create_chat_interaction(
        org_id=tenant.org_id,
        repo_name=request.repo_name,
        pr_number=request.pr_number,
        command=request.command.value,
        question=request.question,
        response=response_text,
        github_user=request.github_user
    )
    
    return ChatResponse(
        response=response_text,
        command=request.command.value,
        finding_title=finding_title
    )


# ============================================================================
# GitHub Integration Endpoints
# ============================================================================

@app.get(
    "/api/github/repos",
    response_model=GitHubReposResponse,
    tags=["GitHub Integration"],
    summary="List GitHub repositories",
)
async def list_github_repos(
    tenant: TenantContext = Depends(require_tenant_context_flexible),
) -> GitHubReposResponse:
    """
    List GitHub repositories for the authenticated user.
    
    Uses the GitHub App installation token to list repositories.
    Returns repos with import status (whether already added to AI AppSec).
    """
    tenant.require_scope("admin:policy")
    
    # Get GitHub App installation token
    from .database import get_supabase_client
    from .github_app_auth import get_installation_token, InstallationNotFoundError
    
    client = get_supabase_client()
    
    # Check for GitHub App installation linked to this org
    result = client.table("github_app_installations").select("*").eq("org_id", tenant.org_id).eq(
        "is_active", True
    ).order("installed_at", desc=True).limit(1).execute()
    
    if not result.data or len(result.data) == 0:
        raise HTTPException(
            status_code=400,
            detail="GitHub App not installed. Please install the GitHub App to import repositories."
        )
    
    installation = result.data[0]
    installation_id = installation.get("installation_id")
    repository_selection = installation.get("repository_selection", "unknown")
    
    logger.info(f"GitHub App installation found: ID={installation_id}, repository_selection={repository_selection}")
    
    if not installation_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub App installation. Please reinstall the GitHub App."
        )
    
    # Get installation token and its permissions
    try:
        github_token, token_permissions = await get_installation_token(installation_id)
    except InstallationNotFoundError:
        logger.warning(
            f"GitHub installation {installation_id} for org {tenant.org_id} became inactive during /api/github/repos"
        )
        return JSONResponse(
            status_code=409,
            content={
                "detail": "GitHub App installation is no longer active. Please reinstall the GitHub App from Settings > Integrations.",
                "error_code": "GITHUB_APP_RECONNECT_REQUIRED",
                "provider": "github",
                "reconnect_required": True,
            },
        )
    
    # Check token permissions to determine access level
    # GitHub API returns permissions field as all False for installation tokens,
    # but the token itself has the actual permissions
    token_has_contents_write = token_permissions.get("contents") == "write"
    token_has_admin = token_permissions.get("admin") == "write" or token_permissions.get("repository_hooks") == "write"
    
    from .github_client import GitHubClient
    
    github_client = GitHubClient(github_token)
    repos = []
    
    try:
        # Get repos using installation repos endpoint
        repos = await github_client.list_installation_repos()
    except Exception as e:
        logger.error(f"Failed to list GitHub repos: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list GitHub repositories: {str(e)}")
    
    # Get existing repo configs to mark import status
    existing_configs = await list_repo_configs(tenant.org_id)
    existing_repo_names = {c["repo_name"] for c in existing_configs}
    
    # Build response with import status
    repo_infos = []
    push_count = 0
    read_only_count = 0
    
    for repo in repos:
        # Use token permissions to determine access, not the repo permissions field
        # The repo permissions field from /installation/repositories is unreliable for GitHub Apps
        if token_has_contents_write:
            # If token has contents:write, the app can push to all repos in the installation
            can_push = True
            can_admin = token_has_admin
            push_count += 1
        else:
            # Fall back to repo permissions (for other token types)
            permissions = repo.permissions or {}
            can_push = permissions.get("push", False)
            can_admin = permissions.get("admin", False)
            if can_push:
                push_count += 1
            else:
                read_only_count += 1
        
        repo_infos.append(GitHubRepoInfo(
            id=repo.id,
            name=repo.name,
            full_name=repo.full_name,
            owner=repo.owner,
            private=repo.private,
            description=repo.description,
            default_branch=repo.default_branch,
            html_url=repo.html_url,
            can_push=can_push,
            can_admin=can_admin,
            imported=repo.full_name in existing_repo_names,
            workflow_installed=False,  # Will be checked separately if needed
        ))
    
    # Log summary
    logger.info(f"Listed {len(repo_infos)} GitHub repos")
    
    return GitHubReposResponse(
        repos=repo_infos,
        total=len(repo_infos),
        github_user=None,  # Installation tokens don't have user info
    )


@app.get(
    "/api/gitlab/repos",
    response_model=GitLabProjectsResponse,
    tags=["GitLab Integration"],
    summary="List GitLab projects",
)
async def list_gitlab_repos(
    tenant: TenantContext = Depends(require_tenant_context_flexible),
    settings: Settings = Depends(get_settings),
) -> GitLabProjectsResponse:
    """List GitLab projects for the authenticated organization connection."""
    tenant.require_scope("admin:policy")

    gitlab_token = await get_gitlab_token_for_tenant(tenant)

    from .gitlab_client import GitLabClient

    client = GitLabClient(gitlab_token, settings.gitlab_instance_url)

    try:
        projects = await client.list_projects()
    except Exception as e:
        logger.error(f"Failed to list GitLab projects: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list GitLab projects: {str(e)}")

    existing_configs = await list_repo_configs(tenant.org_id)
    existing_repo_names = {c["repo_name"] for c in existing_configs}

    project_infos = []
    for project in projects:
        can_push = project.access_level >= 30  # Developer+
        can_admin = project.access_level >= 40  # Maintainer+

        project_infos.append(GitLabProjectInfo(
            id=project.id,
            name=project.name,
            full_name=project.full_name,
            owner=project.owner,
            private=project.private,
            description=project.description,
            default_branch=project.default_branch,
            html_url=project.html_url,
            can_push=can_push,
            can_admin=can_admin,
            imported=project.full_name in existing_repo_names,
        ))

    return GitLabProjectsResponse(projects=project_infos, total=len(project_infos))


@app.post(
    "/api/gitlab/import",
    response_model=GitLabImportResponse,
    tags=["GitLab Integration"],
    summary="Import GitLab projects",
)
async def import_gitlab_repos(
    import_request: GitLabImportRequest,
    tenant: TenantContext = Depends(require_tenant_context_flexible),
) -> GitLabImportResponse:
    """Bulk import GitLab projects to repo configuration."""
    tenant.require_scope("admin:policy")

    default_policy = {
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
            "deserialization": True,
        },
    }

    if import_request.default_policy:
        default_policy = import_request.default_policy

    results = []
    total_imported = 0
    total_failed = 0

    for repo_name in import_request.repos:
        try:
            config = await upsert_repo_config(
                org_id=tenant.org_id,
                repo_name=repo_name,
                policy=default_policy,
                enabled=True,
                source="gitlab",
            )
            results.append(GitLabImportResult(
                repo_name=repo_name,
                success=True,
                config_id=config.get("id"),
            ))
            total_imported += 1
        except Exception as e:
            logger.error(f"Failed to import GitLab project {repo_name}: {e}")
            results.append(GitLabImportResult(
                repo_name=repo_name,
                success=False,
                error=str(e),
            ))
            total_failed += 1

    return GitLabImportResponse(
        results=results,
        total_imported=total_imported,
        total_failed=total_failed,
    )


@app.post(
    "/api/gitlab/webhooks/install",
    response_model=GitLabWebhookInstallResponse,
    tags=["GitLab Integration"],
    summary="Install GitLab merge request webhooks",
)
async def install_gitlab_webhooks(
    install_request: GitLabWebhookInstallRequest,
    request: Request,
    tenant: TenantContext = Depends(require_tenant_context_flexible),
    settings: Settings = Depends(get_settings),
) -> GitLabWebhookInstallResponse:
    """Ensure selected GitLab repos have the webhook pointing to this backend."""
    tenant.require_scope("admin:policy")

    if not settings.gitlab_app_webhook_secret:
        raise HTTPException(status_code=500, detail="GitLab webhook secret not configured")

    gitlab_token = await get_gitlab_token_for_tenant(tenant)
    from .gitlab_client import GitLabClient

    client = GitLabClient(gitlab_token, settings.gitlab_instance_url)
    webhook_url = str(request.url_for("gitlab_webhook_endpoint"))

    results = []
    total_success = 0
    total_failed = 0

    for repo_name in install_request.repos:
        try:
            project = await client.get_project(repo_name)
            if not project:
                results.append(GitLabWebhookInstallResult(
                    repo_name=repo_name,
                    success=False,
                    action="failed",
                    error="Project not found",
                ))
                total_failed += 1
                continue

            hook_result = await client.ensure_merge_request_webhook(
                project.id,
                webhook_url,
                settings.gitlab_app_webhook_secret,
            )

            results.append(GitLabWebhookInstallResult(
                repo_name=repo_name,
                success=True,
                action=hook_result.get("action", "created"),
                hook_id=hook_result.get("hook_id"),
            ))
            total_success += 1
        except Exception as e:
            logger.error(f"Failed to install GitLab webhook for {repo_name}: {e}")
            results.append(GitLabWebhookInstallResult(
                repo_name=repo_name,
                success=False,
                action="failed",
                error=str(e),
            ))
            total_failed += 1

    return GitLabWebhookInstallResponse(
        results=results,
        total_success=total_success,
        total_failed=total_failed,
    )


@app.get(
    "/api/gitlab/repos/{repo_name:path}/webhook/status",
    response_model=GitLabWebhookStatusResponse,
    tags=["GitLab Integration"],
    summary="Get GitLab webhook status for project",
)
async def get_gitlab_webhook_status(
    repo_name: str,
    request: Request,
    tenant: TenantContext = Depends(require_tenant_context_flexible),
    settings: Settings = Depends(get_settings),
) -> GitLabWebhookStatusResponse:
    """Check whether the GitLab webhook is configured for a project."""
    tenant.require_scope("read:metrics")

    gitlab_token = await get_gitlab_token_for_tenant(tenant)
    from .gitlab_client import GitLabClient

    client = GitLabClient(gitlab_token, settings.gitlab_instance_url)

    project = await client.get_project(repo_name)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project {repo_name} not found")

    webhook_url = str(request.url_for("gitlab_webhook_endpoint"))
    status = await client.get_merge_request_webhook_status(project.id, webhook_url)

    return GitLabWebhookStatusResponse(
        configured=status["configured"],
        repo_name=repo_name,
        webhook_url=webhook_url,
        hook_id=status.get("hook_id"),
    )


@app.post(
    "/api/github/import",
    response_model=GitHubImportResponse,
    tags=["GitHub Integration"],
    summary="Import GitHub repos",
)
async def import_github_repos(
    import_request: GitHubImportRequest,
    tenant: TenantContext = Depends(require_tenant_context_flexible),
) -> GitHubImportResponse:
    """
    Bulk import GitHub repositories to AI AppSec.
    
    Creates repo_config entries for selected repos with default or provided policy.
    """
    tenant.require_scope("admin:policy")
    
    from .models import GitHubImportResult
    from .database import list_repo_configs, get_supabase_client
    from .github_app_auth import get_installation_token, InstallationNotFoundError
    from .github_client import GitHubClient

    results = []
    total_imported = 0
    total_failed = 0
    
    # Default policy
    default_policy = {
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
            "deserialization": True,
        }
    }
    
    if import_request.default_policy:
        default_policy = import_request.default_policy.model_dump()

    # Use GitHub App installation token for automatic branch protection setup.
    required_check_context = "ai-appsec/high-vuln-gate"
    supabase_client = get_supabase_client()
    installation_result = supabase_client.table("github_app_installations").select("*").eq(
        "org_id", tenant.org_id
    ).eq("is_active", True).order("installed_at", desc=True).limit(1).execute()

    if not installation_result.data:
        raise HTTPException(
            status_code=400,
            detail="GitHub App not installed. Install and link the GitHub App before importing repositories.",
        )

    installation_id = installation_result.data[0].get("installation_id")
    if not installation_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub App installation. Please reinstall/link the GitHub App.",
        )

    try:
        github_token, _ = await get_installation_token(installation_id)
    except InstallationNotFoundError:
        raise HTTPException(
            status_code=409,
            detail="GitHub App installation is no longer active. Please reconnect the GitHub App.",
        )
    github_client = GitHubClient(github_token)
    
    for repo_name in import_request.repos:
        try:
            parts = repo_name.split("/")
            if len(parts) != 2:
                raise ValueError("Invalid repo format. Expected owner/repo")
            owner, repo = parts

            config = await upsert_repo_config(
                org_id=tenant.org_id,
                repo_name=repo_name,
                policy=default_policy,
                enabled=True,
                source="github",
            )

            # Auto-enforce merge gate for imported repositories.
            repo_data = await github_client.get_repo(owner, repo)
            default_branch = repo_data.default_branch if repo_data else "main"
            await github_client.ensure_required_status_check(
                owner=owner,
                repo=repo,
                branch=default_branch,
                context_name=required_check_context,
            )

            results.append(GitHubImportResult(
                repo_name=repo_name,
                success=True,
                config_id=config.get("id"),
            ))
            total_imported += 1
        except Exception as e:
            logger.error(f"Failed to import repo {repo_name}: {e}")
            results.append(GitHubImportResult(
                repo_name=repo_name,
                success=False,
                error=str(e),
            ))
            total_failed += 1
    
    return GitHubImportResponse(
        results=results,
        total_imported=total_imported,
        total_failed=total_failed,
    )


@app.get(
    "/api/github/repos/{owner}/{repo}/workflow/status",
    response_model=WorkflowStatusResponse,
    tags=["GitHub Integration"],
    summary="Check workflow status",
)
async def check_workflow_status(
    owner: str,
    repo: str,
    tenant: TenantContext = Depends(require_tenant_context_flexible),
) -> WorkflowStatusResponse:
    """Check if the security review workflow is installed in a repository."""
    tenant.require_scope("read:metrics")
    
    # Get GitHub token from secure database storage
    github_token = await get_github_token_for_tenant(tenant)
    
    from .github_client import check_workflow_installed
    
    try:
        status = await check_workflow_installed(github_token, owner, repo)
        return WorkflowStatusResponse(**status)
    except Exception as e:
        logger.error(f"Failed to check workflow status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to check workflow: {str(e)}")


@app.post(
    "/api/github/workflows/install",
    response_model=WorkflowInstallResponse,
    tags=["GitHub Integration"],
    summary="Install workflows in repos",
)
async def install_workflows(
    install_request: WorkflowInstallRequest,
    tenant: TenantContext = Depends(require_tenant_context_flexible),
) -> WorkflowInstallResponse:
    """
    Install the security review workflow in multiple repositories.
    
    Uses the stored GitHub OAuth token from the database.
    Requires write access to the repositories.
    """
    tenant.require_scope("admin:policy")
    
    # Get GitHub token from secure database storage
    github_token = await get_github_token_for_tenant(tenant)
    
    from .github_client import install_workflow_to_repo, GitHubClient
    from .models import WorkflowInstallResult
    
    results = []
    total_success = 0
    total_failed = 0
    required_check_context = "ai-appsec/high-vuln-gate"
    
    for repo_full_name in install_request.repos:
        parts = repo_full_name.split("/")
        if len(parts) != 2:
            results.append(WorkflowInstallResult(
                repo_name=repo_full_name,
                success=False,
                action="failed",
                error="Invalid repo name format. Expected 'owner/repo'",
            ))
            total_failed += 1
            continue
        
        owner, repo = parts
        
        try:
            result = await install_workflow_to_repo(github_token, owner, repo)
            
            if result["success"]:
                # Auto-enforce required status check on the default branch so
                # HIGH findings can block merges without manual GitHub setup.
                protection_error = None
                try:
                    gh_client = GitHubClient(github_token)
                    repo_data = await gh_client.get_repo(owner, repo)
                    default_branch = repo_data.default_branch if repo_data else "main"
                    await gh_client.ensure_required_status_check(
                        owner=owner,
                        repo=repo,
                        branch=default_branch,
                        context_name=required_check_context,
                    )
                except Exception as e:
                    protection_error = (
                        f"Workflow installed, but auto-protection failed: {str(e)}"
                    )

                if protection_error:
                    results.append(WorkflowInstallResult(
                        repo_name=repo_full_name,
                        success=False,
                        action="failed",
                        error=protection_error,
                        commit_sha=result.get("commit_sha"),
                    ))
                    total_failed += 1
                    continue

                results.append(WorkflowInstallResult(
                    repo_name=repo_full_name,
                    success=True,
                    action=result["action"],
                    commit_sha=result.get("commit_sha"),
                ))
                total_success += 1
            else:
                results.append(WorkflowInstallResult(
                    repo_name=repo_full_name,
                    success=False,
                    action="failed",
                    error=result.get("error", "Unknown error"),
                ))
                total_failed += 1
        except Exception as e:
            logger.error(f"Failed to install workflow in {repo_full_name}: {e}")
            results.append(WorkflowInstallResult(
                repo_name=repo_full_name,
                success=False,
                action="failed",
                error=str(e),
            ))
            total_failed += 1
    
    return WorkflowInstallResponse(
        results=results,
        total_success=total_success,
        total_failed=total_failed,
    )


@app.post(
    "/api/github/repos/{owner}/{repo}/secrets",
    tags=["GitHub Integration"],
    summary="Set repository secrets",
)
async def set_repository_secrets(
    owner: str,
    repo: str,
    secrets: dict[str, str],
    tenant: TenantContext = Depends(require_tenant_context_flexible),
):
    """
    Set multiple secrets in a GitHub repository.
    
    Uses the stored GitHub OAuth token from the database.
    Body should be a JSON object with secret names as keys and values as values.
    Example: {"AI_REVIEW_URL": "https://...", "AI_REVIEW_TOKEN": "token_..."}
    
    Requires admin access to the repository.
    """
    tenant.require_scope("admin:policy")
    
    # Get GitHub token from secure database storage
    github_token = await get_github_token_for_tenant(tenant)
    
    from .github_client import GitHubClient
    
    client = GitHubClient(github_token)
    
    # Check if user has admin access
    repo_data = await client.get_repo(owner, repo)
    if not repo_data or not repo_data.permissions.get("admin", False):
        raise HTTPException(
            status_code=403,
            detail="Admin access required to manage repository secrets"
        )
    
    results = []
    total_success = 0
    total_failed = 0
    
    for secret_name, secret_value in secrets.items():
        try:
            result = await client.set_repository_secret(owner, repo, secret_name, secret_value)
            results.append(result)
            if result["success"]:
                total_success += 1
            else:
                total_failed += 1
        except Exception as e:
            logger.error(f"Failed to set secret {secret_name}: {e}")
            results.append({
                "success": False,
                "secret_name": secret_name,
                "error": str(e)
            })
            total_failed += 1
    
    return {
        "results": results,
        "total_success": total_success,
        "total_failed": total_failed,
    }


@app.get(
    "/api/github/repos/{owner}/{repo}/secrets",
    tags=["GitHub Integration"],
    summary="List repository secrets",
)
async def list_repository_secrets(
    owner: str,
    repo: str,
    tenant: TenantContext = Depends(require_tenant_context_flexible),
):
    """
    List secret names in a GitHub repository.
    Uses the stored GitHub OAuth token from the database.
    Note: Secret values cannot be retrieved, only names.
    """
    tenant.require_scope("admin:policy")
    
    # Get GitHub token from secure database storage
    github_token = await get_github_token_for_tenant(tenant)
    
    from .github_client import GitHubClient
    
    try:
        client = GitHubClient(github_token)
        secret_names = await client.list_repository_secrets(owner, repo)
        return {"secrets": secret_names, "total": len(secret_names)}
    except Exception as e:
        logger.error(f"Failed to list secrets: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list secrets: {str(e)}")


# ============================================================================
# Organization Management (JWT-based)
# ============================================================================

@app.post(
    "/api/github/app/installations",
    response_model=GitHubAppInstallationResponse,
    tags=["GitHub Integration"],
    summary="Link GitHub App installation to organization",
)
async def link_github_app_installation(
    request: GitHubAppInstallationRequest,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """
    Link a GitHub App installation to the current organization.
    
    This is called after a user installs the GitHub App on their account.
    It establishes the connection between the GitHub App installation and
    your organization, enabling automatic PR reviews via webhooks.
    
    **Required Permissions:**
    - Any organization member can link installations
    
    **Parameters:**
    - installation_id: The GitHub App installation ID
    - account_login: GitHub username or organization name
    - account_type: 'User' or 'Organization'
    - account_id: GitHub's numeric account ID
    """
    # Allow any org member to link installations (removed admin:policy requirement)
    
    from .github_webhook import store_github_app_installation
    
    logger.info(f"Linking GitHub App installation {request.installation_id} to org {tenant.org_id}")
    
    try:
        result = await store_github_app_installation(
            org_id=tenant.org_id,
            installation_id=request.installation_id,
            account_login=request.account_login,
            account_type=request.account_type,
            account_id=request.account_id,
            repository_selection=request.repository_selection,
            permissions=request.permissions,
            events=request.events
        )
        
        logger.info(f"Successfully linked installation: {result}")
        
        return GitHubAppInstallationResponse(
            success=result["success"],
            installation_id=result["installation_id"],
            org_id=result["org_id"],
            account_login=result["account_login"],
            message=result["message"]
        )
        
    except Exception as e:
        logger.error(f"Failed to link GitHub App installation: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to link installation: {str(e)}"
        )


@app.get(
    "/api/github/app/installations",
    response_model=GitHubAppInstallationsListResponse,
    tags=["GitHub Integration"],
    summary="List linked GitHub App installations",
)
async def list_github_app_installations(
    request: Request,
    user: UserContext = Depends(require_jwt_only),
):
    """
    List all GitHub App installations linked to the current organization.
    
    **Required Permissions:**
    - Any organization member can view installations
    
    Returns a list of installations with their status (active, suspended, etc.)
    """
    # Allow any org member to view installations (not just admins)
    
    from .database import get_supabase_client, get_user_organizations
    
    try:
        lookup_start = time.perf_counter()
        tenant_id = request.headers.get("X-Tenant-ID")

        user_orgs = await get_user_organizations(user.user_id)
        if not user_orgs:
            return GitHubAppInstallationsListResponse(installations=[], total=0)

        selected_org = None
        if tenant_id:
            selected_org = next((org for org in user_orgs if org.get("id") == tenant_id), None)
            if not selected_org:
                raise HTTPException(status_code=403, detail=f"You do not have access to organization {tenant_id}")
        else:
            selected_org = user_orgs[0]

        org_id = selected_org.get("id")
        client = get_supabase_client()
        result = await asyncio.to_thread(
            lambda: client.table("github_app_installations").select("*").eq(
                "org_id", org_id
            ).order("installed_at", desc=True).execute()
        )

        installations = []
        for inst in (result.data or []):
            installations.append(GitHubAppInstallationInfo(
                id=inst["id"],
                installation_id=inst["installation_id"],
                account_login=inst["account_login"],
                account_type=inst["account_type"],
                account_id=inst["account_id"],
                repository_selection=inst.get("repository_selection", "all"),
                permissions=inst.get("permissions", {}),
                events=inst.get("events", []),
                installed_at=inst["installed_at"],
                updated_at=inst["updated_at"],
                is_active=inst.get("is_active", True),
                suspended_at=inst.get("suspended_at"),
                suspended_by=inst.get("suspended_by")
            ))

        elapsed_ms = (time.perf_counter() - lookup_start) * 1000
        add_request_timing("api.github.installations.list", elapsed_ms)

        return GitHubAppInstallationsListResponse(
            installations=installations,
            total=len(installations)
        )
        
    except Exception as e:
        logger.error(f"Failed to list installations: {e}")
        # Return empty list on error rather than failing
        return GitHubAppInstallationsListResponse(
            installations=[],
            total=0
        )


@app.get(
    "/api/github/app/installations/sync",
    response_model=GitHubAppInstallationsListResponse,
    include_in_schema=False,
)
@app.post(
    "/api/github/app/installations/sync",
    response_model=GitHubAppInstallationsListResponse,
    tags=["GitHub Integration"],
    summary="Sync and verify GitHub App installations",
    description="""
    Syncs GitHub App installations with GitHub's records.
    Marks any installations that no longer exist on GitHub as inactive.
    This handles cases where the app is uninstalled directly from GitHub.
    """,
)
async def sync_github_app_installations(
    request: Request,
    user: UserContext = Depends(require_jwt_only),
    settings: Settings = Depends(get_settings),
):
    """
    Sync and verify all GitHub App installations.

    This endpoint:
    1. Fetches installations from GitHub's API
    2. Compares with our database records
    3. Marks any uninstalled/invalid installations as inactive
    4. Returns the current verified status
    """
    from .database import get_supabase_client, get_user_organizations
    from .github_app_auth import generate_app_jwt
    import httpx

    try:
        tenant_id = request.headers.get("X-Tenant-ID")
        user_orgs = await get_user_organizations(user.user_id)

        if not user_orgs:
            return GitHubAppInstallationsListResponse(installations=[], total=0)

        selected_org = None
        if tenant_id:
            selected_org = next((org for org in user_orgs if org.get("id") == tenant_id), None)
            if not selected_org:
                raise HTTPException(status_code=403, detail=f"You do not have access to organization {tenant_id}")
        else:
            selected_org = user_orgs[0]

        org_id = selected_org.get("id")
        client = get_supabase_client()

        # Get our stored installations
        stored_result = await asyncio.to_thread(
            lambda: client.table("github_app_installations").select("*").eq(
                "org_id", org_id
            ).execute()
        )
        stored_installations = {inst["installation_id"]: inst for inst in (stored_result.data or [])}

        # Fetch current installations from GitHub using App JWT
        app_jwt = generate_app_jwt(settings)

        async with httpx.AsyncClient() as http_client:
            response = await http_client.get(
                "https://api.github.com/app/installations",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30.0,
            )

            if response.status_code != 200:
                logger.error(f"GitHub API error during sync: {response.status_code}")
                # If we can't reach GitHub, just return current DB state
                pass
            else:
                github_installations = response.json()
                github_installation_ids = {inst["id"] for inst in github_installations}

                # Mark installations that no longer exist on GitHub as inactive
                for stored_inst_id, stored_inst in stored_installations.items():
                    if stored_inst_id not in github_installation_ids:
                        logger.info(f"Marking installation {stored_inst_id} as inactive - not found on GitHub")
                        await asyncio.to_thread(
                            lambda: client.table("github_app_installations").update({
                                "is_active": False,
                                "suspended_at": datetime.now(UTC).isoformat()
                            }).eq("id", stored_inst["id"]).execute()
                        )

        # Fetch updated installations from DB
        updated_result = await asyncio.to_thread(
            lambda: client.table("github_app_installations").select("*").eq(
                "org_id", org_id
            ).order("installed_at", desc=True).execute()
        )

        installations = []
        for inst in (updated_result.data or []):
            installations.append(GitHubAppInstallationInfo(
                id=inst["id"],
                installation_id=inst["installation_id"],
                account_login=inst["account_login"],
                account_type=inst["account_type"],
                account_id=inst["account_id"],
                repository_selection=inst.get("repository_selection", "all"),
                permissions=inst.get("permissions", {}),
                events=inst.get("events", []),
                installed_at=inst["installed_at"],
                updated_at=inst["updated_at"],
                is_active=inst.get("is_active", True),
                suspended_at=inst.get("suspended_at"),
                suspended_by=inst.get("suspended_by")
            ))

        # Separate active and inactive for cleaner response
        active_installations = [i for i in installations if i.is_active]
        inactive_installations = [i for i in installations if not i.is_active]

        return GitHubAppInstallationsListResponse(
            installations=active_installations + inactive_installations,
            total=len(installations)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to sync installations: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to sync installations: {str(e)}"
        )


@app.get(
    "/api/github/app/installations/{installation_id}",
    response_model=GitHubAppInstallationInfo,
    tags=["GitHub Integration"],
    summary="Get GitHub App installation details",
)
async def get_github_app_installation(
    installation_id: int,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """
    Get details of a specific GitHub App installation.
    
    **Required Permissions:**
    - admin:policy scope
    """
    tenant.require_scope("admin:policy")
    
    from .database import get_supabase_client
    
    try:
        client = get_supabase_client()
        result = client.table("github_app_installations").select("*").eq(
            "org_id", tenant.org_id
        ).eq("installation_id", installation_id).maybe_single().execute()
        
        if not result.data:
            raise HTTPException(
                status_code=404,
                detail=f"Installation {installation_id} not found"
            )
        
        inst = result.data
        return GitHubAppInstallationInfo(
            id=inst["id"],
            installation_id=inst["installation_id"],
            account_login=inst["account_login"],
            account_type=inst["account_type"],
            account_id=inst["account_id"],
            repository_selection=inst.get("repository_selection", "all"),
            permissions=inst.get("permissions", {}),
            events=inst.get("events", []),
            installed_at=inst["installed_at"],
            updated_at=inst["updated_at"],
            is_active=inst.get("is_active", True),
            suspended_at=inst.get("suspended_at"),
            suspended_by=inst.get("suspended_by")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get installation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get installation: {str(e)}"
        )


@app.get(
    "/api/github/app/install-url",
    tags=["GitHub Integration"],
    summary="Get GitHub App installation URL",
)
async def get_github_app_install_url(
    request: Request,
    user: UserContext = Depends(require_jwt_only),
    settings: Settings = Depends(get_settings),
):
    """
    Get the GitHub App installation URL.
    
    This URL can be used to install the GitHub App on a user or organization account.
    """
    from .github_app_auth import get_github_app_info
    
    try:
        app_info = await get_github_app_info(settings)
        install_url = app_info.get("html_url", "").replace("/github-apps/", "/apps/")
        
        if not install_url:
            raise HTTPException(
                status_code=500,
                detail="Could not determine GitHub App installation URL"
            )
        
        return {
            "install_url": f"{install_url}/installations/new",
            "app_name": app_info.get("name", "AI AppSec PR Reviewer"),
            "app_slug": app_info.get("slug", "")
        }
        
    except Exception as e:
        logger.error(f"Failed to get GitHub App install URL: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get installation URL: {str(e)}"
        )


@app.get(
    "/api/github/app/my-installations",
    tags=["GitHub Integration"],
    summary="Get user's GitHub App installations",
)
async def get_my_github_app_installations(
    user: UserContext = Depends(require_jwt_only),
    settings: Settings = Depends(get_settings),
):
    """
    Get the authenticated user's GitHub App installations directly from GitHub.
    
    This fetches installations from GitHub's API using the App JWT.
    Used to discover installations after the user installs the app.
    
    **Required Permissions:**
    - Valid JWT authentication
    
    Returns a list of installations the user has access to.
    """
    from .github_app_auth import generate_app_jwt
    import httpx
    
    try:
        # Use the App JWT to list installations (no OAuth needed)
        app_jwt = generate_app_jwt(settings)
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/app/installations",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30.0
            )
            
            if response.status_code != 200:
                logger.error(f"GitHub API error: {response.status_code} - {response.text}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to fetch installations from GitHub"
                )
            
            data = response.json()
            
            installations = []
            for inst in data:
                account = inst.get("account", {})
                installations.append({
                    "installation_id": inst.get("id"),
                    "account_login": account.get("login"),
                    "account_type": account.get("type"),
                    "account_id": account.get("id"),
                    "repository_selection": inst.get("repository_selection", "all"),
                    "permissions": inst.get("permissions", {}),
                    "events": inst.get("events", []),
                    "created_at": inst.get("created_at"),
                    "updated_at": inst.get("updated_at"),
                })
            
            return {
                "installations": installations,
                "total": len(installations)
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch GitHub App installations: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch installations: {str(e)}"
        )


@app.get(
    "/api/github/app/callback",
    tags=["GitHub Integration"],
    summary="GitHub App install callback redirect",
    include_in_schema=False,
)
async def github_app_callback_redirect(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    """
    Backend callback endpoint for GitHub App setup URL.

    This keeps redirect handling backend-based (like GitLab), while preserving
    the existing frontend callback UI at /github/app/callback.
    """
    frontend_base = (settings.frontend_url or "http://localhost:3000").rstrip("/")
    query_string = request.url.query
    target = f"{frontend_base}/github/app/callback"
    if query_string:
        target = f"{target}?{query_string}"

    return RedirectResponse(url=target, status_code=303)


@app.delete(
    "/api/github/app/installations/{installation_id}",
    tags=["GitHub Integration"],
    summary="Unlink GitHub App installation",
)
async def unlink_github_app_installation(
    installation_id: int,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """
    Unlink a GitHub App installation from the organization.
    
    This does NOT uninstall the app from GitHub - it only removes the
    association in our system. The user must uninstall the app on GitHub
    separately if desired.
    
    **Required Permissions:**
    - admin:policy scope
    """
    tenant.require_scope("admin:policy")
    
    from .database import get_supabase_client
    
    try:
        client = get_supabase_client()
        
        # Verify the installation belongs to this org
        check = client.table("github_app_installations").select("id").eq(
            "org_id", tenant.org_id
        ).eq("installation_id", installation_id).maybe_single().execute()
        
        if not check.data:
            raise HTTPException(
                status_code=404,
                detail=f"Installation {installation_id} not found"
            )
        
        # Soft delete - mark as inactive
        client.table("github_app_installations").update({
            "is_active": False,
            "updated_at": datetime.now(UTC).isoformat()
        }).eq("installation_id", installation_id).execute()
        
        logger.info(
            f"Unlinked GitHub App installation {installation_id} from org {tenant.org_id}"
        )
        
        return {
            "success": True,
            "installation_id": installation_id,
            "message": "Installation unlinked successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unlink installation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to unlink installation: {str(e)}"
        )


@app.post(
    "/api/gitlab/app/installations",
    response_model=GitLabAppInstallationResponse,
    tags=["GitLab Integration"],
    summary="Link GitLab installation to organization",
)
async def link_gitlab_app_installation(
    request: GitLabAppInstallationRequest,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Link a GitLab installation to the current organization."""
    from .gitlab_webhook import store_gitlab_app_installation

    try:
        result = await store_gitlab_app_installation(
            org_id=tenant.org_id,
            installation_id=request.installation_id,
            account_login=request.account_login,
            account_type=request.account_type,
            account_id=request.account_id,
            gitlab_instance_url=request.gitlab_instance_url,
            scopes=request.scopes,
        )

        return GitLabAppInstallationResponse(
            success=result["success"],
            installation_id=result["installation_id"],
            org_id=result["org_id"],
            account_login=result["account_login"],
            message=result["message"],
        )
    except Exception as e:
        logger.error(f"Failed to link GitLab installation: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to link installation: {str(e)}",
        )


@app.get(
    "/api/gitlab/app/installations",
    response_model=GitLabAppInstallationsListResponse,
    tags=["GitLab Integration"],
    summary="List linked GitLab installations",
)
async def list_gitlab_app_installations(
    request: Request,
    user: UserContext = Depends(require_jwt_only),
):
    """List all GitLab installations linked to the selected organization."""
    from .database import get_supabase_client, get_user_organizations

    try:
        tenant_id = request.headers.get("X-Tenant-ID")

        user_orgs = await get_user_organizations(user.user_id)
        if not user_orgs:
            return GitLabAppInstallationsListResponse(installations=[], total=0)

        selected_org = None
        if tenant_id:
            selected_org = next((org for org in user_orgs if org.get("id") == tenant_id), None)
            if not selected_org:
                raise HTTPException(status_code=403, detail=f"You do not have access to organization {tenant_id}")
        else:
            selected_org = user_orgs[0]

        org_id = selected_org.get("id")
        client = get_supabase_client()
        result = await asyncio.to_thread(
            lambda: client.table("gitlab_app_installations").select("*").eq(
                "org_id", org_id
            ).order("installed_at", desc=True).execute()
        )

        installations = []
        rows = result.data or []

        # Backward-compatibility: early OAuth flow persisted gitlab_connections
        # without creating gitlab_app_installations rows. Synthesize one status row
        # so existing connected users appear as connected in UI.
        if not rows:
            connection_result = await asyncio.to_thread(
                lambda: client.table("gitlab_connections").select(
                    "gitlab_user_id, gitlab_username, gitlab_instance_url, scopes, connected_at, last_used_at"
                ).eq("org_id", org_id).eq("is_active", True).order("connected_at", desc=True).limit(1).execute()
            )
            connection_rows = connection_result.data or []
            if connection_rows:
                conn = connection_rows[0]
                synthetic_id = f"oauth-user-{conn.get('gitlab_user_id')}"
                installed_at = conn.get("connected_at") or datetime.now(UTC).isoformat()
                updated_at = conn.get("last_used_at") or installed_at
                installations.append(GitLabAppInstallationInfo(
                    id=str(conn.get("gitlab_user_id")),
                    installation_id=synthetic_id,
                    account_login=conn.get("gitlab_username") or "unknown",
                    account_type="User",
                    account_id=conn.get("gitlab_user_id") or 0,
                    gitlab_instance_url=conn.get("gitlab_instance_url") or "https://gitlab.com",
                    scopes=conn.get("scopes") or [],
                    installed_at=installed_at,
                    updated_at=updated_at,
                    is_active=True,
                ))

        for inst in rows:
            installations.append(GitLabAppInstallationInfo(
                id=inst["id"],
                installation_id=inst["installation_id"],
                account_login=inst["account_login"],
                account_type=inst["account_type"],
                account_id=inst["account_id"],
                gitlab_instance_url=inst.get("gitlab_instance_url", "https://gitlab.com"),
                scopes=inst.get("scopes", []),
                installed_at=inst["installed_at"],
                updated_at=inst["updated_at"],
                is_active=inst.get("is_active", True),
            ))

        return GitLabAppInstallationsListResponse(
            installations=installations,
            total=len(installations),
        )
    except Exception as e:
        logger.error(f"Failed to list GitLab installations: {e}")
        return GitLabAppInstallationsListResponse(
            installations=[],
            total=0,
        )


@app.get(
    "/api/gitlab/connections/verify",
    include_in_schema=False,
)
@app.post(
    "/api/gitlab/connections/verify",
    tags=["GitLab Integration"],
    summary="Verify GitLab connection status",
    description="""
    Verifies that the GitLab OAuth connection is still valid.
    Marks the connection as inactive if the token has been revoked.
    """,
)
async def verify_gitlab_connection(
    request: Request,
    user: UserContext = Depends(require_jwt_only),
):
    """
    Verify GitLab OAuth connection and mark as inactive if revoked.
    """
    from .database import get_supabase_client, get_user_organizations
    import httpx

    try:
        tenant_id = request.headers.get("X-Tenant-ID")
        user_orgs = await get_user_organizations(user.user_id)

        if not user_orgs:
            return {"is_active": False, "is_revoked": False}

        selected_org = None
        if tenant_id:
            selected_org = next((org for org in user_orgs if org.get("id") == tenant_id), None)
            if not selected_org:
                raise HTTPException(status_code=403, detail=f"You do not have access to organization {tenant_id}")
        else:
            selected_org = user_orgs[0]

        org_id = selected_org.get("id")
        client = get_supabase_client()

        # Get the active connection
        result = await asyncio.to_thread(
            lambda: client.table("gitlab_connections").select("*").eq(
                "org_id", org_id
            ).eq("is_active", True).order("connected_at", desc=True).limit(1).execute()
        )

        row = (result.data or [None])[0]
        if not row:
            return {"is_active": False, "is_revoked": False}

        token = row.get("encrypted_access_token")
        if not token:
            await mark_gitlab_org_integrations_inactive(client, org_id, str(row.get("id")))
            return {"is_active": False, "is_revoked": True}

        # Verify the token
        gitlab_instance_url = row.get("gitlab_instance_url", "https://gitlab.com")
        is_revoked = False

        try:
            async with httpx.AsyncClient() as http_client:
                test_response = await http_client.get(
                    f"{gitlab_instance_url}/api/v4/user",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0
                )
                if test_response.status_code == 401:
                    is_revoked = True
        except (httpx.RequestError, httpx.HTTPStatusError):
            # Network error or HTTP error - assume still valid, don't mark as revoked
            pass

        if is_revoked:
            # Mark as inactive
            await mark_gitlab_org_integrations_inactive(client, org_id, str(row.get("id")))
            return {"is_active": False, "is_revoked": True}

        return {"is_active": True, "is_revoked": False}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to verify GitLab connection: {e}")
        return {"is_active": False, "is_revoked": False}


@app.delete(
    "/api/gitlab/app/installations/{installation_id}",
    tags=["GitLab Integration"],
    summary="Unlink GitLab installation",
)
async def unlink_gitlab_app_installation(
    installation_id: str,
    tenant: TenantContext = Depends(require_tenant_context),
):
    """Soft delete a GitLab installation from this organization."""
    tenant.require_scope("admin:policy")

    from .database import get_supabase_client

    try:
        client = get_supabase_client()

        check = await asyncio.to_thread(
            lambda: client.table("gitlab_app_installations").select("id").eq(
                "org_id", tenant.org_id
            ).eq("installation_id", installation_id).maybe_single().execute()
        )

        if not check.data:
            raise HTTPException(
                status_code=404,
                detail=f"Installation {installation_id} not found",
            )

        await asyncio.to_thread(
            lambda: client.table("gitlab_app_installations").update({
                "is_active": False,
                "updated_at": datetime.now(UTC).isoformat(),
            }).eq("installation_id", installation_id).execute()
        )

        return {
            "success": True,
            "installation_id": installation_id,
            "message": "Installation unlinked successfully",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unlink GitLab installation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to unlink installation: {str(e)}",
        )


@app.get(
    "/api/gitlab/app/install-url",
    tags=["GitLab Integration"],
    summary="Get GitLab OAuth authorization URL",
)
async def get_gitlab_app_install_url(
    settings: Settings = Depends(get_settings),
):
    """Return the GitLab OAuth authorization URL for app connect flow."""
    if not settings.gitlab_app_client_id:
        raise HTTPException(status_code=500, detail="GitLab app not configured")

    instance_url = (settings.gitlab_instance_url or "https://gitlab.com").rstrip("/")
    return {
        "install_url": f"{instance_url}/oauth/authorize?client_id={settings.gitlab_app_client_id}&response_type=code",
        "provider": "gitlab",
        "instance_url": instance_url,
    }


@app.get(
    "/api/gitlab/oauth/authorize",
    tags=["GitLab Integration"],
    summary="Start GitLab OAuth flow",
)
async def gitlab_oauth_authorize(
    request: Request,
    user: UserContext = Depends(require_jwt_only),
    settings: Settings = Depends(get_settings),
):
    """Generate state and return GitLab OAuth authorization URL."""
    if not settings.gitlab_app_client_id:
        raise HTTPException(status_code=500, detail="GitLab OAuth client is not configured")

    from .database import get_supabase_client

    state = secrets.token_urlsafe(32)
    state_hash = hashlib.sha256(state.encode()).hexdigest()
    client = get_supabase_client()

    try:
        await asyncio.to_thread(
            lambda: client.table("oauth_states").insert({
                "state_hash": state_hash,
                "user_id": user.user_id,
            }).execute()
        )
    except Exception as e:
        logger.error(f"Failed to persist GitLab OAuth state for user {user.user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to initialize OAuth flow")

    instance_url = (settings.gitlab_instance_url or "https://gitlab.com").rstrip("/")
    redirect_uri = str(request.url_for("gitlab_oauth_callback"))
    authorize_query = urlencode(
        {
            "client_id": settings.gitlab_app_client_id,
            "response_type": "code",
            "scope": "api read_api read_repository write_repository",
            "redirect_uri": redirect_uri,
            "state": state,
        }
    )
    authorization_url = f"{instance_url}/oauth/authorize?{authorize_query}"

    return {
        "provider": "gitlab",
        "authorization_url": authorization_url,
        "state": state,
        "redirect_uri": redirect_uri,
        "instance_url": instance_url,
    }


@app.get(
    "/api/gitlab/oauth/callback",
    tags=["GitLab Integration"],
    summary="Handle GitLab OAuth callback",
)
async def gitlab_oauth_callback(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    """Fast pass-through callback to frontend so users immediately see callback UI."""
    if not settings.frontend_url:
        raise HTTPException(status_code=500, detail="FRONTEND_URL is not configured")

    frontend_base = settings.frontend_url.rstrip("/")
    query_string = request.url.query
    target_url = f"{frontend_base}/gitlab/app/callback"
    if query_string:
        target_url = f"{target_url}?{query_string}"

    return RedirectResponse(url=target_url, status_code=303)


@app.post(
    "/api/gitlab/oauth/complete",
    tags=["GitLab Integration"],
    summary="Complete GitLab OAuth flow",
)
async def gitlab_oauth_complete(
    payload: Dict[str, Optional[str]],
    request: Request,
    user: UserContext = Depends(require_jwt_only),
    settings: Settings = Depends(get_settings),
):
    """Finalize GitLab OAuth from frontend callback screen."""
    code = payload.get("code")
    state = payload.get("state")
    error = payload.get("error")

    if error:
        raise HTTPException(status_code=400, detail=f"GitLab OAuth error: {error}")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing OAuth code/state")

    if not settings.gitlab_app_client_id or not settings.gitlab_app_client_secret:
        raise HTTPException(status_code=500, detail="GitLab OAuth client is not configured")

    from .database import get_supabase_client, get_user_organizations
    from .gitlab_webhook import store_gitlab_app_installation
    import httpx

    client = get_supabase_client()
    state_hash = hashlib.sha256(state.encode()).hexdigest()

    try:
        state_row_result = await asyncio.to_thread(
            lambda: client.table("oauth_states").select("*").eq(
                "state_hash", state_hash
            ).eq("used", False).maybe_single().execute()
        )
        state_row = state_row_result.data
    except Exception as e:
        logger.error(f"Failed to verify GitLab OAuth state: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify OAuth state")

    if not state_row:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    user_id = state_row.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="OAuth state missing user context")

    if user_id != user.user_id:
        raise HTTPException(status_code=403, detail="OAuth state does not belong to authenticated user")

    redirect_uri = str(request.url_for("gitlab_oauth_callback"))
    instance_url = (settings.gitlab_instance_url or "https://gitlab.com").rstrip("/")

    try:
        async with httpx.AsyncClient() as http_client:
            token_response = await http_client.post(
                f"{instance_url}/oauth/token",
                data={
                    "client_id": settings.gitlab_app_client_id,
                    "client_secret": settings.gitlab_app_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
                timeout=30.0,
            )

            if token_response.status_code >= 400:
                logger.error(f"GitLab token exchange failed: {token_response.status_code} {token_response.text}")
                raise HTTPException(status_code=400, detail="Failed to exchange OAuth code")

            token_data = token_response.json()
            access_token = token_data.get("access_token")
            if not access_token:
                raise HTTPException(status_code=400, detail="GitLab access token missing in response")

            user_response = await http_client.get(
                f"{instance_url}/api/v4/user",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30.0,
            )

            if user_response.status_code >= 400:
                logger.error(f"GitLab user fetch failed: {user_response.status_code} {user_response.text}")
                raise HTTPException(status_code=400, detail="Failed to fetch GitLab user profile")

            gitlab_user = user_response.json()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"GitLab OAuth completion error: {e}")
        raise HTTPException(status_code=500, detail="GitLab OAuth flow failed")

    orgs = await get_user_organizations(user.user_id)
    org_id = orgs[0].get("id") if orgs else None

    if not org_id:
        raise HTTPException(status_code=400, detail="User is not in an organization")

    scopes = (token_data.get("scope") or "").split()
    token_hash = hashlib.sha256(access_token.encode()).hexdigest()

    try:
        await asyncio.to_thread(
            lambda: client.table("gitlab_connections").upsert(
                {
                    "user_id": user.user_id,
                    "gitlab_user_id": gitlab_user.get("id"),
                    "gitlab_username": gitlab_user.get("username"),
                    "gitlab_instance_url": instance_url,
                    "access_token_hash": token_hash,
                    "encrypted_access_token": access_token,
                    "scopes": scopes,
                    "is_active": True,
                    "org_id": org_id,
                },
                on_conflict="user_id",
            ).execute()
        )

        await store_gitlab_app_installation(
            org_id=org_id,
            installation_id=f"oauth-user-{gitlab_user.get('id')}",
            account_login=gitlab_user.get("username") or "unknown",
            account_type="User",
            account_id=gitlab_user.get("id") or 0,
            gitlab_instance_url=instance_url,
            scopes=scopes,
        )

        await asyncio.to_thread(
            lambda: client.table("oauth_states").update({"used": True}).eq("id", state_row.get("id")).execute()
        )
    except Exception as e:
        logger.error(f"Failed to persist GitLab OAuth connection: {e}")
        raise HTTPException(status_code=500, detail="Failed to persist GitLab connection")

    return {
        "connected": True,
        "provider": "gitlab",
        "gitlab_username": gitlab_user.get("username"),
        "gitlab_user_id": gitlab_user.get("id"),
        "org_id": org_id,
        "instance_url": instance_url,
        "scopes": scopes,
    }


@app.post(
    "/api/organizations",
    response_model=CreateOrgResponse,
    tags=["Organizations"],
    summary="Create a new organization with bootstrap token",
)
async def create_organization_endpoint(
    request: CreateOrgRequest,
    http_request: Request,
    user: UserContext = Depends(get_user_from_jwt),
    settings: Settings = Depends(get_settings),
) -> CreateOrgResponse:
    """
    Create a new organization for the authenticated user.
    
    Automatically creates a bootstrap API token with full access for the user.
    The user becomes the owner of the organization.
    
    **Important:** The token is only shown once! Save it securely.
    """
    if not settings.database_configured:
        raise HTTPException(
            status_code=500,
            detail="Database not configured. Cannot create organization."
        )
    
    from .database import create_organization, get_organization_by_slug
    import re
    
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(http_request)
    
    # Generate slug if not provided
    org_slug = request.org_slug
    if not org_slug:
        # Convert name to slug: lowercase, replace spaces with hyphens, remove special chars
        org_slug = re.sub(r'[^a-z0-9-]', '', request.org_name.lower().replace(' ', '-'))
        org_slug = re.sub(r'-+', '-', org_slug).strip('-')  # Remove multiple/trailing hyphens
    
    # Validate slug
    if not org_slug or len(org_slug) < 2:
        raise HTTPException(
            status_code=400,
            detail="Organization slug must be at least 2 characters"
        )
    
    # Check if org already exists
    existing = await get_organization_by_slug(org_slug)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Organization with slug '{org_slug}' already exists. Please choose a different name."
        )
    
    try:
        # Create organization with user as owner
        # This now auto-generates a CI/CD token
        org, cicd_token = await create_organization(
            name=request.org_name,
            slug=org_slug,
            user_id=user.user_id,
        )
        
        logger.info(f"Created organization {org['id']} for user {user.email}")
        
        # Get the CI/CD token data for response
        from .database import get_cicd_token
        cicd_token_data = await get_cicd_token(org["id"])
        
        # Audit log
        audit.log(AuditEvent(
            event_type=AuditEventType.ORG_CREATED,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            org_id=org["id"],
            actor_type="user",
            actor_id=user.user_id,
            resource_type="org",
            resource_id=org["id"],
            action="create",
            ip_address=ip_address,
            success=True,
            details={
                "org_name": org["name"],
                "org_slug": org["slug"],
                "cicd_token_id": cicd_token_data["id"] if cicd_token_data else None,
            }
        ))
        
        if cicd_token:
            logger.info(f"Auto-generated CI/CD token for organization {org['id']}")
        
        return CreateOrgResponse(
            org_id=org["id"],
            org_name=org["name"],
            org_slug=org["slug"],
            api_token=cicd_token,  # Return the CI/CD token
            token_prefix=cicd_token_data["prefix"] if cicd_token_data else None,
        )
    except Exception as e:
        logger.error(f"Organization creation failed: {e}")
        audit.log(AuditEvent(
            event_type=AuditEventType.ORG_CREATED,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            actor_type="user",
            actor_id=user.user_id,
            resource_type="org",
            resource_id=None,
            action="create",
            ip_address=ip_address,
            success=False,
            failure_reason=str(e)[:200],
            details={"org_slug": org_slug}
        ))
        raise HTTPException(status_code=500, detail=f"Failed to create organization: {str(e)}")


# ============================================================================
# Organization Invitations
# ============================================================================

@app.post(
    "/api/invitations",
    response_model=InvitationResponse,
    tags=["Invitations"],
    summary="Invite a user to join your organization",
)
async def create_invitation_endpoint(
    request: CreateInvitationRequest,
    http_request: Request,
    user: UserContext = Depends(get_user_with_org),
    settings: Settings = Depends(get_settings),
) -> InvitationResponse:
    """
    Invite a user by email to join your organization.
    
    Requires admin or owner role. Sends an invitation email with a secure token.
    """
    if not settings.database_configured:
        raise HTTPException(status_code=500, detail="Database not configured")
    
    # Check role permission
    if user.role not in ["admin", "owner"]:
        raise HTTPException(
            status_code=403,
            detail="Only admins and owners can invite users"
        )
    
    # Validate role
    if request.role not in ["admin", "member"]:
        raise HTTPException(
            status_code=400,
            detail="Role must be 'admin' or 'member'"
        )
    
    # Owners only can invite other admins
    if request.role == "admin" and user.role != "owner":
        raise HTTPException(
            status_code=403,
            detail="Only owners can invite users as admins"
        )
    
    # Initialize audit logger early for error logging
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(http_request)
    
    # Check team member limit before creating invitation
    can_add, limit_message = await check_can_add_member(user.org_id)
    if not can_add:
        logger.warning(f"Invitation blocked for org {user.org_id}: {limit_message}")
        audit.log_auth_failure(
            request_id=request_id,
            reason=f"Team member limit reached: {limit_message}",
            ip_address=ip_address,
            user_agent=get_user_agent(http_request),
        )
        raise HTTPException(
            status_code=403,
            detail=limit_message or "Team member limit reached. Upgrade your plan to add more members."
        )
    
    from .invitations import create_invitation
    
    try:
        invitation = await create_invitation(
            org_id=user.org_id,
            email=request.email,
            role=request.role,
            invited_by=user.user_id,
            expires_in_days=request.expires_in_days,
        )
        
        # Build invitation URL
        frontend_url = getattr(settings, 'frontend_url', None) or "http://localhost:3000"
        invite_token = invitation.get('invite_token')
        
        if not invite_token:
            logger.error(f"Invitation {invitation.get('id')} missing invite_token! Data: {invitation}")
            raise HTTPException(status_code=500, detail="Failed to generate invitation token")
            
        invite_url = f"{frontend_url}/auth/accept-invite?token={invite_token}"
        
        # Audit log
        audit.log(AuditEvent(
            event_type=AuditEventType.USER_INVITED,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            org_id=user.org_id,
            actor_type="user",
            actor_id=user.user_id,
            resource_type="invitation",
            resource_id=invitation['id'],
            action="create",
            ip_address=ip_address,
            success=True,
            details={
                "invited_email": request.email,
                "role": request.role,
            }
        ))
        
        logger.info(f"Created invitation for {request.email} to org {user.org_id}")
        
        return InvitationResponse(
            id=invitation["id"],
            email=invitation["email"],
            role=invitation["role"],
            invite_token=invitation["invite_token"],
            invite_url=invite_url,
            expires_at=invitation["expires_at"],
            created_at=invitation["created_at"],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create invitation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/api/invitations",
    response_model=InvitationListResponse,
    tags=["Invitations"],
    summary="List pending invitations for your organization",
)
async def list_invitations_endpoint(
    user: UserContext = Depends(get_user_with_org),
    settings: Settings = Depends(get_settings),
) -> InvitationListResponse:
    """
    Get all pending invitations for your organization.
    
    Requires membership in the organization.
    """
    if not settings.database_configured:
        raise HTTPException(status_code=500, detail="Database not configured")
    
    from .invitations import get_pending_invitations
    
    try:
        invitations = await get_pending_invitations(user.org_id)
        
        return InvitationListResponse(
            invitations=[
                PendingInvitation(
                    id=inv["id"],
                    email=inv["email"],
                    role=inv["role"],
                    invite_token=inv["invite_token"],
                    invited_by_email=inv["invited_by_email"],
                    expires_at=inv["expires_at"],
                    created_at=inv["created_at"],
                )
                for inv in invitations
            ],
            total=len(invitations),
        )
    except Exception as e:
        logger.error(f"Failed to list invitations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post(
    "/api/invitations/accept",
    response_model=AcceptInvitationResponse,
    tags=["Invitations"],
    summary="Accept an invitation to join an organization",
)
async def accept_invitation_endpoint(
    request: AcceptInvitationRequest,
    user: UserContext = Depends(get_user_from_jwt),
    settings: Settings = Depends(get_settings),
) -> AcceptInvitationResponse:
    """
    Accept an invitation using the token from the invitation email.
    
    Adds you as a member of the organization.
    """
    if not settings.database_configured:
        raise HTTPException(status_code=500, detail="Database not configured")
    
    from .invitations import accept_invitation
    
    try:
        org_info = await accept_invitation(
            invite_token=request.invite_token,
            user_id=user.user_id,
        )
        
        logger.info(f"User {user.email} joined organization {org_info['org_name']}")
        
        return AcceptInvitationResponse(
            org_id=org_info["org_id"],
            org_name=org_info["org_name"],
            org_slug=org_info["org_slug"],
            role=org_info["role"],
            message=f"Successfully joined {org_info['org_name']}!",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to accept invitation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete(
    "/api/invitations/{invitation_id}",
    tags=["Invitations"],
    summary="Revoke a pending invitation",
)
async def revoke_invitation_endpoint(
    invitation_id: str,
    user: UserContext = Depends(get_user_with_org),
    settings: Settings = Depends(get_settings),
):
    """
    Revoke a pending invitation.
    
    Requires admin or owner role.
    """
    if not settings.database_configured:
        raise HTTPException(status_code=500, detail="Database not configured")
    
    # Check role permission
    if user.role not in ["admin", "owner"]:
        raise HTTPException(
            status_code=403,
            detail="Only admins and owners can revoke invitations"
        )
    
    from .invitations import revoke_invitation
    
    try:
        await revoke_invitation(invitation_id, user.user_id)
        
        logger.info(f"Revoked invitation {invitation_id}")
        
        return {"success": True, "message": "Invitation revoked successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke invitation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/api/organizations",
    tags=["Organizations"],
    summary="List user's organizations",
)
async def list_user_organizations(
    user: UserContext = Depends(get_user_from_jwt),
    settings: Settings = Depends(get_settings),
):
    """
    List all organizations the authenticated user is a member of.
    """
    if not settings.database_configured:
        raise HTTPException(
            status_code=500,
            detail="Database not configured."
        )
    
    from .database import get_user_organizations
    
    try:
        org_lookup_start = time.perf_counter()
        orgs = await get_user_organizations(user.user_id)
        org_lookup_ms = (time.perf_counter() - org_lookup_start) * 1000
        add_request_timing("api.organizations.list", org_lookup_ms)
        logger.info(
            f"[timing][api/organizations] org_lookup_ms={org_lookup_ms:.2f} user_id={user.user_id} count={len(orgs)}"
        )
        logger.info(
            f"[api/organizations] user_id={user.user_id} email={user.email} orgs_count={len(orgs)} orgs={orgs}"
        )
        return {"organizations": orgs, "total": len(orgs)}
    except Exception as e:
        logger.error(f"Failed to list organizations for user {user.user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list organizations: {str(e)}")


@app.post(
    "/api/setup/quick-start",
    response_model=QuickSetupResponse,
    tags=["Setup"],
    summary="Quick start setup",
)
async def quick_start_setup(
    setup_request: QuickSetupRequest,
    _auth: bool = Depends(verify_auth_token),
    settings: Settings = Depends(get_settings),
) -> QuickSetupResponse:
    """
    One-step setup: creates organization and API token.
    
    Returns all the values needed to configure GitHub Actions secrets.
    
    Note: This endpoint uses legacy auth (API_AUTH_TOKEN) since org doesn't exist yet.
    """
    if not settings.database_configured:
        raise HTTPException(
            status_code=500,
            detail="Database not configured. Cannot create organization."
        )
    
    from .database import create_organization, get_organization_by_slug
    import re
    
    # Generate slug if not provided
    org_slug = setup_request.org_slug
    if not org_slug:
        # Convert name to slug: lowercase, replace spaces with hyphens, remove special chars
        org_slug = re.sub(r'[^a-z0-9-]', '', setup_request.org_name.lower().replace(' ', '-'))
        org_slug = re.sub(r'-+', '-', org_slug).strip('-')  # Remove multiple/trailing hyphens
    
    # Check if org already exists
    existing = await get_organization_by_slug(org_slug)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Organization with slug '{org_slug}' already exists"
        )
    
    try:
        # Create organization
        org = await create_organization(
            name=setup_request.org_name,
            slug=org_slug,
            user_id=None,  # No user in this context
        )
        
        # Create API token with all scopes for GitHub Actions
        api_token, token_data = await create_api_token(
            org_id=org["id"],
            name=setup_request.token_name,
            scopes=["*"],  # Full access
            created_by=None,
            expires_in_days=None,  # Never expires
            allow_wildcard=True,  # Allow wildcard scope for bootstrap token
        )
        
        # Build response with instructions
        api_url = settings.api_base_url if hasattr(settings, 'api_base_url') else "https://your-api-url.com"
        
        return QuickSetupResponse(
            org_id=org["id"],
            org_name=org["name"],
            org_slug=org["slug"],
            api_token=api_token,
            token_prefix=token_data["prefix"],
            secrets_to_add={
                "AI_REVIEW_URL": api_url,
                "AI_REVIEW_TOKEN": api_token,
                "AI_REVIEW_TENANT_ID": org["id"],
            }
        )
    except Exception as e:
        logger.error(f"Quick setup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Setup failed: {str(e)}")


# ============================================================================
# Pricing & Subscription Endpoints
# ============================================================================

@app.get(
    "/api/pricing/plans",
    tags=["Pricing"],
    summary="Get all pricing plans",
)
async def get_pricing_plans():
    """
    Get all available pricing plans with features and limits.
    
    This endpoint is public - no authentication required.
    """
    from .subscriptions import get_all_plans
    from .models import PricingPlan, PlanFeatures, PlanLimits
    
    plans_data = await get_all_plans()
    
    plans = []
    for plan in plans_data:
        plans.append(PricingPlan(
            id=plan["id"],
            name=plan["name"],
            description=plan.get("description"),
            price_monthly_cents=plan.get("price_monthly_cents", 0),
            price_yearly_cents=plan.get("price_yearly_cents", 0),
            limits=PlanLimits(
                max_repos=plan.get("max_repos", 1),
                max_prs_per_month=plan.get("max_prs_per_month", 30),
                max_team_members=plan.get("max_team_members", 1),
            ),
            features=PlanFeatures(
                advisory_mode=plan.get("feature_advisory_mode", True),
                enforcement_mode=plan.get("feature_enforcement_mode", False),
                dashboard=plan.get("feature_dashboard", False),
                audit_logs=plan.get("feature_audit_logs", False),
                sso=plan.get("feature_sso", False),
                policy_as_code=plan.get("feature_policy_as_code", False),
                siem_integration=plan.get("feature_siem_integration", False),
                custom_rules=plan.get("feature_custom_rules", False),
                priority_support=plan.get("feature_priority_support", False),
                dedicated_support=plan.get("feature_dedicated_support", False),
            ),
            is_popular=(plan["id"] == "team"),  # Team is the recommended plan
        ))
    
    from .models import PricingPlansResponse
    return PricingPlansResponse(plans=plans)


@app.get(
    "/api/subscription",
    tags=["Subscription"],
    summary="Get current subscription",
)
async def get_subscription_endpoint(
    tenant: TenantContext = Depends(require_tenant_context_flexible),
):
    """
    Get the current subscription and usage for the organization.
    """
    from .subscriptions import get_subscription, get_usage_status, get_organization_plan
    from .models import SubscriptionResponse, UsageStatus, PlanFeatures
    
    subscription = await get_subscription(tenant.org_id)
    usage = await get_usage_status(tenant.org_id)
    plan = await get_organization_plan(tenant.org_id)
    
    # Build subscription response
    return SubscriptionResponse(
        id=subscription["id"] if subscription else "default",
        org_id=tenant.org_id,
        plan_id=usage.plan_id,
        plan_name=usage.plan_name,
        status=subscription.get("status", "active") if subscription else "active",
        billing_cycle=subscription.get("billing_cycle", "monthly") if subscription else "monthly",
        current_period_start=subscription.get("current_period_start") if subscription else None,
        current_period_end=subscription.get("current_period_end") if subscription else None,
        trial_end=subscription.get("trial_end") if subscription else None,
        usage=UsageStatus(
            within_limits=usage.within_limits,
            repos_used=usage.repos_used,
            repos_limit=usage.repos_limit,
            repos_remaining=usage.repos_remaining,
            prs_used=usage.prs_used,
            prs_limit=usage.prs_limit,
            prs_remaining=usage.prs_remaining,
            members_used=usage.members_used,
            members_limit=usage.members_limit,
            members_remaining=usage.members_remaining,
            plan_id=usage.plan_id,
            plan_name=usage.plan_name,
        ),
        features=PlanFeatures(
            advisory_mode=plan.feature_advisory_mode,
            enforcement_mode=plan.feature_enforcement_mode,
            dashboard=plan.feature_dashboard,
            audit_logs=plan.feature_audit_logs,
            sso=plan.feature_sso,
            policy_as_code=plan.feature_policy_as_code,
            siem_integration=plan.feature_siem_integration,
            custom_rules=plan.feature_custom_rules,
            priority_support=plan.feature_priority_support,
            dedicated_support=plan.feature_dedicated_support,
        ),
    )


@app.get(
    "/api/subscription/usage",
    tags=["Subscription"],
    summary="Get current usage",
)
async def get_usage_endpoint(
    tenant: TenantContext = Depends(require_tenant_context_flexible),
):
    """
    Get current usage statistics for the organization.
    """
    from .subscriptions import get_usage_status
    from .models import UsageStatus
    
    usage = await get_usage_status(tenant.org_id)
    
    return UsageStatus(
        within_limits=usage.within_limits,
        repos_used=usage.repos_used,
        repos_limit=usage.repos_limit,
        repos_remaining=usage.repos_remaining,
        prs_used=usage.prs_used,
        prs_limit=usage.prs_limit,
        prs_remaining=usage.prs_remaining,
        members_used=usage.members_used,
        members_limit=usage.members_limit,
        members_remaining=usage.members_remaining,
        plan_id=usage.plan_id,
        plan_name=usage.plan_name,
    )


@app.get(
    "/api/subscription/features",
    tags=["Subscription"],
    summary="Get current plan's feature flags",
)
async def get_plan_features_endpoint(
    tenant: TenantContext = Depends(require_tenant_context_flexible),
):
    """
    Get current plan's feature flags for organization.
    """
    from .subscriptions import get_organization_plan
    
    plan = await get_organization_plan(tenant.org_id)
    
    return {
        "plan_id": plan.plan_id,
        "plan_name": plan.plan_name,
        "features": {
            "advisory_mode": plan.feature_advisory_mode,
            "enforcement_mode": plan.feature_enforcement_mode,
            "dashboard": plan.feature_dashboard,
            "audit_logs": plan.feature_audit_logs,
            "sso": plan.feature_sso,
            "policy_as_code": plan.feature_policy_as_code,
            "siem_integration": plan.feature_siem_integration,
            "custom_rules": plan.feature_custom_rules,
            "priority_support": plan.feature_priority_support,
            "dedicated_support": plan.feature_dedicated_support,
        }
    }


@app.post(
    "/api/subscription/upgrade",
    tags=["Subscription"],
    summary="Upgrade subscription plan",
)
async def upgrade_subscription_endpoint(
    request: Request,
    tenant: TenantContext = Depends(require_tenant_context_flexible),
):
    """
    Upgrade the organization's subscription plan.
    
    For paid plans, this will return a checkout URL for payment processing.
    Requires dashboard JWT authentication (no CI/CD API tokens).
    """
    from .subscriptions import update_subscription_plan, get_plan_limits
    from .models import UpgradePlanRequest, UpgradePlanResponse, SubscriptionResponse, UsageStatus, PlanFeatures
    
    # Parse request body
    body = await request.json()
    upgrade_request = UpgradePlanRequest(**body)
    
    # Only admins/owners can upgrade
    if not tenant.is_admin_or_owner():
        raise HTTPException(
            status_code=403,
            detail=f"Only organization admins and owners can upgrade the subscription. Your role: {tenant.user_role}"
        )
    
    # Get target plan
    target_plan = await get_plan_limits(upgrade_request.plan_id)
    
    # For enterprise, return contact sales message
    if upgrade_request.plan_id == "enterprise":
        raise HTTPException(
            status_code=400,
            detail="Please contact sales@aiappsec.com for Enterprise pricing"
        )
    
    # For paid plans, create Stripe checkout session
    if target_plan.price_monthly_cents > 0:
        from .stripe_integration import create_checkout_session, initialize_stripe
        from .config import get_settings
        
        settings = get_settings()
        initialize_stripe(settings)
        
        # Check if Stripe is configured
        if settings.stripe_secret_key:
            try:
                checkout_data = await create_checkout_session(
                    org_id=tenant.org_id,
                    org_name=tenant.org_name or "Organization",
                    plan_id=upgrade_request.plan_id,
                    billing_cycle=upgrade_request.billing_cycle,
                    user_email=tenant.user_email or "",
                    settings=settings,
                )
                
                # Return checkout URL for frontend to redirect
                return {
                    "success": True,
                    "requires_payment": True,
                    "checkout_url": checkout_data["checkout_url"],
                    "session_id": checkout_data["session_id"],
                    "message": "Please complete payment to upgrade your plan"
                }
            except ValueError as e:
                logger.error(f"Stripe checkout error: {e}")
                raise HTTPException(status_code=400, detail=str(e))
        else:
            # Demo mode - direct upgrade without payment
            logger.warning(f"Stripe not configured. Demo mode: Upgrading {tenant.org_id} to {upgrade_request.plan_id}")
    
    # Free plan or demo mode - update directly
    await update_subscription_plan(
        tenant.org_id,
        upgrade_request.plan_id,
        upgrade_request.billing_cycle,
    )
    
    # Get updated subscription info
    from .subscriptions import get_subscription, get_usage_status, get_organization_plan
    
    subscription = await get_subscription(tenant.org_id)
    usage = await get_usage_status(tenant.org_id)
    plan = await get_organization_plan(tenant.org_id)
    
    return UpgradePlanResponse(
        success=True,
        message=f"Successfully upgraded to {target_plan.plan_name} plan!",
        subscription=SubscriptionResponse(
            id=subscription["id"] if subscription else "default",
            org_id=tenant.org_id,
            plan_id=usage.plan_id,
            plan_name=usage.plan_name,
            status="active",
            billing_cycle=upgrade_request.billing_cycle,
            current_period_start=subscription.get("current_period_start") if subscription else None,
            current_period_end=subscription.get("current_period_end") if subscription else None,
            trial_end=None,
            usage=UsageStatus(
                within_limits=usage.within_limits,
                repos_used=usage.repos_used,
                repos_limit=usage.repos_limit,
                repos_remaining=usage.repos_remaining,
                prs_used=usage.prs_used,
                prs_limit=usage.prs_limit,
                prs_remaining=usage.prs_remaining,
                members_used=usage.members_used,
                members_limit=usage.members_limit,
                members_remaining=usage.members_remaining,
                plan_id=usage.plan_id,
                plan_name=usage.plan_name,
            ),
            features=PlanFeatures(
                advisory_mode=plan.feature_advisory_mode,
                enforcement_mode=plan.feature_enforcement_mode,
                dashboard=plan.feature_dashboard,
                audit_logs=plan.feature_audit_logs,
                sso=plan.feature_sso,
                policy_as_code=plan.feature_policy_as_code,
                siem_integration=plan.feature_siem_integration,
                custom_rules=plan.feature_custom_rules,
                priority_support=plan.feature_priority_support,
                dedicated_support=plan.feature_dedicated_support,
            ),
        ),
        checkout_url=None,  # Would be Stripe checkout URL in production
    )


@app.post(
    "/api/webhooks/stripe",
    tags=["Webhooks"],
    summary="Stripe webhook handler",
    include_in_schema=False,  # Hide from public API docs
)
async def stripe_webhook_endpoint(request: Request):
    """
    Handle Stripe webhook events.
    
    This endpoint receives and processes webhook events from Stripe,
    such as successful payments, subscription updates, etc.
    """
    from .stripe_integration import handle_webhook_event, initialize_stripe
    from .config import get_settings
    
    settings = get_settings()
    initialize_stripe(settings)
    
    # Get raw body and signature header
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    
    if not sig_header:
        logger.error("Missing Stripe signature header")
        raise HTTPException(status_code=400, detail="Missing signature header")
    
    try:
        result = await handle_webhook_event(payload, sig_header, settings)
        return {"received": True, "result": result}
    except ValueError as e:
        logger.error(f"Webhook error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected webhook error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


@app.post(
    "/api/webhooks/github",
    tags=["Webhooks"],
    summary="GitHub App webhook handler",
    include_in_schema=False,  # Hide from public API docs
)
async def github_webhook_endpoint(request: Request):
    """
    Handle GitHub App webhook events for automatic PR reviews.
    
    This endpoint receives webhook events from the GitHub App when:
    - Pull requests are opened
    - Pull requests are synchronized (new commits pushed)
    - Pull requests are reopened
    
    The handler automatically:
    1. Verifies the webhook signature
    2. Fetches the PR diff from GitHub
    3. Loads the repository policy
    4. Performs a security review using the LLM
    5. Posts findings as a comment on the PR
    
    Required environment variables:
    - GITHUB_WEBHOOK_SECRET: Secret for verifying webhooks
    - GITHUB_APP_ID: GitHub App ID
    - GITHUB_APP_PRIVATE_KEY: Private key for GitHub App authentication
    """
    from .github_webhook import (
        verify_webhook_signature,
        process_pull_request_webhook,
        record_webhook_event
    )
    from .config import get_settings
    
    settings = get_settings()
    
    # Verify webhook secret is configured
    if not settings.github_app_webhook_secret:
        logger.error("GitHub webhook secret not configured")
        raise HTTPException(status_code=500, detail="Webhook handler not configured")
    
    # Get raw body for signature verification
    payload_bytes = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    event_type = request.headers.get("X-GitHub-Event")
    
    if not signature:
        logger.error("Missing GitHub signature header")
        raise HTTPException(status_code=400, detail="Missing signature header")
    
    # Verify signature
    if not verify_webhook_signature(payload_bytes, signature, settings.github_app_webhook_secret):
        logger.error("Invalid GitHub webhook signature")
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Parse JSON payload
    try:
        import json
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    # Handle different event types
    if event_type == "pull_request":
        return await _handle_pull_request_webhook(payload, settings, record_webhook_event)
    elif event_type == "installation":
        return await _handle_installation_webhook(payload)
    elif event_type == "issue_comment":
        return await _handle_issue_comment_webhook(payload, settings)
    elif event_type == "pull_request_review_comment":
        return await _handle_pull_request_review_comment_webhook(payload, settings)
    elif event_type == "pull_request_review_thread":
        return await _handle_pull_request_review_thread(payload, settings)
    else:
        logger.info(f"Ignoring event type: {event_type}")
        return {"received": True, "status": "ignored", "reason": f"Event type '{event_type}' not processed"}


@app.post(
    "/api/webhooks/gitlab",
    tags=["Webhooks"],
    summary="GitLab webhook handler",
    include_in_schema=False,
)
async def gitlab_webhook_endpoint(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    """Handle GitLab merge request webhooks for automatic reviews."""
    from .gitlab_webhook import verify_webhook_token, process_merge_request_webhook, process_note_webhook

    if not settings.gitlab_app_webhook_secret:
        logger.error("GitLab webhook secret not configured")
        raise HTTPException(status_code=500, detail="Webhook handler not configured")

    payload_bytes = await request.body()
    token = request.headers.get("X-Gitlab-Token")

    if not token:
        logger.error("Missing GitLab token header")
        raise HTTPException(status_code=400, detail="Missing webhook token")

    if not verify_webhook_token(payload_bytes, token, settings.gitlab_app_webhook_secret):
        logger.error("Invalid GitLab webhook token")
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    object_kind = payload.get("object_kind")
    if object_kind == "note":
        try:
            result = await process_note_webhook(payload, settings)
            return {"received": True, **result}
        except ValueError as e:
            logger.error(f"GitLab note webhook processing error: {e}")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Unexpected GitLab note webhook error: {e}")
            raise HTTPException(status_code=500, detail="Webhook processing failed")

    if object_kind != "merge_request":
        return {
            "received": True,
            "status": "ignored",
            "reason": f"Object kind '{object_kind}' not processed",
        }

    try:
        result = await process_merge_request_webhook(payload, settings)
        return {"received": True, **result}
    except ValueError as e:
        logger.error(f"GitLab webhook processing error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected GitLab webhook error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


async def _handle_pull_request_webhook(payload, settings, record_webhook_event):
    """Handle pull request webhook events."""
    from .github_webhook import process_pull_request_webhook
    
    # Only process specific actions
    action = payload.get("action")
    if action not in ["opened", "synchronize", "reopened"]:
        logger.info(f"Ignoring PR action: {action}")
        return {"received": True, "status": "ignored", "reason": f"Action '{action}' not processed"}
    
    # Check for draft PRs - skip them
    pr_data = payload.get("pull_request", {})
    if pr_data.get("draft", False):
        logger.info("Skipping draft PR")
        return {"received": True, "status": "ignored", "reason": "Draft PR"}
    
    try:
        # Process the webhook
        result = await process_pull_request_webhook(payload, settings)
        return {"received": True, **result}
    except ValueError as e:
        logger.error(f"Webhook processing error: {e}")
        # Record error if possible
        try:
            installation_id = payload.get("installation", {}).get("id")
            repo_name = payload.get("repository", {}).get("full_name")
            pr_number = payload.get("pull_request", {}).get("number")
            if installation_id and repo_name and pr_number:
                await record_webhook_event(
                    event_type="pull_request",
                    action=action,
                    repo_name=repo_name,
                    pr_number=pr_number,
                    org_id=None,
                    installation_id=installation_id,
                    status="error",
                    error_message=str(e)
                )
        except Exception:
            pass  # Don't fail if recording fails
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected webhook error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


async def _handle_installation_webhook(payload):
    """Handle installation webhook events."""
    from .github_webhook import (
        process_installation_created,
        process_installation_deleted,
        process_installation_suspend
    )
    
    action = payload.get("action")
    
    try:
        if action == "created":
            result = await process_installation_created(payload)
        elif action == "deleted":
            result = await process_installation_deleted(payload)
        elif action == "suspend":
            result = await process_installation_suspend(payload)
        else:
            logger.info(f"Ignoring installation action: {action}")
            return {"received": True, "status": "ignored", "reason": f"Action '{action}' not processed"}
        
        return {"received": True, **result}
        
    except ValueError as e:
        logger.error(f"Installation webhook error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected installation webhook error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")


async def _handle_issue_comment_webhook(payload: dict, settings):
    """
    Handle issue_comment webhook events for /review and /ignore commands.
    
    Commands:
    - /review - Re-trigger analysis for the PR
    - /ignore [fingerprint] - Dismiss a finding (dismisses by fingerprint if provided, otherwise all)
    """
    from .github_webhook import (
        process_pull_request_webhook,
        resolve_org_from_installation,
        get_installation_token,
        record_webhook_event,
        post_pr_comment
    )
    
    action = payload.get("action")
    
    # Only process created comments (not edited/deleted)
    if action != "created":
        logger.info(f"Ignoring issue_comment action: {action}")
        return {"received": True, "status": "ignored", "reason": f"Action '{action}' not processed"}
    
    # Get comment details
    comment = payload.get("comment", {})
    body = comment.get("body", "")
    author = comment.get("user", {}).get("login")
    
    # Only process commands (comments starting with /)
    if not body.strip().startswith("/"):
        logger.info(f"Ignoring non-command comment")
        return {"received": True, "status": "ignored", "reason": "Not a command"}
    
    # Get issue/PR details
    issue = payload.get("issue", {})
    pr_number = issue.get("number")
    
    # Check if this is a PR comment (not a regular issue)
    pull_request = issue.get("pull_request", {})
    if not pull_request:
        logger.info(f"Ignoring comment on non-PR issue")
        return {"received": True, "status": "ignored", "reason": "Not a PR"}
    
    # Get repository info
    repository = payload.get("repository", {})
    repo_full_name = repository.get("full_name")
    installation = payload.get("installation", {})
    installation_id = installation.get("id")
    
    if not all([pr_number, repo_full_name, installation_id]):
        logger.error(f"Missing required fields in issue_comment payload")
        return {"received": True, "status": "error", "reason": "Missing required fields"}
    
    # Resolve org from installation
    org_id = await resolve_org_from_installation(installation_id)
    if not org_id:
        logger.warning(f"Could not resolve org for installation {installation_id}")
        return {"received": True, "status": "error", "reason": "Organization not found"}
    
    # Parse command
    command_parts = body.strip().split()
    command = command_parts[0].lower()
    args = command_parts[1:] if len(command_parts) > 1 else []
    
    logger.info(f"Processing command: {command} from {author} on PR #{pr_number}")
    
    try:
        if command == "/review":
            # Re-trigger analysis
            logger.info(f"Re-triggering review for PR #{pr_number}")
            
            # Record the command in webhook events
            await record_webhook_event(
                event_type="issue_comment",
                action="review_command",
                repo_name=repo_full_name,
                pr_number=pr_number,
                org_id=org_id,
                installation_id=installation_id,
                status="processing"
            )
            
            # Process the webhook as if it was a new PR event
            # We need to construct a minimal payload
            pr_payload = {
                "action": "synchronize",  # Treat as update
                "repository": repository,
                "pull_request": {
                    "number": pr_number,
                    "title": issue.get("title"),
                    "user": {"login": author}
                },
                "installation": installation
            }
            
            # Process the PR webhook
            result = await process_pull_request_webhook(pr_payload, settings)
            
            # Acknowledge the command
            await post_pr_comment(
                owner=repo_full_name.split("/")[0],
                repo=repo_full_name.split("/")[1],
                pr_number=pr_number,
                body=f"@${author} Re-triggered security analysis as requested via /review command.",
                installation_id=installation_id,
                settings=settings
            )
            
            return {"received": True, "status": "success", "command": "review", "result": result}
        
        elif command == "/ignore":
            # Dismiss a finding
            fingerprint = args[0] if args else None
            if fingerprint:
                import re
                normalized = fingerprint.strip().strip("`")
                match = re.search(r"([a-f0-9]{8,64})", normalized, re.IGNORECASE)
                fingerprint = match.group(1) if match else normalized
            
            if fingerprint:
                # Dismiss specific finding by fingerprint
                logger.info(f"Ignoring finding with fingerprint: {fingerprint}")
                
                # Store the suppression in the database
                from .database import create_suppression_rule
                
                # Create suppression rule for this fingerprint
                try:
                    await create_suppression_rule(
                        org_id=org_id,
                        fingerprint=fingerprint,
                        reason=f"Ignored by {author} via /ignore command in {repo_full_name}",
                        created_by=None
                    )
                    
                    await post_pr_comment(
                        owner=repo_full_name.split("/")[0],
                        repo=repo_full_name.split("/")[1],
                        pr_number=pr_number,
                        body=f"@${author} The finding with fingerprint `{fingerprint}` has been ignored. Future reviews will suppress this finding.",
                        installation_id=installation_id,
                        settings=settings
                    )
                except Exception as e:
                    logger.error(f"Failed to create suppression: {e}")
                    await post_pr_comment(
                        owner=repo_full_name.split("/")[0],
                        repo=repo_full_name.split("/")[1],
                        pr_number=pr_number,
                        body=f"@${author} Failed to ignore the finding: {str(e)}",
                        installation_id=installation_id,
                        settings=settings
                    )
                
                return {"received": True, "status": "success", "command": "ignore", "fingerprint": fingerprint}
            else:
                # No fingerprint provided - show help
                await post_pr_comment(
                    owner=repo_full_name.split("/")[0],
                    repo=repo_full_name.split("/")[1],
                    pr_number=pr_number,
                    body=f"""@${author} To dismiss a finding, provide its fingerprint.

Usage:
- `/ignore <fingerprint>` - Dismiss a specific finding

You can find the fingerprint in the finding's comment. Example: `/ignore a1b2c3d4e5f6`""",
                    installation_id=installation_id,
                    settings=settings
                )
                
                return {"received": True, "status": "success", "command": "ignore", "error": "No fingerprint provided"}
        
        elif command == "/help":
            # Show help
            await post_pr_comment(
                owner=repo_full_name.split("/")[0],
                repo=repo_full_name.split("/")[1],
                pr_number=pr_number,
                body=f"""@${author} **AI AppSec PR Reviewer Commands:**

- `/review` - Re-run the security analysis
- `/ignore <fingerprint>` - Dismiss a finding (provide fingerprint from finding comment)
- `/help` - Show this help message

**Resolve Findings:**
- Click "Resolve conversation" on a finding to mark it as resolved
- Click "Unresolve" to reopen a finding

**Example:** `/ignore a1b2c3d4e5f6`""",
                installation_id=installation_id,
                settings=settings
            )
            
            return {"received": True, "status": "success", "command": "help"}
        
        else:
            # Unknown command
            logger.info(f"Unknown command: {command}")
            return {"received": True, "status": "ignored", "reason": f"Unknown command: {command}"}
    
    except Exception as e:
        logger.error(f"Error processing issue_comment command: {e}")
        await post_pr_comment(
            owner=repo_full_name.split("/")[0],
            repo=repo_full_name.split("/")[1],
            pr_number=pr_number,
            body=f"@${author} Error processing command: {str(e)}",
            installation_id=installation_id,
            settings=settings
        )
        return {"received": True, "status": "error", "reason": str(e)}


async def _handle_pull_request_review_comment_webhook(payload: dict, settings):
    """
    Handle pull_request_review_comment webhook events for slash commands.

    GitHub sends comments posted on a PR diff thread as pull_request_review_comment,
    not issue_comment. Adapt the payload shape and reuse command handling.
    """
    action = payload.get("action")
    if action != "created":
        logger.info(f"Ignoring pull_request_review_comment action: {action}")
        return {"received": True, "status": "ignored", "reason": f"Action '{action}' not processed"}

    pr = payload.get("pull_request", {}) or {}
    pr_number = pr.get("number")
    if not pr_number:
        logger.error("Missing pull_request.number in pull_request_review_comment payload")
        return {"received": True, "status": "error", "reason": "Missing PR number"}

    # Re-shape payload into issue_comment format to reuse existing command logic.
    adapted_payload = {
        "action": action,
        "comment": payload.get("comment", {}),
        "issue": {
            "number": pr_number,
            "title": pr.get("title"),
            "pull_request": {"url": pr.get("url") or "review-comment"},
        },
        "repository": payload.get("repository", {}),
        "installation": payload.get("installation", {}),
    }

    return await _handle_issue_comment_webhook(adapted_payload, settings)


async def _handle_pull_request_review_thread(payload: dict, settings):
    """
    Handle pull_request_review_thread webhook events.
    
    This event is triggered when:
    - A conversation thread is resolved
    - A conversation thread is unresolved
    
    We use this to mark findings as resolved/unresolved in the database.
    """
    from .github_webhook import (
        resolve_org_from_installation,
        record_webhook_event,
        get_installation_token,
        get_settings
    )
    from .database import get_supabase_client
    
    action = payload.get("action")
    
    # Debug: Log the full payload structure
    logger.info(f"review_thread payload keys: {payload.keys()}")
    logger.info(f"review_thread action: {action}")
    
    # Get thread from different possible locations
    thread = payload.get("thread", {})
    if not thread:
        # Try different payload structures
        thread = payload.get("pull_request_review_thread", {})
    
    logger.info(f"Thread keys: {thread.keys() if thread else 'None'}")
    
    # Only process resolve/unresolve actions
    if action not in ["resolved", "unresolved"]:
        logger.info(f"Ignoring review_thread action: {action}")
        return {"received": True, "status": "ignored", "reason": f"Action '{action}' not processed"}
    
    # Get repository and installation info
    repository = payload.get("repository", {})
    repo_full_name = repository.get("full_name")
    installation = payload.get("installation", {})
    installation_id = installation.get("id")
    
    # Get PR number from different possible locations
    pr_number = None
    pr = payload.get("pull_request", {})
    if pr:
        pr_number = pr.get("number")
    # Try to get from thread
    if not pr_number and thread:
        pr_number = thread.get("pull_request_thread", {}).get("number")
    
    logger.info(f"Repo: {repo_full_name}, Installation: {installation_id}, PR: {pr_number}")
    
    # Get comments from thread
    comments = thread.get("comments", [])
    logger.info(f"Thread has {len(comments)} comments")
    
    # Get thread details - file_path should be in thread or first comment
    file_path = thread.get("path")  # File being commented on
    line = thread.get("line")  # Line number
    
    # If not in thread, try to get from first comment
    if not file_path and comments:
        first_comment = comments[0] if comments else {}
        file_path = first_comment.get("path")
        line = first_comment.get("line")
    
    logger.info(f"Thread file_path: {file_path}, line: {line}")
    
    # Get comment body
    first_comment = {}
    comment_body = ""
    
    if comments:
        first_comment = comments[0]
        comment_body = first_comment.get("body", "")
    else:
        # Check if there's a comment in the payload directly
        comment = payload.get("comment", {})
        if comment:
            comment_body = comment.get("body", "")
            logger.info(f"Found comment in payload: {comment_body[:500] if comment_body else 'empty'}")
    
    logger.info(f"Comment body FULL: {comment_body}")
    
    # Check if this is our bot's comment (contains fingerprint)
    # Supported formats:
    # - `a1b2c3d4e5f6`
    # - /ignore a1b2c3d4e5f6
    # - `/ignore a1b2c3d4e5f6`
    import re
    fingerprint_match = (
        re.search(r'/ignore\s+`?([a-f0-9]{8,64})`?', comment_body, re.IGNORECASE)
        or re.search(r'`([a-f0-9]{8,64})`', comment_body, re.IGNORECASE)
    )
    
    logger.info(f"Fingerprint regex match: {fingerprint_match}")
    
    # If no fingerprint in comment, we can still try to locate the finding
    # by (latest review, file_path, line) as a safe fallback.
    if not fingerprint_match and file_path:
        logger.info(
            f"No fingerprint found in comment, will fallback to latest review/thread location: "
            f"{file_path}:{line}"
        )
        fingerprint = None
    elif fingerprint_match:
        fingerprint = fingerprint_match.group(1)
    else:
        logger.info(f"Not our bot's comment - no fingerprint, no file_path. Comment: {comment_body[:300]}")
        return {"received": True, "status": "ignored", "reason": "Not an AI AppSec finding"}
    
    if not all([installation_id, repo_full_name]):
        logger.error("Missing required fields in review_thread payload")
        return {"received": True, "status": "error", "reason": "Missing required fields"}
    
    # Resolve org from installation
    org_id = await resolve_org_from_installation(installation_id)
    if not org_id:
        logger.warning(f"Could not resolve org for installation {installation_id}")
        return {"received": True, "status": "error", "reason": "Organization not found"}
    
    logger.info(f"Processing review_thread {action} for fingerprint {fingerprint or 'N/A'} in {repo_full_name}")
    
    try:
        client = get_supabase_client()
        
        # Determine if we should use direct fingerprint matching.
        use_fingerprint = bool(
            isinstance(fingerprint, str)
            and re.fullmatch(r"[a-f0-9]{8,64}", fingerprint, re.IGNORECASE)
        )

        # Fallback target ids when fingerprint is unavailable in thread comments.
        target_finding_ids = []
        if not use_fingerprint and file_path and pr_number:
            try:
                review_result = (
                    client.table("reviews")
                    .select("id")
                    .eq("org_id", org_id)
                    .eq("repo_name", repo_full_name)
                    .eq("pr_number", pr_number)
                    .order("created_at", desc=True)
                    .limit(1)
                    .execute()
                )

                latest_review_id = None
                if review_result and review_result.data:
                    latest_review_id = review_result.data[0].get("id")

                if latest_review_id:
                    findings_result = (
                        client.table("findings")
                        .select("id,fingerprint,line_start,line_end,line_range,status")
                        .eq("org_id", org_id)
                        .eq("review_id", latest_review_id)
                        .eq("file_path", file_path)
                        .execute()
                    )

                    candidates = findings_result.data if findings_result and findings_result.data else []
                    logger.info(
                        f"Fallback candidate findings for {file_path} in latest review "
                        f"{latest_review_id}: {len(candidates)}"
                    )

                    line_num = None
                    try:
                        line_num = int(line) if line is not None else None
                    except (TypeError, ValueError):
                        line_num = None

                    if line_num is not None and candidates:
                        # Prefer exact line range matches first.
                        exact_matches = []
                        for finding in candidates:
                            start = finding.get("line_start")
                            end = finding.get("line_end")
                            if isinstance(start, int):
                                end_val = end if isinstance(end, int) else start
                                if start <= line_num <= end_val:
                                    exact_matches.append(finding)

                        if exact_matches:
                            target_finding_ids = [f["id"] for f in exact_matches if f.get("id")]
                        else:
                            # If no exact range match, pick the closest line_start.
                            by_distance = [
                                (abs((f.get("line_start") or line_num) - line_num), f)
                                for f in candidates
                                if f.get("id")
                            ]
                            by_distance.sort(key=lambda item: item[0])
                            if by_distance:
                                target_finding_ids = [by_distance[0][1]["id"]]
                    elif len(candidates) == 1:
                        only_id = candidates[0].get("id")
                        if only_id:
                            target_finding_ids = [only_id]

                    if target_finding_ids:
                        logger.info(
                            f"Using fallback target finding id(s): {target_finding_ids}"
                        )
                    else:
                        logger.warning(
                            f"Could not uniquely map thread to finding for {file_path}:{line}; "
                            "skipping broad file-level update"
                        )
                else:
                    logger.warning(
                        f"No review found for org={org_id}, repo={repo_full_name}, pr={pr_number}; "
                        "cannot use fallback matching"
                    )
            except Exception as fallback_error:
                logger.warning(f"Fallback matching failed: {fallback_error}")
        
        if action == "resolved":
            # Build update data
            update_data = {
                "status": "resolved",
                "resolved_reason": "resolved_by_user",
                "resolved_at": datetime.utcnow().isoformat()
            }
            
            # Update by fingerprint or narrowed fallback target id(s)
            if use_fingerprint:
                result = client.table("findings").update(update_data).eq("org_id", org_id).eq("fingerprint", fingerprint).execute()
                logger.info(f"Marked finding {fingerprint} as resolved")
            elif target_finding_ids:
                result = client.table("findings").update(update_data).eq("org_id", org_id).in_("id", target_finding_ids).execute()
                logger.info(f"Marked {len(target_finding_ids)} finding(s) as resolved via fallback")
            else:
                logger.warning("No fingerprint or fallback target ids to resolve")
                return {"received": True, "status": "error", "reason": "No matching criteria"}
            
            # Record the event
            await record_webhook_event(
                event_type="pull_request_review_thread",
                action="resolved",
                repo_name=repo_full_name,
                pr_number=pr_number,
                org_id=org_id,
                installation_id=installation_id,
                status="completed"
            )
            
            return {"received": True, "status": "success", "action": "resolved", "fingerprint": fingerprint}
        
        elif action == "unresolved":
            # Build update data
            update_data = {
                "status": "open",
                "resolved_reason": None,
                "resolved_at": None
            }
            
            # Update by fingerprint or narrowed fallback target id(s)
            if use_fingerprint:
                result = client.table("findings").update(update_data).eq("org_id", org_id).eq("fingerprint", fingerprint).execute()
                logger.info(f"Marked finding {fingerprint} as open (unresolved)")
            elif target_finding_ids:
                result = client.table("findings").update(update_data).eq("org_id", org_id).in_("id", target_finding_ids).execute()
                logger.info(f"Marked {len(target_finding_ids)} finding(s) as open via fallback")
            else:
                logger.warning("No fingerprint or fallback target ids to unresolve")
                return {"received": True, "status": "error", "reason": "No matching criteria"}
            
            # Record the event
            await record_webhook_event(
                event_type="pull_request_review_thread",
                action="unresolved",
                repo_name=repo_full_name,
                pr_number=pr_number,
                org_id=org_id,
                installation_id=installation_id,
                status="completed"
            )
            
            return {"received": True, "status": "success", "action": "unresolved", "fingerprint": fingerprint}
    
    except Exception as e:
        logger.error(f"Error processing review_thread: {e}")
        return {"received": True, "status": "error", "reason": str(e)}


@app.post(
    "/api/subscription/cancel",
    tags=["Subscription"],
    summary="Cancel subscription",
)
async def cancel_subscription_endpoint(
    tenant: TenantContext = Depends(require_tenant_context_flexible),
):
    """
    Cancel the organization's subscription.
    
    The subscription will remain active until the end of the current billing period.
    """
    from .stripe_integration import cancel_subscription, initialize_stripe
    from .config import get_settings
    
    # Only admins/owners can cancel
    if not tenant.is_admin_or_owner():
        raise HTTPException(
            status_code=403,
            detail=f"Only organization admins and owners can cancel the subscription. Your role: {tenant.user_role}"
        )
    
    settings = get_settings()
    initialize_stripe(settings)
    
    try:
        result = await cancel_subscription(tenant.org_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get(
    "/api/subscription/portal",
    tags=["Subscription"],
    summary="Get billing portal URL",
)
async def get_billing_portal_endpoint(
    request: Request,
    tenant: TenantContext = Depends(require_tenant_context_flexible),
):
    """
    Get a URL to the Stripe Customer Portal for managing billing.
    
    Users can update payment methods, view invoices, and manage their subscription.
    """
    from .stripe_integration import get_customer_portal_url, initialize_stripe
    from .config import get_settings
    
    settings = get_settings()
    initialize_stripe(settings)
    
    # Determine return URL
    return_url = request.headers.get("Referer") or f"{settings.cors_origins_list[0]}/dashboard/settings"
    
    try:
        portal_url = await get_customer_portal_url(tenant.org_id, return_url)
        return {"portal_url": portal_url}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unexpected errors.
    
    Note: We only log the error type, not the full exception
    to avoid accidentally logging sensitive data like diffs.
    """
    # Log only error type and message, not full traceback with request data
    logger.error(f"Unexpected error: {type(exc).__name__}: {str(exc)[:100]}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An unexpected error occurred",
            "error_code": "INTERNAL_ERROR"
        }
    )


# Entry point for running with uvicorn directly
if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level=settings.log_level.lower()
    )

