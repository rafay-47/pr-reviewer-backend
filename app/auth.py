"""
Authentication utilities for the AI AppSec PR Reviewer.

Provides multiple authentication methods:
1. Supabase JWT authentication (for user login)
2. API token authentication (for programmatic access)
"""

import logging
import asyncio
import time
from dataclasses import dataclass
from typing import Optional
from datetime import datetime
import httpx

from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt import PyJWTError
from jwt.algorithms import RSAAlgorithm, ECAlgorithm

from .config import Settings, get_settings
from .database import get_organization_by_id, get_user_organizations
from .audit_log import get_audit_logger, AuditEventType
from .security import get_request_id, get_client_identifier, get_user_agent
from .security import add_request_timing

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

# Cache for JWKS keys (in production, use Redis or similar)
_jwks_cache = {}
_jwks_fetch_locks: dict[str, asyncio.Lock] = {}
JWKS_CACHE_TTL_SECONDS = 3600

# Short-lived org membership cache to reduce repeated org_members lookups
# across requests for the same user/org in hot API paths.
_org_membership_cache: dict[str, tuple[dict, float]] = {}
ORG_MEMBERSHIP_CACHE_TTL_SECONDS = 30
ORG_MEMBERSHIP_CACHE_MAX_ENTRIES = 2000


def _org_membership_cache_key(user_id: str, org_id: Optional[str]) -> str:
    return f"{user_id}:{org_id or '__implicit__'}"


def _get_cached_org_membership(cache_key: str) -> Optional[dict]:
    entry = _org_membership_cache.get(cache_key)
    if not entry:
        return None

    membership_data, expires_at = entry
    if expires_at < time.monotonic():
        _org_membership_cache.pop(cache_key, None)
        return None

    return membership_data


def _set_cached_org_membership(cache_key: str, membership_data: dict) -> None:
    now = time.monotonic()
    expires_at = now + ORG_MEMBERSHIP_CACHE_TTL_SECONDS

    # Opportunistically prune expired entries before adding a new one.
    if len(_org_membership_cache) >= ORG_MEMBERSHIP_CACHE_MAX_ENTRIES:
        expired_keys = [
            key for key, (_, cache_expires_at) in _org_membership_cache.items()
            if cache_expires_at < now
        ]
        for key in expired_keys:
            _org_membership_cache.pop(key, None)

        # If still full, evict oldest inserted entry.
        if len(_org_membership_cache) >= ORG_MEMBERSHIP_CACHE_MAX_ENTRIES:
            oldest_key = next(iter(_org_membership_cache), None)
            if oldest_key:
                _org_membership_cache.pop(oldest_key, None)

    _org_membership_cache[cache_key] = (membership_data, expires_at)


async def fetch_jwks(supabase_url: str) -> dict:
    """
    Fetch JSON Web Key Set (JWKS) from Supabase.
    
    Args:
        supabase_url: The Supabase project URL
        
    Returns:
        JWKS dictionary
    """
    cache_key = f"{supabase_url}_jwks"
    fetch_start = time.perf_counter()

    # Check cache first (short-circuit hot path)
    if cache_key in _jwks_cache:
        cached_data, cached_time = _jwks_cache[cache_key]
        cache_age_seconds = (datetime.now() - cached_time).total_seconds()
        if cache_age_seconds < JWKS_CACHE_TTL_SECONDS:
            elapsed_ms = (time.perf_counter() - fetch_start) * 1000
            logger.info(
                f"[timing][auth/fetch_jwks] cache_hit=true age_s={cache_age_seconds:.2f} total_ms={elapsed_ms:.2f}"
            )
            add_request_timing("auth.fetch_jwks", elapsed_ms)
            return cached_data

    # Deduplicate concurrent misses for the same Supabase URL
    lock = _jwks_fetch_locks.setdefault(cache_key, asyncio.Lock())
    async with lock:
        # Re-check cache after waiting for lock (another request may have fetched it)
        if cache_key in _jwks_cache:
            cached_data, cached_time = _jwks_cache[cache_key]
            cache_age_seconds = (datetime.now() - cached_time).total_seconds()
            if cache_age_seconds < JWKS_CACHE_TTL_SECONDS:
                elapsed_ms = (time.perf_counter() - fetch_start) * 1000
                logger.info(
                    f"[timing][auth/fetch_jwks] cache_hit_after_lock=true age_s={cache_age_seconds:.2f} total_ms={elapsed_ms:.2f}"
                )
                add_request_timing("auth.fetch_jwks", elapsed_ms)
                return cached_data
    
        # Try multiple JWKS endpoints (Supabase may use different paths)
        jwks_urls = [
            f"{supabase_url}/auth/v1/.well-known/jwks.json",  # Standard path
            f"{supabase_url}/auth/v1/jwks",  # Alternative path
        ]

        last_error = None
        async with httpx.AsyncClient() as client:
            for jwks_url in jwks_urls:
                endpoint_start = time.perf_counter()
                try:
                    # Don't require authentication for JWKS endpoint (it should be public)
                    response = await client.get(jwks_url, timeout=5.0, follow_redirects=True)
                    endpoint_ms = (time.perf_counter() - endpoint_start) * 1000
                    if response.status_code == 200:
                        jwks = response.json()
                        # Cache the result
                        _jwks_cache[cache_key] = (jwks, datetime.now())
                        elapsed_ms = (time.perf_counter() - fetch_start) * 1000
                        logger.info(
                            f"[timing][auth/fetch_jwks] cache_hit=false endpoint_ms={endpoint_ms:.2f} total_ms={elapsed_ms:.2f} source={jwks_url}"
                        )
                        add_request_timing("auth.fetch_jwks", elapsed_ms)
                        logger.info(f"Successfully fetched JWKS from {jwks_url}")
                        return jwks
                    else:
                        logger.warning(f"JWKS endpoint returned {response.status_code}: {jwks_url}")
                        last_error = f"HTTP {response.status_code}"
                except Exception as e:
                    logger.warning(f"Failed to fetch JWKS from {jwks_url}: {e}")
                    last_error = str(e)
    
    # If all attempts failed
    elapsed_ms = (time.perf_counter() - fetch_start) * 1000
    logger.error(f"All JWKS endpoints failed. Last error: {last_error}")
    logger.info(f"[timing][auth/fetch_jwks] failed=true total_ms={elapsed_ms:.2f}")
    add_request_timing("auth.fetch_jwks", elapsed_ms)
    raise HTTPException(
        status_code=500,
        detail="Failed to fetch JWT public keys from Supabase"
    )


def get_signing_key_from_jwks(token: str, jwks: dict):
    """
    Get the signing key from JWKS for the given JWT token.
    
    Args:
        token: JWT token
        jwks: JSON Web Key Set
        
    Returns:
        Public key object for verification (RSA or EC key)
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        alg = unverified_header.get("alg")
        
        logger.info(f"Looking for key with kid={kid}, alg={alg}")
        
        if not kid:
            logger.error("JWT token missing key ID (kid)")
            raise HTTPException(
                status_code=401,
                detail="JWT missing key ID (kid)"
            )
        
        # Find matching key in JWKS
        keys = jwks.get("keys", [])
        logger.info(f"JWKS contains {len(keys)} keys")
        
        for key_data in keys:
            if key_data.get("kid") == kid:
                logger.info(f"Found matching key: {key_data.get('kty')} {key_data.get('alg', 'unknown')}")
                
                # Convert JWK to cryptography key object
                if alg == "RS256":
                    import json
                    key_obj = RSAAlgorithm.from_jwk(json.dumps(key_data))
                    logger.info("Successfully created RSA public key")
                    return key_obj
                elif alg == "ES256":
                    import json
                    key_obj = ECAlgorithm.from_jwk(json.dumps(key_data))
                    logger.info("Successfully created EC public key")
                    return key_obj
                else:
                    logger.error(f"Unsupported algorithm in JWKS: {alg}")
                    raise HTTPException(
                        status_code=401,
                        detail=f"Unsupported algorithm: {alg}"
                    )
        
        logger.error(f"No matching key found for kid={kid} in JWKS")
        raise HTTPException(
            status_code=401,
            detail=f"No matching key found for kid: {kid}"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get signing key: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=401,
            detail=f"Failed to extract signing key: {str(e)}"
        )


@dataclass
class UserContext:
    """Authenticated user context from Supabase JWT."""
    user_id: str
    email: Optional[str] = None
    org_id: Optional[str] = None
    org_name: Optional[str] = None
    org_slug: Optional[str] = None
    role: Optional[str] = None  # Role in the organization


def verify_supabase_jwt(token: str, settings: Settings) -> dict:
    """
    Verify and decode a Supabase JWT token.
    
    Args:
        token: The JWT token to verify
        settings: Application settings
        
    Returns:
        Decoded token payload
        
    Raises:
        HTTPException: If token is invalid
    """
    try:
        # Basic JWT format check (should have 3 dot-separated parts)
        parts = token.split('.') if token else []
        if len(parts) != 3:
            logger.warning(f"Token is not a valid JWT format: expected 3 parts, got {len(parts)}")
            raise HTTPException(
                status_code=401,
                detail="Invalid token format. Expected a valid JWT."
            )
        
        # Decode without verification to check the algorithm
        unverified_header = jwt.get_unverified_header(token)
        algorithm = unverified_header.get("alg", "HS256")
        
        logger.info(f"JWT algorithm detected: {algorithm}")
        leeway_seconds = settings.jwt_clock_skew_seconds
        
        # HS256 - Symmetric key (JWT secret)
        if algorithm == "HS256":
            jwt_secret = settings.supabase_jwt_secret
            
            if not jwt_secret:
                logger.error("SUPABASE_JWT_SECRET not configured for HS256")
                raise HTTPException(
                    status_code=500,
                    detail="JWT authentication not configured"
                )
            
            payload = jwt.decode(
                token,
                jwt_secret,
                algorithms=["HS256"],
                audience="authenticated",
                options={"verify_aud": True},
                leeway=leeway_seconds,
            )
        # RS256/ES256 - Asymmetric keys (JWKS not supported in sync context)
        elif algorithm in ["RS256", "ES256"]:
            logger.error(f"Algorithm {algorithm} requires async verification - use verify_supabase_jwt_async()")
            raise HTTPException(
                status_code=500,
                detail="JWT verification requires async context"
            )
        else:
            logger.error(f"Unsupported JWT algorithm: {algorithm}")
            raise HTTPException(
                status_code=401,
                detail=f"Unsupported JWT algorithm: {algorithm}"
            )
        
        logger.info(f"JWT verified successfully for user: {payload.get('sub', 'unknown')}")
        return payload
    except jwt.ExpiredSignatureError as e:
        logger.warning(f"JWT expired: {e}")
        raise HTTPException(
            status_code=401,
            detail="Authentication token has expired. Please log in again."
        )
    except jwt.ImmatureSignatureError as e:
        logger.warning(
            "JWT not yet valid (iat/nbf): %s. Allowed clock skew=%ss",
            e,
            settings.jwt_clock_skew_seconds,
        )
        raise HTTPException(
            status_code=401,
            detail="Authentication token is not yet valid (clock skew detected). Please retry in a moment.",
        )
    except PyJWTError as e:
        logger.warning(f"JWT verification failed: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token"
        )


async def verify_supabase_jwt_async(token: str, settings: Settings) -> dict:
    """
    Verify and decode a Supabase JWT token (async version).
    
    Supports HS256 (symmetric) and ES256/RS256 (asymmetric) algorithms.
    For asymmetric algorithms, fetches public keys from JWKS endpoint.
    
    Args:
        token: The JWT token to verify
        settings: Application settings
        
    Returns:
        Decoded token payload
        
    Raises:
        HTTPException: If token is invalid
    """
    verify_start = time.perf_counter()
    try:
        # Basic JWT format check (should have 3 dot-separated parts)
        parts = token.split('.') if token else []
        if len(parts) != 3:
            logger.warning(f"Token is not a valid JWT format: expected 3 parts, got {len(parts)}")
            raise HTTPException(
                status_code=401,
                detail="Invalid token format. Expected a valid JWT."
            )
        
        # Decode without verification to check the algorithm
        unverified_header = jwt.get_unverified_header(token)
        algorithm = unverified_header.get("alg", "HS256")
        
        logger.info(f"JWT algorithm detected: {algorithm}")
        leeway_seconds = settings.jwt_clock_skew_seconds
        
        # HS256 - Symmetric key (simple secret)
        if algorithm == "HS256":
            jwt_secret = settings.supabase_jwt_secret
            
            if not jwt_secret:
                logger.error("SUPABASE_JWT_SECRET not configured for HS256")
                raise HTTPException(
                    status_code=500,
                    detail="JWT authentication not configured. Please set SUPABASE_JWT_SECRET."
                )
            
            payload = jwt.decode(
                token,
                jwt_secret,
                algorithms=["HS256"],
                audience="authenticated",
                options={"verify_aud": True},
                leeway=leeway_seconds,
            )
            logger.info(f"JWT verified successfully with HS256")
            
        # RS256/ES256 - Asymmetric keys (requires public key from JWKS)
        elif algorithm in ["RS256", "ES256"]:
            if not settings.supabase_url:
                logger.error("SUPABASE_URL not configured for RS256/ES256")
                raise HTTPException(
                    status_code=500,
                    detail="JWT authentication not configured. Please set SUPABASE_URL."
                )
            
            # Fetch JWKS (contains public keys)
            jwks_start = time.perf_counter()
            jwks = await fetch_jwks(settings.supabase_url)
            jwks_ms = (time.perf_counter() - jwks_start) * 1000
            logger.info(f"[timing][auth/verify_jwt] jwks_fetch_ms={jwks_ms:.2f} alg={algorithm}")
            add_request_timing("auth.verify_jwt.jwks", jwks_ms)
            
            # Get the signing key for this token
            signing_key = get_signing_key_from_jwks(token, jwks)
            
            # Verify signature with public key
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[algorithm],
                audience="authenticated",
                options={"verify_aud": True},
                leeway=leeway_seconds,
            )
            logger.info(f"JWT verified successfully with {algorithm}")
            
        else:
            logger.error(f"Unsupported JWT algorithm: {algorithm}")
            raise HTTPException(
                status_code=401,
                detail=f"Unsupported JWT algorithm: {algorithm}"
            )
        
        logger.info(f"JWT verified successfully for user: {payload.get('sub', 'unknown')}")
        total_ms = (time.perf_counter() - verify_start) * 1000
        logger.info(f"[timing][auth/verify_jwt] total_ms={total_ms:.2f} alg={algorithm}")
        add_request_timing("auth.verify_jwt", total_ms)
        return payload
    except jwt.ExpiredSignatureError as e:
        logger.warning(f"JWT expired: {e}")
        raise HTTPException(
            status_code=401,
            detail="Authentication token has expired. Please log in again."
        )
    except jwt.ImmatureSignatureError as e:
        logger.warning(
            "JWT not yet valid (iat/nbf): %s. Allowed clock skew=%ss",
            e,
            settings.jwt_clock_skew_seconds,
        )
        raise HTTPException(
            status_code=401,
            detail="Authentication token is not yet valid (clock skew detected). Please retry in a moment.",
        )
    except PyJWTError as e:
        logger.warning(f"JWT verification failed: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token"
        )


async def get_user_from_jwt(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    settings: Settings = Depends(get_settings),
) -> UserContext:
    """
    Extract and validate user from Supabase JWT token.
    
    This dependency allows users to authenticate with their Supabase login
    credentials to access the API.
    
    Args:
        request: FastAPI request
        credentials: HTTP Bearer credentials
        settings: Application settings
        
    Returns:
        UserContext with user information
        
    Raises:
        HTTPException: If authentication fails
    """
    dependency_start = time.perf_counter()
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(request)
    user_agent = get_user_agent(request)
    
    if not credentials or not credentials.credentials:
        audit.log_auth_failure(
            request_id=request_id,
            reason="No authentication token provided",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please provide a valid JWT token."
        )
    
    token = credentials.credentials
    
    # Verify JWT token
    try:
        payload = await verify_supabase_jwt_async(token, settings)
    except HTTPException:
        audit.log_auth_failure(
            request_id=request_id,
            reason="Invalid JWT token",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise
    
    # Extract user information
    user_id = payload.get("sub")
    email = payload.get("email")
    
    if not user_id:
        audit.log_auth_failure(
            request_id=request_id,
            reason="Missing user ID in JWT",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid token: missing user ID"
        )
    
    # Log successful authentication
    logger.info(f"User authenticated via JWT: {user_id} ({email})")
    
    user_context = UserContext(
        user_id=user_id,
        email=email,
    )
    elapsed_ms = (time.perf_counter() - dependency_start) * 1000
    logger.info(f"[timing][auth/get_user_from_jwt] total_ms={elapsed_ms:.2f} user_id={user_id}")
    add_request_timing("auth.get_user_from_jwt", elapsed_ms)
    return user_context


async def get_user_with_org(
    request: Request,
    user: UserContext = Depends(get_user_from_jwt),
) -> UserContext:
    """
    Get user context with organization membership.
    
    Resolves the user's organization from the database and adds it to the context.
    This dependency is used for endpoints that require organization membership.
    
    Args:
        request: FastAPI request
        user: Authenticated user context
        
    Returns:
        UserContext with organization information
        
    Raises:
        HTTPException: If user is not a member of any organization
    """
    dependency_start = time.perf_counter()
    cached_user = getattr(request.state, "user_with_org", None)
    if cached_user:
        elapsed_ms = (time.perf_counter() - dependency_start) * 1000
        logger.info(f"[timing][auth/get_user_with_org] cache_hit=true total_ms={elapsed_ms:.2f}")
        add_request_timing("auth.get_user_with_org", elapsed_ms)
        return cached_user

    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(request)
    
    # Check for explicit org ID in header
    org_id = request.headers.get("X-Tenant-ID")
    cache_key = _org_membership_cache_key(user.user_id, org_id)

    cached_membership = _get_cached_org_membership(cache_key)
    if cached_membership:
        user.org_id = cached_membership.get("org_id")
        user.org_name = cached_membership.get("org_name")
        user.org_slug = cached_membership.get("org_slug")
        user.role = cached_membership.get("role")

        request.state.user_with_org = user
        elapsed_ms = (time.perf_counter() - dependency_start) * 1000
        logger.info(
            f"[timing][auth/get_user_with_org] cache_hit=org_membership mode={'explicit' if org_id else 'implicit'} total_ms={elapsed_ms:.2f}"
        )
        add_request_timing("auth.get_user_with_org", elapsed_ms)
        return user
    
    membership_start = time.perf_counter()
    user_orgs = await get_user_organizations(user.user_id)
    membership_ms = (time.perf_counter() - membership_start) * 1000

    if not org_id:
        logger.info(f"[timing][auth/get_user_with_org] org_lookup_ms={membership_ms:.2f} mode=implicit")

        if not user_orgs:
            audit.log_auth_failure(
                request_id=request_id,
                reason="User not a member of any organization",
                ip_address=ip_address,
                user_agent=get_user_agent(request),
            )
            raise HTTPException(
                status_code=403,
                detail="You must be a member of an organization to perform this action. "
                       "Please contact your administrator to be added to an organization."
            )

        selected_org = user_orgs[0]
        resolved_org_id = selected_org.get("id")
        user.org_id = resolved_org_id
        user.org_name = selected_org.get("name")
        user.org_slug = selected_org.get("slug")
        user.role = selected_org.get("role")

        _set_cached_org_membership(cache_key, {
            "org_id": resolved_org_id,
            "org_name": user.org_name,
            "org_slug": user.org_slug,
            "role": user.role,
        })
    else:
        logger.info(f"[timing][auth/get_user_with_org] org_lookup_ms={membership_ms:.2f} mode=explicit")

        selected_org = next((org for org in user_orgs if org.get("id") == org_id), None)
        if not selected_org:
            audit.log_auth_failure(
                request_id=request_id,
                reason=f"User not authorized for organization {org_id}",
                ip_address=ip_address,
                user_agent=get_user_agent(request),
            )
            raise HTTPException(
                status_code=403,
                detail=f"You do not have access to organization {org_id}"
            )

        user.org_id = org_id
        user.org_name = selected_org.get("name")
        user.org_slug = selected_org.get("slug")
        user.role = selected_org.get("role")

        _set_cached_org_membership(cache_key, {
            "org_id": org_id,
            "org_name": user.org_name,
            "org_slug": user.org_slug,
            "role": user.role,
        })
    
    logger.info(f"User {user.user_id} accessing org {user.org_id} as {user.role}")
    request.state.user_with_org = user

    elapsed_ms = (time.perf_counter() - dependency_start) * 1000
    logger.info(f"[timing][auth/get_user_with_org] cache_hit=false total_ms={elapsed_ms:.2f}")
    add_request_timing("auth.get_user_with_org", elapsed_ms)

    return user


def require_org_role(required_role: str = "member"):
    """
    Dependency factory to require specific organization role.
    
    Args:
        required_role: Minimum required role ('owner', 'admin', 'member')
        
    Returns:
        Dependency that validates user has the required role
    """
    role_hierarchy = {"owner": 3, "admin": 2, "member": 1}
    
    async def check_role(user: UserContext = Depends(get_user_with_org)) -> UserContext:
        user_level = role_hierarchy.get(user.role or "member", 0)
        required_level = role_hierarchy.get(required_role, 1)
        
        if user_level < required_level:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required role: {required_role}"
            )
        
        return user
    
    return check_role


async def get_user_flexible(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    settings: Settings = Depends(get_settings),
) -> UserContext:
    """
    Flexible authentication that accepts both JWT and API tokens.
    
    This allows users to authenticate with either:
    1. Supabase JWT (from login)
    2. API tokens (for programmatic access)
    
    Args:
        request: FastAPI request
        credentials: HTTP Bearer credentials
        settings: Application settings
        
    Returns:
        UserContext with user information
        
    Raises:
        HTTPException: If authentication fails
    """
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(request)
    user_agent = get_user_agent(request)
    
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required"
        )
    
    token = credentials.credentials.strip() if credentials.credentials else ""
    
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Empty authorization token"
        )
    
    logger.info(f"get_user_flexible: Token type check - starts_with_aiappsec={token.startswith('aiappsec_')}, length={len(token)}, prefix={token[:20] if len(token) > 20 else token}")
    
    # Check if it's an API token
    if token.startswith("aiappsec_"):
        # Handle API token authentication
        from .database import validate_api_token
        
        token_data = await validate_api_token(
            token,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        if not token_data:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired API token"
            )
        
        # Get org details
        from .database import get_organization_by_id
        org = await get_organization_by_id(token_data["org_id"])
        
        # Create user context from API token
        return UserContext(
            user_id=f"token_{token_data['id']}",  # Synthetic user ID for API tokens
            email=None,
            org_id=token_data["org_id"],
            org_name=org.get("name") if org else None,
            org_slug=org.get("slug") if org else None,
            role="admin",  # API tokens have admin access to their org
        )
    else:
        # Handle JWT authentication
        logger.info(f"Token does not start with 'aiappsec_', treating as JWT. Token prefix: {token[:20]}...")
        
        # Basic JWT format check (should have 3 dot-separated parts)
        parts = token.split('.')
        if len(parts) != 3:
            logger.warning(f"Token is not a valid JWT format: expected 3 parts, got {len(parts)}")
            audit.log_auth_failure(
                request_id=request_id,
                reason=f"Invalid token format: not a JWT (parts={len(parts)})",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise HTTPException(
                status_code=401,
                detail="Invalid token format. Expected a valid JWT or API token (starting with 'aiappsec_')."
            )
        
        try:
            return await get_user_from_jwt(request, credentials, settings)
        except HTTPException:
            audit.log_auth_failure(
                request_id=request_id,
                reason="Invalid JWT token",
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise


async def require_cicd_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> UserContext:
    """
    Require CI/CD API token authentication.
    
    This dependency is for CI/CD endpoints only (review-pr, explain-finding).
    It ONLY accepts API tokens (starting with 'aiappsec_') and rejects JWT tokens.
    
    Args:
        request: FastAPI request
        credentials: HTTP Bearer credentials
        
    Returns:
        UserContext with user information
        
    Raises:
        HTTPException: If authentication fails or non-API token is used
    """
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(request)
    user_agent = get_user_agent(request)
    
    if not credentials:
        audit.log_auth_failure(
            request_id=request_id,
            reason="No authorization header provided",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Authorization header required. CI/CD endpoints require an API token."
        )
    
    token = credentials.credentials.strip() if credentials.credentials else ""
    
    if not token:
        audit.log_auth_failure(
            request_id=request_id,
            reason="Empty authorization token",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Empty authorization token"
        )
    
    # Reject JWT tokens - CI/CD endpoints only accept API tokens
    if not token.startswith("aiappsec_"):
        audit.log_auth_failure(
            request_id=request_id,
            reason="JWT token used on CI/CD endpoint - API token required",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="CI/CD endpoints require an API token (starting with 'aiappsec_'). "
                   "JWT tokens are not accepted. Please use a CI/CD token from your dashboard."
        )
    
    # Validate the API token
    from .database import validate_api_token
    
    token_data = await validate_api_token(
        token,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    
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
    
    # Get org details
    from .database import get_organization_by_id
    org = await get_organization_by_id(token_data["org_id"])
    
    logger.info(f"CI/CD token authenticated for org {token_data['org_id']}")
    
    # Create user context from API token
    return UserContext(
        user_id=f"token_{token_data['id']}",
        email=None,
        org_id=token_data["org_id"],
        org_name=org.get("name") if org else None,
        org_slug=org.get("slug") if org else None,
        role="admin",
    )


async def _has_active_github_app_installation(org_id: str) -> bool:
    """Return True when the organization has at least one active GitHub App installation."""
    from .database import get_supabase_client

    client = get_supabase_client()

    def _query_installations():
        return client.table("github_app_installations").select("id").eq(
            "org_id", org_id
        ).eq("is_active", True).limit(1).execute()

    result = await asyncio.to_thread(_query_installations)
    return bool(result and result.data)


async def require_review_pr_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    settings: Settings = Depends(get_settings),
) -> UserContext:
    """
    Authentication for /review-pr.

    Accepts either:
    - CI/CD API token (always valid for /review-pr)
    - Dashboard JWT, but only if the user's organization has an active GitHub App installation

    JWT users without an active GitHub App installation must use a CI/CD token.
    """
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail=(
                "Authorization header required. Provide a CI/CD token or a dashboard JWT "
                "for an organization with an active GitHub App installation."
            ),
        )

    token = credentials.credentials.strip() if credentials.credentials else ""
    if not token:
        raise HTTPException(status_code=401, detail="Empty authorization token")

    # API token path remains unchanged.
    if token.startswith("aiappsec_"):
        return await require_cicd_token(request, credentials)

    # JWT path is allowed only when org has active GitHub App installation.
    jwt_user = await require_jwt_only(request, credentials, settings)
    user_with_org = await get_user_with_org(request, jwt_user)

    if not user_with_org.org_id:
        raise HTTPException(
            status_code=403,
            detail="No organization context found for authenticated user",
        )

    try:
        has_github_app = await _has_active_github_app_installation(user_with_org.org_id)
    except Exception as e:
        logger.error(
            "Failed to verify GitHub App installation for org %s: %s",
            user_with_org.org_id,
            e,
        )
        raise HTTPException(
            status_code=503,
            detail="Unable to verify GitHub App installation status. Please try again.",
        )

    if not has_github_app:
        raise HTTPException(
            status_code=403,
            detail=(
                "CI/CD token is required for /review-pr when your organization has not "
                "installed the GitHub App yet."
            ),
        )

    return user_with_org


async def require_jwt_only(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    settings: Settings = Depends(get_settings),
) -> UserContext:
    """
    Require Supabase JWT authentication only.
    
    This dependency is for frontend/dashboard endpoints.
    It ONLY accepts Supabase JWT tokens and rejects API tokens.
    
    Args:
        request: FastAPI request
        credentials: HTTP Bearer credentials
        settings: Application settings
        
    Returns:
        UserContext with user information
        
    Raises:
        HTTPException: If authentication fails or API token is used
    """
    audit = get_audit_logger()
    request_id = get_request_id()
    ip_address = get_client_identifier(request)
    user_agent = get_user_agent(request)
    
    if not credentials:
        audit.log_auth_failure(
            request_id=request_id,
            reason="No authorization header provided",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Authorization header required. Please log in."
        )
    
    token = credentials.credentials.strip() if credentials.credentials else ""
    
    if not token:
        audit.log_auth_failure(
            request_id=request_id,
            reason="Empty authorization token",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Empty authorization token"
        )
    
    # Reject API tokens - frontend endpoints only accept JWT
    if token.startswith("aiappsec_"):
        audit.log_auth_failure(
            request_id=request_id,
            reason="API token used on frontend endpoint - JWT required",
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
    
    # Validate JWT format
    parts = token.split('.')
    if len(parts) != 3:
        logger.warning(f"Token is not a valid JWT format: expected 3 parts, got {len(parts)}")
        audit.log_auth_failure(
            request_id=request_id,
            reason=f"Invalid token format: not a JWT (parts={len(parts)})",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid token format. Expected a valid JWT token from Supabase login."
        )
    
    # Verify JWT
    try:
        user_context = await get_user_from_jwt(request, credentials, settings)
        logger.info(f"JWT authenticated for user {user_context.user_id}")
        return user_context
    except HTTPException:
        audit.log_auth_failure(
            request_id=request_id,
            reason="Invalid JWT token",
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise
