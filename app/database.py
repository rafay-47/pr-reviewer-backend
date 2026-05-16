"""
Database client for Supabase integration.

Provides async database access for the AI AppSec PR Reviewer.
Uses supabase-py for connection management with production-ready
security features including token lifecycle management.
"""

import hashlib
import asyncio
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
from functools import lru_cache

from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions

logger = logging.getLogger(__name__)

# Token configuration
TOKEN_PREFIX = "aiappsec_"
TOKEN_ENTROPY_BYTES = 32  # 256 bits of entropy
ALLOWED_SCOPES = [
    "review:pr",
    "explain:finding",
    "admin:policy",
    "admin:tokens",
    "read:metrics",
    "feedback:write",
    "*",  # Wildcard scope (may be restricted in production)
]

# Simplified token types for better UX
# CI/CD tokens are ONLY for GitHub Actions and CI/CD pipelines
# Frontend/dashboard access uses Supabase JWT only
TOKEN_TYPES = {
    "cicd": {
        "name": "CI/CD Token",
        "description": "For GitHub Actions and CI/CD pipelines only. Can submit PR reviews and explain findings.",
        "scopes": ["review:pr", "explain:finding"],
        "auto_generate": True,
        "recommended_use": "GitHub Actions, CI/CD pipelines only - NOT for frontend use",
    },
}

DEFAULT_TOKEN_TYPE = "cicd"
TOKEN_USAGE_UPDATE_MIN_INTERVAL_SECONDS = 60

# Global Supabase client
_supabase_client: Optional[Client] = None

# Small in-memory cache for organization metadata.
_organization_cache: dict[str, tuple[dict, float]] = {}
ORGANIZATION_CACHE_TTL_SECONDS = 60
ORGANIZATION_CACHE_MAX_ENTRIES = 2000
_organization_fetch_locks: dict[str, asyncio.Lock] = {}

_user_organizations_cache: dict[str, tuple[list[dict], float]] = {}
USER_ORGANIZATIONS_CACHE_TTL_SECONDS = 30
USER_ORGANIZATIONS_CACHE_MAX_ENTRIES = 5000
_user_organizations_fetch_locks: dict[str, asyncio.Lock] = {}


def _get_cached_organization(org_id: str) -> Optional[dict]:
    entry = _organization_cache.get(org_id)
    if not entry:
        return None

    org_data, expires_at = entry
    if expires_at < time.monotonic():
        _organization_cache.pop(org_id, None)
        return None

    return org_data


def _set_cached_organization(org_id: str, org_data: dict) -> None:
    now = time.monotonic()
    expires_at = now + ORGANIZATION_CACHE_TTL_SECONDS

    if len(_organization_cache) >= ORGANIZATION_CACHE_MAX_ENTRIES:
        expired_keys = [
            key for key, (_, cache_expires_at) in _organization_cache.items()
            if cache_expires_at < now
        ]
        for key in expired_keys:
            _organization_cache.pop(key, None)

        if len(_organization_cache) >= ORGANIZATION_CACHE_MAX_ENTRIES:
            oldest_key = next(iter(_organization_cache), None)
            if oldest_key:
                _organization_cache.pop(oldest_key, None)

    _organization_cache[org_id] = (org_data, expires_at)


def _get_cached_user_organizations(user_id: str) -> Optional[list[dict]]:
    entry = _user_organizations_cache.get(user_id)
    if not entry:
        return None

    organizations, expires_at = entry
    if expires_at < time.monotonic():
        _user_organizations_cache.pop(user_id, None)
        return None

    return organizations


def _set_cached_user_organizations(user_id: str, organizations: list[dict]) -> None:
    now = time.monotonic()
    expires_at = now + USER_ORGANIZATIONS_CACHE_TTL_SECONDS

    if len(_user_organizations_cache) >= USER_ORGANIZATIONS_CACHE_MAX_ENTRIES:
        expired_keys = [
            key for key, (_, cache_expires_at) in _user_organizations_cache.items()
            if cache_expires_at < now
        ]
        for key in expired_keys:
            _user_organizations_cache.pop(key, None)

        if len(_user_organizations_cache) >= USER_ORGANIZATIONS_CACHE_MAX_ENTRIES:
            oldest_key = next(iter(_user_organizations_cache), None)
            if oldest_key:
                _user_organizations_cache.pop(oldest_key, None)

    _user_organizations_cache[user_id] = (organizations, expires_at)


def invalidate_user_organizations_cache(user_id: str) -> None:
    """Invalidate cached organization memberships for a user."""
    _user_organizations_cache.pop(user_id, None)


def get_supabase_client() -> Client:
    """Get or create the Supabase client singleton."""
    global _supabase_client
    
    if _supabase_client is None:
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_KEY")  # Use service key for backend
        
        if not url or not key:
            raise ValueError(
                "SUPABASE_URL and SUPABASE_SERVICE_KEY environment variables are required"
            )
        
        _supabase_client = create_client(url, key)
        logger.info("Supabase client initialized")
    
    return _supabase_client


async def _execute_query(query):
    """Run blocking Supabase query execution off the event loop."""
    return await asyncio.to_thread(query.execute)


def hash_token(token: str) -> str:
    """Hash a token using SHA256."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_api_token() -> tuple[str, str]:
    """
    Generate a new API token with production-grade entropy.
    
    Returns:
        Tuple of (full_token, prefix) where prefix is first 16 chars
    """
    # Generate 256 bits of cryptographically secure randomness
    random_part = secrets.token_hex(TOKEN_ENTROPY_BYTES)
    full_token = f"{TOKEN_PREFIX}{random_part}"
    prefix = full_token[:16]  # "aiappsec_" + 7 chars
    return full_token, prefix


def validate_scopes(scopes: list[str], allow_wildcard: bool = False) -> list[str]:
    """
    Validate and sanitize token scopes.
    
    Args:
        scopes: List of requested scopes
        allow_wildcard: Whether to allow wildcard (*) scope
        
    Returns:
        Validated list of scopes
        
    Raises:
        ValueError: If invalid scopes are provided
    """
    if not scopes:
        raise ValueError("At least one scope is required")
    
    validated = []
    for scope in scopes:
        if scope not in ALLOWED_SCOPES:
            raise ValueError(f"Invalid scope: {scope}. Allowed scopes: {ALLOWED_SCOPES}")
        if scope == "*" and not allow_wildcard:
            raise ValueError("Wildcard scope (*) is not allowed. Please specify explicit scopes.")
        validated.append(scope)
    
    return validated


# ============================================================================
# Organization Functions
# ============================================================================

async def get_organization_by_id(org_id: str) -> Optional[dict]:
    """Get an organization by ID."""
    lookup_start = time.perf_counter()
    cached_org = _get_cached_organization(org_id)
    if cached_org:
        elapsed_ms = (time.perf_counter() - lookup_start) * 1000
        logger.info(f"[timing][db/get_organization_by_id] cache_hit=true total_ms={elapsed_ms:.2f}")
        return cached_org

    lock = _organization_fetch_locks.setdefault(org_id, asyncio.Lock())
    async with lock:
        # Another in-flight request may have populated the cache while we waited.
        cached_org_after_lock = _get_cached_organization(org_id)
        if cached_org_after_lock:
            elapsed_ms = (time.perf_counter() - lookup_start) * 1000
            logger.info(f"[timing][db/get_organization_by_id] cache_hit=after_lock total_ms={elapsed_ms:.2f}")
            return cached_org_after_lock

        client = get_supabase_client()
        try:
            query_start = time.perf_counter()
            result = await _execute_query(
                client.table("organizations").select("*").eq("id", org_id).maybe_single()
            )
            query_ms = (time.perf_counter() - query_start) * 1000

            org_data = result.data if result and result.data else None
            if org_data:
                _set_cached_organization(org_id, org_data)

            elapsed_ms = (time.perf_counter() - lookup_start) * 1000
            logger.info(
                f"[timing][db/get_organization_by_id] cache_hit=false query_ms={query_ms:.2f} total_ms={elapsed_ms:.2f}"
            )
            return org_data
        except Exception as e:
            logger.warning(f"Error fetching organization {org_id}: {e}")
            return None


async def get_organization_by_slug(slug: str) -> Optional[dict]:
    """Get an organization by slug."""
    client = get_supabase_client()
    try:
        result = client.table("organizations").select("*").eq("slug", slug).maybe_single().execute()
        return result.data if result and result.data else None
    except Exception as e:
        logger.warning(f"Error fetching organization by slug {slug}: {e}")
        return None


async def create_organization(name: str, slug: str, user_id: Optional[str] = None) -> tuple[dict, Optional[str]]:
    """
    Create a new organization.
    
    Automatically generates a CI/CD token for the organization.
    
    Returns:
        Tuple of (organization_dict, cicd_token_plaintext)
        The CI/CD token is only returned once - it cannot be retrieved again.
    """
    client = get_supabase_client()
    
    # Create organization
    org_result = client.table("organizations").insert({
        "name": name,
        "slug": slug
    }).execute()
    
    org = org_result.data[0]
    org_id = org["id"]
    _set_cached_organization(org_id, org)
    
    # Add owner if user_id provided
    if user_id:
        logger.info(f"[db/create_organization] Adding user_id={user_id} as owner to org_id={org_id}")
        member_result = client.table("org_members").insert({
            "org_id": org_id,
            "user_id": user_id,
            "role": "owner"
        }).execute()
        logger.info(f"[db/create_organization] org_members insert result: data={member_result.data}")
        invalidate_user_organizations_cache(user_id)
    
    # Auto-generate CI/CD token for the organization
    cicd_token = None
    try:
        cicd_token, _ = await create_api_token(
            org_id=org_id,
            name="Default API Token",
            token_type="cicd",
            created_by=user_id,
            expires_in_days=0,  # Never expires
        )
        logger.info(f"Auto-generated CI/CD token for organization {org_id}")
    except Exception as e:
        logger.error(f"Failed to auto-generate CI/CD token for org {org_id}: {e}")
        # Don't fail org creation if token generation fails
    
    return org, cicd_token


async def get_user_organizations(user_id: str) -> list[dict]:
    """Get all organizations for a user."""
    lookup_start = time.perf_counter()
    cached = _get_cached_user_organizations(user_id)
    if cached is not None:
        elapsed_ms = (time.perf_counter() - lookup_start) * 1000
        logger.info(
            f"[timing][db/get_user_organizations] cache_hit=true total_ms={elapsed_ms:.2f} user_id={user_id} count={len(cached)}"
        )
        return cached

    lock = _user_organizations_fetch_locks.setdefault(user_id, asyncio.Lock())
    async with lock:
        cached_after_lock = _get_cached_user_organizations(user_id)
        if cached_after_lock is not None:
            elapsed_ms = (time.perf_counter() - lookup_start) * 1000
            logger.info(
                f"[timing][db/get_user_organizations] cache_hit=after_lock total_ms={elapsed_ms:.2f} user_id={user_id} count={len(cached_after_lock)}"
            )
            return cached_after_lock

        client = get_supabase_client()
        query_start = time.perf_counter()
        result = await _execute_query(
            client.table("org_members").select(
                "org_id, role, organizations(*)"
            ).eq("user_id", user_id)
        )
        query_ms = (time.perf_counter() - query_start) * 1000
        logger.info(
            f"[db/get_user_organizations] user_id={user_id} raw_data_count={len(result.data) if result.data else 0} raw_data={result.data}"
        )
    
    # Transform the nested structure to a flat structure expected by the frontend
        if not result.data:
            _set_cached_user_organizations(user_id, [])
            elapsed_ms = (time.perf_counter() - lookup_start) * 1000
            logger.info(
                f"[timing][db/get_user_organizations] cache_hit=false query_ms={query_ms:.2f} total_ms={elapsed_ms:.2f} user_id={user_id} count=0"
            )
            return []
    
        organizations = []
        for item in result.data:
            org_data = item.get("organizations", {})
            if org_data:
                organizations.append({
                    "id": org_data.get("id"),
                    "name": org_data.get("name"),
                    "slug": org_data.get("slug"),
                    "role": item.get("role"),
                    "settings": org_data.get("settings", {})
                })
                if org_data.get("id"):
                    _set_cached_organization(org_data["id"], org_data)
    
        _set_cached_user_organizations(user_id, organizations)
        elapsed_ms = (time.perf_counter() - lookup_start) * 1000
        logger.info(
            f"[timing][db/get_user_organizations] cache_hit=false query_ms={query_ms:.2f} total_ms={elapsed_ms:.2f} user_id={user_id} count={len(organizations)}"
        )
        return organizations


# ============================================================================
# Repo Config Functions
# ============================================================================

async def get_repo_config(org_id: str, repo_name: str) -> Optional[dict]:
    """Get repository configuration."""
    client = get_supabase_client()
    try:
        result = client.table("repo_configs").select("*").eq(
            "org_id", org_id
        ).eq("repo_name", repo_name).maybe_single().execute()
        return result.data if result and result.data else None
    except Exception as e:
        # Log but don't fail - no config is a valid state
        logger.warning(f"Error fetching repo config for {repo_name}: {e}")
        return None


async def upsert_repo_config(
    org_id: str, 
    repo_name: str, 
    policy: dict, 
    enabled: bool = True,
    source: str = "manual",
    github_repo_id: Optional[str] = None
) -> dict:
    """Create or update repository configuration."""
    client = get_supabase_client()
    
    data = {
        "org_id": org_id,
        "repo_name": repo_name,
        "policy": policy,
        "enabled": enabled,
        "source": source,
        "updated_at": datetime.utcnow().isoformat()
    }
    
    # Only set github_repo_id if provided
    if github_repo_id:
        data["github_repo_id"] = github_repo_id
    
    result = client.table("repo_configs").upsert(
        data, 
        on_conflict="org_id,repo_name"
    ).execute()
    return result.data[0] if result.data else {}


async def list_repo_configs(org_id: str) -> list[dict]:
    """List all repo configs for an organization."""
    client = get_supabase_client()
    result = client.table("repo_configs").select("*").eq("org_id", org_id).execute()
    return result.data if result.data else []


# ============================================================================
# API Token Functions
# ============================================================================

async def create_api_token(
    org_id: str,
    name: str,
    scopes: Optional[list[str]] = None,
    token_type: Optional[str] = None,
    created_by: Optional[str] = None,
    expires_in_days: Optional[int] = None,
    max_lifetime_days: int = 90,
    default_lifetime_days: int = 30,
    allow_wildcard: bool = False,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> tuple[str, dict]:
    """
    Create a new API token for an organization.
    
    Args:
        org_id: Organization ID
        name: Human-readable name for the token
        scopes: List of permission scopes
        token_type: Type of token (cicd, etc.)
        created_by: User ID who created the token
        expires_in_days: Days until expiration (None = default, 0 = never)
        max_lifetime_days: Maximum allowed lifetime (enforced)
        default_lifetime_days: Default lifetime if not specified
        allow_wildcard: Whether to allow wildcard scope
        ip_address: IP address of the request
        user_agent: User agent of the request
        
    Returns:
        Tuple of (plaintext_token, token_record)
        The plaintext token is only returned once - it cannot be retrieved again.
    """
    from .config import get_settings
    
    settings = get_settings()
    client = get_supabase_client()
    
    # Normalize legacy/null token types to a supported type.
    normalized_token_type = token_type or DEFAULT_TOKEN_TYPE
    if normalized_token_type == "custom":
        normalized_token_type = DEFAULT_TOKEN_TYPE

    if normalized_token_type not in TOKEN_TYPES:
        raise ValueError(f"Unsupported token type: {normalized_token_type}")

    # Use defaults from token type if scopes are not explicitly provided.
    type_config = TOKEN_TYPES[normalized_token_type]
    if not scopes:
        scopes = type_config["scopes"]
    
    # Validate scopes
    scopes = validate_scopes(scopes or ["review:pr"], allow_wildcard=allow_wildcard)
    
    # Calculate expiration
    if expires_in_days is None:
        expires_in_days = default_lifetime_days
    
    if expires_in_days == 0:
        # Never expires
        expires_at = None
    else:
        # Enforce maximum lifetime
        if expires_in_days > max_lifetime_days:
            expires_in_days = max_lifetime_days
        expires_at = (datetime.utcnow() + timedelta(days=expires_in_days)).isoformat()
    
    # Generate token
    plaintext_token, prefix = generate_api_token()
    token_hash = hash_token(plaintext_token)
    
    # Create record
    token_data = {
        "org_id": org_id,
        "name": name,
        "token_hash": token_hash,
        "prefix": prefix,
        "scopes": scopes,
        "token_type": normalized_token_type,
        "created_by": created_by,
        "expires_at": expires_at,
        "last_used_at": None,
        "last_used_ip": None,
        "is_active": True,
    }
    
    result = client.table("api_tokens").insert(token_data).execute()
    
    if not result.data:
        raise RuntimeError("Failed to create API token")
    
    token_record = result.data[0]
    
    # Log token creation for audit
    logger.info(
        f"Created API token {token_record['id']} for org {org_id} "
        f"with scopes {scopes}"
    )
    
    return plaintext_token, token_record


async def validate_api_token(
    token: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Optional[dict]:
    """
    Validate an API token and return token data if valid.
    
    Args:
        token: The plaintext token to validate
        ip_address: IP address for audit logging
        user_agent: User agent for audit logging
        
    Returns:
        Token data if valid, None otherwise
    """
    client = get_supabase_client()
    
    # Hash the token to look it up
    token_hash = hash_token(token)
    
    # Find token by hash. Use a list query to avoid PostgREST 406 responses
    # that can occur with maybe_single() when no row exists.
    try:
        result = client.table("api_tokens").select("*").eq(
            "token_hash", token_hash
        ).eq("is_active", True).limit(1).execute()
    except Exception as e:
        logger.warning(f"API token validation query failed: {e}")
        return None

    if not result or not result.data:
        logger.warning("API token validation failed: hash not found")
        return None

    token_data = result.data[0]
    if not isinstance(token_data, dict):
        logger.warning("API token validation failed: unexpected token payload shape")
        return None
    
    # Check expiration
    if token_data.get("expires_at"):
        expires_at = datetime.fromisoformat(token_data["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires_at:
            logger.warning(f"API token {token_data['id']} expired")
            # Deactivate expired token
            try:
                client.table("api_tokens").update({"is_active": False}).eq("id", token_data["id"]).execute()
            except Exception as e:
                logger.warning(f"Failed to deactivate expired API token {token_data.get('id')}: {e}")
            return None
    
    # Defer and throttle token usage writes to keep request path fast.
    token_id = token_data.get("id")
    should_update_usage = True
    last_used_at_raw = token_data.get("last_used_at")
    if last_used_at_raw:
        try:
            last_used_at = datetime.fromisoformat(str(last_used_at_raw).replace("Z", "+00:00"))
            if last_used_at.tzinfo is None:
                last_used_at = last_used_at.replace(tzinfo=timezone.utc)
            seconds_since_last_use = (datetime.now(timezone.utc) - last_used_at).total_seconds()
            should_update_usage = seconds_since_last_use >= TOKEN_USAGE_UPDATE_MIN_INTERVAL_SECONDS
        except Exception:
            # If parsing fails, fall back to updating usage.
            should_update_usage = True

    if token_id and should_update_usage:
        update_data = {"last_used_at": datetime.utcnow().isoformat()}
        if ip_address:
            update_data["last_used_ip"] = ip_address

        def _update_token_usage() -> None:
            try:
                client.table("api_tokens").update(update_data).eq("id", token_id).execute()
            except Exception as e:
                logger.warning(f"Failed to update last_used_at for API token {token_id}: {e}")

        asyncio.create_task(asyncio.to_thread(_update_token_usage))
    
    return token_data


async def list_api_tokens(org_id: str) -> list[dict]:
    """List all active API tokens for an organization."""
    client = get_supabase_client()
    
    result = client.table("api_tokens").select(
        "id, name, prefix, scopes, token_type, created_at, expires_at, last_used_at, is_active, revoked_at"
    ).eq("org_id", org_id).eq("is_active", True).order("created_at", desc=True).execute()
    
    return result.data if result.data else []


async def get_cicd_token(org_id: str) -> Optional[dict]:
    """
    Get the CI/CD token for an organization.
    
    Returns the first active CI/CD token found for the org.
    Used for retrieving token metadata (not the plaintext token).
    
    Args:
        org_id: Organization ID
        
    Returns:
        Token data dict or None if no CI/CD token exists
    """
    client = get_supabase_client()
    
    result = client.table("api_tokens").select(
        "id, name, prefix, scopes, token_type, created_at, expires_at, last_used_at, is_active, revoked_at"
    ).eq("org_id", org_id).eq("is_active", True).order("created_at", desc=True).limit(20).execute()

    rows = result.data if result and result.data else []
    if not rows:
        return None

    # Preferred path: active CI/CD token.
    for row in rows:
        if (row.get("token_type") or "").lower() == "cicd":
            return row

    # Legacy path: pre-migration rows may be "custom" or null token_type.
    legacy = None
    for row in rows:
        token_type = row.get("token_type")
        if token_type is None or str(token_type).lower() in {"", "custom"}:
            legacy = row
            break

    if not legacy:
        return None

    # Normalize legacy token type to cicd so subsequent reads are consistent.
    try:
        client.table("api_tokens").update(
            {
                "token_type": "cicd",
            }
        ).eq("id", legacy["id"]).execute()
    except Exception as e:
        logger.warning(f"Failed to normalize legacy token_type for token {legacy.get('id')}: {e}")

    legacy["token_type"] = "cicd"
    return legacy


async def revoke_api_token(token_id: str, org_id: str) -> bool:
    """Revoke (deactivate) an API token."""
    client = get_supabase_client()
    
    result = client.table("api_tokens").update({
        "is_active": False,
        "revoked_at": datetime.utcnow().isoformat()
    }).eq("id", token_id).eq("org_id", org_id).execute()
    
    return len(result.data) > 0 if result.data else False


async def rotate_api_token(
    token_id: str,
    org_id: str,
    rotated_by: Optional[str] = None,
    max_lifetime_days: int = 90,
) -> tuple[str, dict]:
    """
    Rotate an API token (revoke old, create new with same settings).
    
    Returns:
        Tuple of (new_plaintext_token, new_token_record)
    """
    client = get_supabase_client()
    
    # Get existing token
    result = client.table("api_tokens").select("*").eq("id", token_id).eq("org_id", org_id).maybe_single().execute()
    
    if not result.data:
        raise ValueError("Token not found")
    
    old_token = result.data
    
    # Calculate new expiration based on old token's remaining time or max lifetime
    expires_in_days = max_lifetime_days
    if old_token.get("expires_at"):
        expires_at = datetime.fromisoformat(old_token["expires_at"].replace("Z", "+00:00"))
        remaining_days = (expires_at - datetime.now(timezone.utc)).days
        if remaining_days > 0 and remaining_days < max_lifetime_days:
            expires_in_days = remaining_days
    
    # Create new token with same settings
    new_plaintext, new_token = await create_api_token(
        org_id=org_id,
        name=old_token["name"],
        scopes=old_token["scopes"],
        token_type=old_token.get("token_type"),
        created_by=rotated_by,
        expires_in_days=expires_in_days,
    )
    
    # Revoke old token
    await revoke_api_token(token_id, org_id)
    
    logger.info(f"Rotated API token {token_id} -> {new_token['id']}")
    
    return new_plaintext, new_token


async def regenerate_cicd_token(
    org_id: str,
    created_by: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> tuple[str, dict]:
    """
    Regenerate an organization's CI/CD token.

    Revokes existing active CI/CD/legacy custom tokens and creates a new CI/CD token.
    Returns plaintext token once.
    """
    client = get_supabase_client()

    # Revoke existing active CI/CD tokens.
    client.table("api_tokens").update({
        "is_active": False,
        "revoked_at": datetime.utcnow().isoformat(),
    }).eq("org_id", org_id).eq("is_active", True).eq("token_type", "cicd").execute()

    # Revoke active legacy custom tokens as they are treated as CI/CD tokens.
    client.table("api_tokens").update({
        "is_active": False,
        "revoked_at": datetime.utcnow().isoformat(),
    }).eq("org_id", org_id).eq("is_active", True).eq("token_type", "custom").execute()

    new_plaintext, new_token = await create_api_token(
        org_id=org_id,
        name="Default CI/CD Token",
        token_type="cicd",
        created_by=created_by,
        expires_in_days=0,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    logger.info(f"Regenerated CI/CD token for org {org_id}: {new_token['id']}")
    return new_plaintext, new_token


# ============================================================================
# Review Functions
# ============================================================================

async def create_review(
    org_id: str,
    repo_name: str,
    pr_number: int,
    review_time_ms: int = 0,
    findings_count: int = 0,
    high_count: int = 0,
    medium_count: int = 0,
    low_count: int = 0,
    needs_review_count: int = 0,
    success: bool = True,
    should_block: bool = False,
    new_findings_count: int = 0,
    resolved_findings_count: int = 0,
    still_present_count: int = 0,
    active_findings_count: int = 0,
    active_high_count: int = 0,
    active_medium_count: int = 0,
    active_low_count: int = 0,
    pr_title: Optional[str] = None,
    pr_author: Optional[str] = None,
) -> dict:
    """Create a new review record with metrics."""
    client = get_supabase_client()
    
    data = {
        "org_id": org_id,
        "repo_name": repo_name,
        "pr_number": pr_number,
        "review_time_ms": review_time_ms,
        "findings_count": findings_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "needs_review_count": needs_review_count,
        "success": success,
        "should_block": should_block,
        "new_findings_count": new_findings_count,
        "resolved_findings_count": resolved_findings_count,
        "still_present_count": still_present_count,
        "active_findings_count": active_findings_count,
        "active_high_count": active_high_count,
        "active_medium_count": active_medium_count,
        "active_low_count": active_low_count,
    }
    
    # Add optional fields if provided
    if pr_title:
        data["pr_title"] = pr_title
    if pr_author:
        data["pr_author"] = pr_author
    
    result = client.table("reviews").insert(data).execute()
    
    return result.data[0] if result.data else {}


async def create_findings(review_id: str, org_id: str, findings: list[dict]) -> list[dict]:
    """Create findings for a review with resilient row normalization."""
    client = get_supabase_client()
    if not findings:
        return []

    def _normalize_risk(value: Any) -> str:
        raw = str(value or "MEDIUM").upper()
        return raw if raw in {"HIGH", "MEDIUM", "LOW"} else "MEDIUM"

    def _normalize_confidence(value: Any) -> str:
        raw = str(value or "MEDIUM").upper()
        return raw if raw in {"HIGH", "MEDIUM", "LOW", "NEEDS_REVIEW"} else "MEDIUM"

    def _normalize_uuid(value: Any) -> str:
        try:
            return str(uuid.UUID(str(value)))
        except Exception:
            return str(uuid.uuid4())

    def _normalize_int(value: Any) -> Optional[int]:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except Exception:
            return None

    normalized_rows: list[dict] = []
    for finding in findings:
        file_path = str(finding.get("file_path") or finding.get("file") or "unknown")
        line_range = str(finding.get("line_range") or "")
        title = str(finding.get("title") or "Unknown Issue")
        risk = _normalize_risk(finding.get("risk"))
        confidence = _normalize_confidence(finding.get("confidence"))
        severity = _normalize_risk(finding.get("severity") or risk)

        fingerprint = finding.get("fingerprint")
        if not fingerprint:
            # Stable fallback fingerprint to satisfy DB NOT NULL constraint.
            seed = f"{file_path}|{risk}|{title}|{line_range}"
            fingerprint = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

        normalized_rows.append(
            {
                "id": _normalize_uuid(finding.get("id")),
                "review_id": review_id,
                "org_id": org_id,
                "fingerprint": str(fingerprint),
                "title": title,
                "risk": risk,
                "confidence": confidence,
                "file_path": file_path,
                "line_range": line_range or None,
                "line_start": _normalize_int(finding.get("line_start")),
                "line_end": _normalize_int(finding.get("line_end")),
                "evidence": finding.get("evidence"),
                "description": finding.get("description"),
                "impact": finding.get("impact"),
                "recommendation": finding.get("recommendation"),
                "example_fix": finding.get("example_fix"),
                "category": finding.get("category"),
                "owasp": finding.get("owasp"),
                "cwe": finding.get("cwe"),
                "is_new": bool(finding.get("is_new", True)),
                "status": str(finding.get("status") or "open"),
                "resolution_method": finding.get("resolution_method"),
                "resolved_at": finding.get("resolved_at"),
                "resolved_by_user_id": finding.get("resolved_by_user_id"),
                "resolved_reason": finding.get("resolved_reason"),
                "resolved_notes": finding.get("resolved_notes"),
                "severity": severity,
                "original_code": finding.get("original_code"),
                "suggested_fix": finding.get("suggested_fix"),
                "created_at": finding.get("created_at") or datetime.utcnow().isoformat(),
            }
        )

    try:
        result = client.table("findings").insert(normalized_rows).execute()
        return result.data if result.data else []
    except Exception as bulk_error:
        logger.error(
            "Bulk findings insert failed for review %s (org=%s): %s. Falling back to row-by-row insert.",
            review_id,
            org_id,
            bulk_error,
        )

    inserted_rows: list[dict] = []
    for row in normalized_rows:
        try:
            result = client.table("findings").insert(row).execute()
            if result.data:
                inserted_rows.extend(result.data)
        except Exception as row_error:
            logger.error(
                "Skipping invalid finding insert for review %s (fingerprint=%s, title=%s): %s",
                review_id,
                row.get("fingerprint"),
                row.get("title"),
                row_error,
            )

    return inserted_rows


async def get_review(review_id: str) -> Optional[dict]:
    """Get a review by ID."""
    client = get_supabase_client()
    result = client.table("reviews").select("*").eq("id", review_id).maybe_single().execute()
    return result.data if result and result.data else None


async def get_org_reviews(org_id: str, limit: int = 100) -> list[dict]:
    """Get recent reviews for an organization."""
    client = get_supabase_client()
    result = client.table("reviews").select("*").eq("org_id", org_id).order(
        "created_at", desc=True
    ).limit(limit).execute()
    return result.data if result.data else []


async def get_recent_reviews(org_id: str, limit: int = 50) -> list[dict]:
    """Get recent reviews for an organization."""
    client = get_supabase_client()
    try:
        result = client.table("reviews").select("*").eq("org_id", org_id).order(
            "created_at", desc=True
        ).limit(limit).execute()
        return result.data if result and result.data else []
    except Exception as e:
        logger.warning(f"Error fetching recent reviews for org {org_id}: {e}")
        return []


# ============================================================================
# Dashboard Stats Functions
# ============================================================================

async def get_dashboard_stats(org_id: str, days: int = 30) -> dict:
    """Get dashboard statistics for an organization."""
    client = get_supabase_client()
    
    try:
        # Get total reviews within time period
        from datetime import datetime, timedelta
        time_ago = (datetime.utcnow() - timedelta(days=days)).isoformat()
        reviews_query = client.table("reviews").select(
            "id, review_time_ms, success, should_block", count="exact"
        ).eq("org_id", org_id).gte("created_at", time_ago)

        findings_query = client.table("findings").select(
            "severity, status", count="exact"
        ).eq("org_id", org_id)

        reviews_result, findings_result = await asyncio.gather(
            _execute_query(reviews_query),
            _execute_query(findings_query),
        )
        total_reviews = reviews_result.count if hasattr(reviews_result, 'count') else 0
        
        # Calculate review metrics
        review_times = [r.get("review_time_ms", 0) for r in (reviews_result.data or []) if r.get("review_time_ms")]
        avg_review_time_ms = sum(review_times) / len(review_times) if review_times else 0
        success_count = sum(1 for r in (reviews_result.data or []) if r.get("success"))
        success_rate = (success_count / total_reviews * 100) if total_reviews > 0 else 0
        blocked_count = sum(1 for r in (reviews_result.data or []) if r.get("should_block"))
        
        # Get findings counts by severity
        total_findings = findings_result.count if hasattr(findings_result, 'count') else 0
        
        # Count by severity
        high_findings = 0
        medium_findings = 0
        low_findings = 0
        resolved_findings = 0
        
        for finding in (findings_result.data or []):
            severity = finding.get("severity", "medium")
            status = finding.get("status", "open")
            
            if severity in ["critical", "high"]:
                high_findings += 1
            elif severity == "medium":
                medium_findings += 1
            elif severity == "low":
                low_findings += 1
            
            if status in ["resolved", "false_positive", "accepted_risk", "wont_fix"]:
                resolved_findings += 1
        
        return {
            "total_reviews": total_reviews,
            "total_findings": total_findings,
            "high_findings": high_findings,
            "medium_findings": medium_findings,
            "low_findings": low_findings,
            "avg_review_time_ms": avg_review_time_ms,
            "success_rate": success_rate,
            "blocked_count": blocked_count,
            "resolved_findings": resolved_findings,
        }
    except Exception as e:
        logger.warning(f"Error fetching dashboard stats for org {org_id}: {e}")
        # Return safe defaults
        return {
            "total_reviews": 0,
            "total_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "avg_review_time_ms": 0,
            "success_rate": 0,
            "blocked_count": 0,
            "resolved_findings": 0,
        }


async def get_findings_by_category(org_id: str) -> list[dict]:
    """Get findings grouped by category."""
    client = get_supabase_client()
    
    try:
        result = await _execute_query(
            client.table("findings").select("category, severity").eq("org_id", org_id)
        )
        
        if not result.data:
            return []
        
        # Group by category
        categories = {}
        for finding in result.data:
            category = finding.get("category", "unknown")
            severity = finding.get("severity", "medium")
            
            if category not in categories:
                categories[category] = {"category": category, "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            
            categories[category]["count"] += 1
            if severity in ["critical", "high", "medium", "low"]:
                categories[category][severity] += 1
        
        # Convert to list format with proper structure
        return list(categories.values())
    except Exception as e:
        logger.warning(f"Error fetching findings by category for org {org_id}: {e}")
        return []


async def get_top_risky_repos(org_id: str, limit: int = 5) -> list[dict]:
    """Get top repositories by number of findings."""
    client = get_supabase_client()
    
    # Get all findings grouped by repo
    result = client.table("findings").select("repo_name, severity").eq("org_id", org_id).execute()
    
    if not result.data:
        return []
    
    # Group by repo
    repos = {}
    for finding in result.data:
        repo = finding.get("repo_name", "unknown")
        severity = finding.get("severity", "medium")
        
        if repo not in repos:
            repos[repo] = {"total": 0, "critical": 0, "high": 0}
        
        repos[repo]["total"] += 1
        if severity in ["critical", "high"]:
            repos[repo][severity] += 1
    
    # Sort by critical/high count, then total
    sorted_repos = sorted(
        repos.items(),
        key=lambda x: (x[1]["critical"] + x[1]["high"], x[1]["total"]),
        reverse=True
    )
    
    return [
        {"repo_name": repo, **counts}
        for repo, counts in sorted_repos[:limit]
    ]


async def get_review_trend(org_id: str, days: int = 30) -> list[dict]:
    """Get review trend data for charting."""
    client = get_supabase_client()
    
    try:
        # Get reviews from last N days
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
        reviews_query = client.table("reviews").select("created_at, id").eq(
            "org_id", org_id
        ).gte("created_at", start_date)

        findings_query = client.table("findings").select(
            "created_at, severity, review_id"
        ).eq("org_id", org_id).gte("created_at", start_date)

        reviews_result, findings_result = await asyncio.gather(
            _execute_query(reviews_query),
            _execute_query(findings_query),
        )
        
        from collections import defaultdict
        
        # Group reviews by day
        daily_reviews = defaultdict(int)
        for review in (reviews_result.data or []):
            date_str = review["created_at"][:10]  # YYYY-MM-DD
            daily_reviews[date_str] += 1
        
        # Group findings by day and severity
        daily_findings = defaultdict(int)
        daily_high_findings = defaultdict(int)
        for finding in (findings_result.data or []):
            date_str = finding["created_at"][:10]  # YYYY-MM-DD
            daily_findings[date_str] += 1
            severity = finding.get("severity", "medium")
            if severity in ["critical", "high"]:
                daily_high_findings[date_str] += 1
        
        # Fill in missing days and build trend
        trend = []
        for i in range(days):
            date = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
            trend.append({
                "date": date,
                "review_count": daily_reviews.get(date, 0),
                "findings_count": daily_findings.get(date, 0),
                "high_count": daily_high_findings.get(date, 0)
            })
        
        # Reverse to get chronological order
        trend.reverse()
        
        return trend
    except Exception as e:
        logger.warning(f"Error fetching review trend for org {org_id}: {e}")
        return []


# ============================================================================
# Webhook Event Functions
# ============================================================================

async def record_webhook_event(
    org_id: str,
    repo_name: str,
    event_type: str,
    github_event_id: str,
    pr_number: Optional[int] = None,
    payload: Optional[dict] = None,
    processed: bool = False,
) -> dict:
    """Record a webhook event for tracking."""
    client = get_supabase_client()
    
    result = client.table("webhook_events").insert({
        "org_id": org_id,
        "repo_name": repo_name,
        "event_type": event_type,
        "github_event_id": github_event_id,
        "pr_number": pr_number,
        "payload": payload,
        "processed": processed,
    }).execute()
    
    return result.data[0] if result.data else {}


async def get_recent_webhook_events(org_id: str, limit: int = 50) -> list[dict]:
    """Get recent webhook events for an organization."""
    client = get_supabase_client()
    result = client.table("webhook_events").select("*").eq("org_id", org_id).order(
        "created_at", desc=True
    ).limit(limit).execute()
    return result.data if result.data else []


# ============================================================================
# Active Findings Functions
# ============================================================================

async def get_active_findings_stats(org_id: str, days: int = 30) -> dict:
    """Get statistics for active (non-resolved) findings.
    
    Queries the findings table directly for accurate real-time counts,
    rather than using cached counts from the reviews table.
    """
    client = get_supabase_client()
    
    # Use the new RPC function that queries findings table directly
    try:
        result = await _execute_query(
            client.rpc("get_active_findings_dashboard_stats", {
                "p_org_id": org_id,
                "p_days": days
            })
        )
        if result.data:
            return result.data
    except Exception as e:
        logger.warning(f"RPC get_active_findings_dashboard_stats failed: {e}")
    
    # Fallback: query findings table directly for accurate counts
    try:
        # Get total reviews from reviews table
        reviews_query = client.table("reviews").select("id", count="exact").eq("org_id", org_id)

        findings_query = client.table("findings").select(
            "id, severity, status"
        ).eq("org_id", org_id)

        reviews_result, result = await asyncio.gather(
            _execute_query(reviews_query),
            _execute_query(findings_query),
        )
        total_reviews = reviews_result.count if hasattr(reviews_result, 'count') else 0

        # Get active findings counts directly from findings table
        
        stats = {
            "total_reviews": total_reviews,
            "total_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "avg_review_time_ms": 0,
            "success_rate": 0,
            "blocked_count": 0,
        }
        
        if result.data:
            for finding in result.data:
                # Only count findings with status 'open' or null (default to open)
                status = finding.get("status", "open")
                if status == "open":
                    stats["total_findings"] += 1
                    # Check for severity in multiple possible field names
                    # The findings table stores it as 'severity' but API might use 'risk'
                    severity = finding.get("severity") or finding.get("risk", "medium")
                    # Normalize severity to lowercase for comparison
                    severity_lower = str(severity).lower()
                    if severity_lower in ["critical", "high"]:
                        stats["high_findings"] += 1
                    elif severity_lower == "medium":
                        stats["medium_findings"] += 1
                    elif severity_lower == "low":
                        stats["low_findings"] += 1
        
        return stats
    except Exception as e:
        logger.error(f"Error fetching active findings stats: {e}")
        return {
            "total_reviews": 0,
            "total_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "avg_review_time_ms": 0,
            "success_rate": 0,
            "blocked_count": 0,
            "resolved_findings": 0,  # Added missing field
        }


async def get_active_findings_by_category(org_id: str, limit: int = 10) -> list[dict]:
    """Get active (open) findings grouped by category."""
    client = get_supabase_client()
    
    try:
        # Filter by status='open' - findings with status 'open' or null are considered active
        result = await _execute_query(
            client.table("findings").select("category, severity, status").eq("org_id", org_id).or_("status.eq.open,status.is.null")
        )
        
        if not result.data:
            return []
        
        # Group by category
        categories = {}
        for finding in result.data:
            category = finding.get("category", "unknown")
            severity = finding.get("severity", "medium")
            
            if category not in categories:
                categories[category] = {"category": category, "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            
            categories[category]["count"] += 1
            if severity in ["critical", "high", "medium", "low"]:
                categories[category][severity] += 1
        
        # Sort by total count and limit
        sorted_categories = sorted(
            categories.values(),
            key=lambda x: x["count"],
            reverse=True
        )
        
        return sorted_categories[:limit]
    except Exception as e:
        logger.warning(f"Error fetching active findings by category for org {org_id}: {e}")
        return []


async def get_active_findings_trend(org_id: str, days: int = 30) -> list[dict]:
    """Get trend of active findings over time."""
    client = get_supabase_client()
    
    try:
        result = await _execute_query(
            client.rpc("get_active_findings_trend", {
                "p_org_id": org_id,
                "p_days": days
            })
        )
        
        if not result.data:
            return []
        
        # Normalize the data to ensure consistent field names
        normalized = []
        for item in result.data:
            normalized.append({
                "date": item.get("date", ""),
                "review_count": item.get("review_count", item.get("count", 0)),
                "findings_count": item.get("findings_count", 0),
                "high_count": item.get("high_count", 0)
            })
        
        return normalized
    except Exception as e:
        logger.error(f"Error getting active findings trend: {e}")
        return []


async def get_top_risky_repos_active(org_id: str, days: int = 30, limit: int = 10) -> list[dict]:
    """Get top risky repositories based on active findings."""
    client = get_supabase_client()
    
    try:
        result = await _execute_query(
            client.rpc("get_top_risky_repos_active", {
                "p_org_id": org_id,
                "p_days": days,
                "p_limit": limit
            })
        )
        
        return result.data if result.data else []
    except Exception as e:
        logger.error(f"Error getting top risky repos: {e}")
        return []


# ============================================================================
# Feedback Functions
# ============================================================================

async def create_feedback(
    org_id: str,
    fingerprint: str,
    label: str,
    finding_id: Optional[str] = None,
    repo_name: Optional[str] = None,
    comment: Optional[str] = None,
    created_by: Optional[str] = None,
    created_by_github: Optional[str] = None
) -> dict:
    """Create feedback on a finding."""
    client = get_supabase_client()
    
    result = client.table("finding_feedback").insert({
        "org_id": org_id,
        "finding_id": finding_id,
        "fingerprint": fingerprint,
        "repo_name": repo_name,
        "label": label,
        "comment": comment,
        "created_by": created_by,
        "created_by_github": created_by_github
    }).execute()
    
    return result.data[0] if result.data else {}


async def get_feedback_for_org(org_id: str, limit: int = 100) -> list[dict]:
    """Get recent feedback for an organization."""
    client = get_supabase_client()
    result = client.table("finding_feedback").select("*").eq(
        "org_id", org_id
    ).order("created_at", desc=True).limit(limit).execute()
    return result.data if result.data else []


async def get_feedback_stats(org_id: str) -> dict:
    """Get feedback statistics."""
    client = get_supabase_client()
    
    result = client.table("finding_feedback").select("label").eq("org_id", org_id).execute()
    
    stats = {
        "true_positive": 0,
        "false_positive": 0,
        "accepted_risk": 0,
        "total": 0
    }
    
    if result.data:
        for item in result.data:
            label = item.get("label")
            if label in stats:
                stats[label] += 1
            stats["total"] += 1
    
    return stats


# ============================================================================
# Suppression Rules Functions
# ============================================================================

async def get_active_suppressions(org_id: str) -> list[dict]:
    """Get active suppression rules for an organization."""
    client = get_supabase_client()
    
    result = client.table("suppression_rules").select("*").eq(
        "org_id", org_id
    ).eq("is_active", True).execute()
    
    # Filter out expired rules
    active_rules = []
    now = datetime.now(timezone.utc)  # Use timezone-aware datetime
    
    for rule in (result.data or []):
        if rule.get("expires_at"):
            expires_at = datetime.fromisoformat(rule["expires_at"].replace("Z", "+00:00"))
            if expires_at < now:
                continue
        active_rules.append(rule)
    
    return active_rules


async def create_suppression_rule(
    org_id: str,
    reason: str,
    fingerprint: Optional[str] = None,
    title_pattern: Optional[str] = None,
    file_pattern: Optional[str] = None,
    category: Optional[str] = None,
    expires_in_days: Optional[int] = None,
    created_by: Optional[str] = None
) -> dict:
    """Create a new suppression rule."""
    client = get_supabase_client()
    
    expires_at = None
    if expires_in_days:
        expires_at = (datetime.utcnow() + timedelta(days=expires_in_days)).isoformat()
    
    result = client.table("suppression_rules").insert({
        "org_id": org_id,
        "fingerprint": fingerprint,
        "title_pattern": title_pattern,
        "file_pattern": file_pattern,
        "category": category,
        "reason": reason,
        "expires_at": expires_at,
        "created_by": created_by
    }).execute()
    
    return result.data[0] if result.data else {}


async def delete_suppression_rule(rule_id: str, org_id: str) -> bool:
    """Deactivate a suppression rule."""
    client = get_supabase_client()
    result = client.table("suppression_rules").update({
        "is_active": False
    }).eq("id", rule_id).eq("org_id", org_id).execute()
    return len(result.data) > 0 if result.data else False


# ============================================================================
# Chat Functions
# ============================================================================

async def create_chat_interaction(
    org_id: str,
    repo_name: str,
    pr_number: int,
    command: str,
    response: str,
    finding_id: Optional[str] = None,
    question: Optional[str] = None,
    github_user: Optional[str] = None
) -> dict:
    """Record a chat interaction."""
    client = get_supabase_client()
    
    result = client.table("chat_interactions").insert({
        "org_id": org_id,
        "repo_name": repo_name,
        "pr_number": pr_number,
        "command": command,
        "finding_id": finding_id,
        "question": question,
        "response": response,
        "github_user": github_user
    }).execute()
    
    return result.data[0] if result.data else {}


async def get_finding_by_id(finding_id: str) -> Optional[dict]:
    """Get a finding by ID."""
    client = get_supabase_client()
    try:
        result = client.table("findings").select("*").eq("id", finding_id).maybe_single().execute()
        return result.data if result and result.data else None
    except Exception as e:
        logger.warning(f"Error fetching finding {finding_id}: {e}")
        return None


async def get_finding_by_id_for_org(finding_id: str, org_id: str) -> Optional[dict]:
    """Get a finding by ID, ensuring it belongs to the specified organization.
    
    Args:
        finding_id: The finding ID
        org_id: The organization ID to check ownership
        
    Returns:
        The finding dict if found and belongs to org, None otherwise
    """
    client = get_supabase_client()
    try:
        result = client.table("findings").select("*").eq("id", finding_id).eq("org_id", org_id).maybe_single().execute()
        return result.data if result and result.data else None
    except Exception as e:
        logger.warning(f"Error fetching finding {finding_id} for org {org_id}: {e}")
        return None


async def get_recent_findings(org_id: str, limit: int = 10) -> list[dict]:
    """Get recent findings for an organization."""
    client = get_supabase_client()
    fn_start = time.perf_counter()
    try:
        # Fetch findings with review metadata in a single query.
        findings_query_start = time.perf_counter()
        result = await _execute_query(
            client.table("findings").select(
                "*, reviews:review_id(repo_name,pr_number,pr_title)"
            ).eq("org_id", org_id).order("created_at", desc=True).limit(limit)
        )
        findings_query_ms = (time.perf_counter() - findings_query_start) * 1000
        findings_count = len(result.data) if result.data else 0
        logger.info(
            f"[timing][db/get_recent_findings] findings_query_ms={findings_query_ms:.2f} org_id={org_id} limit={limit} findings_count={findings_count}"
        )
        
        logger.info(f"[get_recent_findings] Found {findings_count} findings for org {org_id}")
        
        if not result.data:
            total_ms = (time.perf_counter() - fn_start) * 1000
            logger.info(
                f"[timing][db/get_recent_findings] total_ms={total_ms:.2f} org_id={org_id} returned_count=0"
            )
            return []
        
        # Flatten the response to include repo_name and pr_number at top level
        flatten_start = time.perf_counter()
        findings = []
        for item in result.data:
            finding = dict(item)

            # Embedded review data may come back as dict or list depending on relationship config.
            review_data = finding.pop("reviews", None)
            if isinstance(review_data, list):
                review_data = review_data[0] if review_data else None
            if isinstance(review_data, dict):
                finding["repo_name"] = review_data.get("repo_name")
                finding["pr_number"] = review_data.get("pr_number")
                finding["pr_title"] = review_data.get("pr_title")

            findings.append(finding)
        flatten_ms = (time.perf_counter() - flatten_start) * 1000
        total_ms = (time.perf_counter() - fn_start) * 1000
        logger.info(
            f"[timing][db/get_recent_findings] flatten_ms={flatten_ms:.2f} total_ms={total_ms:.2f} returned_count={len(findings)}"
        )
        
        logger.info(f"[get_recent_findings] Returning {len(findings)} findings")
        return findings
    except Exception as e:
        logger.warning(f"Error fetching recent findings for org {org_id}: {e}")
        return []


async def get_findings_for_pr(org_id: str, repo_name: str, pr_number: int) -> list[dict]:
    """Get all findings for a specific PR."""
    client = get_supabase_client()
    
    # First get the latest review for this PR
    review = client.table("reviews").select("id").eq(
        "org_id", org_id
    ).eq("repo_name", repo_name).eq(
        "pr_number", pr_number
    ).order("created_at", desc=True).limit(1).execute()
    
    if not review.data:
        return []
    
    review_id = review.data[0]["id"]
    
    # Get all findings for this review
    result = client.table("findings").select("*").eq("review_id", review_id).execute()
    return result.data if result.data else []


# ============================================================================
# Finding Resolution Functions
# ============================================================================

async def get_previous_pr_review(
    org_id: str,
    repo_name: str,
    pr_number: int,
    exclude_id: Optional[str] = None
) -> Optional[dict]:
    """
    Get the most recent previous review for a PR.
    
    Args:
        org_id: Organization ID
        repo_name: Repository name
        pr_number: PR number
        exclude_id: Optional review ID to exclude (the current one)
        
    Returns:
        Previous review data or None
    """
    client = get_supabase_client()
    
    query = client.table("reviews").select("*").eq("org_id", org_id).eq(
        "repo_name", repo_name
    ).eq("pr_number", pr_number).order("created_at", desc=True).limit(2)
    
    result = query.execute()
    
    if not result.data or len(result.data) == 0:
        return None
    
    # If exclude_id is provided, return the one that's not excluded
    if exclude_id:
        for review in result.data:
            if review["id"] != exclude_id:
                return review
        return None
    else:
        # Return the most recent (first)
        return result.data[0]


async def get_previous_pr_findings(
    org_id: str,
    repo_name: str,
    pr_number: int,
    current_review_id: Optional[str] = None
) -> list[dict]:
    """
    Get findings from the previous review of a PR.
    
    This is used to determine which findings are new vs. existing.
    """
    client = get_supabase_client()
    
    # Get the previous review (excluding current)
    previous_review = await get_previous_pr_review(org_id, repo_name, pr_number, current_review_id)
    
    if not previous_review:
        return []
    
    # Get findings from previous review
    result = client.table("findings").select("*").eq("review_id", previous_review["id"]).execute()
    return result.data if result.data else []


async def mark_findings_resolved(
    org_id: str,
    fingerprints: list[str],
    resolved_by: Optional[str] = None,
    resolution_reason: str = "fixed"
) -> int:
    """
    Mark specific findings as resolved by fingerprint.
    
    Args:
        org_id: The organization ID
        fingerprints: List of finding fingerprints to resolve
        resolved_by: User ID who resolved them
        resolution_reason: Reason for resolution (fixed, false_positive, etc.)
        
    Returns:
        Number of findings marked as resolved
    """
    if not fingerprints:
        return 0
    
    client = get_supabase_client()
    
    # Update findings status by matching fingerprints
    result = client.table("findings").update({
        "status": "resolved",
        "resolved_reason": resolution_reason,
        "resolved_at": datetime.utcnow().isoformat(),
        "resolved_by_user_id": resolved_by
    }).eq("org_id", org_id).in_("fingerprint", fingerprints).execute()
    
    count = len(result.data) if result.data else 0
    logger.info(f"Marked {count} findings as resolved for org {org_id}")
    
    return count


async def compare_pr_reviews(*args):
    """
    Compare current and previous findings to identify new, existing, and resolved.

    Supports two call patterns:
    1) compare_pr_reviews(current_findings: list[dict], previous_findings: list[dict])
       -> tuple[new_findings, existing_findings, resolved_findings]
    2) compare_pr_reviews(org_id, repo_name, pr_number, current_fingerprints, previous_fingerprints)
       -> dict with counts and fingerprint lists used by persistence flows
    """
    if len(args) == 5:
        _, _, _, current_fingerprints, previous_fingerprints = args

        current_set = {fp for fp in (current_fingerprints or []) if fp}
        previous_set = {fp for fp in (previous_fingerprints or []) if fp}

        new_fingerprints = sorted(current_set - previous_set)
        resolved_fingerprints = sorted(previous_set - current_set)
        still_present_fingerprints = sorted(current_set & previous_set)

        return {
            "new_count": len(new_fingerprints),
            "resolved_count": len(resolved_fingerprints),
            "still_present_count": len(still_present_fingerprints),
            "new_fingerprints": new_fingerprints,
            "resolved_fingerprints": resolved_fingerprints,
            "still_present_fingerprints": still_present_fingerprints,
        }

    if len(args) != 2:
        raise TypeError(
            "compare_pr_reviews expects either 2 args (current_findings, previous_findings) "
            "or 5 args (org_id, repo_name, pr_number, current_fingerprints, previous_fingerprints)"
        )

    current_findings, previous_findings = args

    # Create fingerprint sets
    current_fps = {f.get("fingerprint", f.get("id")): f for f in current_findings}
    previous_fps = {f.get("fingerprint", f.get("id")): f for f in previous_findings}
    
    # Find new findings (in current but not in previous)
    new_findings = []
    for fp, finding in current_fps.items():
        if fp not in previous_fps:
            new_findings.append(finding)
    
    # Find existing findings (in both)
    existing_findings = []
    for fp, finding in current_fps.items():
        if fp in previous_fps:
            existing_findings.append(finding)
    
    # Find resolved findings (in previous but not in current)
    resolved_findings = []
    for fp, finding in previous_fps.items():
        if fp not in current_fps:
            resolved_findings.append(finding)
    
    return new_findings, existing_findings, resolved_findings


async def link_review_to_previous(
    review_id: str,
    previous_review_id: str
) -> bool:
    """
    Link a review to its previous version for tracking.
    
    Args:
        review_id: Current review ID
        previous_review_id: Previous review ID
        
    Returns:
        True if successful
    """
    client = get_supabase_client()
    
    try:
        result = client.table("reviews").update({
            "previous_review_id": previous_review_id
        }).eq("id", review_id).execute()
        
        return len(result.data) > 0 if result.data else False
    except Exception as e:
        logger.warning(f"Error linking review {review_id} to previous: {e}")
        return False


async def resolve_finding(
    finding_id: str,
    org_id: str,
    user_id: Optional[str] = None,
    reason: str = "fixed",
    comment: Optional[str] = None
) -> dict:
    """
    Resolve a finding with reason and optional comment.
    
    Returns:
        Resolution result with finding data
    """
    client = get_supabase_client()
    
    try:
        result = client.rpc('resolve_finding', {
            'p_finding_id': finding_id,
            'p_org_id': org_id,
            'p_user_id': user_id,
            'p_reason': reason,
            'p_comment': comment
        }).execute()
        
        return result.data if result.data else {}
    except Exception as e:
        logger.error(f"Error resolving finding: {e}")
        raise


async def bulk_resolve_findings(
    finding_ids: list[str],
    org_id: str,
    user_id: Optional[str] = None,
    reason: str = "fixed",
    comment: Optional[str] = None
) -> dict:
    """
    Resolve multiple findings at once.
    
    Returns:
        Result with count of resolved findings
    """
    client = get_supabase_client()
    
    try:
        result = client.rpc('bulk_resolve_findings', {
            'p_finding_ids': finding_ids,
            'p_org_id': org_id,
            'p_user_id': user_id,
            'p_reason': reason,
            'p_comment': comment
        }).execute()
        
        return result.data if result.data else {"resolved_count": 0}
    except Exception as e:
        logger.error(f"Error bulk resolving findings: {e}")
        raise


async def auto_resolve_pr_findings(
    org_id: str,
    repo_name: str,
    pr_number: int,
    review_id: str
) -> int:
    """
    Automatically resolve findings that were fixed in a new PR version.
    
    This marks findings from previous reviews of the same PR as resolved
    when they no longer appear in the current review.
    
    Args:
        org_id: Organization ID
        repo_name: Repository name
        pr_number: PR number
        review_id: Current review ID
        
    Returns:
        Number of auto-resolved findings
    """
    client = get_supabase_client()
    
    try:
        result = client.rpc('auto_resolve_pr_findings', {
            'p_org_id': org_id,
            'p_repo_name': repo_name,
            'p_pr_number': pr_number,
            'p_review_id': review_id
        }).execute()
        
        return result.data if result.data else 0
    except Exception as e:
        logger.error(f"Error auto-resolving PR findings: {e}")
        return 0


async def reopen_finding(
    finding_id: str,
    org_id: str,
    user_id: Optional[str] = None,
    reason: Optional[str] = None
) -> bool:
    """
    Reopen a resolved finding.
    
    Returns:
        True if successful, False otherwise
    """
    client = get_supabase_client()
    
    try:
        result = client.rpc('reopen_finding', {
            'p_finding_id': finding_id,
            'p_org_id': org_id,
            'p_user_id': user_id,
            'p_reason': reason
        }).execute()
        
        return result.data if result.data else False
    except Exception as e:
        logger.error(f"Error reopening finding: {e}")
        return False


async def get_finding_status_history(
    finding_id: str,
    org_id: str
) -> list[dict]:
    """Get status change history for a finding."""
    client = get_supabase_client()
    
    try:
        result = client.table("finding_status_history").select("*").eq(
            "finding_id", finding_id
        ).eq("org_id", org_id).order("created_at", desc=True).execute()
        
        return result.data if result.data else []
    except Exception as e:
        logger.error(f"Error fetching status history: {e}")
        return []



