"""
GitHub App authentication utilities.

Provides functions for:
- Generating JWT for GitHub App authentication
- Exchanging JWT for installation access tokens
- Caching installation tokens
"""

import time
import jwt
import logging
from typing import Optional, Dict
from datetime import datetime, timedelta, timezone

import httpx

from .config import Settings, get_settings

logger = logging.getLogger(__name__)

# Cache for installation tokens: {installation_id: (token, expires_at, permissions)}
_installation_token_cache: Dict[int, tuple[str, datetime, Dict[str, str]]] = {}


def generate_app_jwt(settings: Optional[Settings] = None) -> str:
    """
    Generate a JWT for GitHub App authentication.
    
    The JWT is used to authenticate as the GitHub App itself.
    It must be signed with the app's private key.
    
    Args:
        settings: Application settings (uses cached settings if not provided)
        
    Returns:
        JWT token string
        
    Raises:
        ValueError: If GitHub App credentials are not configured
    """
    if settings is None:
        settings = get_settings()
    
    if not settings.github_app_id:
        raise ValueError("GITHUB_APP_ID not configured")
    
    if not settings.github_app_private_key:
        raise ValueError("GITHUB_APP_PRIVATE_KEY not configured")
    
    now = int(time.time())
    payload = {
        "iat": now - 60,  # Issued at (with 60 second clock drift tolerance)
        "exp": now + 600,  # Expires in 10 minutes (max allowed by GitHub)
        "iss": settings.github_app_id,  # GitHub App ID
    }
    
    # Sign with RSA private key
    token = jwt.encode(
        payload,
        settings.github_app_private_key,
        algorithm="RS256"
    )
    
    return token


async def get_installation_token(
    installation_id: int,
    settings: Optional[Settings] = None,
    force_refresh: bool = False
) -> tuple[str, Dict[str, str]]:
    """
    Get an installation access token for a specific GitHub App installation.

    Installation tokens are cached and refreshed automatically when they expire.
    Tokens expire after 1 hour (GitHub's default).

    Args:
        installation_id: The GitHub App installation ID
        settings: Application settings
        force_refresh: Force a new token to be generated

    Returns:
        Tuple of (installation access token, token permissions dict)

    Raises:
        ValueError: If GitHub App credentials are not configured
        InstallationNotFoundError: If the installation has been uninstalled
        httpx.HTTPError: If the API request fails (other errors)
    """
    global _installation_token_cache

    if settings is None:
        settings = get_settings()

    # Check cache first
    if not force_refresh and installation_id in _installation_token_cache:
        token, expires_at, permissions = _installation_token_cache[installation_id]
        # Refresh if token expires in less than 5 minutes
        # Use timezone-aware datetime to match expires_at format
        if datetime.now(timezone.utc) < expires_at - timedelta(minutes=5):
            logger.debug(f"Using cached installation token for installation {installation_id}")
            return token, permissions

    # Generate app JWT
    app_jwt = generate_app_jwt(settings)

    # Exchange for installation token
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"https://api.github.com/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30.0
            )

            # Handle 404 - installation was uninstalled
            if response.status_code == 404:
                logger.warning(f"GitHub App installation {installation_id} not found - may have been uninstalled")
                # Mark installation as inactive in database
                await mark_installation_inactive(installation_id)
                raise InstallationNotFoundError(
                    f"Installation {installation_id} not found. "
                    "The GitHub App may have been uninstalled from the organization."
                )

            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"GitHub App installation {installation_id} not found - may have been uninstalled")
                await mark_installation_inactive(installation_id)
                raise InstallationNotFoundError(
                    f"Installation {installation_id} not found. "
                    "The GitHub App may have been uninstalled from the organization."
                ) from e
            raise

    token = data["token"]
    expires_at_str = data.get("expires_at")
    permissions = data.get("permissions", {})

    # Parse expiration time
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
    else:
        # Default to 1 hour if not provided - use timezone-aware datetime
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    # Cache the token with permissions
    _installation_token_cache[installation_id] = (token, expires_at, permissions)

    # Log token generation (minimal info)
    logger.info(f"Generated installation token for installation {installation_id} "
                f"(contents={permissions.get('contents', 'none')})")
    return token, permissions


async def mark_installation_inactive(installation_id: int) -> None:
    """Mark a GitHub App installation as inactive when it's uninstalled."""
    from .database import get_supabase_client
    client = get_supabase_client()
    try:
        client.table("github_app_installations").update({
            "is_active": False,
            "suspended_at": datetime.utcnow().isoformat()
        }).eq("installation_id", installation_id).execute()
        logger.info(f"Marked installation {installation_id} as inactive")
    except Exception as e:
        logger.error(f"Failed to mark installation {installation_id} as inactive: {e}")


class InstallationNotFoundError(Exception):
    """Raised when a GitHub App installation is not found (uninstalled)."""
    pass


async def get_installation_for_repo(
    owner: str,
    repo: str,
    settings: Optional[Settings] = None
) -> Optional[int]:
    """
    Get the installation ID for a specific repository.
    
    This queries the GitHub API to find which installation has access to the repo.
    
    Args:
        owner: Repository owner (user or org)
        repo: Repository name
        settings: Application settings
        
    Returns:
        Installation ID or None if not found
    """
    if settings is None:
        settings = get_settings()
    
    try:
        app_jwt = generate_app_jwt(settings)
        
        async with httpx.AsyncClient() as client:
            # Query the repository to get installation info
            response = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/installation",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30.0
            )
            
            if response.status_code == 404:
                logger.warning(f"No GitHub App installation found for {owner}/{repo}")
                return None
            
            response.raise_for_status()
            data = response.json()
            
            installation_id = data.get("id")
            if installation_id:
                logger.info(f"Found installation {installation_id} for {owner}/{repo}")
                return installation_id
            
            return None
            
    except Exception as e:
        logger.error(f"Failed to get installation for {owner}/{repo}: {e}")
        return None


def clear_token_cache():
    """Clear the installation token cache. Useful for testing."""
    global _installation_token_cache
    _installation_token_cache.clear()
    logger.info("Cleared installation token cache")


async def get_github_app_info(settings: Optional[Settings] = None) -> dict:
    """
    Get GitHub App information including installation URL.
    
    Args:
        settings: Application settings
        
    Returns:
        Dict with app information including html_url for installation
        
    Raises:
        ValueError: If GitHub App credentials are not configured
        httpx.HTTPError: If the API request fails
    """
    if settings is None:
        settings = get_settings()
    
    try:
        app_jwt = generate_app_jwt(settings)
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/app",
                headers={
                    "Authorization": f"Bearer {app_jwt}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error(f"Failed to get GitHub App info: {e}")
        raise
