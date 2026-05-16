"""
Application configuration using Pydantic Settings.

Loads configuration from environment variables with sensible defaults.
Production-ready security configuration.
"""

from functools import lru_cache
from typing import Literal, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from dotenv import load_dotenv
import os

load_dotenv()


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra='ignore',  # Ignore extra environment variables
    )
    
    # Environment mode
    environment: Literal["development", "staging", "production"] = "development"
    
    # Frontend URL (for CORS and redirects)
    frontend_url: Optional[str] = os.getenv("FRONTEND_URL")

    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    
    # LLM Configuration
    llm_provider: Literal["claude", "openai", "gemini", "groq"] = "claude"
    llm_api_key: Optional[str] = None
    llm_model: Optional[str] = None
    
    # Database (Supabase)
    supabase_url: Optional[str] = os.getenv("SUPABASE_URL")
    supabase_service_key: Optional[str] = os.getenv("SUPABASE_SERVICE_KEY")
    supabase_jwt_secret: Optional[str] = os.getenv("SUPABASE_JWT_SECRET")
    
    # Redis Configuration (for production rate limiting)
    redis_url: Optional[str] = os.getenv("REDIS_URL")
    
    # API Authentication - Basic Bearer token (legacy, still supported)
    api_auth_token: Optional[str] = None
    
    # Multi-tenant mode - when enabled, requires X-Tenant-ID or scoped tokens
    multi_tenant_mode: bool = os.getenv("MULTI_TENANT_MODE", "false").lower() == "true"
    
    # HMAC Authentication - Enterprise security
    hmac_secret: Optional[str] = os.getenv("HMAC_SECRET")
    hmac_timestamp_tolerance: int = 300  # 5 minutes tolerance for timestamp
    
    # Rate Limiting
    rate_limit_requests: int = 100  # Max requests per window
    rate_limit_window: int = 3600   # Window in seconds (1 hour)
    rate_limit_token_creation: int = 10  # Max token creations per hour
    
    # Request Size Limits
    max_diff_size: int = 500000     # 500KB max diff size
    max_request_size: int = 1000000  # 1MB max total request size
    
    # Token Security Settings
    token_max_lifetime_days: int = 90  # Maximum token lifetime (enforced)
    token_default_lifetime_days: int = 30  # Default token lifetime
    token_inactivity_timeout_days: int = 180  # Revoke after inactivity
    allow_wildcard_scopes: bool = False  # Disable wildcard scopes in production
    # JWT verification leeway to absorb small NTP drift between systems.
    jwt_clock_skew_seconds: int = 180
    
    # CORS Configuration
    cors_allowed_origins: str = os.getenv("CORS_ALLOWED_ORIGINS", "*")  # Comma-separated list
    cors_allow_credentials: bool = True
    
    # Security Headers
    enable_security_headers: bool = True
    
    # Cookie Settings (for HttpOnly token storage)
    cookie_secure: bool = True  # Require HTTPS
    cookie_samesite: Literal["strict", "lax", "none"] = "strict"
    cookie_domain: Optional[str] = None
    
    # Logging - Security settings
    log_level: str = "DEBUG"
    # SECURITY: Never enable in production - diffs may contain sensitive source code
    log_diff_content: bool = False
    
    # Audit Logging
    enable_audit_logging: bool = True
    
    # Stripe Configuration
    stripe_secret_key: Optional[str] = os.getenv("STRIPE_SECRET_KEY")
    stripe_publishable_key: Optional[str] = os.getenv("STRIPE_PUBLISHABLE_KEY")
    stripe_webhook_secret: Optional[str] = os.getenv("STRIPE_WEBHOOK_SECRET")
    stripe_price_id_team_monthly: Optional[str] = os.getenv("STRIPE_PRICE_ID_TEAM_MONTHLY")
    stripe_price_id_team_yearly: Optional[str] = os.getenv("STRIPE_PRICE_ID_TEAM_YEARLY")
    
    # GitHub App Configuration
    github_app_id: Optional[str] = os.getenv("GITHUB_APP_ID")
    github_app_private_key: Optional[str] = os.getenv("GITHUB_APP_PRIVATE_KEY")
    github_app_webhook_secret: Optional[str] = os.getenv("GITHUB_APP_WEBHOOK_SECRET")

    # GitLab App Configuration
    gitlab_app_client_id: Optional[str] = os.getenv("GITLAB_APP_CLIENT_ID")
    gitlab_app_client_secret: Optional[str] = os.getenv("GITLAB_APP_CLIENT_SECRET")
    gitlab_app_webhook_secret: Optional[str] = os.getenv("GITLAB_APP_WEBHOOK_SECRET")
    gitlab_instance_url: str = os.getenv("GITLAB_INSTANCE_URL", "https://gitlab.com")
    
    # Graceful Shutdown
    shutdown_timeout_seconds: int = 30
    
    @field_validator('cors_allowed_origins')
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        """Validate CORS origins format."""
        v = (v or "").strip().strip('"').strip("'")
        if v and v != "*":
            origins = [o.strip().strip('"').strip("'") for o in v.split(",")]
            for origin in origins:
                if origin and not (origin.startswith("http://") or origin.startswith("https://")):
                    raise ValueError(f"Invalid CORS origin format: {origin}")
            return ",".join(o for o in origins if o)
        return v

    @field_validator("jwt_clock_skew_seconds")
    @classmethod
    def validate_jwt_clock_skew(cls, v: int) -> int:
        """Keep JWT leeway in a safe operational range."""
        if v < 0:
            raise ValueError("JWT_CLOCK_SKEW_SECONDS cannot be negative")
        if v > 600:
            raise ValueError("JWT_CLOCK_SKEW_SECONDS cannot exceed 600 seconds")
        return v
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"
    
    @property
    def cors_origins_list(self) -> list[str]:
        """Get list of allowed CORS origins."""
        if not self.cors_allowed_origins:
            # Default based on environment
            if self.is_production:
                return []  # No origins allowed by default in production
            return ["http://localhost:3000", "http://127.0.0.1:3000"]
        return [
            o.strip().strip('"').strip("'")
            for o in self.cors_allowed_origins.split(",")
            if o.strip().strip('"').strip("'")
        ]
    
    @property
    def database_configured(self) -> bool:
        """Check if database is configured."""
        return bool(self.supabase_url and self.supabase_service_key)
    
    @property
    def redis_configured(self) -> bool:
        """Check if Redis is configured."""
        return bool(self.redis_url)
    
    @property
    def effective_model(self) -> str:
        """Get the effective model name based on provider."""
        if self.llm_model:
            return self.llm_model
        model_defaults = {
            "claude": "claude-sonnet-4-20250514",
            "openai": "gpt-4o",
            "gemini": "gemini-2.0-flash",
            "groq": "llama-3.3-70b-versatile",
        }
        return model_defaults.get(self.llm_provider, "gpt-4o")
    
    @property
    def hmac_enabled(self) -> bool:
        """Check if HMAC authentication is enabled."""
        return bool(self.hmac_secret)
    
    def validate_config(self) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []
        warnings = []
        
        if not self.llm_api_key:
            errors.append("LLM_API_KEY is required")
        
        # In multi-tenant mode, we rely on database tokens
        # In single-tenant mode, we need API_AUTH_TOKEN
        if not self.multi_tenant_mode:
            if not self.api_auth_token:
                errors.append("API_AUTH_TOKEN is required for secure operation (or enable MULTI_TENANT_MODE)")
            if self.api_auth_token and len(self.api_auth_token) < 32:
                errors.append("API_AUTH_TOKEN should be at least 32 characters for security")
        
        # Check database config for multi-tenant mode
        if self.multi_tenant_mode:
            if not self.supabase_url:
                errors.append("SUPABASE_URL is required for multi-tenant mode")
            if not self.supabase_service_key:
                errors.append("SUPABASE_SERVICE_KEY is required for multi-tenant mode")
        
        if self.hmac_enabled and self.hmac_secret and len(self.hmac_secret) < 32:
            errors.append("HMAC_SECRET should be at least 32 characters for security")
        
        # Production-specific checks
        if self.is_production:
            if not self.cors_allowed_origins:
                errors.append("CORS_ALLOWED_ORIGINS must be explicitly set in production")
            if self.allow_wildcard_scopes:
                errors.append("Wildcard scopes must be disabled in production (ALLOW_WILDCARD_SCOPES=false)")
            if not self.cookie_secure:
                errors.append("COOKIE_SECURE must be true in production")
            if not self.redis_configured:
                warnings.append("Redis not configured - using in-memory rate limiting (not recommended for production)")
            if not self.enable_audit_logging:
                warnings.append("Audit logging is disabled in production")
        
        return errors
    
    def get_warnings(self) -> list[str]:
        """Get configuration warnings (non-blocking issues)."""
        warnings = []
        
        if self.is_production:
            if not self.redis_configured:
                warnings.append("Redis not configured - using in-memory rate limiting (not recommended for production)")
            if not self.enable_audit_logging:
                warnings.append("Audit logging is disabled in production")
            if self.log_diff_content:
                warnings.append("log_diff_content is enabled - this may expose sensitive source code")
        
        return warnings


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()

