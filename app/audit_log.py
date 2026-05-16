"""
Audit logging system for the AI AppSec PR Reviewer.

Provides comprehensive audit trail for security-relevant events
including authentication, authorization, and administrative actions.
"""

import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger("audit")


class AuditEventType(str, Enum):
    """Types of auditable events."""
    # Authentication Events
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    AUTH_TOKEN_EXPIRED = "auth.token_expired"
    AUTH_TOKEN_REVOKED = "auth.token_revoked"
    
    # Token Management
    TOKEN_CREATED = "token.created"
    TOKEN_ROTATED = "token.rotated"
    TOKEN_REVOKED = "token.revoked"
    TOKEN_VALIDATED = "token.validated"
    TOKEN_VALIDATION_FAILED = "token.validation_failed"
    
    # Authorization Events
    AUTHZ_SUCCESS = "authz.success"
    AUTHZ_FAILURE = "authz.failure"
    SCOPE_DENIED = "authz.scope_denied"
    
    # Administrative Actions
    ORG_CREATED = "admin.org_created"
    ORG_UPDATED = "admin.org_updated"
    USER_INVITED = "admin.user_invited"
    USER_JOINED = "admin.user_joined"
    POLICY_UPDATED = "admin.policy_updated"
    SUPPRESSION_CREATED = "admin.suppression_created"
    SUPPRESSION_DELETED = "admin.suppression_deleted"
    REPO_CONFIG_UPDATED = "admin.repo_config_updated"
    
    # Security Review Events
    REVIEW_STARTED = "review.started"
    REVIEW_COMPLETED = "review.completed"
    REVIEW_FAILED = "review.failed"
    
    # Rate Limiting
    RATE_LIMIT_EXCEEDED = "security.rate_limit_exceeded"
    
    # Security Incidents
    SUSPICIOUS_ACTIVITY = "security.suspicious_activity"
    BRUTE_FORCE_DETECTED = "security.brute_force_detected"


@dataclass
class AuditEvent:
    """Represents an auditable event."""
    event_type: AuditEventType
    timestamp: str
    request_id: Optional[str] = None
    org_id: Optional[str] = None
    actor_type: Optional[str] = None  # 'user', 'service', 'system'
    actor_id: Optional[str] = None
    resource_type: Optional[str] = None  # 'api_token', 'org', etc
    resource_id: Optional[str] = None
    action: Optional[str] = None
    details: Optional[dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True  # True or False
    failure_reason: Optional[str] = None
    # Legacy fields for backward compatibility
    user_id: Optional[str] = None
    token_id: Optional[str] = None
    token_prefix: Optional[str] = None
    outcome: Optional[str] = None  # Deprecated: use success + failure_reason
    error_message: Optional[str] = None  # Deprecated: use failure_reason
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, filtering None values."""
        data = asdict(self)
        # Convert enum to string
        data["event_type"] = self.event_type.value
        
        # Map legacy fields to new schema for backward compatibility
        if self.outcome:
            data["success"] = (self.outcome == "success")
            data["failure_reason"] = self.error_message if self.outcome != "success" else None
        
        # Filter None values for cleaner logs
        # Also filter out legacy fields that have been mapped
        exclude_keys = {"outcome", "error_message", "user_id", "token_id", "token_prefix"}
        return {k: v for k, v in data.items() if v is not None and k not in exclude_keys}
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """
    Centralized audit logger for security events.
    
    Logs events to both the application log and optionally
    to a database for persistence and analysis.
    """
    
    def __init__(self, enabled: bool = True, db_client=None):
        self.enabled = enabled
        self.db_client = db_client
        self._setup_logger()
    
    def _setup_logger(self):
        """Setup dedicated audit logger with structured output."""
        self.audit_logger = logging.getLogger("audit")
        # Ensure audit logs are always at INFO level regardless of global config
        self.audit_logger.setLevel(logging.INFO)
        
        # Add handler if not already present
        if not self.audit_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - AUDIT - %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S%z'
            ))
            self.audit_logger.addHandler(handler)
    
    def log(self, event: AuditEvent) -> None:
        """Log an audit event."""
        if not self.enabled:
            return
        
        # Log to structured logger
        self.audit_logger.info(event.to_json())
        
        # Persist to database if available
        if self.db_client:
            self._persist_to_db(event)
    
    def _persist_to_db(self, event: AuditEvent) -> None:
        """Persist audit event to database."""
        try:
            if self.db_client:
                # Map legacy resource field to new schema
                resource_type, resource_id = self._parse_resource(event)
                
                # Map legacy user_id/token_id to actor_id
                actor_id = event.actor_id or event.user_id or event.token_id
                actor_type = event.actor_type or ("user" if event.user_id else "service")
                
                self.db_client.table("audit_logs").insert({
                    "event_type": event.event_type.value,
                    "request_id": event.request_id,
                    "org_id": event.org_id,
                    "actor_type": actor_type,
                    "actor_id": str(actor_id) if actor_id else None,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "action": event.action,
                    "details": event.details,
                    "ip_address": event.ip_address,
                    "user_agent": event.user_agent,
                    "success": event.success,
                    "failure_reason": event.failure_reason or event.error_message,
                    "created_at": event.timestamp,
                }).execute()
        except Exception as e:
            # Don't fail the request if audit logging fails
            logger.error(f"Failed to persist audit log: {e}")
    
    def _parse_resource(self, event: AuditEvent) -> tuple[Optional[str], Optional[str]]:
        """Parse resource fields into type and id."""
        # New schema: resource_type and resource_id are separate fields
        
        # If resource_type/resource_id are already set, use them
        if event.resource_type or event.resource_id:
            return event.resource_type, event.resource_id
        
        # Legacy mapping from token_id to api_token resource
        if event.token_id:
            return "api_token", event.token_id
        
        # Legacy mapping from user_id (auth events without token)
        if event.user_id and not event.token_id:
            return "user", event.user_id
        
        return None, None
    
    # Convenience methods for common events
    
    def log_auth_success(
        self,
        request_id: str,
        org_id: str,
        token_id: Optional[str] = None,
        token_prefix: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """Log successful authentication."""
        self.log(AuditEvent(
            event_type=AuditEventType.AUTH_SUCCESS,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            org_id=org_id,
            actor_id=token_id,
            resource_type="api_token" if token_id else None,
            resource_id=token_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={
                "token_prefix": token_prefix,
            },
        ))
    
    def log_auth_failure(
        self,
        request_id: str,
        reason: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        token_prefix: Optional[str] = None,
    ) -> None:
        """Log failed authentication."""
        self.log(AuditEvent(
            event_type=AuditEventType.AUTH_FAILURE,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            ip_address=ip_address,
            user_agent=user_agent,
            token_prefix=token_prefix,
            outcome="failure",
            error_message=reason,
        ))
    
    def log_token_created(
        self,
        request_id: str,
        org_id: str,
        token_id: str,
        token_prefix: str,
        scopes: list[str],
        created_by: Optional[str] = None,
        expires_at: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log token creation."""
        self.log(AuditEvent(
            event_type=AuditEventType.TOKEN_CREATED,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            org_id=org_id,
            actor_id=created_by,
            resource_type="api_token",
            resource_id=token_id,
            ip_address=ip_address,
            action="create",
            details={
                "scopes": scopes,
                "expires_at": expires_at,
                "token_prefix": token_prefix,
            },
        ))
    
    def log_token_revoked(
        self,
        request_id: str,
        org_id: str,
        token_id: str,
        revoked_by: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log token revocation."""
        self.log(AuditEvent(
            event_type=AuditEventType.TOKEN_REVOKED,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            org_id=org_id,
            actor_id=revoked_by,
            resource_type="api_token",
            resource_id=token_id,
            ip_address=ip_address,
            action="revoke",
        ))
    
    def log_token_rotated(
        self,
        request_id: str,
        org_id: str,
        old_token_id: str,
        new_token_id: str,
        new_token_prefix: str,
        rotated_by: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Log token rotation."""
        self.log(AuditEvent(
            event_type=AuditEventType.TOKEN_ROTATED,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            org_id=org_id,
            actor_id=rotated_by,
            resource_type="api_token",
            resource_id=new_token_id,
            ip_address=ip_address,
            action="rotate",
            details={
                "old_token_id": old_token_id,
                "new_token_prefix": new_token_prefix,
            },
        ))
    
    def log_authz_failure(
        self,
        request_id: str,
        org_id: str,
        required_scope: str,
        token_scopes: list[str],
        ip_address: Optional[str] = None,
    ) -> None:
        """Log authorization failure."""
        self.log(AuditEvent(
            event_type=AuditEventType.SCOPE_DENIED,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            org_id=org_id,
            ip_address=ip_address,
            outcome="failure",
            error_message=f"Missing required scope: {required_scope}",
            details={
                "required_scope": required_scope,
                "token_scopes": token_scopes,
            },
        ))
    
    def log_rate_limit_exceeded(
        self,
        request_id: str,
        ip_address: str,
        limit_type: str,
        limit_value: int,
    ) -> None:
        """Log rate limit exceeded."""
        self.log(AuditEvent(
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            ip_address=ip_address,
            outcome="blocked",
            details={
                "limit_type": limit_type,
                "limit_value": limit_value,
            },
        ))
    
    def log_review_completed(
        self,
        request_id: str,
        org_id: Optional[str],
        repo_name: str,
        pr_number: int,
        findings_count: int,
        review_time_ms: int,
        should_block: bool,
    ) -> None:
        """Log security review completion."""
        self.log(AuditEvent(
            event_type=AuditEventType.REVIEW_COMPLETED,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            org_id=org_id,
            resource_type="review",
            resource_id=f"{repo_name}#{pr_number}",
            action="review",
            details={
                "findings_count": findings_count,
                "review_time_ms": review_time_ms,
                "should_block": should_block,
            },
        ))
    
    def log_suspicious_activity(
        self,
        request_id: str,
        ip_address: str,
        activity_type: str,
        details: dict[str, Any],
    ) -> None:
        """Log suspicious activity for security monitoring."""
        self.log(AuditEvent(
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
            timestamp=datetime.utcnow().isoformat(),
            request_id=request_id,
            ip_address=ip_address,
            outcome="flagged",
            error_message=activity_type,
            details=details,
        ))


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger(enabled: bool = True, db_client=None) -> AuditLogger:
    """Get or create the global audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(enabled=enabled, db_client=db_client)
    return _audit_logger


def set_audit_logger(audit_logger: AuditLogger) -> None:
    """Set a custom audit logger (useful for testing)."""
    global _audit_logger
    _audit_logger = audit_logger
