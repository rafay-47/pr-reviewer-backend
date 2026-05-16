"""
Models for GitHub App installation management.
"""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class GitHubAppInstallationRequest(BaseModel):
    """Request to link a GitHub App installation to an organization."""
    installation_id: int = Field(..., description="GitHub App installation ID")
    account_login: str = Field(..., description="GitHub account login (user or org name)")
    account_type: str = Field(..., description="Account type: 'User' or 'Organization'")
    account_id: int = Field(..., description="GitHub account ID")
    repository_selection: str = Field(default="all", description="Repository selection: 'all' or 'selected'")
    permissions: Optional[Dict[str, Any]] = Field(default=None, description="Granted permissions")
    events: Optional[List[str]] = Field(default=None, description="Subscribed events")


class GitHubAppInstallationResponse(BaseModel):
    """Response after linking a GitHub App installation."""
    success: bool
    installation_id: int
    org_id: str
    account_login: str
    message: str


class GitHubAppInstallationInfo(BaseModel):
    """Information about a linked GitHub App installation."""
    id: str
    installation_id: int
    account_login: str
    account_type: str
    account_id: int
    repository_selection: str
    permissions: Dict[str, Any]
    events: List[str]
    installed_at: str
    updated_at: str
    is_active: bool
    suspended_at: Optional[str] = None
    suspended_by: Optional[str] = None


class GitHubAppInstallationsListResponse(BaseModel):
    """List of GitHub App installations for an organization."""
    installations: List[GitHubAppInstallationInfo]
    total: int
