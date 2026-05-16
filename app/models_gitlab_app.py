"""
Models for GitLab App installation management.
"""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class GitLabAppInstallationRequest(BaseModel):
    """Request to link a GitLab App installation to an organization."""
    installation_id: str = Field(..., description="GitLab installation identifier")
    account_login: str = Field(..., description="GitLab account/group login")
    account_type: str = Field(..., description="Account type: 'User' or 'Group'")
    account_id: int = Field(..., description="GitLab account ID")
    gitlab_instance_url: str = Field(default="https://gitlab.com", description="GitLab instance URL")
    scopes: Optional[List[str]] = Field(default=None, description="Granted OAuth scopes")


class GitLabAppInstallationResponse(BaseModel):
    """Response after linking a GitLab App installation."""
    success: bool
    installation_id: str
    org_id: str
    account_login: str
    message: str


class GitLabAppInstallationInfo(BaseModel):
    """Information about a linked GitLab App installation."""
    id: str
    installation_id: str
    account_login: str
    account_type: str
    account_id: int
    gitlab_instance_url: str
    scopes: List[str]
    installed_at: str
    updated_at: str
    is_active: bool


class GitLabAppInstallationsListResponse(BaseModel):
    """List of GitLab App installations for an organization."""
    installations: List[GitLabAppInstallationInfo]
    total: int
