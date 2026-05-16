"""
Models for GitLab project integration.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class GitLabProjectInfo(BaseModel):
    """GitLab project metadata for integration UI."""
    id: int
    name: str
    full_name: str
    owner: str
    private: bool
    description: Optional[str] = None
    default_branch: str
    html_url: str
    can_push: bool
    can_admin: bool
    imported: bool = False


class GitLabProjectsResponse(BaseModel):
    """List of GitLab projects."""
    projects: List[GitLabProjectInfo]
    total: int


class GitLabImportRequest(BaseModel):
    """Request to import GitLab projects to repo configs."""
    repos: List[str] = Field(..., description="List of repos in namespace/project format")
    default_policy: Optional[Dict[str, Any]] = Field(default=None, description="Optional default policy override")


class GitLabImportResult(BaseModel):
    """Per-project import result."""
    repo_name: str
    success: bool
    config_id: Optional[str] = None
    error: Optional[str] = None


class GitLabImportResponse(BaseModel):
    """Bulk GitLab import response."""
    results: List[GitLabImportResult]
    total_imported: int
    total_failed: int


class GitLabWebhookInstallRequest(BaseModel):
    """Request to install GitLab webhooks across projects."""
    repos: List[str] = Field(..., description="List of repos in namespace/project format")


class GitLabWebhookInstallResult(BaseModel):
    """Per-project webhook install result."""
    repo_name: str
    success: bool
    action: str
    hook_id: Optional[int] = None
    error: Optional[str] = None


class GitLabWebhookInstallResponse(BaseModel):
    """Bulk GitLab webhook install response."""
    results: List[GitLabWebhookInstallResult]
    total_success: int
    total_failed: int


class GitLabWebhookStatusResponse(BaseModel):
    """Webhook status for a GitLab project."""
    configured: bool
    repo_name: str
    webhook_url: str
    hook_id: Optional[int] = None
