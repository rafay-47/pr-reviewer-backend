"""
Organization invitation management endpoints and logic.

Handles creating, accepting, revoking, and listing invitations.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import HTTPException

from .database import get_supabase_client
from .auth import UserContext
from .subscriptions import check_can_add_member

logger = logging.getLogger(__name__)


async def create_invitation(
    org_id: str,
    email: str,
    role: str,
    invited_by: str,
    expires_in_days: int = 7
) -> dict:
    """
    Create an invitation for a user to join an organization.
    
    Args:
        org_id: Organization ID
        email: Email address to invite
        role: Role to assign (admin or member)
        invited_by: User ID of inviter
        expires_in_days: Days until expiration
        
    Returns:
        Invitation details including token
    """
    supabase = get_supabase_client()
    
    try:
        # Call stored procedure to create invitation
        result = supabase.rpc(
            "create_invitation",
            {
                "p_org_id": org_id,
                "p_email": email.lower().strip(),
                "p_role": role,
                "p_invited_by": invited_by,
                "p_expires_in_days": expires_in_days,
            }
        ).execute()
        
        invitation_id = result.data
        logger.info(f"Stored procedure returned invitation ID: {invitation_id}")
        
        # Get the created invitation
        invitation = supabase.table("org_invitations").select("*").eq("id", invitation_id).single().execute()
        
        logger.info(f"Retrieved invitation data: {invitation.data}")
        if invitation.data and 'invite_token' in invitation.data:
            logger.info(f"Invite token: {invitation.data['invite_token'][:20]}...")
        else:
            logger.error(f"No invite_token in invitation data! Keys: {list(invitation.data.keys()) if invitation.data else 'None'}")
        
        logger.info(f"Created invitation {invitation_id} for {email} to org {org_id}")
        
        return invitation.data
    except Exception as e:
        error_msg = str(e)
        
        # Handle common errors
        if "already a member" in error_msg:
            raise HTTPException(
                status_code=409,
                detail=f"User {email} is already a member of this organization"
            )
        
        logger.error(f"Failed to create invitation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create invitation: {error_msg}"
        )


async def get_pending_invitations(org_id: str) -> list[dict]:
    """
    Get all pending invitations for an organization.
    
    Args:
        org_id: Organization ID
        
    Returns:
        List of pending invitations
    """
    supabase = get_supabase_client()
    
    try:
        result = supabase.rpc(
            "get_pending_invitations",
            {"p_org_id": org_id}
        ).execute()
        
        return result.data or []
    except Exception as e:
        logger.error(f"Failed to get pending invitations: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch invitations: {str(e)}"
        )


async def accept_invitation(invite_token: str, user_id: str) -> dict:
    """
    Accept an invitation and join the organization.
    
    Args:
        invite_token: Invitation token or invitation ID
        user_id: User ID accepting the invitation
        
    Returns:
        Organization details
    """
    supabase = get_supabase_client()
    
    logger.info(f"Attempting to accept invitation: token={invite_token[:10]}..., user_id={user_id}")
    
    try:
        # First, try to find the invitation by invite_token
        invitation = supabase.table("org_invitations").select("*").eq(
            "invite_token", invite_token
        ).is_("accepted_at", "null").is_("revoked_at", "null").gt(
            "expires_at", datetime.utcnow().isoformat()
        ).maybe_single().execute()
        
        # If not found by token, try by ID (for backward compatibility)
        if not invitation.data:
            logger.info(f"Token not found, trying as invitation ID: {invite_token}")
            invitation = supabase.table("org_invitations").select("*").eq(
                "id", invite_token
            ).is_("accepted_at", "null").is_("revoked_at", "null").gt(
                "expires_at", datetime.utcnow().isoformat()
            ).maybe_single().execute()
            
            if not invitation.data:
                raise Exception("Invalid or expired invitation")
        
        invitation_data = invitation.data

        # Enforce team member limits at acceptance time as well, since limits may
        # have changed after the invitation was created.
        can_add, limit_message = await check_can_add_member(invitation_data["org_id"])
        if not can_add:
            raise HTTPException(
                status_code=403,
                detail=limit_message or "Team member limit reached. Upgrade your plan to add more members.",
            )
        
        # Call stored procedure to accept invitation
        result = supabase.rpc(
            "accept_invitation",
            {
                "p_invite_token": invitation_data["invite_token"],  # Always use the actual token
                "p_user_id": user_id,
            }
        ).execute()
        
        org_info = result.data
        
        logger.info(f"User {user_id} accepted invitation to org {org_info['org_id']}")
        
        return org_info
    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Full error from Supabase: {repr(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        
        # Check if it's a Supabase APIError with detailed info
        if hasattr(e, 'message'):
            error_msg = str(getattr(e, 'message'))
            logger.error(f"Error message from APIError: {error_msg}")
        
        # Handle common errors
        if "Invalid or expired" in error_msg:
            raise HTTPException(
                status_code=404,
                detail="Invitation not found or has expired"
            )
        elif "different email" in error_msg:
            raise HTTPException(
                status_code=403,
                detail="This invitation was sent to a different email address"
            )
        elif "already a member" in error_msg:
            raise HTTPException(
                status_code=409,
                detail="You are already a member of this organization"
            )
        
        logger.error(f"Failed to accept invitation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to accept invitation: {error_msg}"
        )


async def revoke_invitation(invitation_id: str, user_id: str) -> bool:
    """
    Revoke a pending invitation.
    
    Args:
        invitation_id: Invitation ID
        user_id: User ID revoking (must be admin/owner)
        
    Returns:
        True if revoked successfully
    """
    supabase = get_supabase_client()
    
    try:
        result = supabase.rpc(
            "revoke_invitation",
            {
                "p_invitation_id": invitation_id,
                "p_user_id": user_id,
            }
        ).execute()
        
        logger.info(f"Revoked invitation {invitation_id}")
        
        return True
    except Exception as e:
        error_msg = str(e)
        
        if "Permission denied" in error_msg:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to revoke this invitation"
            )
        
        logger.error(f"Failed to revoke invitation: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to revoke invitation: {error_msg}"
        )


async def get_invitation_by_token(invite_token: str) -> Optional[dict]:
    """
    Get invitation details by token (for preview before accepting).
    
    Args:
        invite_token: Invitation token
        
    Returns:
        Invitation details or None
    """
    supabase = get_supabase_client()
    
    try:
        # Get invitation with organization details
        result = supabase.table("org_invitations").select(
            "*, organizations(id, name, slug)"
        ).eq("invite_token", invite_token).is_("accepted_at", "null").is_("revoked_at", "null").gt("expires_at", datetime.utcnow().isoformat()).maybe_single().execute()
        
        if not result.data:
            return None
        
        return result.data
    except Exception as e:
        logger.error(f"Failed to get invitation by token: {e}")
        return None
