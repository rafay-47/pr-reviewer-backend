"""
Stripe payment integration for AI AppSec PR Reviewer.

Handles subscription creation, upgrades, and webhook processing.
"""

import logging
import os
from typing import Optional
import stripe

from .config import Settings, get_settings
from .database import get_supabase_client

logger = logging.getLogger(__name__)


def initialize_stripe(settings: Settings):
    """Initialize Stripe with API key."""
    if settings.stripe_secret_key:
        stripe.api_key = settings.stripe_secret_key
        logger.info("Stripe initialized successfully")
    else:
        logger.warning("Stripe not configured - payment processing disabled")


def get_price_id(plan_id: str, billing_cycle: str, settings: Settings) -> Optional[str]:
    """
    Get Stripe price ID for a plan and billing cycle.
    
    Args:
        plan_id: Plan identifier (team, enterprise)
        billing_cycle: 'monthly' or 'yearly'
        settings: Application settings
        
    Returns:
        Stripe price ID or None if not configured
    """
    price_mapping = {
        'team': {
            'monthly': settings.stripe_price_id_team_monthly,
            'yearly': settings.stripe_price_id_team_yearly,
        },
        # Enterprise plans can be added here when configured
        # 'enterprise': {
        #     'monthly': settings.stripe_price_id_enterprise_monthly,
        #     'yearly': settings.stripe_price_id_enterprise_yearly,
        # },
    }
    
    plan_prices = price_mapping.get(plan_id, {})
    return plan_prices.get(billing_cycle)


async def create_checkout_session(
    org_id: str,
    org_name: str,
    plan_id: str,
    billing_cycle: str,
    user_email: str,
    settings: Settings,
) -> dict:
    """
    Create a Stripe Checkout session for subscription purchase.
    
    Args:
        org_id: Organization ID
        org_name: Organization name
        plan_id: Target plan ID (team, enterprise)
        billing_cycle: 'monthly' or 'yearly'
        user_email: User's email address
        settings: Application settings
        
    Returns:
        Dictionary with checkout_url and session_id
        
    Raises:
        ValueError: If Stripe is not configured or plan is invalid
    """
    if not settings.stripe_secret_key:
        raise ValueError("Stripe is not configured. Please contact support.")
    
    # Get price ID based on plan and billing cycle
    price_id = get_price_id(plan_id, billing_cycle, settings)
    
    if not price_id:
        raise ValueError(f"No Stripe price configured for {plan_id} {billing_cycle}")
    
    # Determine success/cancel URLs
    base_url = settings.frontend_url or "http://localhost:3000"
    
    try:
        # Create Stripe Checkout session
        print(base_url)
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{base_url}/dashboard?upgrade=success&plan={plan_id}",
            cancel_url=f"{base_url}/pricing?upgrade=cancelled",
            customer_email=user_email if user_email else None,
            metadata={
                'org_id': org_id,
                'org_name': org_name,
                'plan_id': plan_id,
                'billing_cycle': billing_cycle,
            },
            subscription_data={
                'metadata': {
                    'org_id': org_id,
                    'plan_id': plan_id,
                },
                'trial_period_days': 14 if plan_id == 'team' else None,  # 14-day trial for Team plan
            },
            allow_promotion_codes=True,
        )
        
        logger.info(f"Created Stripe checkout session for {org_id}: {session.id}")
        
        return {
            'checkout_url': session.url,
            'session_id': session.id,
        }
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating checkout session: {e}")
        raise ValueError(f"Failed to create checkout session: {str(e)}")


async def handle_webhook_event(
    payload: bytes,
    sig_header: str,
    settings: Settings,
) -> dict:
    """
    Handle Stripe webhook events.
    
    Args:
        payload: Raw request body
        sig_header: Stripe signature header
        settings: Application settings
        
    Returns:
        Dictionary with event details
        
    Raises:
        ValueError: If webhook verification fails
    """
    if not settings.stripe_webhook_secret:
        raise ValueError("Stripe webhook secret not configured")
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.stripe_webhook_secret
        )
    except ValueError as e:
        logger.error(f"Invalid webhook payload: {e}")
        raise ValueError("Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid webhook signature: {e}")
        raise ValueError("Invalid signature")
    
    logger.info(f"Received Stripe webhook: {event['type']}")
    
    # Handle different event types
    event_type = event['type']
    
    if event_type == 'checkout.session.completed':
        return await handle_checkout_completed(event)
    elif event_type == 'customer.subscription.created':
        return await handle_subscription_created(event)
    elif event_type == 'customer.subscription.updated':
        return await handle_subscription_updated(event)
    elif event_type == 'customer.subscription.deleted':
        return await handle_subscription_deleted(event)
    elif event_type == 'invoice.payment_succeeded':
        return await handle_payment_succeeded(event)
    elif event_type == 'invoice.payment_failed':
        return await handle_payment_failed(event)
    else:
        logger.info(f"Unhandled webhook event type: {event_type}")
        return {'status': 'ignored', 'event_type': event_type}


async def handle_checkout_completed(event: dict) -> dict:
    """Handle successful checkout session completion."""
    session = event['data']['object']
    org_id = session['metadata'].get('org_id')
    plan_id = session['metadata'].get('plan_id')
    billing_cycle = session['metadata'].get('billing_cycle')
    
    if not org_id or not plan_id:
        logger.error(f"Missing metadata in checkout session: {session['id']}")
        return {'status': 'error', 'message': 'Missing metadata'}
    
    logger.info(f"Checkout completed for org {org_id}: {plan_id} {billing_cycle}")
    
    # Get Stripe subscription ID
    subscription_id = session.get('subscription')
    
    # Update subscription in database
    from .subscriptions import update_subscription_plan
    await update_subscription_plan(
        org_id=org_id,
        plan_id=plan_id,
        billing_cycle=billing_cycle,
        stripe_subscription_id=subscription_id,
        status='active'
    )
    
    return {'status': 'success', 'org_id': org_id, 'plan_id': plan_id}


async def handle_subscription_created(event: dict) -> dict:
    """Handle subscription creation."""
    subscription = event['data']['object']
    org_id = subscription['metadata'].get('org_id')
    
    logger.info(f"Subscription created: {subscription['id']} for org {org_id}")
    
    # Update database with subscription details
    client = get_supabase_client()
    if org_id:
        client.table('subscriptions').update({
            'stripe_subscription_id': subscription['id'],
            'stripe_customer_id': subscription['customer'],
            'status': subscription['status'],
            'updated_at': 'now()',
        }).eq('org_id', org_id).execute()
    
    return {'status': 'success', 'subscription_id': subscription['id']}


async def handle_subscription_updated(event: dict) -> dict:
    """Handle subscription update."""
    subscription = event['data']['object']
    org_id = subscription['metadata'].get('org_id')
    
    logger.info(f"Subscription updated: {subscription['id']} for org {org_id}")
    
    # Update status in database
    client = get_supabase_client()
    if org_id:
        client.table('subscriptions').update({
            'status': subscription['status'],
            'updated_at': 'now()',
        }).eq('stripe_subscription_id', subscription['id']).execute()
    
    return {'status': 'success', 'subscription_id': subscription['id']}


async def handle_subscription_deleted(event: dict) -> dict:
    """Handle subscription cancellation."""
    subscription = event['data']['object']
    org_id = subscription['metadata'].get('org_id')
    
    logger.info(f"Subscription cancelled: {subscription['id']} for org {org_id}")
    
    # Downgrade to free plan
    from .subscriptions import update_subscription_plan
    if org_id:
        await update_subscription_plan(
            org_id=org_id,
            plan_id='free',
            billing_cycle='monthly',
            status='canceled'
        )
    
    return {'status': 'success', 'subscription_id': subscription['id']}


async def handle_payment_succeeded(event: dict) -> dict:
    """Handle successful payment."""
    invoice = event['data']['object']
    subscription_id = invoice.get('subscription')
    
    logger.info(f"Payment succeeded for subscription: {subscription_id}")
    
    # Update payment status in database
    client = get_supabase_client()
    if subscription_id:
        client.table('subscriptions').update({
            'status': 'active',
            'updated_at': 'now()',
        }).eq('stripe_subscription_id', subscription_id).execute()
    
    return {'status': 'success', 'subscription_id': subscription_id}


async def handle_payment_failed(event: dict) -> dict:
    """Handle failed payment."""
    invoice = event['data']['object']
    subscription_id = invoice.get('subscription')
    
    logger.warning(f"Payment failed for subscription: {subscription_id}")
    
    # Update payment status in database
    client = get_supabase_client()
    if subscription_id:
        client.table('subscriptions').update({
            'status': 'past_due',
            'updated_at': 'now()',
        }).eq('stripe_subscription_id', subscription_id).execute()
    
    return {'status': 'success', 'subscription_id': subscription_id}


async def cancel_subscription(org_id: str) -> dict:
    """
    Cancel an organization's Stripe subscription.
    
    Args:
        org_id: Organization ID
        
    Returns:
        Dictionary with cancellation details
    """
    client = get_supabase_client()
    
    # Get subscription
    result = client.table('subscriptions').select('stripe_subscription_id').eq('org_id', org_id).execute()
    
    if not result.data or not result.data[0].get('stripe_subscription_id'):
        raise ValueError("No active subscription found")
    
    stripe_subscription_id = result.data[0]['stripe_subscription_id']
    
    try:
        # Cancel at period end (don't immediately cancel)
        subscription = stripe.Subscription.modify(
            stripe_subscription_id,
            cancel_at_period_end=True
        )
        
        logger.info(f"Cancelled subscription {stripe_subscription_id} for org {org_id}")
        
        return {
            'success': True,
            'cancels_at': subscription.cancel_at,
            'message': 'Subscription will be cancelled at the end of the billing period'
        }
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error cancelling subscription: {e}")
        raise ValueError(f"Failed to cancel subscription: {str(e)}")


async def get_customer_portal_url(org_id: str, return_url: str) -> str:
    """
    Create a Stripe Customer Portal session for subscription management.
    
    Args:
        org_id: Organization ID
        return_url: URL to return to after portal session
        
    Returns:
        Customer portal URL
    """
    client = get_supabase_client()
    
    # Get customer ID
    result = client.table('subscriptions').select('stripe_customer_id').eq('org_id', org_id).execute()
    
    if not result.data or not result.data[0].get('stripe_customer_id'):
        raise ValueError("No Stripe customer found for this organization")
    
    customer_id = result.data[0]['stripe_customer_id']
    
    try:
        session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        
        return session.url
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating portal session: {e}")
        raise ValueError(f"Failed to create portal session: {str(e)}")
