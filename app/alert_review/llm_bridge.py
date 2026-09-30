"""
LLM Bridge for Alert Review Service.

Bridges the 6-stage alert review pipeline with the existing multi-provider LLM infrastructure
(Claude, OpenAI, Gemini, Groq) with retries and exponential backoff.
"""

import logging
from typing import Optional, Callable, Awaitable

from ..config import get_settings
from ..llm_client import (
    _call_claude,
    _call_openai,
    _call_gemini,
    _call_groq,
    _retry_with_backoff,
    _retry_groq_with_fallback,
)

logger = logging.getLogger(__name__)


async def default_llm_caller(
    system_prompt: str,
    user_prompt: str,
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None
) -> str:
    """
    Execute prompt against configured LLM provider with retries.
    
    Args:
        system_prompt: System prompt instructing the model.
        user_prompt: User/context prompt with alert and code context.
        provider: Provider name ('claude', 'openai', 'gemini', 'groq').
        api_key: API key.
        model: Specific model identifier.
        
    Returns:
        Raw text response from LLM.
    """
    settings = get_settings()

    provider_name = (provider or settings.llm_provider).lower()
    key = api_key or settings.llm_api_key
    model_name = model or settings.effective_model

    if not key:
        raise ValueError("LLM API key not configured. Set LLM_API_KEY environment variable.")

    async def _make_call():
        if provider_name == "claude":
            return await _call_claude(system_prompt, user_prompt, key, model_name)
        elif provider_name == "openai":
            return await _call_openai(system_prompt, user_prompt, key, model_name)
        elif provider_name == "gemini":
            return await _call_gemini(system_prompt, user_prompt, key, model_name)
        elif provider_name == "groq":
            return await _call_groq(system_prompt, user_prompt, key, model_name)
        else:
            raise ValueError(f"Unsupported LLM provider: {provider_name}")

    if provider_name == "groq":
        return await _retry_groq_with_fallback(_make_call, provider_name)
    else:
        return await _retry_with_backoff(_make_call)
