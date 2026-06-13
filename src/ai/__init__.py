"""
AI Provider abstraction layer
Easily switch between Gemini, Groq, Claude, Ollama
"""

from .provider import AIProvider, AIResponse
from .gemini import GeminiProvider
from .groq import GroqProvider
from .claude import ClaudeProvider
from .ollama import OllamaProvider

__all__ = [
    "AIProvider",
    "AIResponse",
    "GeminiProvider",
    "GroqProvider",
    "ClaudeProvider",
    "OllamaProvider",
    "get_provider",
]


def get_provider(config: dict) -> AIProvider:
    """
    Factory function to get the configured AI provider
    
    Args:
        config: Configuration dictionary
        
    Returns:
        AIProvider instance
        
    Raises:
        ValueError: If provider is not supported
    """
    provider_name = config.get("ai", {}).get("provider", "gemini").lower()
    
    providers = {
        "gemini": GeminiProvider,
        "groq": GroqProvider,
        "claude": ClaudeProvider,
        "ollama": OllamaProvider,
    }
    
    if provider_name not in providers:
        raise ValueError(
            f"Unknown AI provider: {provider_name}. "
            f"Supported: {', '.join(providers.keys())}"
        )
    
    provider_class = providers[provider_name]
    return provider_class(config)
