"""
Anthropic Claude AI Provider
High quality responses - requires API credits
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime

try:
    from anthropic import Anthropic
    CLAUDE_AVAILABLE = True
except ImportError:
    CLAUDE_AVAILABLE = False

from .provider import AIProvider, AIResponse


logger = logging.getLogger(__name__)


class ClaudeProvider(AIProvider):
    """Anthropic Claude Provider"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Claude provider"""
        super().__init__(config)
        
        if not CLAUDE_AVAILABLE:
            raise ImportError(
                "anthropic not installed. "
                "Install with: pip install anthropic"
            )
        
        if not self.api_key:
            raise ValueError(
                "Claude API key not found. "
                "Get key at: https://console.anthropic.com/ "
                "Set in config or environment variable CLAUDE_API_KEY"
            )
        
        self.client = Anthropic(api_key=self.api_key)
        logger.info(f"Claude provider initialized with model: {self.model}")
    
    def default_model(self) -> str:
        """Default Claude model"""
        return "claude-sonnet-4.5"
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> AIResponse:
        """Generate response using Claude"""
        try:
            if system_prompt is None:
                system_prompt = self._build_system_prompt()
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}]
            )
            
            content = response.content[0].text
            tokens_used = response.usage.input_tokens + response.usage.output_tokens
            
            return AIResponse(
                content=content,
                model=self.model,
                provider="claude",
                timestamp=datetime.now(),
                tokens_used=tokens_used,
                finish_reason=response.stop_reason,
            )
            
        except Exception as e:
            logger.error(f"Claude generation failed: {e}")
            raise RuntimeError(f"Claude API error: {str(e)}") from e
    
    def is_available(self) -> bool:
        """Check if Claude is available"""
        return CLAUDE_AVAILABLE and self.api_key is not None
