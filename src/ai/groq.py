"""
Groq AI Provider (FREE & FAST!)
14,400 free requests per day
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

from .provider import AIProvider, AIResponse


logger = logging.getLogger(__name__)


class GroqProvider(AIProvider):
    """
    Groq AI Provider - Super fast and free!
    
    Free tier: 14,400 requests/day
    Get key at: https://console.groq.com/
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Groq provider"""
        super().__init__(config)
        
        if not GROQ_AVAILABLE:
            raise ImportError(
                "groq not installed. "
                "Install with: pip install groq"
            )
        
        if not self.api_key:
            raise ValueError(
                "Groq API key not found. "
                "Get free key at: https://console.groq.com/ "
                "Set in config or environment variable GROQ_API_KEY"
            )
        
        self.client = Groq(api_key=self.api_key)
        logger.info(f"Groq provider initialized with model: {self.model}")
    
    def default_model(self) -> str:
        """Default Groq model"""
        return "llama-3.3-70b-versatile"
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> AIResponse:
        """Generate response using Groq"""
        try:
            if system_prompt is None:
                system_prompt = self._build_system_prompt()
            
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            
            content = response.choices[0].message.content
            tokens_used = response.usage.total_tokens if response.usage else None
            
            return AIResponse(
                content=content,
                model=self.model,
                provider="groq",
                timestamp=datetime.now(),
                tokens_used=tokens_used,
                finish_reason=response.choices[0].finish_reason,
            )
            
        except Exception as e:
            logger.error(f"Groq generation failed: {e}")
            raise RuntimeError(f"Groq API error: {str(e)}") from e
    
    def is_available(self) -> bool:
        """Check if Groq is available"""
        return GROQ_AVAILABLE and self.api_key is not None
