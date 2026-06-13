"""
Google Gemini AI Provider (FREE!)
No credit card required - 15 requests/min, 1500/day
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from .provider import AIProvider, AIResponse


logger = logging.getLogger(__name__)


class GeminiProvider(AIProvider):
    """
    Google Gemini AI Provider
    
    Free tier: 15 requests/min, 1500/day
    No credit card required!
    Get key at: https://ai.google.dev/
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Gemini provider"""
        super().__init__(config)
        
        if not GEMINI_AVAILABLE:
            raise ImportError(
                "google-generativeai not installed. "
                "Install with: pip install google-generativeai"
            )
        
        if not self.api_key:
            raise ValueError(
                "Gemini API key not found. "
                "Get free key at: https://ai.google.dev/ "
                "Set in config or environment variable GEMINI_API_KEY"
            )
        
        # Configure Gemini
        genai.configure(api_key=self.api_key)
        
        # Initialize model
        generation_config = {
            "temperature": self.temperature,
            "max_output_tokens": self.max_tokens,
        }
        
        self.model_instance = genai.GenerativeModel(
            model_name=self.model,
            generation_config=generation_config,
        )
        
        logger.info(f"Gemini provider initialized with model: {self.model}")
    
    def default_model(self) -> str:
        """Default Gemini model"""
        return "models/gemini-2.5-flash"
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> AIResponse:
        """
        Generate response using Gemini
        
        Args:
            prompt: User prompt
            system_prompt: System instructions
            **kwargs: Additional parameters
            
        Returns:
            AIResponse object
        """
        try:
            # Build full prompt with system instructions
            if system_prompt is None:
                system_prompt = self._build_system_prompt()
            
            full_prompt = f"{system_prompt}\n\n{prompt}"
            
            # Generate response
            response = self.model_instance.generate_content(full_prompt)
            
            # Extract content
            content = response.text
            
            # Extract token usage if available
            tokens_used = None
            if hasattr(response, 'usage_metadata'):
                tokens_used = (
                    response.usage_metadata.prompt_token_count +
                    response.usage_metadata.candidates_token_count
                )
            
            # Build response
            ai_response = AIResponse(
                content=content,
                model=self.model,
                provider="gemini",
                timestamp=datetime.now(),
                tokens_used=tokens_used,
                finish_reason=response.candidates[0].finish_reason.name if response.candidates else None,
                metadata={
                    "safety_ratings": [
                        {
                            "category": rating.category.name,
                            "probability": rating.probability.name
                        }
                        for rating in response.candidates[0].safety_ratings
                    ] if response.candidates else []
                }
            )
            
            logger.debug(f"Gemini response: {len(content)} chars, {tokens_used} tokens")
            
            return ai_response
            
        except Exception as e:
            logger.error(f"Gemini generation failed: {e}")
            raise RuntimeError(f"Gemini API error: {str(e)}") from e
    
    def is_available(self) -> bool:
        """Check if Gemini is available"""
        if not GEMINI_AVAILABLE:
            return False
        
        if not self.api_key:
            return False
        
        try:
            # Test with a simple prompt
            genai.configure(api_key=self.api_key)
            return True
        except Exception as e:
            logger.warning(f"Gemini not available: {e}")
            return False
    
    def get_rate_limits(self) -> Dict[str, Any]:
        """
        Get Gemini free tier rate limits
        
        Returns:
            Dictionary with rate limit info
        """
        return {
            "requests_per_minute": 15,
            "requests_per_day": 1500,
            "tokens_per_minute": 1_000_000,  # 1M tokens/min
            "cost": "FREE",
            "credit_card_required": False,
        }
