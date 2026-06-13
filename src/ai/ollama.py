"""
Ollama Local AI Provider (FREE & OFFLINE!)
Runs AI models locally on your computer
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

from .provider import AIProvider, AIResponse


logger = logging.getLogger(__name__)


class OllamaProvider(AIProvider):
    """
    Ollama Local AI Provider
    
    Runs models locally - completely free and offline!
    Install: https://ollama.com/
    Models: llama3.3, qwen2.5-coder, mistral, etc.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Ollama provider"""
        super().__init__(config)
        
        if not OLLAMA_AVAILABLE:
            raise ImportError(
                "ollama not installed. "
                "Install with: pip install ollama"
            )
        
        # Ollama doesn't need API key
        self.client = ollama.Client()
        logger.info(f"Ollama provider initialized with model: {self.model}")
    
    def default_model(self) -> str:
        """Default Ollama model"""
        return "llama3.3:70b"
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> AIResponse:
        """Generate response using Ollama"""
        try:
            if system_prompt is None:
                system_prompt = self._build_system_prompt()
            
            full_prompt = f"{system_prompt}\n\n{prompt}"
            
            response = self.client.generate(
                model=self.model,
                prompt=full_prompt,
                options={
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens,
                }
            )
            
            content = response['response']
            
            return AIResponse(
                content=content,
                model=self.model,
                provider="ollama",
                timestamp=datetime.now(),
                tokens_used=None,  # Ollama doesn't provide token count
                finish_reason="completed",
            )
            
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            raise RuntimeError(f"Ollama error: {str(e)}") from e
    
    def is_available(self) -> bool:
        """Check if Ollama is available"""
        if not OLLAMA_AVAILABLE:
            return False
        
        try:
            # Test connection to Ollama
            self.client.list()
            return True
        except Exception:
            return False
