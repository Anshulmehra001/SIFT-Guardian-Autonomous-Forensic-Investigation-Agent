"""
Base AI Provider interface
All providers must implement this interface
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class AIResponse:
    """Standardized AI response format"""
    
    content: str
    model: str
    provider: str
    timestamp: datetime
    tokens_used: Optional[int] = None
    confidence: Optional[float] = None
    finish_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "content": self.content,
            "model": self.model,
            "provider": self.provider,
            "timestamp": self.timestamp.isoformat(),
            "tokens_used": self.tokens_used,
            "confidence": self.confidence,
            "finish_reason": self.finish_reason,
            "metadata": self.metadata or {},
        }


class AIProvider(ABC):
    """
    Abstract base class for AI providers
    Implement this to add new AI providers
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize provider
        
        Args:
            config: Full configuration dictionary
        """
        self.config = config
        self.ai_config = config.get("ai", {})
        self.api_key = self._get_api_key()
        self.model = self.ai_config.get("model", self.default_model())
        self.temperature = self.ai_config.get("temperature", 0.1)
        self.max_tokens = self.ai_config.get("max_tokens", 4096)
        self.timeout = self.ai_config.get("timeout", 60)
    
    @abstractmethod
    def default_model(self) -> str:
        """
        Get default model name for this provider
        
        Returns:
            Model name string
        """
        pass
    
    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> AIResponse:
        """
        Generate AI response
        
        Args:
            prompt: User prompt
            system_prompt: Optional system instructions
            **kwargs: Provider-specific parameters
            
        Returns:
            AIResponse object
            
        Raises:
            Exception: If generation fails
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if provider is available and configured
        
        Returns:
            True if provider can be used
        """
        pass
    
    def _get_api_key(self) -> Optional[str]:
        """
        Get API key from config or environment
        
        Returns:
            API key string or None
        """
        import os
        
        api_key = self.ai_config.get("api_key", "")
        
        # Handle environment variable syntax ${VAR_NAME}
        if api_key.startswith("${") and api_key.endswith("}"):
            env_var = api_key[2:-1]
            api_key = os.getenv(env_var, "")
        
        return api_key if api_key else None
    
    def _build_system_prompt(self) -> str:
        """
        Build default system prompt for forensic analysis
        
        Returns:
            System prompt string
        """
        return """You are a forensic investigation AI agent specializing in digital forensics and incident response.

Your role:
- Analyze digital evidence with precision
- Identify indicators of compromise
- Cross-validate findings across multiple artifacts
- Distinguish facts from inferences
- Question your own conclusions

Forensic principles:
1. Evidence is sovereign - never reinterpret to fit hypothesis
2. Every claim must cite specific artifacts
3. State confidence level for each finding
4. Acknowledge what artifacts do NOT prove
5. Suggest corroborating sources
6. Flag contradictions for re-investigation

Analysis methodology:
- Use MITRE ATT&CK framework for tactics/techniques
- Consider timeline and context
- Cross-reference multiple artifact types
- Validate assumptions against evidence
- Admit uncertainty when appropriate

Output format:
- Clear, structured findings
- Evidence citations (file, offset, timestamp)
- Confidence scores (0.0 to 1.0)
- Recommendations for additional analysis"""
    
    def _extract_tokens_used(self, response: Any) -> Optional[int]:
        """
        Extract token usage from provider response
        
        Args:
            response: Provider-specific response object
            
        Returns:
            Token count or None
        """
        # Override in subclasses to extract token info
        return None
    
    def get_provider_name(self) -> str:
        """
        Get provider name
        
        Returns:
            Provider name string
        """
        return self.__class__.__name__.replace("Provider", "").lower()
