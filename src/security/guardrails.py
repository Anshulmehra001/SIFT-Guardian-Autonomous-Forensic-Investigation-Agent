"""
Security Guardrails - Architectural constraints (not prompts!)
Prevents dangerous operations at code level
"""

import logging
import re
from typing import List, Dict, Any, Optional
from pathlib import Path


logger = logging.getLogger(__name__)


class SecurityGuardrails:
    """
    Architectural security constraints
    This is NOT prompt-based - it's enforced in code!
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize security guardrails
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.security_config = config.get("security", {})
        
        # Load allowed tools
        self.allowed_tools = set(self.security_config.get("allowed_tools", []))
        
        # Load blocked patterns
        self.blocked_patterns = self.security_config.get("blocked_patterns", [])
        
        # Compile regex patterns for efficiency
        self.blocked_regex = [
            re.compile(re.escape(pattern)) for pattern in self.blocked_patterns
        ]
        
        logger.info(
            f"Security guardrails initialized: "
            f"{len(self.allowed_tools)} allowed tools, "
            f"{len(self.blocked_patterns)} blocked patterns"
        )
    
    def check_tool_allowed(self, tool: str) -> bool:
        """
        Check if tool is whitelisted
        
        Args:
            tool: Tool name or path
            
        Returns:
            True if allowed, False if blocked
        """
        if not self.security_config.get("command_whitelist_enabled", True):
            return True
        
        # Extract base tool name
        tool_name = Path(tool).name
        
        # Check exact match
        if tool_name in self.allowed_tools:
            logger.debug(f"Tool allowed (exact match): {tool_name}")
            return True
        
        # Check if any allowed tool matches
        for allowed in self.allowed_tools:
            if tool_name.startswith(allowed):
                logger.debug(f"Tool allowed (prefix match): {tool_name}")
                return True
        
        logger.warning(f"Tool BLOCKED (not in whitelist): {tool_name}")
        return False
    
    def check_command_safe(self, command: str) -> tuple[bool, Optional[str]]:
        """
        Check if command is safe to execute
        
        Args:
            command: Full command string
            
        Returns:
            Tuple of (is_safe, reason_if_blocked)
        """
        # Check blocked patterns
        for pattern, regex in zip(self.blocked_patterns, self.blocked_regex):
            if regex.search(command):
                reason = f"Blocked pattern detected: {pattern}"
                logger.warning(f"Command BLOCKED: {reason}")
                logger.debug(f"Blocked command: {command}")
                return False, reason
        
        # Check for command injection patterns
        injection_patterns = [
            r'\$\(',      # Command substitution
            r'`',         # Backticks
            r'eval\s',    # Eval command
            r'exec\s',    # Exec command
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, command):
                reason = f"Command injection pattern detected: {pattern}"
                logger.warning(f"Command BLOCKED: {reason}")
                return False, reason
        
        logger.debug(f"Command passed safety check: {command[:50]}...")
        return True, None
    
    def sanitize_path(self, path: str) -> Optional[str]:
        """
        Sanitize and validate file path
        
        Args:
            path: File path to sanitize
            
        Returns:
            Sanitized path or None if invalid
        """
        if not self.security_config.get("sanitize_inputs", True):
            return path
        
        try:
            # Convert to Path object
            p = Path(path)
            
            # Block path traversal
            if self.security_config.get("block_path_traversal", True):
                if ".." in p.parts:
                    logger.warning(f"Path traversal attempt blocked: {path}")
                    return None
            
            # Block dangerous paths
            dangerous_paths = [
                "/proc",
                "/sys",
                "/dev",
                "/etc/shadow",
                "/etc/passwd",
            ]
            
            path_str = str(p.resolve())
            for dangerous in dangerous_paths:
                if path_str.startswith(dangerous):
                    logger.warning(f"Dangerous path blocked: {path}")
                    return None
            
            return path_str
            
        except Exception as e:
            logger.error(f"Path sanitization failed: {e}")
            return None
    
    def validate_evidence_access(self, evidence_path: str) -> bool:
        """
        Validate evidence file access
        
        Args:
            evidence_path: Path to evidence file
            
        Returns:
            True if access is allowed
        """
        # Sanitize path
        safe_path = self.sanitize_path(evidence_path)
        if not safe_path:
            return False
        
        # Check if file exists
        if not Path(safe_path).exists():
            logger.warning(f"Evidence file not found: {safe_path}")
            return False
        
        # Check read-only requirement
        if self.security_config.get("evidence_readonly", True):
            # In production, would mount evidence read-only
            # For now, just log the intention
            logger.debug(f"Evidence access (read-only): {safe_path}")
        
        return True
    
    def check_execution_time(self, elapsed_seconds: float) -> bool:
        """
        Check if execution time is within limits
        
        Args:
            elapsed_seconds: Seconds elapsed
            
        Returns:
            True if within limits
        """
        max_time = self.security_config.get("max_execution_time", 300)
        
        if elapsed_seconds > max_time:
            logger.warning(
                f"Execution time limit exceeded: {elapsed_seconds}s > {max_time}s"
            )
            return False
        
        return True
    
    def get_security_report(self) -> Dict[str, Any]:
        """
        Get security configuration report
        
        Returns:
            Dictionary with security settings
        """
        return {
            "whitelist_enabled": self.security_config.get("command_whitelist_enabled", True),
            "allowed_tools_count": len(self.allowed_tools),
            "blocked_patterns_count": len(self.blocked_patterns),
            "evidence_readonly": self.security_config.get("evidence_readonly", True),
            "hash_verification": self.security_config.get("require_hash_verification", True),
            "path_traversal_protection": self.security_config.get("block_path_traversal", True),
            "max_execution_time": self.security_config.get("max_execution_time", 300),
        }
