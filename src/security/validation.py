"""
Input validation and sanitization
"""

import re
import logging
from typing import Optional, List


logger = logging.getLogger(__name__)


class InputValidator:
    """Input validation utilities"""
    
    @staticmethod
    def sanitize_command_input(input_str: str) -> str:
        """
        Sanitize command input to prevent injection
        
        Args:
            input_str: Raw input string
            
        Returns:
            Sanitized string
        """
        # Remove dangerous characters
        dangerous_chars = ['`', '$', '(', ')', '{', '}', '|', '&', ';', '\n', '\r']
        
        sanitized = input_str
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()
    
    @staticmethod
    def validate_hash(hash_str: str, algorithm: str = "sha256") -> bool:
        """
        Validate hash format
        
        Args:
            hash_str: Hash string to validate
            algorithm: Hash algorithm (sha256, md5, etc)
            
        Returns:
            True if valid format
        """
        hash_lengths = {
            "md5": 32,
            "sha1": 40,
            "sha256": 64,
            "sha512": 128,
        }
        
        expected_length = hash_lengths.get(algorithm.lower())
        if not expected_length:
            return False
        
        # Check length and hex characters only
        if len(hash_str) != expected_length:
            return False
        
        return bool(re.match(r'^[a-fA-F0-9]+$', hash_str))
    
    @staticmethod
    def is_safe_filename(filename: str) -> bool:
        """
        Check if filename is safe
        
        Args:
            filename: Filename to check
            
        Returns:
            True if safe
        """
        # Block path separators and special chars
        unsafe_chars = ['/', '\\', '..', '\0', '\n', '\r', '|', '&', ';', '`', '$']
        
        for char in unsafe_chars:
            if char in filename:
                logger.warning(f"Unsafe filename detected: {filename}")
                return False
        
        return True
