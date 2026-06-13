"""
Real forensic analysis modules
"""

from .file_analyzer import FileAnalyzer
from .registry_analyzer import RegistryAnalyzer
from .memory_analyzer import MemoryAnalyzer
from .yara_scanner import YARAScanner

__all__ = [
    'FileAnalyzer',
    'RegistryAnalyzer', 
    'MemoryAnalyzer',
    'YARAScanner'
]
