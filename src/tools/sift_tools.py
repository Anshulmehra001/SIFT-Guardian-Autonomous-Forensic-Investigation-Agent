"""
SIFT Tool Integration
Executes actual SIFT forensic tools via WSL
"""

import subprocess
import logging
import json
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import re

logger = logging.getLogger(__name__)


class SIFTToolExecutor:
    """
    Executes real SIFT forensic tools
    Integrates with WSL Ubuntu for Linux tools
    """
    
    def __init__(self, use_wsl: bool = True):
        """
        Initialize SIFT tool executor
        
        Args:
            use_wsl: Whether to use WSL for Linux tools
        """
        self.use_wsl = use_wsl
        self.available_tools = self._check_available_tools()
        
        logger.info(f"SIFT tools initialized: {len(self.available_tools)} available")
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """Check which SIFT tools are available"""
        tools = {
            'strings': False,
            'file': False,
            'md5sum': False,
            'sha256sum': False,
            'volatility': False,
            'volatility3': False,
            'regripper': False,
            'bulk_extractor': False,
            'foremost': False,
            'binwalk': False,
            'exiftool': False,
        }
        
        if not self.use_wsl:
            return tools
        
        # Check each tool
        for tool in tools.keys():
            try:
                result = subprocess.run(
                    ['wsl', 'which', tool],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                tools[tool] = result.returncode == 0
            except Exception as e:
                logger.debug(f"Could not check {tool}: {e}")
        
        return tools
    
    def is_tool_available(self, tool: str) -> bool:
        """Check if specific tool is available"""
        return self.available_tools.get(tool, False)
    
    def execute_strings(self, file_path: str, min_length: int = 4) -> Tuple[List[str], str]:
        """
        Execute 'strings' command on file
        
        Returns:
            Tuple of (strings_list, raw_output)
        """
        if not self.is_tool_available('strings'):
            return [], "strings command not available"
        
        try:
            # Convert Windows path to WSL path
            wsl_path = self._convert_to_wsl_path(file_path)
            
            result = subprocess.run(
                ['wsl', 'strings', '-n', str(min_length), wsl_path],
                capture_output=True,
                timeout=30,
                text=True
            )
            
            if result.returncode == 0:
                strings_list = result.stdout.strip().split('\n')
                return strings_list[:100], result.stdout  # First 100 strings
            else:
                return [], result.stderr
        
        except Exception as e:
            logger.error(f"strings execution failed: {e}")
            return [], str(e)
    
    def execute_file(self, file_path: str) -> Tuple[str, str]:
        """
        Execute 'file' command to identify file type
        
        Returns:
            Tuple of (file_type, raw_output)
        """
        if not self.is_tool_available('file'):
            return "unknown", "file command not available"
        
        try:
            wsl_path = self._convert_to_wsl_path(file_path)
            
            result = subprocess.run(
                ['wsl', 'file', '-b', wsl_path],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if result.returncode == 0:
                return result.stdout.strip(), result.stdout
            else:
                return "error", result.stderr
        
        except Exception as e:
            logger.error(f"file execution failed: {e}")
            return "error", str(e)
    
    def execute_hash(self, file_path: str, algorithm: str = 'sha256') -> Tuple[str, str]:
        """
        Calculate file hash using Linux tools
        
        Args:
            file_path: Path to file
            algorithm: 'md5' or 'sha256'
            
        Returns:
            Tuple of (hash_value, raw_output)
        """
        tool = f"{algorithm}sum"
        
        if not self.is_tool_available(tool):
            return "", f"{tool} not available"
        
        try:
            wsl_path = self._convert_to_wsl_path(file_path)
            
            result = subprocess.run(
                ['wsl', tool, wsl_path],
                capture_output=True,
                timeout=60,
                text=True
            )
            
            if result.returncode == 0:
                # Parse hash from output (format: "hash  filename")
                hash_value = result.stdout.split()[0] if result.stdout else ""
                return hash_value, result.stdout
            else:
                return "", result.stderr
        
        except Exception as e:
            logger.error(f"{algorithm} hash failed: {e}")
            return "", str(e)
    
    def execute_binwalk(self, file_path: str) -> Tuple[List[Dict], str]:
        """
        Execute binwalk for firmware analysis
        
        Returns:
            Tuple of (findings_list, raw_output)
        """
        if not self.is_tool_available('binwalk'):
            return [], "binwalk not available"
        
        try:
            wsl_path = self._convert_to_wsl_path(file_path)
            
            result = subprocess.run(
                ['wsl', 'binwalk', wsl_path],
                capture_output=True,
                timeout=60,
                text=True
            )
            
            findings = []
            if result.returncode == 0:
                # Parse binwalk output
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('DECIMAL'):
                        findings.append({'raw': line.strip()})
            
            return findings, result.stdout
        
        except Exception as e:
            logger.error(f"binwalk execution failed: {e}")
            return [], str(e)
    
    def execute_exiftool(self, file_path: str) -> Tuple[Dict[str, str], str]:
        """
        Execute exiftool for metadata extraction
        
        Returns:
            Tuple of (metadata_dict, raw_output)
        """
        if not self.is_tool_available('exiftool'):
            return {}, "exiftool not available"
        
        try:
            wsl_path = self._convert_to_wsl_path(file_path)
            
            result = subprocess.run(
                ['wsl', 'exiftool', '-j', wsl_path],
                capture_output=True,
                timeout=30,
                text=True
            )
            
            metadata = {}
            if result.returncode == 0:
                try:
                    # Parse JSON output
                    data = json.loads(result.stdout)
                    if data and isinstance(data, list):
                        metadata = data[0]
                except json.JSONDecodeError:
                    pass
            
            return metadata, result.stdout
        
        except Exception as e:
            logger.error(f"exiftool execution failed: {e}")
            return {}, str(e)
    
    def execute_volatility3(self, memory_path: str, plugin: str) -> Tuple[List[str], str]:
        """
        Execute Volatility 3 for memory forensics
        
        Args:
            memory_path: Path to memory dump
            plugin: Volatility plugin (e.g., 'windows.pslist')
            
        Returns:
            Tuple of (results_list, raw_output)
        """
        if not self.is_tool_available('volatility3'):
            return [], "volatility3 not available"
        
        try:
            wsl_path = self._convert_to_wsl_path(memory_path)
            
            result = subprocess.run(
                ['wsl', 'volatility3', '-f', wsl_path, plugin],
                capture_output=True,
                timeout=120,
                text=True
            )
            
            results = []
            if result.returncode == 0:
                # Parse output lines
                for line in result.stdout.split('\n'):
                    if line.strip():
                        results.append(line.strip())
            
            return results, result.stdout
        
        except Exception as e:
            logger.error(f"volatility3 execution failed: {e}")
            return [], str(e)
    
    def _convert_to_wsl_path(self, windows_path: str) -> str:
        """
        Convert Windows path to WSL path
        
        Example: D:\\evidence\\file.bin -> /mnt/d/evidence/file.bin
        """
        path = Path(windows_path)
        
        # Get drive letter and path
        parts = path.parts
        if len(parts) > 0 and ':' in parts[0]:
            drive = parts[0].replace(':', '').lower()
            rest = '/'.join(parts[1:])
            wsl_path = f"/mnt/{drive}/{rest}"
        else:
            wsl_path = str(path).replace('\\', '/')
        
        return wsl_path
    
    def get_tool_status(self) -> Dict[str, Any]:
        """Get status of all SIFT tools"""
        status = {
            'wsl_enabled': self.use_wsl,
            'tools_available': sum(self.available_tools.values()),
            'tools_total': len(self.available_tools),
            'tools': self.available_tools
        }
        
        return status
