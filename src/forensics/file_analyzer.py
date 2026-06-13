"""
Real File Analysis - Works with actual files
Uses Python libraries for genuine forensic analysis
"""

import os
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class FileAnalyzer:
    """Real file analysis using Python forensic libraries"""
    
    def __init__(self):
        self.supported_types = ['.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs', '.js']
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Perform real analysis on a file
        
        Returns actual data, not simulated
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        analysis = {
            'file_path': str(path.absolute()),
            'file_name': path.name,
            'file_size': path.stat().st_size,
            'file_extension': path.suffix.lower(),
            'timestamps': self._get_timestamps(path),
            'hashes': self._calculate_hashes(file_path),
            'strings': self._extract_strings(file_path),
            'entropy': self._calculate_entropy(file_path),
            'suspicious_indicators': [],
            'malware_patterns': []
        }
        
        # Check for suspicious indicators
        analysis['suspicious_indicators'] = self._check_suspicious(analysis)
        
        # YARA-style pattern scanning
        from .yara_scanner import YARAScanner
        scanner = YARAScanner()
        analysis['malware_patterns'] = scanner.scan_strings(analysis['strings'])
        analysis['malware_summary'] = scanner.get_summary(analysis['malware_patterns'])
        
        # PE analysis if executable
        if path.suffix.lower() in ['.exe', '.dll', '.sys']:
            try:
                analysis['pe_info'] = self._analyze_pe(file_path)
            except Exception as e:
                logger.warning(f"PE analysis failed: {e}")
                analysis['pe_info'] = None
        
        return analysis
    
    def _get_timestamps(self, path: Path) -> Dict[str, str]:
        """Get real file timestamps"""
        stat = path.stat()
        return {
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
        }
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate real file hashes"""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for h in hashes.values():
                        h.update(chunk)
            
            return {name: h.hexdigest() for name, h in hashes.items()}
        except Exception as e:
            logger.error(f"Hash calculation failed: {e}")
            return {}
    
    def _extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract readable strings from file (real extraction)"""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 100)  # First 100KB
                
            current_string = []
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= min_length:
                        strings.append(''.join(current_string))
                    current_string = []
            
            # Get last string
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))
            
            return strings[:50]  # Return first 50 strings
        
        except Exception as e:
            logger.error(f"String extraction failed: {e}")
            return []
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy (detect encryption/packing)"""
        import math
        from collections import Counter
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 100)  # First 100KB
            
            if not data:
                return 0.0
            
            # Calculate byte frequency
            counter = Counter(data)
            entropy = 0.0
            
            for count in counter.values():
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
            
            return round(entropy, 2)
        
        except Exception as e:
            logger.error(f"Entropy calculation failed: {e}")
            return 0.0
    
    def _analyze_pe(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze PE file structure (Windows executable)
        Falls back to basic analysis if pefile not available
        """
        try:
            import pefile
            pe = pefile.PE(file_path)
            
            info = {
                'machine': hex(pe.FILE_HEADER.Machine),
                'timestamp': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                'sections': [],
                'imports': [],
                'exports': []
            }
            
            # Get sections
            for section in pe.sections:
                info['sections'].append({
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy()
                })
            
            # Get imports (first 20)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT[:5]:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    funcs = [imp.name.decode('utf-8', errors='ignore') 
                            for imp in entry.imports[:10] if imp.name]
                    info['imports'].append({
                        'dll': dll,
                        'functions': funcs
                    })
            
            return info
        
        except ImportError:
            logger.warning("pefile not installed, using basic analysis")
            return self._basic_pe_analysis(file_path)
        except Exception as e:
            logger.error(f"PE analysis error: {e}")
            return None
    
    def _basic_pe_analysis(self, file_path: str) -> Dict[str, Any]:
        """Basic PE analysis without pefile library"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)
            
            # Check PE signature
            if data[:2] != b'MZ':
                return {'error': 'Not a valid PE file'}
            
            return {
                'format': 'PE',
                'signature': 'MZ',
                'note': 'Install pefile for detailed analysis'
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _check_suspicious(self, analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """Check for suspicious indicators"""
        indicators = []
        
        # High entropy (packed/encrypted)
        if analysis.get('entropy', 0) > 7.0:
            indicators.append({
                'type': 'HIGH_ENTROPY',
                'severity': 'MEDIUM',
                'description': f"High entropy ({analysis['entropy']}) suggests packing or encryption"
            })
        
        # Suspicious strings
        suspicious_strings = [
            'powershell', 'cmd.exe', 'reg.exe', 'schtasks',
            'RunDLL', 'WScript', 'CreateProcess', 'VirtualAlloc',
            'keylog', 'password', 'credential'
        ]
        
        found_strings = []
        for string in analysis.get('strings', []):
            for suspicious in suspicious_strings:
                if suspicious.lower() in string.lower():
                    found_strings.append(string)
                    break
        
        if found_strings:
            indicators.append({
                'type': 'SUSPICIOUS_STRINGS',
                'severity': 'LOW',
                'description': f"Found {len(found_strings)} suspicious strings",
                'examples': found_strings[:5]
            })
        
        # Double extension
        if analysis['file_name'].count('.') > 1:
            indicators.append({
                'type': 'DOUBLE_EXTENSION',
                'severity': 'LOW',
                'description': 'File has multiple extensions (possible obfuscation)'
            })
        
        # Suspicious size (very small executables)
        if analysis['file_extension'] in ['.exe', '.dll'] and analysis['file_size'] < 10000:
            indicators.append({
                'type': 'SUSPICIOUS_SIZE',
                'severity': 'LOW',
                'description': f"Unusually small executable ({analysis['file_size']} bytes)"
            })
        
        return indicators
