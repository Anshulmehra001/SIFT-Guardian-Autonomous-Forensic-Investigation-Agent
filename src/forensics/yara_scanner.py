"""
YARA Rule Scanner
Simple malware detection using pattern matching
"""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class YARAScanner:
    """
    Simple YARA-style pattern scanner
    Detects malware indicators without needing YARA library
    """
    
    # Simple malware patterns (common IOCs)
    MALWARE_PATTERNS = {
        'ransomware': [
            'CryptLocker', 'WannaCry', 'Ryuk', 'REvil',
            '.encrypted', '.locked', '.crypted',
            'YOUR FILES ARE ENCRYPTED',
            'pay ransom', 'bitcoin address'
        ],
        'trojan': [
            'RAT', 'Backdoor', 'RemoteAccess',
            'C2_SERVER', 'COMMAND_AND_CONTROL',
            'reverse_shell', 'bind_shell'
        ],
        'credential_theft': [
            'mimikatz', 'LaZagne', 'password dump',
            'LSASS', 'SAM database', 'credential',
            'keylogger', 'keystroke'
        ],
        'persistence': [
            'HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
            'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
            'schtasks', 'WMI subscription',
            'service install', 'startup folder'
        ],
        'powershell_abuse': [
            'powershell -enc', 'powershell -nop',
            'IEX(', 'Invoke-Expression',
            'DownloadString', 'DownloadFile',
            'System.Net.WebClient'
        ],
        'obfuscation': [
            'base64', 'FromBase64String',
            'rot13', 'xor',
            'char(', '[char]'
        ],
        'lateral_movement': [
            'PsExec', 'WMI', 'DCOM',
            'admin$', 'c$',
            'net use', 'net share'
        ],
        'data_exfiltration': [
            'ftp', 'sftp', 'http upload',
            'compress', 'archive', '.zip',
            'copy to network', 'send to'
        ]
    }
    
    def __init__(self):
        """Initialize scanner"""
        self.matches = []
    
    def scan_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        """
        Scan strings for malware patterns
        
        Args:
            strings: List of strings extracted from file
            
        Returns:
            List of pattern matches
        """
        matches = []
        
        for category, patterns in self.MALWARE_PATTERNS.items():
            for pattern in patterns:
                pattern_lower = pattern.lower()
                
                for string in strings:
                    if pattern_lower in string.lower():
                        matches.append({
                            'category': category,
                            'pattern': pattern,
                            'matched_string': string[:100],  # First 100 chars
                            'severity': self._get_severity(category)
                        })
                        break  # One match per pattern
        
        return matches
    
    def scan_file_content(self, content: bytes, max_size: int = 1024*1024) -> List[Dict[str, Any]]:
        """
        Scan raw file content
        
        Args:
            content: File content as bytes
            max_size: Maximum bytes to scan
            
        Returns:
            List of pattern matches
        """
        # Convert to string (try UTF-8, fallback to latin-1)
        try:
            text = content[:max_size].decode('utf-8', errors='ignore')
        except:
            text = content[:max_size].decode('latin-1', errors='ignore')
        
        matches = []
        
        for category, patterns in self.MALWARE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in text.lower():
                    # Find context around match
                    index = text.lower().find(pattern.lower())
                    context_start = max(0, index - 50)
                    context_end = min(len(text), index + len(pattern) + 50)
                    context = text[context_start:context_end]
                    
                    matches.append({
                        'category': category,
                        'pattern': pattern,
                        'context': context.replace('\n', ' ').replace('\r', ''),
                        'severity': self._get_severity(category),
                        'offset': index
                    })
        
        return matches
    
    def _get_severity(self, category: str) -> str:
        """Get severity level for category"""
        severity_map = {
            'ransomware': 'critical',
            'trojan': 'high',
            'credential_theft': 'high',
            'persistence': 'high',
            'powershell_abuse': 'medium',
            'obfuscation': 'medium',
            'lateral_movement': 'high',
            'data_exfiltration': 'high'
        }
        return severity_map.get(category, 'medium')
    
    def get_summary(self, matches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get summary of scan results
        
        Args:
            matches: List of pattern matches
            
        Returns:
            Summary statistics
        """
        if not matches:
            return {
                'total_matches': 0,
                'categories': [],
                'max_severity': 'none',
                'risk_score': 0
            }
        
        categories = list(set(m['category'] for m in matches))
        severities = [m['severity'] for m in matches]
        
        # Calculate risk score
        severity_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2}
        risk_score = sum(severity_scores.get(s, 0) for s in severities)
        risk_score = min(100, risk_score)  # Cap at 100
        
        # Get max severity
        severity_order = ['critical', 'high', 'medium', 'low', 'none']
        max_severity = 'none'
        for sev in severity_order:
            if sev in severities:
                max_severity = sev
                break
        
        return {
            'total_matches': len(matches),
            'categories': categories,
            'max_severity': max_severity,
            'risk_score': risk_score,
            'critical_count': severities.count('critical'),
            'high_count': severities.count('high'),
            'medium_count': severities.count('medium')
        }
