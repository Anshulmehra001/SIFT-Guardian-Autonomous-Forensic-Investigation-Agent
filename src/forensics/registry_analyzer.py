"""
Real Windows Registry Analysis
Works with actual registry hives on Windows or exported hives
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class RegistryAnalyzer:
    """Analyze Windows Registry for forensic artifacts"""
    
    # Known persistence locations
    AUTORUN_KEYS = [
        r'Software\Microsoft\Windows\CurrentVersion\Run',
        r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'Software\Microsoft\Windows\CurrentVersion\RunServices',
        r'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    ]
    
    def __init__(self):
        self.use_live_registry = self._check_windows()
    
    def _check_windows(self) -> bool:
        """Check if running on Windows with registry access"""
        try:
            import winreg
            return True
        except ImportError:
            return False
    
    def analyze_persistence(self) -> List[Dict[str, Any]]:
        """
        Analyze registry for persistence mechanisms
        Returns REAL registry data
        """
        findings = []
        
        if self.use_live_registry:
            findings = self._analyze_live_registry()
        else:
            findings.append({
                'location': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'note': 'Not on Windows - use exported hive for analysis'
            })
        
        return findings
    
    def _analyze_live_registry(self) -> List[Dict[str, Any]]:
        """Analyze live Windows registry"""
        try:
            import winreg
            
            findings = []
            hives = [
                (winreg.HKEY_LOCAL_MACHINE, 'HKLM'),
                (winreg.HKEY_CURRENT_USER, 'HKCU')
            ]
            
            for hive, hive_name in hives:
                for key_path in self.AUTORUN_KEYS:
                    try:
                        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                        
                        # Enumerate values
                        index = 0
                        while True:
                            try:
                                name, value, value_type = winreg.EnumValue(key, index)
                                
                                findings.append({
                                    'hive': hive_name,
                                    'key_path': key_path,
                                    'value_name': name,
                                    'value_data': value,
                                    'value_type': value_type,
                                    'suspicious': self._check_suspicious_value(value)
                                })
                                
                                index += 1
                            except OSError:
                                break
                        
                        winreg.CloseKey(key)
                    
                    except FileNotFoundError:
                        # Key doesn't exist
                        pass
                    except Exception as e:
                        logger.error(f"Error reading {key_path}: {e}")
            
            return findings
        
        except Exception as e:
            logger.error(f"Registry analysis failed: {e}")
            return []
    
    def _check_suspicious_value(self, value: str) -> bool:
        """Check if registry value is suspicious"""
        if not isinstance(value, str):
            return False
        
        suspicious_indicators = [
            'powershell',
            'cmd.exe',
            'wscript',
            'cscript',
            'rundll32',
            'regsvr32',
            'mshta',
            'AppData\\Roaming',
            'Temp\\',
            '.bat',
            '.vbs',
            '.ps1'
        ]
        
        value_lower = value.lower()
        return any(indicator.lower() in value_lower for indicator in suspicious_indicators)
    
    def analyze_hive_file(self, hive_path: str) -> List[Dict[str, Any]]:
        """
        Analyze exported registry hive file
        Requires python-registry or regipy
        """
        try:
            from Registry import Registry
            
            reg = Registry.Registry(hive_path)
            findings = []
            
            for key_path in self.AUTORUN_KEYS:
                try:
                    key = reg.open(key_path)
                    
                    for value in key.values():
                        findings.append({
                            'key_path': key_path,
                            'value_name': value.name(),
                            'value_data': value.value(),
                            'timestamp': key.timestamp().isoformat(),
                            'suspicious': self._check_suspicious_value(str(value.value()))
                        })
                
                except Registry.RegistryKeyNotFoundException:
                    pass
                except Exception as e:
                    logger.error(f"Error analyzing {key_path}: {e}")
            
            return findings
        
        except ImportError:
            logger.warning("python-registry not installed")
            return [{'note': 'Install python-registry for hive analysis'}]
        except Exception as e:
            logger.error(f"Hive analysis failed: {e}")
            return []
