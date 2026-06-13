"""
Audit Logger - Immutable forensic logging with SHA-256 chain
Every action is logged and hashed for integrity
"""

import json
import logging
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path


logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Immutable audit logging system
    Each entry is SHA-256 hashed and chained to previous entry
    """
    
    def __init__(self, config: Dict[str, Any], case_id: str):
        """
        Initialize audit logger
        
        Args:
            config: Configuration dictionary
            case_id: Unique case identifier
        """
        self.config = config
        self.audit_config = config.get("audit", {})
        self.case_id = case_id
        
        # Setup log directory
        log_dir = Path(self.audit_config.get("log_directory", "./audit_logs"))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create case-specific log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = log_dir / f"audit_{case_id}_{timestamp}.jsonl"
        
        # Initialize chain
        self.entry_count = 0
        self.previous_hash = "0" * 64  # Genesis hash
        
        # Hash algorithm
        self.hash_algo = self.audit_config.get("hash_algorithm", "sha256")
        
        logger.info(f"Audit logger initialized: {self.log_file}")
        
        # Log initialization
        self._log_entry("audit_init", {
            "case_id": case_id,
            "timestamp": datetime.now().isoformat(),
            "log_file": str(self.log_file),
        })
    
    def log_tool_execution(
        self,
        tool: str,
        command: str,
        output: str,
        exit_code: int = 0,
        duration_ms: Optional[int] = None,
        **metadata
    ) -> str:
        """
        Log forensic tool execution
        
        Args:
            tool: Tool name
            command: Full command executed
            output: Tool output
            exit_code: Exit code
            duration_ms: Execution time in milliseconds
            **metadata: Additional metadata
            
        Returns:
            Audit ID for this entry
        """
        entry = {
            "tool": tool,
            "command": command,
            "output": output[:1000],  # Truncate long output
            "output_length": len(output),
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            **metadata
        }
        
        return self._log_entry("tool_execution", entry)
    
    def log_finding(
        self,
        finding_id: str,
        description: str,
        confidence: float,
        evidence: List[str],
        **metadata
    ) -> str:
        """
        Log investigation finding
        
        Args:
            finding_id: Unique finding identifier
            description: Finding description
            confidence: Confidence score (0.0 to 1.0)
            evidence: List of evidence artifacts
            **metadata: Additional metadata
            
        Returns:
            Audit ID
        """
        entry = {
            "finding_id": finding_id,
            "description": description,
            "confidence": confidence,
            "evidence": evidence,
            **metadata
        }
        
        return self._log_entry("finding", entry)
    
    def log_self_correction(
        self,
        original_finding: str,
        contradiction: str,
        corrected_finding: str,
        **metadata
    ) -> str:
        """
        Log self-correction event
        
        Args:
            original_finding: Original finding that was incorrect
            contradiction: What contradicted it
            corrected_finding: Corrected finding
            **metadata: Additional metadata
            
        Returns:
            Audit ID
        """
        entry = {
            "original_finding": original_finding,
            "contradiction": contradiction,
            "corrected_finding": corrected_finding,
            **metadata
        }
        
        return self._log_entry("self_correction", entry)
    
    def log_evidence_access(
        self,
        evidence_path: str,
        access_type: str,
        hash_sha256: Optional[str] = None,
        **metadata
    ) -> str:
        """
        Log evidence file access
        
        Args:
            evidence_path: Path to evidence
            access_type: Type of access (read, verify, etc)
            hash_sha256: Evidence file hash
            **metadata: Additional metadata
            
        Returns:
            Audit ID
        """
        entry = {
            "evidence_path": evidence_path,
            "access_type": access_type,
            "hash_sha256": hash_sha256,
            **metadata
        }
        
        return self._log_entry("evidence_access", entry)
    
    def log_security_event(
        self,
        event_type: str,
        severity: str,
        details: str,
        **metadata
    ) -> str:
        """
        Log security event
        
        Args:
            event_type: Event type
            severity: Severity level
            details: Event details
            **metadata: Additional metadata
            
        Returns:
            Audit ID
        """
        entry = {
            "event_type": event_type,
            "severity": severity,
            "details": details,
            **metadata
        }
        
        return self._log_entry("security_event", entry)
    
    def _log_entry(self, event_type: str, data: Dict[str, Any]) -> str:
        """
        Write audit log entry with hash chaining
        
        Args:
            event_type: Type of event
            data: Event data
            
        Returns:
            Audit ID for this entry
        """
        # Generate audit ID
        audit_id = f"{self.case_id}-{self.entry_count:06d}"
        
        # Build entry
        entry = {
            "audit_id": audit_id,
            "entry_number": self.entry_count,
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "case_id": self.case_id,
            "data": data,
            "previous_hash": self.previous_hash,
        }
        
        # Calculate hash
        entry_hash = self._calculate_hash(entry)
        entry["entry_hash"] = entry_hash
        
        # Write to log file
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
            raise
        
        # Update chain
        self.previous_hash = entry_hash
        self.entry_count += 1
        
        logger.debug(f"Audit logged: {event_type} [{audit_id}]")
        
        return audit_id
    
    def _calculate_hash(self, entry: Dict[str, Any]) -> str:
        """
        Calculate SHA-256 hash of entry
        
        Args:
            entry: Entry dictionary
            
        Returns:
            Hex digest of hash
        """
        # Create deterministic JSON string
        entry_copy = entry.copy()
        entry_copy.pop("entry_hash", None)  # Remove hash if present
        
        entry_json = json.dumps(entry_copy, sort_keys=True)
        
        # Hash with previous hash for chaining
        combined = f"{self.previous_hash}{entry_json}"
        
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """
        Verify audit log integrity
        
        Returns:
            True if integrity is intact
        """
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                previous_hash = "0" * 64
                
                for line_num, line in enumerate(f, 1):
                    entry = json.loads(line)
                    
                    # Check previous hash
                    if entry["previous_hash"] != previous_hash:
                        logger.error(
                            f"Integrity check failed at entry {line_num}: "
                            f"Hash chain broken"
                        )
                        return False
                    
                    # Recalculate hash
                    stored_hash = entry.pop("entry_hash")
                    stored_prev = entry.pop("previous_hash")
                    entry["previous_hash"] = stored_prev
                    
                    calculated_hash = self._calculate_hash(entry)
                    
                    if calculated_hash != stored_hash:
                        logger.error(
                            f"Integrity check failed at entry {line_num}: "
                            f"Hash mismatch"
                        )
                        return False
                    
                    previous_hash = stored_hash
            
            logger.info("Audit log integrity verified")
            return True
            
        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return False
    
    def get_entries_by_type(self, event_type: str) -> List[Dict[str, Any]]:
        """
        Get all entries of specific type
        
        Args:
            event_type: Event type to filter
            
        Returns:
            List of matching entries
        """
        entries = []
        
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    entry = json.loads(line)
                    if entry["event_type"] == event_type:
                        entries.append(entry)
        except Exception as e:
            logger.error(f"Failed to read audit log: {e}")
        
        return entries
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get audit log summary
        
        Returns:
            Summary dictionary
        """
        return {
            "case_id": self.case_id,
            "log_file": str(self.log_file),
            "entry_count": self.entry_count,
            "current_hash": self.previous_hash,
            "integrity_verified": self.verify_integrity(),
        }
