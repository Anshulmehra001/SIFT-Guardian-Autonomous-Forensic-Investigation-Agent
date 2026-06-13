"""
Finding management system
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid


@dataclass
class Finding:
    """
    Represents a security finding
    """
    id: str = field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8]}")
    description: str = ""
    confidence: float = 0.0  # 0.0 to 1.0
    severity: str = "info"  # critical, high, medium, low, info
    evidence: List[str] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    audit_ids: List[str] = field(default_factory=list)
    validated: bool = False
    corrected: bool = False
    correction_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "description": self.description,
            "confidence": self.confidence,
            "severity": self.severity,
            "evidence": self.evidence,
            "artifacts": self.artifacts,
            "mitre_tactics": self.mitre_tactics,
            "timestamp": self.timestamp.isoformat(),
            "audit_ids": self.audit_ids,
            "validated": self.validated,
            "corrected": self.corrected,
            "correction_reason": self.correction_reason,
        }


class FindingManager:
    """Manages investigation findings"""
    
    def __init__(self):
        self.findings: List[Finding] = []
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding"""
        self.findings.append(finding)
    
    def get_findings(self, min_confidence: float = 0.0) -> List[Finding]:
        """Get findings above confidence threshold"""
        return [f for f in self.findings if f.confidence >= min_confidence]
    
    def get_by_severity(self, severity: str) -> List[Finding]:
        """Get findings by severity"""
        return [f for f in self.findings if f.severity == severity]
    
    def mark_corrected(self, finding_id: str, reason: str) -> None:
        """Mark finding as corrected"""
        for finding in self.findings:
            if finding.id == finding_id:
                finding.corrected = True
                finding.correction_reason = reason
                break
    
    def get_summary(self) -> Dict[str, Any]:
        """Get findings summary"""
        return {
            "total": len(self.findings),
            "by_severity": {
                "critical": len(self.get_by_severity("critical")),
                "high": len(self.get_by_severity("high")),
                "medium": len(self.get_by_severity("medium")),
                "low": len(self.get_by_severity("low")),
            },
            "corrected": len([f for f in self.findings if f.corrected]),
            "validated": len([f for f in self.findings if f.validated]),
        }
