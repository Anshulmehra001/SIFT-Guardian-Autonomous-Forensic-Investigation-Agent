"""
Self-Correction System - Detects contradictions and re-investigates
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from .findings import Finding


logger = logging.getLogger(__name__)


class SelfCorrector:
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize self-corrector"""
        self.config = config
        self.correction_config = config.get("self_correction", {})
        self.enabled = self.correction_config.get("enabled", True)
        self.confidence_threshold = self.correction_config.get("confidence_threshold", 0.75)
        self.max_iterations = self.correction_config.get("max_iterations", 3)
        self.iteration_count = 0
        
        logger.info(f"Self-corrector initialized (enabled: {self.enabled})")
    
    def check_finding(self, finding: Finding, existing_findings: List[Finding]) -> Tuple[bool, Optional[str]]:
        """Check if finding has contradictions or issues"""
        if not self.enabled:
            return False, None
        
        logger.debug(f"Checking finding {finding.id} for contradictions...")
        
        if finding.confidence < self.confidence_threshold:
            logger.info(
                f"Finding {finding.id} below confidence threshold: "
                f"{finding.confidence} < {self.confidence_threshold}"
            )
            return True, f"Low confidence: {finding.confidence}"
        
        for existing in existing_findings:
            contradiction = self._detect_contradiction(finding, existing)
            if contradiction:
                logger.warning(
                    f"Contradiction detected between {finding.id} and {existing.id}: "
                    f"{contradiction}"
                )
                return True, contradiction
        
        return False, None
    
    def _detect_contradiction(self, finding1: Finding, finding2: Finding) -> Optional[str]:
        """Detect contradictions between two findings"""
        
        if finding1.timestamp < finding2.timestamp:
            if "after" in finding1.description.lower() and finding2.id in finding1.description:
                return "Temporal contradiction: Event order doesn't match timestamps"
        
        execution_keywords = ["executed", "ran", "launched", "started"]
        presence_keywords = ["present", "exists", "found", "located"]
        
        f1_claims_execution = any(kw in finding1.description.lower() for kw in execution_keywords)
        f2_claims_only_presence = any(kw in finding2.description.lower() for kw in presence_keywords)
        
        if f1_claims_execution and f2_claims_only_presence:
            common_artifacts = set(finding1.evidence) & set(finding2.evidence)
            if common_artifacts:
                return (
                    f"Execution vs presence contradiction: "
                    f"One finding claims execution, other only confirms presence"
                )
        
        common_evidence = set(finding1.evidence) & set(finding2.evidence)
        if common_evidence:
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            diff = abs(severity_order[finding1.severity] - severity_order[finding2.severity])
            
            if diff >= 2:
                return (
                    f"Severity mismatch: Same evidence rated as "
                    f"{finding1.severity} and {finding2.severity}"
                )
        
        return None
    
    def should_reinvestigate(self, finding: Finding) -> bool:
        """Determine if finding needs reinvestigation"""
        if not self.enabled:
            return False
        
        if self.iteration_count >= self.max_iterations:
            logger.warning("Max self-correction iterations reached")
            return False
        
        if finding.confidence < self.confidence_threshold:
            return True
        
        if len(finding.evidence) < 2 and self.correction_config.get("cross_validate", True):
            logger.info(f"Finding {finding.id} needs more corroborating evidence")
            return True
        
        return False
    
    def generate_reinvestigation_prompt(
        self,
        finding: Finding,
        contradiction: Optional[str] = None
    ) -> str:
        """Generate prompt for reinvestigation"""
        self.iteration_count += 1
        
        prompt = f"""
SELF-CORRECTION REQUIRED - Iteration {self.iteration_count}/{self.max_iterations}

Original Finding:
{finding.description}
Confidence: {finding.confidence}
Evidence: {', '.join(finding.evidence)}

"""
        
        if contradiction:
            prompt += f"""
Contradiction Detected:
{contradiction}

"""
        
        prompt += "Re-investigate this finding with more careful analysis and additional evidence collection."
        
        return prompt
    
    def record_correction(
        self,
        original: Finding,
        corrected: Finding,
        reason: str
    ) -> Dict[str, Any]:
        """Record a correction event"""
        correction = {
            "original_finding_id": original.id,
            "original_description": original.description,
            "original_confidence": original.confidence,
            "corrected_finding_id": corrected.id,
            "corrected_description": corrected.description,
            "corrected_confidence": corrected.confidence,
            "correction_reason": reason,
            "iteration": self.iteration_count,
        }
        
        logger.info(
            f"Self-correction recorded: {original.id} -> {corrected.id} "
            f"(confidence: {original.confidence:.2f} -> {corrected.confidence:.2f})"
        )
        
        return correction
    
    def reset_iterations(self) -> None:
        """Reset iteration counter"""
        self.iteration_count = 0
