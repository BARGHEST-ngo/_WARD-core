"""
Scoring service for risk assessment.

This service handles all scoring logic in a clean, focused way.
"""

from typing import Dict, List, Tuple
import logging
import re

from ward_core.logic.models import Detection, RiskLevel, ScoringConfig, HeuristicResult


class ScoringService:
    """
    Service responsible for calculating scores and risk levels.
    
    This replaces the complex scoring logic scattered throughout correlate.py.
    """
    
    def __init__(self, config: ScoringConfig):
        """
        Initialize the scoring service.
        
        Args:
            config: Scoring configuration
        """
        self.config = config
        self.logger = logging.getLogger("scoring.service")

        # Initialize episode service (local import to avoid circular dependency)
        from .episode_service import EpisodeService
        self.episode_service = EpisodeService()
    
    def calculate_overall_score(
        self, 
        heuristic_results: Dict[str, HeuristicResult],
        detections: List[Detection]
    ) -> Tuple[float, RiskLevel]:
        """
        Calculate overall score and risk level with enhanced spyware detection.
        
        Args:
            heuristic_results: Results from all heuristics
            detections: All detections (after quality gates and grouping)
            
        Returns:
            Tuple of (overall_score, risk_level)
        """
        if not heuristic_results:
            return 0.0, RiskLevel.LOW
        
        # Step 1: Check for critical spyware indicators (escalates to MEDIUM/HIGH)
        critical_indicators = self._check_critical_spyware_indicators(detections)
        if critical_indicators:
            self.logger.info(f"Critical spyware indicators detected: {critical_indicators}")
            # Escalate risk level based on critical indicators
            risk_level = self._escalate_risk_for_critical_indicators(critical_indicators)
            # Calculate base score but ensure it meets minimum for the escalated risk level
            base_score = self._calculate_base_score(heuristic_results, detections)
            final_score = max(base_score, self._get_minimum_score_for_risk_level(risk_level))
            return final_score, risk_level
        
        # Step 2: Calculate weighted scores
        weighted_scores = self._calculate_weighted_scores(heuristic_results)
        
        # Step 3: Apply category multipliers
        category_adjusted_scores = self._apply_category_multipliers(weighted_scores, heuristic_results)
        
        # Step 4: Calculate raw overall score
        raw_score = sum(category_adjusted_scores.values())
        
        # Step 5: Apply moderation factors
        moderated_score = self._apply_moderation_factors(raw_score, heuristic_results, detections)
        
        # Step 6: Normalize to 0-100 scale
        final_score = min(100.0, max(0.0, moderated_score))
        
        # Step 7: Determine risk level
        risk_level = self._determine_risk_level(final_score)
        
        self.logger.info(f"Score calculation: raw={raw_score:.1f}, moderated={moderated_score:.1f}, final={final_score:.1f}")
        
        return final_score, risk_level
    
    def _calculate_weighted_scores(self, heuristic_results: Dict[str, HeuristicResult]) -> Dict[str, float]:
        """Calculate weighted scores for each heuristic."""
        weighted_scores = {}
        
        for name, result in heuristic_results.items():
            if result.error:
                weighted_scores[name] = 0.0
                continue
            
            # Get heuristic weight (from config or default)
            weight = getattr(result, 'weight', 1.0)
            
            # Normalize score (assuming max score of 10.0 for most heuristics)
            max_score = getattr(result, 'max_score', 10.0)
            normalized_score = min(1.0, result.score / max_score) if max_score > 0 else 0.0
            
            # Apply weight
            weighted_score = normalized_score * weight
            weighted_scores[name] = weighted_score
        
        return weighted_scores
    
    def _apply_category_multipliers(
        self, 
        weighted_scores: Dict[str, float],
        heuristic_results: Dict[str, HeuristicResult]
    ) -> Dict[str, float]:
        """Apply category-based multipliers to scores."""
        # Map heuristics to categories
        heuristic_categories = {
            "permission_analysis": "Permission Abuse",
            "behavioral_analysis": "Persistence",
            "resource_analysis": "Persistence", 
            "network_analysis": "Network Behavior",
            "exploitation_crash": "Crash or Kernel Abuse",
            "memory_exploitation": "Crash or Kernel Abuse",
            "crash_analysis": "Crash or Kernel Abuse",
            "kernel_threats": "Crash or Kernel Abuse",
            "system_security": "System Privilege Abuse",
            "system_anomalies": "System Privilege Abuse"
        }
        
        category_adjusted = {}
        
        for name, weighted_score in weighted_scores.items():
            category = heuristic_categories.get(name, "Privacy Abuse")  # Default category
            multiplier = self.config.category_weights.get(category, 1.0)
            
            category_adjusted[name] = weighted_score * multiplier
        
        return category_adjusted
    
    def _apply_moderation_factors(
        self,
        raw_score: float,
        heuristic_results: Dict[str, HeuristicResult],
        detections: List[Detection]
    ) -> float:
        """Apply moderation factors to prevent score inflation."""
        
        # Breadth factor: how many heuristics triggered
        total_heuristics = len(heuristic_results)
        triggered_heuristics = len([r for r in heuristic_results.values() if r.score > 0])
        breadth_factor = triggered_heuristics / total_heuristics if total_heuristics > 0 else 0.0
        
        # Confidence factor: average confidence of triggered heuristics
        confidence_factor = self._calculate_confidence_factor(heuristic_results)
        
        # Apply moderation formula
        moderated_score = raw_score * (
            0.6 + self.config.breadth_factor_weight * breadth_factor
        ) * confidence_factor
        
        self.logger.debug(f"Moderation factors: breadth={breadth_factor:.2f}, confidence={confidence_factor:.2f}")
        
        return moderated_score
    
    def _calculate_confidence_factor(self, heuristic_results: Dict[str, HeuristicResult]) -> float:
        """Calculate confidence factor from heuristic results."""
        confidence_map = {'low': 0.6, 'medium': 0.8, 'high': 1.0}
        confidences = []
        
        for result in heuristic_results.values():
            if result.score > 0 and not result.error:
                # Get confidence from metadata or default to medium
                confidence_str = 'medium'  # Default
                if result.metadata and 'config' in result.metadata:
                    config_data = result.metadata['config']
                    if isinstance(config_data, dict):
                        confidence_str = config_data.get('confidence', 'medium')
                
                confidence_value = confidence_map.get(confidence_str, 0.8)
                confidences.append(confidence_value)
        
        return sum(confidences) / len(confidences) if confidences else 0.8
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level based on score."""
        if score >= self.config.risk_thresholds["CRITICAL"]:
            return RiskLevel.CRITICAL
        elif score >= self.config.risk_thresholds["HIGH"]:
            return RiskLevel.HIGH
        elif score >= self.config.risk_thresholds["MEDIUM"]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _check_critical_spyware_indicators(self, detections: List[Detection]) -> List[str]:
        """Check for critical spyware indicators that should escalate risk level."""
        critical_indicators = []
        
        # Critical spyware patterns that indicate high-risk behavior
        critical_patterns = {
            'accessibility_hijack': [
                'accessibility.*service.*abuse',
                'accessibility.*hijack',
                'accessibility.*escalation',
                'accessibility.*privilege.*escalation',
                'accessibility.*service.*dangerous.*permissions',  # NEW
                'accessibility.*device.*takeover'  # NEW
            ],
            'device_takeover': [
                'device.*takeover',
                'accessibility.*installation.*rights',
                'accessibility.*system.*overlay',
                'accessibility.*dangerous.*permissions'
            ],
            'persistent_surveillance': [
                'persistent.*foreground.*service',
                'long.*running.*service',
                'persistent.*surveillance',
                'foreground.*service.*hours',
                'surveillance.*service'
            ],
            'policy_violation': [
                'play.*store.*disabled',
                'policy.*violation',
                'google.*play.*disabled',
                'vending.*disabled'
            ],
            'malicious_intent': [
                'blocked.*operations',
                'malicious.*intent',
                'high.*risk.*blocked',
                'attempted.*sms.*access',
                'attempted.*media.*projection'
            ],
            'sandbox_escape': [
                'sandbox.*escape',
                'container.*escape',
                'isolation.*bypass',
                'privilege.*escalation.*root',
                'uid.*escalation',
                'system.*uid.*abuse'
            ],
            'persistent_malware': [
                'persistent.*malware',
                'boot.*persistence',
                'system.*persistence',
                'survive.*reboot'
            ],
            'data_exfiltration': [
                'mass.*data.*exfiltration',
                'bulk.*data.*upload',
                'sensitive.*data.*exfiltration',
                'personal.*data.*theft'
            ],
            'command_control': [
                'command.*control',
                'c2.*communication',
                'remote.*control',
                'backdoor.*communication'
            ]
        }
        
        for detection in detections:
            # Check detection title and description
            detection_text = f"{detection.title} {detection.description}".lower()
            
            for indicator_type, patterns in critical_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, detection_text, re.IGNORECASE):
                        critical_indicators.append(indicator_type)
                        break  # One match per indicator type is enough
        
        return list(set(critical_indicators))  # Remove duplicates
    
    def _escalate_risk_for_critical_indicators(self, critical_indicators: List[str]) -> RiskLevel:
        """Determine risk level escalation based on critical indicators."""
        # Map critical indicators to risk levels
        indicator_risk_mapping = {
            'accessibility_hijack': RiskLevel.HIGH,
            'device_takeover': RiskLevel.CRITICAL,  # NEW: Most severe
            'persistent_surveillance': RiskLevel.HIGH,  # NEW
            'policy_violation': RiskLevel.MEDIUM,  # NEW
            'malicious_intent': RiskLevel.MEDIUM,  # NEW
            'sandbox_escape': RiskLevel.HIGH,
            'persistent_malware': RiskLevel.MEDIUM,
            'data_exfiltration': RiskLevel.MEDIUM,
            'command_control': RiskLevel.HIGH
        }
        
        # Find the highest risk level among detected indicators
        max_risk_level = RiskLevel.LOW
        for indicator in critical_indicators:
            risk_level = indicator_risk_mapping.get(indicator, RiskLevel.LOW)
            if self._risk_level_value(risk_level) > self._risk_level_value(max_risk_level):
                max_risk_level = risk_level
        
        return max_risk_level
    
    def _risk_level_value(self, risk_level: RiskLevel) -> int:
        """Get numeric value for risk level comparison."""
        risk_values = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4
        }
        return risk_values.get(risk_level, 1)
    
    def _get_minimum_score_for_risk_level(self, risk_level: RiskLevel) -> float:
        """Get minimum score required for a given risk level."""
        risk_thresholds = {
            RiskLevel.LOW: 0.0,
            RiskLevel.MEDIUM: 49.0,
            RiskLevel.HIGH: 74.0,
            RiskLevel.CRITICAL: 100.0
        }
        return risk_thresholds.get(risk_level, 0.0)
    
    def _calculate_base_score(self, heuristic_results: Dict[str, HeuristicResult], detections: List[Detection]) -> float:
        """Calculate base score without critical indicator escalation."""
        # Calculate weighted scores
        weighted_scores = self._calculate_weighted_scores(heuristic_results)
        
        # Apply category multipliers
        category_adjusted_scores = self._apply_category_multipliers(weighted_scores, heuristic_results)
        
        # Calculate raw overall score
        raw_score = sum(category_adjusted_scores.values())
        
        # Apply moderation factors
        moderated_score = self._apply_moderation_factors(raw_score, heuristic_results, detections)
        
        # Normalize to 0-100 scale
        return min(100.0, max(0.0, moderated_score))
    
    def consolidate_crash_detections(self, detections: List[Detection]) -> List[Detection]:
        """Consolidate repetitive crash detections using shared episode service."""
        # Separate crash and non-crash detections
        crash_detections = []
        other_detections = []

        for detection in detections:
            if self._is_crash_detection(detection):
                crash_detections.append(detection)
            else:
                other_detections.append(detection)

        # Use shared episode service for consolidation
        consolidated_crashes = self.episode_service.consolidate_by_root_cause(
            crash_detections,
            get_root_cause=self._identify_crash_root_cause,
            create_consolidated=self._create_consolidated_crash_detection
        )

        return other_detections + consolidated_crashes
    
    def _is_crash_detection(self, detection: Detection) -> bool:
        """Check if detection is related to crashes."""
        crash_keywords = ['crash', 'segfault', 'null pointer', 'stack overflow', 'memory corruption']
        detection_text = f"{detection.title} {detection.description}".lower()
        return any(keyword in detection_text for keyword in crash_keywords)
    
    def _identify_crash_root_cause(self, detection: Detection) -> str:
        """Identify the root cause of a crash detection."""
        # Extract package name or process name as root cause
        package = getattr(detection, 'package', 'unknown')
        if package and package != 'unknown':
            return f"crash_{package}"
        
        # Try to extract from technical details
        tech_details = getattr(detection, 'technical_details', {})
        if isinstance(tech_details, dict):
            package = tech_details.get('package_name', tech_details.get('process_name', 'unknown'))
            return f"crash_{package}"
        
        return "crash_unknown"
    
    def _create_consolidated_crash_detection(self, root_cause: str, crash_detections: List[Detection]) -> Detection:
        """Create a consolidated crash detection from multiple similar crashes."""
        # Count total crashes
        total_crashes = len(crash_detections)
        
        # Get the highest severity among all crashes
        max_severity = max(detection.severity for detection in crash_detections)
        
        # Combine evidence
        combined_evidence = []
        for detection in crash_detections:
            combined_evidence.extend(detection.evidence)
        
        # Create consolidated detection
        return Detection(
            category="System Stability",
            title=f"Multiple Crashes: {root_cause}",
            description=f"Detected {total_crashes} crashes with root cause: {root_cause}",
            severity=max_severity,
            confidence=0.9,  # High confidence for consolidated findings
            evidence=combined_evidence[:10],  # Limit evidence to prevent spam
            technical_details={
                'heuristic_name': 'crash_consolidation',
                'root_cause': root_cause,
                'total_crashes': total_crashes,
                'consolidated_from': [d.title for d in crash_detections]
            }
        )
    
    def get_severity_weight(self, severity: str) -> float:
        """Get weight for a severity level."""
        weights = {
            'low': 1.0,
            'medium': 2.5,
            'high': 5.0,
            'critical': 10.0
        }
        return weights.get(severity.lower(), 2.5)
