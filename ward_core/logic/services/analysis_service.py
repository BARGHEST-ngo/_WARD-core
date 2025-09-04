"""
Core analysis service.

This service orchestrates the entire analysis process with 'hopefully' a clean separation of concerns.
Main services: 
1. Run heuristics
2. Apply quality gates (filter detections based on quality criteria)
3. Group detections by time windows (dedupe)
4. Deduplicate detections across heuristics (dedupe)
5. Calculate scores and risk levels
"""

import time
from typing import List, Dict, Any
import logging

from ward_core.logic.models import AnalysisResult, AnalysisConfig, LogData, Detection, EvidenceType
from ward_core.logic.models import HeuristicResult as AnalysisHeuristicResult
from ward_core.heuristics.base import HeuristicRegistry, EvidenceQualityGate, TimeWindowGrouper, SuspiciousIndicatorGate
from .scoring_service import ScoringService
from .correlation_service import CorrelationService


class AnalysisService:
    """
    Main analysis service that orchestrates the entire analysis process.
    
    This service replaces the monolithic correlate.py with a clean, focused implementation.
    """
    
    def __init__(self, config: AnalysisConfig):
        """
        Initialize the analysis service.
        
        Args:
            config: Analysis configuration
        """
        self.config = config
        self.logger = logging.getLogger("analysis.service")
        
        # Initialize components
        self.heuristic_registry = HeuristicRegistry()
        
        # Manually register implemented heuristics
        self._register_implemented_heuristics()
        
        self.scoring_service = ScoringService(config.scoring)
        self.correlation_service = CorrelationService()
        
        # Initialize quality gates
        self.quality_gates = [
            EvidenceQualityGate(
                require_log_evidence=config.quality_gates.require_log_evidence,
                min_evidence_items=config.quality_gates.min_evidence_items
            ),
            SuspiciousIndicatorGate(
                min_suspicious_indicators=config.quality_gates.min_suspicious_indicators
            )
        ]
        
        self.time_grouper = TimeWindowGrouper(
            window_minutes=config.quality_gates.time_window_minutes
        )
    
    def analyze(self, log_data: LogData) -> AnalysisResult:
        """
        Run the complete analysis process.
        
        Args:
            log_data: The log data to analyze
            
        Returns:
            Complete analysis result
        """
        start_time = time.time()
        
        self.logger.info(f"Starting analysis with {len(self.config.get_enabled_heuristics())} heuristics")
        self.logger.info(f"Analyzing {log_data.get_line_count():,} log lines from {log_data.get_package_count()} packages")
        
        try:
            # Step 1: Run heuristics
            heuristic_results = self._run_heuristics(log_data)
            
            # Step 2: Collect all detections
            all_detections = self._collect_detections(heuristic_results)
            
            # Step 3: Apply quality gates
            filtered_detections = self._apply_quality_gates(all_detections)
            
            # Step 4: Consolidate crash detections to reduce noise
            consolidated_detections = self.scoring_service.consolidate_crash_detections(filtered_detections)

            # Step 4.5: Deduplicate similar detections across heuristics
            deduplicated_detections = self._deduplicate_detections(consolidated_detections)

            # Step 5: Group similar detections by time windows
            grouped_detections = self._group_detections(deduplicated_detections)
            
            # Step 6: Calculate scores and risk levels with enhanced spyware detection
            overall_score, risk_level = self.scoring_service.calculate_overall_score(
                heuristic_results, grouped_detections
            )
            
            # Step 6: Create final result
            execution_time = time.time() - start_time
            
            result = AnalysisResult(
                overall_score=overall_score,
                risk_level=risk_level,
                detections=grouped_detections,
                heuristic_results=heuristic_results,
                device_id=log_data.device_info.device_id,
                device_model=log_data.device_info.device_model,
                android_version=log_data.device_info.android_version,
                build_fingerprint=log_data.device_info.build_fingerprint,
                timestamp=log_data.timestamp,
                total_heuristics=len(self.config.heuristics),
                triggered_heuristics=len([r for r in heuristic_results.values() if r.score > 0]),
                lines_analyzed=log_data.get_line_count(),
                packages_analyzed=log_data.get_package_count(),
                execution_time=execution_time,
                missing_sections=log_data.missing_sections,
                coverage_score=self._calculate_coverage_score(log_data),
                confidence_score=self._calculate_confidence_score(heuristic_results)
            )
            
            self.logger.info(f"Analysis completed in {execution_time:.1f}s")
            self.logger.info(f"Found {len(grouped_detections)} detections with risk level: {risk_level.value}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}", exc_info=True)
            raise
    
    def _run_heuristics(self, log_data: LogData) -> Dict[str, AnalysisHeuristicResult]:
        """Run all enabled heuristics."""
        results = {}
        enabled_heuristics = self.config.get_enabled_heuristics()
        
        # Create heuristic instances
        heuristic_instances = self.heuristic_registry.create_instances(
            {name: self.config.heuristics[name] for name in enabled_heuristics}
        )
        
        for i, (name, heuristic) in enumerate(heuristic_instances.items(), 1):
            self.logger.info(f"[{i}/{len(heuristic_instances)}] Running {name}...")
            
            try:
                base_result = heuristic.run(log_data)
                
                # Convert to AnalysisHeuristicResult with normalized score and weight
                heuristic_config = self.config.heuristics.get(name)
                weight = heuristic_config.weight if heuristic_config else 1.0
                normalized_score = min(1.0, base_result.score / heuristic.max_score) if heuristic.max_score > 0 else 0.0
                
                analysis_result = AnalysisHeuristicResult(
                    name=name,
                    score=base_result.score,
                    normalized_score=normalized_score,
                    weight=weight,
                    detections=base_result.detections,
                    execution_time=base_result.execution_time,
                    error=base_result.error,
                    metadata=getattr(base_result, 'metadata', {})
                )
                
                results[name] = analysis_result
                
                self.logger.info(f"[✓] {name} completed in {base_result.execution_time:.1f}s - "
                               f"found {len(base_result.detections)} detections")
                
            except Exception as e:
                self.logger.error(f"[!] Error running heuristic {name}: {e}")
                # Create error result
                results[name] = AnalysisHeuristicResult(
                    name=name,
                    score=0.0,
                    normalized_score=0.0,
                    weight=1.0,
                    detections=[],
                    execution_time=0.0,
                    error=str(e),
                    metadata={}
                )
        
        return results
    
    def _collect_detections(self, heuristic_results: Dict[str, AnalysisHeuristicResult]) -> List[Detection]:
        """Collect all detections from heuristic results."""
        all_detections = []
        
        for result in heuristic_results.values():
            all_detections.extend(result.detections)
        
        self.logger.info(f"Collected {len(all_detections)} total detections")
        return all_detections
    
    def _apply_quality_gates(self, detections: List[Detection]) -> List[Detection]:
        """Apply quality gates to filter detections."""
        filtered = detections
        
        for gate in self.quality_gates:
            before_count = len(filtered)
            filtered_before = filtered.copy()
            filtered = gate.filter(filtered)
            after_count = len(filtered)
            
            if before_count != after_count:
                gate_name = gate.__class__.__name__
                self.logger.info(f"Quality gate {gate_name}: {before_count} → {after_count} detections")
                
                # Show which detections were filtered out
                filtered_out = [d for d in filtered_before if d not in filtered]
                for detection in filtered_out:
                    self.logger.info(f"  Filtered out: {detection.title} (Package: {detection.package}, Category: {detection.category})")
                    self.logger.info(f"    Evidence count: {len(detection.evidence)}")
                    self.logger.info(f"    Evidence types: {[e.type.value for e in detection.evidence]}")
                    if hasattr(gate, '_passes_quality_check'):
                        reason = self._get_filter_reason(gate, detection)
                        self.logger.info(f"    Reason: {reason}")
        
        self.logger.info(f"Quality gates filtered {len(detections)} → {len(filtered)} detections")
        return filtered
    
    def _get_filter_reason(self, gate, detection: Detection) -> str:
        """Get the reason why a detection was filtered by a specific gate."""
        if isinstance(gate, EvidenceQualityGate):
            if len(detection.evidence) < gate.min_evidence_items:
                return f"Insufficient evidence items ({len(detection.evidence)} < {gate.min_evidence_items})"
            if gate.require_log_evidence:
                has_log_evidence = any(e.type == EvidenceType.LOG_ANCHOR for e in detection.evidence)
                if not has_log_evidence:
                    return "No log evidence found (require_log_evidence=True)"
        elif isinstance(gate, SuspiciousIndicatorGate):
            indicator_count = gate._count_suspicious_indicators(detection)
            return f"Insufficient suspicious indicators ({indicator_count} < {gate.min_suspicious_indicators})"
        
        return "Unknown reason"
    
    def _group_detections(self, detections: List[Detection]) -> List[Detection]:
        """Group similar detections by time windows."""
        if not detections:
            return []
        
        before_count = len(detections)
        grouped = self.time_grouper.group_detections(detections)
        after_count = len(grouped)
        
        if before_count != after_count:
            self.logger.info(f"Time window grouping: {before_count} → {after_count} detections")
        
        return grouped

    def _deduplicate_detections(self, detections: List[Detection]) -> List[Detection]:
        """
        Deduplicate similar detections across different heuristics to reduce noise.
        Addresses the issue of overlapping detections between heuristics.
        """
        if not detections:
            return detections

        # Group detections by similarity
        similarity_groups = {}

        for detection in detections:
            # Create similarity key based on package, category, and core issue
            # Use detection.package (the actual package field) instead of technical_details
            package = detection.package or 'unknown'
            category = detection.category

            # Normalize title to identify similar issues
            title_normalized = detection.title.lower()

            # Special handling for common overlapping patterns
            if 'selinux' in title_normalized and 'avc' in title_normalized:
                similarity_key = f"selinux_avc_{package}"
            elif 'permission' in title_normalized and ('camera' in title_normalized or 'record_audio' in title_normalized):
                sensor_type = 'camera' if 'camera' in title_normalized else 'audio'
                similarity_key = f"sensor_permission_{package}_{sensor_type}"
            elif 'covert' in title_normalized and ('camera' in title_normalized or 'record_audio' in title_normalized):
                sensor_type = 'camera' if 'camera' in title_normalized else 'audio'
                similarity_key = f"covert_sensor_{package}_{sensor_type}"
            elif 'excessive' in title_normalized and 'cpu' in title_normalized:
                similarity_key = f"cpu_usage_{package}"
            else:
                # Use detection ID to ensure each detection is unique - no more inappropriate grouping
                # This prevents merging separate package detections (com.li.activity, com.android.massistant)
                similarity_key = f"{package}_{category}_{detection.id}"

            if similarity_key not in similarity_groups:
                similarity_groups[similarity_key] = []
            similarity_groups[similarity_key].append(detection)

        # Deduplicate each group
        deduplicated = []
        for group_detections in similarity_groups.values():
            if len(group_detections) == 1:
                # Single detection - keep as is
                deduplicated.append(group_detections[0])
            else:
                # Multiple similar detections - keep the highest severity/confidence one
                best_detection = max(group_detections, key=lambda d: (
                    {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(d.severity.name, 0),
                    d.confidence
                ))

                # Add deduplication info to technical details
                best_detection.technical_details['deduplicated_count'] = len(group_detections)
                best_detection.technical_details['deduplicated_titles'] = [d.title for d in group_detections if d != best_detection]

                deduplicated.append(best_detection)

        self.logger.info(f"Deduplication: {len(detections)} -> {len(deduplicated)} detections")
        return deduplicated

    def _calculate_coverage_score(self, log_data: LogData) -> float:
        """Calculate coverage score based on missing sections."""
        if not log_data.missing_sections:
            return 1.0
        
        critical_sections = {
            'package.txt', 'appops.txt', 'accessibility.txt', 
            'netstats.txt', 'batterystats-checkin.txt'
        }
        
        missing_critical = len([
            section for section in log_data.missing_sections 
            if any(critical in section for critical in critical_sections)
        ])
        
        # Reduce score based on missing critical sections
        penalty = self.config.scoring.coverage_penalty * missing_critical
        return max(0.7, 1.0 - penalty)  # Floor at 0.7
    
    def _calculate_confidence_score(self, heuristic_results: Dict[str, AnalysisHeuristicResult]) -> float:
        """Calculate overall confidence score."""
        if not heuristic_results:
            return 0.8
        
        # Average confidence from heuristic configs
        confidence_map = {'low': 0.6, 'medium': 0.8, 'high': 1.0}
        confidences = []
        
        for name, result in heuristic_results.items():
            config = self.config.heuristics.get(name)
            if config and not result.error:
                confidence_value = confidence_map.get(config.confidence, 0.8)
                confidences.append(confidence_value)
        
        return sum(confidences) / len(confidences) if confidences else 0.8
    
    def _register_implemented_heuristics(self) -> None:
        """Register all implemented heuristics manually."""
        try:
            # Import and register SystemSecurityHeuristic
            from ward_core.heuristics.system.system_security import SystemSecurityHeuristic
            self.heuristic_registry.register(SystemSecurityHeuristic)
            self.logger.info("Registered SystemSecurityHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import SystemSecurityHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register SystemSecurityHeuristic: {e}")
        
        try:
            # Import and register PermissionAnalysisHeuristic
            from ward_core.heuristics.permissions.permission_analysis import PermissionAnalysisHeuristic
            self.heuristic_registry.register(PermissionAnalysisHeuristic)
            self.logger.info("Registered PermissionAnalysisHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import PermissionAnalysisHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register PermissionAnalysisHeuristic: {e}")
        
        try:
            # Import and register BehavioralAnalysisHeuristic
            from ward_core.heuristics.behavior.behavioral_analysis import BehavioralAnalysisHeuristic
            self.heuristic_registry.register(BehavioralAnalysisHeuristic)
            self.logger.info("Registered BehavioralAnalysisHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import BehavioralAnalysisHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register BehavioralAnalysisHeuristic: {e}")
        
        try:
            # Import and register ExploitationCrashHeuristic
            from ward_core.heuristics.crashes.exploitation_crash import ExploitationCrashHeuristic
            self.heuristic_registry.register(ExploitationCrashHeuristic)
            self.logger.info("Registered ExploitationCrashHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import ExploitationCrashHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register ExploitationCrashHeuristic: {e}")

        try:
            # Import and register MemoryExploitationHeuristic
            from ward_core.heuristics.memory.memory_exploitation import MemoryExploitationHeuristic
            self.heuristic_registry.register(MemoryExploitationHeuristic)
            self.logger.info("Registered MemoryExploitationHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import MemoryExploitationHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register MemoryExploitationHeuristic: {e}")





        try:
            # Import and register SystemAnomaliesHeuristic
            from ward_core.heuristics.anomalies.system_anomalies import SystemAnomaliesHeuristic
            self.heuristic_registry.register(SystemAnomaliesHeuristic)
            self.logger.info("Registered SystemAnomaliesHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import SystemAnomaliesHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register SystemAnomaliesHeuristic: {e}")

        try:
            # Import and register ProcessAnomalyHeuristic
            from ward_core.heuristics.anomalies.process_anomaly import ProcessAnomalyHeuristic
            self.heuristic_registry.register(ProcessAnomalyHeuristic)
            self.logger.info("Registered ProcessAnomalyHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import ProcessAnomalyHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register ProcessAnomalyHeuristic: {e}")

        try:
            # Import and register InstallationContextHeuristic
            from ward_core.heuristics.context.installation_context import InstallationContextHeuristic
            self.heuristic_registry.register(InstallationContextHeuristic)
            self.logger.info("Registered InstallationContextHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import InstallationContextHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register InstallationContextHeuristic: {e}")

        try:
            # Import and register UserAnalysisHeuristic
            from ward_core.heuristics.user.user_analysis import UserAnalysisHeuristic
            self.heuristic_registry.register(UserAnalysisHeuristic)
            self.logger.info("Registered UserAnalysisHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import UserAnalysisHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register UserAnalysisHeuristic: {e}")

        try:
            # Import and register DexAnalysisHeuristic
            from ward_core.heuristics.memory.dex_analysis import DexAnalysisHeuristic
            self.heuristic_registry.register(DexAnalysisHeuristic)
            self.logger.info("Registered DexAnalysisHeuristic")
        except ImportError as e:
            self.logger.debug(f"Could not import DexAnalysisHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register DexAnalysisHeuristic: {e}")

        try:
            # Import and register MemoryExploitationHeuristic (Enhanced with Kernel Exploit Detection)
            from ward_core.heuristics.memory.memory_exploitation import MemoryExploitationHeuristic
            self.heuristic_registry.register(MemoryExploitationHeuristic)
            self.logger.info("Registered MemoryExploitationHeuristic with kernel exploit detection")
        except ImportError as e:
            self.logger.debug(f"Could not import MemoryExploitationHeuristic: {e}")
        except Exception as e:
            self.logger.error(f"Failed to register MemoryExploitationHeuristic: {e}")

        # Add more heuristics here as they are implemented
        # except ImportError:
        #     pass
