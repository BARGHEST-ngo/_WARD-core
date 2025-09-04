"""
Specialized parsers for Android forensic data formats.

This package contains specialized parsers for different Android system outputs,
each optimized for extracting forensically relevant information.
"""

from .package_parser import PackageParser
from .appops_parser import AppOpsParser
from .accessibility_parser import AccessibilityParser
from .network_stats_parser import NetworkStatsParser
from .battery_stats_parser import BatteryStatsParser
from .logcat_parser import LogcatParser
from .system_properties_parser import SystemPropertiesParser
from .dumpsys_generic_parser import DumpsysGenericParser

# New parsers for missing file types
from .simple_parsers import SimpleTextParser, PackageListParser, ProcessListParser, NetworkConnectionParser
from .forensic_parsers import DmesgParser, BinderParser, SensorServiceParser, NetworkPolicyParser
from .activity_services_parser import ActivityServicesParser
from .fallback_parser import FallbackParser

# Crash analysis parsers
from .tombstone_parser import TombstoneParser
from .anr_trace_parser import ANRTraceParser
from .dropbox_parser import DropBoxParser

__all__ = [
    'PackageParser',
    'AppOpsParser',
    'AccessibilityParser',
    'NetworkStatsParser',
    'BatteryStatsParser',
    'LogcatParser',
    'SystemPropertiesParser',
    'DumpsysGenericParser',
    # New parsers for complete forensic coverage
    'SimpleTextParser',
    'PackageListParser',
    'ProcessListParser',
    'NetworkConnectionParser',
    'DmesgParser',
    'BinderParser',
    'SensorServiceParser',
    'NetworkPolicyParser',
    'ActivityServicesParser',
    'FallbackParser',
    # Crash analysis parsers
    'TombstoneParser',
    'ANRTraceParser',
    'DropBoxParser'
]
