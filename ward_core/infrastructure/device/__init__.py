"""
Device detection and management infrastructure.

Handles ADB device detection and management for Android forensic analysis.
"""

from .adb_device_detector import AdbDeviceDetector, AdbDevice

__all__ = [
    'AdbDeviceDetector',
    'AdbDevice'
]


