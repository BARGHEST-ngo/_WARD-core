"""
ADB Device Detection Service

Handles detection of connected ADB devices following clean architecture principles.
"""

import subprocess
import logging
import re
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AdbDevice:
    """Represents a detected ADB device."""
    serial: str
    state: str  # 'device', 'offline', 'unauthorized', etc.
    model: Optional[str] = None
    android_version: Optional[str] = None
    manufacturer: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not self.serial:
            raise ValueError("Device serial cannot be empty")
    
    def is_ready(self) -> bool:
        """Check if device is ready for data collection."""
        return self.state == 'device'
    
    def get_display_name(self) -> str:
        """Get a human-readable device name."""
        if self.model and self.manufacturer:
            return f"{self.manufacturer} {self.model} ({self.serial})"
        elif self.model:
            return f"{self.model} ({self.serial})"
        else:
            return self.serial


class AdbDeviceDetector:
    """
    Service for detecting and managing ADB device connections.
    
    This service handles ADB device detection while maintaining clean separation
    from the collection logic.
    """
    
    def __init__(self):
        """Initialize the ADB device detector."""
        self.logger = logging.getLogger("adb.detector")
        self._adb_command = self._find_adb_command()
    
    def _find_adb_command(self) -> Optional[str]:
        """Find the ADB command in the system."""
        # Common ADB locations
        possible_paths = [
            "adb",  # In PATH
            "adb.exe",  # Windows in PATH
            r"C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe",
            r"C:\Android\android-sdk\platform-tools\adb.exe",
            r"C:\Users\%USERNAME%\AppData\Local\Android\Sdk\platform-tools\adb.exe",
            "/usr/bin/adb",  # Linux/macOS
            "/usr/local/bin/adb",
            "~/Android/Sdk/platform-tools/adb"  # User SDK
        ]
        
        for adb_path in possible_paths:
            try:
                # Expand user path if needed
                if adb_path.startswith("~"):
                    adb_path = str(Path(adb_path).expanduser())
                
                # Test if ADB command works
                result = subprocess.run(
                    [adb_path, "version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    self.logger.info(f"Found ADB at: {adb_path}")
                    return adb_path
                    
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        
        self.logger.warning("ADB command not found in common locations")
        return None
    
    def is_adb_available(self) -> bool:
        """Check if ADB is available on the system."""
        return self._adb_command is not None
    
    def detect_devices(self) -> List[AdbDevice]:
        """
        Detect all connected ADB devices.
        
        Returns:
            List of detected ADB devices
        """
        if not self._adb_command:
            self.logger.error("ADB command not available")
            return []
        
        try:
            self.logger.info("Detecting ADB devices...")
            
            # Run adb devices command
            result = subprocess.run(
                [self._adb_command, "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                self.logger.error(f"ADB devices command failed: {result.stderr}")
                return []
            
            # Parse output
            devices = self._parse_device_list(result.stdout)
            
            # Enrich device information
            enriched_devices = []
            for device in devices:
                try:
                    enriched_device = self._enrich_device_info(device)
                    enriched_devices.append(enriched_device)
                except Exception as e:
                    self.logger.warning(f"Failed to enrich device {device.serial}: {e}")
                    enriched_devices.append(device)  # Use basic info
            
            self.logger.info(f"Detected {len(enriched_devices)} ADB devices")
            return enriched_devices
            
        except subprocess.TimeoutExpired:
            self.logger.error("ADB devices detection timed out")
            return []
        except Exception as e:
            self.logger.error(f"ADB device detection failed: {e}")
            return []
    
    def _parse_device_list(self, adb_output: str) -> List[AdbDevice]:
        """Parse the output of 'adb devices -l' command."""
        devices = []
        lines = adb_output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header line
            line = line.strip()
            if not line:
                continue
            
            # Parse device line: "serial state model:... product:... device:..."
            parts = line.split()
            if len(parts) < 2:
                continue
            
            serial = parts[0]
            state = parts[1]
            
            # Extract model from additional info if available
            model = None
            if len(parts) > 2:
                for part in parts[2:]:
                    if part.startswith('model:'):
                        model = part.split(':', 1)[1]
                        break
            
            devices.append(AdbDevice(serial=serial, state=state, model=model))
        
        return devices
    
    def _enrich_device_info(self, device: AdbDevice) -> AdbDevice:
        """Enrich device information with additional properties."""
        if not device.is_ready():
            return device  # Can't query offline/unauthorized devices
        
        try:
            # Get device properties
            properties = self._get_device_properties(device.serial)
            
            # Extract useful information
            if not device.model and 'ro.product.model' in properties:
                device.model = properties['ro.product.model']
            
            if not device.manufacturer and 'ro.product.manufacturer' in properties:
                device.manufacturer = properties['ro.product.manufacturer']
            
            if not device.android_version and 'ro.build.version.release' in properties:
                device.android_version = properties['ro.build.version.release']
            
            return device
            
        except Exception as e:
            self.logger.warning(f"Failed to enrich device {device.serial}: {e}")
            return device
    
    def _get_device_properties(self, device_serial: str) -> Dict[str, str]:
        """Get device properties using getprop command."""
        result = subprocess.run(
            [self._adb_command, "-s", device_serial, "shell", "getprop"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to get device properties: {result.stderr}")
        
        properties = {}
        for line in result.stdout.split('\n'):
            # Parse property lines: [key]: [value]
            match = re.match(r'\[([^\]]+)\]:\s*\[([^\]]*)\]', line.strip())
            if match:
                key, value = match.groups()
                properties[key] = value
        
        return properties
    
    def get_ready_devices(self) -> List[AdbDevice]:
        """Get only devices that are ready for data collection."""
        all_devices = self.detect_devices()
        ready_devices = [device for device in all_devices if device.is_ready()]
        
        self.logger.info(f"Found {len(ready_devices)} ready devices out of {len(all_devices)} total")
        return ready_devices
    
    def get_single_device(self) -> Optional[AdbDevice]:
        """
        Get a single ADB device for collection.
        
        Returns:
            Single ready device, or None if no device or multiple devices
        """
        ready_devices = self.get_ready_devices()
        
        if len(ready_devices) == 0:
            self.logger.warning("No ADB devices ready for collection")
            return None
        elif len(ready_devices) == 1:
            device = ready_devices[0]
            self.logger.info(f"Using device: {device.get_display_name()}")
            return device
        else:
            self.logger.warning(f"Multiple devices detected ({len(ready_devices)}). Please specify device serial.")
            self.logger.info("Available devices:")
            for device in ready_devices:
                self.logger.info(f"  - {device.get_display_name()}")
            return None
    
    def select_device_by_serial(self, serial: str) -> Optional[AdbDevice]:
        """
        Select a specific device by serial number.
        
        Args:
            serial: Device serial number
            
        Returns:
            Device if found and ready, None otherwise
        """
        ready_devices = self.get_ready_devices()
        
        for device in ready_devices:
            if device.serial == serial:
                self.logger.info(f"Selected device: {device.get_display_name()}")
                return device
        
        self.logger.error(f"Device with serial '{serial}' not found or not ready")
        return None
    
    def wait_for_device(self, timeout: int = 30) -> Optional[AdbDevice]:
        """
        Wait for a single device to become available.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            Ready device or None if timeout
        """
        if not self._adb_command:
            return None
        
        try:
            self.logger.info(f"Waiting for ADB device (timeout: {timeout}s)...")
            
            # Use adb wait-for-device command
            result = subprocess.run(
                [self._adb_command, "wait-for-device"],
                timeout=timeout,
                capture_output=True
            )
            
            if result.returncode == 0:
                # Device is available, get it
                return self.get_single_device()
            else:
                self.logger.error("ADB wait-for-device failed")
                return None
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"No ADB device detected within {timeout} seconds")
            return None
        except Exception as e:
            self.logger.error(f"Failed to wait for device: {e}")
            return None


