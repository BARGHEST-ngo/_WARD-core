"""
Improved package parser that correctly handles dumpsys package format.

This fixes the parsing issues in the original data loader.
"""

import re
from typing import Dict, Any, List, Set
from pathlib import Path


class ImprovedPackageParser:
    """
    Improved parser for dumpsys package output.
    
    Handles the multi-line format where package info is spread across multiple lines
    within each package section.
    """
    
    def parse_package_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a dumpsys package file and extract package information.
        
        Args:
            file_path: Path to the dumpsys package file
            
        Returns:
            Dictionary with package_uids, installer_info, and package_permissions
        """
        result = {
            'package_uids': {},
            'installer_info': {},
            'package_permissions': {},
        }
        
        if not Path(file_path).exists():
            return result
        
        current_package = None
        current_permissions = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    
                    # Look for package start: "Package [com.example.app] (hash):"
                    pkg_match = re.search(r'Package \[([\w.]+)\]', line)
                    if pkg_match:
                        # Save previous package permissions if any
                        if current_package and current_permissions:
                            result['package_permissions'][current_package] = current_permissions
                        
                        # Start new package
                        current_package = pkg_match.group(1)
                        current_permissions = set()
                        continue
                    
                    # If we're in a package section, look for details
                    if current_package:
                        # Look for userId: "userId=10012"
                        uid_match = re.search(r'userId=(\d+)', line)
                        if uid_match:
                            result['package_uids'][current_package] = int(uid_match.group(1))
                        
                        # Look for installer: "installerPackageName=com.android.vending"
                        installer_match = re.search(r'installerPackageName=([\w.]+|null)', line)
                        if installer_match:
                            installer = installer_match.group(1)
                            if installer != 'null':
                                result['installer_info'][current_package] = installer
                            else:
                                result['installer_info'][current_package] = 'unknown'
                        
                        # Look for permissions: "android.permission.INTERNET: granted=true"
                        perm_match = re.search(r'(android\.permission\.[\w_]+|[\w.]+\.permission\.[\w_]+): granted=true', line)
                        if perm_match:
                            current_permissions.add(perm_match.group(1))
                        
                        # Alternative permission format: "android.permission.INTERNET: granted=true, flags=[...]"
                        perm_match2 = re.search(r'(android\.permission\.[\w_]+|[\w.]+\.permission\.[\w_]+): granted=true,', line)
                        if perm_match2:
                            current_permissions.add(perm_match2.group(1))
                        
                        # Reset current package when we hit certain section boundaries
                        if (line.startswith('Shared users:') or 
                            line.startswith('Settings version:') or
                            line.startswith('KeySets:') or
                            line.startswith('Verifiers:')):
                            if current_package and current_permissions:
                                result['package_permissions'][current_package] = current_permissions
                            current_package = None
                            current_permissions = set()
                
                # Don't forget the last package
                if current_package and current_permissions:
                    result['package_permissions'][current_package] = current_permissions
        
        except Exception as e:
            print(f"Error parsing package file: {e}")
        
        return result
    
    def enhance_log_data(self, log_data_dict: Dict[str, Any], package_file_path: str) -> Dict[str, Any]:
        """
        Enhance existing log data with improved package parsing.
        
        Args:
            log_data_dict: Existing log data dictionary
            package_file_path: Path to the dumpsys package file
            
        Returns:
            Enhanced log data dictionary
        """
        # Parse the package file
        package_data = self.parse_package_file(package_file_path)
        
        # Merge with existing data (our parsing takes precedence)
        log_data_dict['package_uids'].update(package_data['package_uids'])
        log_data_dict['installer_info'].update(package_data['installer_info'])
        
        # Convert permission sets to lists for JSON serialization
        for pkg, perms in package_data['package_permissions'].items():
            if pkg not in log_data_dict['package_permissions']:
                log_data_dict['package_permissions'][pkg] = []
            # Convert set to list and merge
            existing_perms = set(log_data_dict['package_permissions'][pkg])
            merged_perms = existing_perms.union(perms)
            log_data_dict['package_permissions'][pkg] = list(merged_perms)
        
        return log_data_dict



