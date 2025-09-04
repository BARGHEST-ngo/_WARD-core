"""
Heuristic registry for plugin management.

Provides a centralized registry for discovering and managing heuristic plugins.
"""

import importlib
import pkgutil
from typing import Dict, List, Type, Optional
import logging

from .base_heuristic import BaseHeuristic
from ward_core.logic.models import HeuristicConfig


class HeuristicRegistry:
    """
    Registry for managing heuristic plugins.
    
    This class handles the discovery, registration, and instantiation of heuristics.
    """
    
    def __init__(self):
        """Initialize the registry."""
        self._heuristics: Dict[str, Type[BaseHeuristic]] = {}
        self._instances: Dict[str, BaseHeuristic] = {}
        self.logger = logging.getLogger("heuristic.registry")
    
    def register(self, heuristic_class: Type[BaseHeuristic]) -> None:
        """
        Register a heuristic class.
        
        Args:
            heuristic_class: The heuristic class to register
        """
        if not issubclass(heuristic_class, BaseHeuristic):
            raise ValueError(f"Class {heuristic_class} must inherit from BaseHeuristic")
        
        # Create a temporary instance to get the name
        temp_instance = heuristic_class()
        name = temp_instance.name
        
        if name in self._heuristics:
            self.logger.warning(f"Heuristic {name} is already registered, overwriting")
        
        self._heuristics[name] = heuristic_class
        self.logger.info(f"Registered heuristic: {name}")
    
    def get_heuristic_class(self, name: str) -> Optional[Type[BaseHeuristic]]:
        """
        Get a heuristic class by name.
        
        Args:
            name: Name of the heuristic
            
        Returns:
            Heuristic class or None if not found
        """
        return self._heuristics.get(name)
    
    def get_heuristic_instance(self, name: str, config: Optional[HeuristicConfig] = None) -> Optional[BaseHeuristic]:
        """
        Get a heuristic instance by name.
        
        Args:
            name: Name of the heuristic
            config: Configuration for the heuristic
            
        Returns:
            Heuristic instance or None if not found
        """
        # Check if we have a cached instance with matching config
        cache_key = f"{name}_{hash(str(config))}"
        if cache_key in self._instances:
            return self._instances[cache_key]
        
        heuristic_class = self.get_heuristic_class(name)
        if heuristic_class is None:
            return None
        
        try:
            instance = heuristic_class(config)
            self._instances[cache_key] = instance
            return instance
        except Exception as e:
            self.logger.error(f"Failed to instantiate heuristic {name}: {e}")
            return None
    
    def get_available_heuristics(self) -> List[str]:
        """
        Get list of all available heuristic names.
        
        Returns:
            List of heuristic names
        """
        return list(self._heuristics.keys())
    
    def discover_heuristics(self, package_name: str = "heuristics") -> int:
        """
        Automatically discover and register heuristics from a package.
        
        Args:
            package_name: Name of the package to search for heuristics
            
        Returns:
            Number of heuristics discovered and registered
        """
        discovered_count = 0
        
        try:
            # Import the heuristics package
            heuristics_package = importlib.import_module(package_name)
            
            # Walk through all modules in the package
            for importer, modname, ispkg in pkgutil.walk_packages(
                heuristics_package.__path__,
                prefix=f"{package_name}."
            ):
                if ispkg:
                    continue
                
                try:
                    # Import the module
                    module = importlib.import_module(modname)
                    
                    # Look for classes that inherit from BaseHeuristic
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        
                        if (isinstance(attr, type) and 
                            issubclass(attr, BaseHeuristic) and 
                            attr != BaseHeuristic):
                            
                            self.register(attr)
                            discovered_count += 1
                            
                except Exception as e:
                    self.logger.warning(f"Failed to import heuristic module {modname}: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to discover heuristics from package {package_name}: {e}")
        
        self.logger.info(f"Discovered {discovered_count} heuristics")
        return discovered_count
    
    def create_instances(self, heuristic_configs: Dict[str, HeuristicConfig]) -> Dict[str, BaseHeuristic]:
        """
        Create instances of multiple heuristics.
        
        Args:
            heuristic_configs: Dictionary mapping heuristic names to their configs
            
        Returns:
            Dictionary mapping heuristic names to their instances
        """
        instances = {}
        
        for name, config in heuristic_configs.items():
            instance = self.get_heuristic_instance(name, config)
            if instance is not None:
                instances[name] = instance
            else:
                self.logger.error(f"Failed to create instance for heuristic: {name}")
        
        return instances
    
    def clear(self) -> None:
        """Clear all registered heuristics and instances."""
        self._heuristics.clear()
        self._instances.clear()
        self.logger.info("Cleared heuristic registry")


# Global registry instance
registry = HeuristicRegistry()

