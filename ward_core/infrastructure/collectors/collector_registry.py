"""
Registry for managing data collectors.

Provides centralized registration and discovery of data collectors.
"""

from typing import Dict, List, Type, Optional
import logging

from .base_collector import BaseCollector, CollectionConfig, CollectionError


class CollectorRegistry:
    """
    Registry for managing and discovering data collectors.
    
    This class handles registration, discovery, and instantiation of collectors.
    """
    
    def __init__(self):
        """Initialize the collector registry."""
        self._collectors: Dict[str, Type[BaseCollector]] = {}
        self._instances: Dict[str, BaseCollector] = {}
        self.logger = logging.getLogger("collector.registry")
    
    def register(self, collector_class: Type[BaseCollector]) -> None:
        """
        Register a collector class.
        
        Args:
            collector_class: Collector class to register
            
        Raises:
            ValueError: If collector class is invalid
        """
        if not issubclass(collector_class, BaseCollector):
            raise ValueError(f"Class {collector_class} must inherit from BaseCollector")
        
        # Create temporary instance to get collector type
        temp_instance = collector_class()
        collector_type = temp_instance.collector_type
        
        if collector_type in self._collectors:
            self.logger.warning(f"Collector {collector_type} is already registered, overwriting")
        
        self._collectors[collector_type] = collector_class
        self.logger.info(f"Registered collector: {collector_type}")
    
    def get_collector(self, collector_type: str, config: Optional[CollectionConfig] = None) -> BaseCollector:
        """
        Get a collector instance by type.
        
        Args:
            collector_type: Type of collector to get
            config: Configuration for the collector
            
        Returns:
            Collector instance
            
        Raises:
            CollectionError: If collector type is not found
        """
        if collector_type not in self._collectors:
            available_types = list(self._collectors.keys())
            raise CollectionError(
                f"Unknown collector type: {collector_type}. "
                f"Available types: {available_types}"
            )
        
        # Check if we have a cached instance with matching config
        cache_key = f"{collector_type}_{hash(str(config))}"
        if cache_key in self._instances:
            return self._instances[cache_key]
        
        # Create new instance
        collector_class = self._collectors[collector_type]
        try:
            instance = collector_class(config)
            self._instances[cache_key] = instance
            return instance
        except Exception as e:
            raise CollectionError(f"Failed to instantiate collector {collector_type}: {e}")
    
    def get_collector_for_target(self, target: str, config: Optional[CollectionConfig] = None) -> BaseCollector:
        """
        Get the best collector for a specific target.
        
        Args:
            target: Target to collect from
            config: Configuration for the collector
            
        Returns:
            Best collector for the target
            
        Raises:
            CollectionError: If no suitable collector is found
        """
        # Try each registered collector to see if it can handle the target
        for collector_type, collector_class in self._collectors.items():
            try:
                # Create temporary instance to test capability
                temp_instance = collector_class(config)
                if temp_instance.can_collect_from(target):
                    return self.get_collector(collector_type, config)
            except Exception as e:
                self.logger.debug(f"Collector {collector_type} cannot handle target {target}: {e}")
                continue
        
        raise CollectionError(f"No suitable collector found for target: {target}")
    
    def get_available_collectors(self) -> List[str]:
        """
        Get list of all registered collector types.
        
        Returns:
            List of collector type identifiers
        """
        return list(self._collectors.keys())
    
    def get_collectors_for_sources(self, source_types: List[str]) -> List[str]:
        """
        Get collectors that support specific source types.
        
        Args:
            source_types: List of source types to support
            
        Returns:
            List of collector types that support the given sources
        """
        matching_collectors = []
        
        for collector_type, collector_class in self._collectors.items():
            try:
                temp_instance = collector_class()
                supported_sources = set(temp_instance.get_supported_sources())
                required_sources = set(source_types)
                
                # Check if collector supports any of the required sources
                if supported_sources.intersection(required_sources):
                    matching_collectors.append(collector_type)
            except Exception as e:
                self.logger.debug(f"Error checking sources for collector {collector_type}: {e}")
        
        return matching_collectors
    
    def auto_discover(self, package_name: str = "infrastructure.collectors") -> int:
        """
        Automatically discover and register collectors from a package.
        
        Args:
            package_name: Package to search for collectors
            
        Returns:
            Number of collectors discovered and registered
        """
        discovered_count = 0
        
        try:
            import importlib
            import pkgutil
            
            # Import the collectors package
            collectors_package = importlib.import_module(package_name)
            
            # Walk through all modules in the package
            for importer, modname, ispkg in pkgutil.walk_packages(
                collectors_package.__path__,
                prefix=f"{package_name}."
            ):
                if ispkg:
                    continue
                
                try:
                    # Import the module
                    module = importlib.import_module(modname)
                    
                    # Look for classes that inherit from BaseCollector
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        
                        if (isinstance(attr, type) and 
                            issubclass(attr, BaseCollector) and 
                            attr != BaseCollector):
                            
                            self.register(attr)
                            discovered_count += 1
                            
                except Exception as e:
                    self.logger.warning(f"Failed to import collector module {modname}: {e}")
        
        except Exception as e:
            self.logger.error(f"Failed to auto-discover collectors from package {package_name}: {e}")
        
        self.logger.info(f"Auto-discovered {discovered_count} collectors")
        return discovered_count
    
    def clear(self) -> None:
        """Clear all registered collectors and cached instances."""
        self._collectors.clear()
        self._instances.clear()
        self.logger.info("Cleared collector registry")


# Global registry instance
registry = CollectorRegistry()


