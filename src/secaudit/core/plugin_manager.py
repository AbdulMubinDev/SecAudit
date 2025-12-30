"""
Plugin management system for SecAudit
"""
import importlib
import inspect
import os
import sys
from typing import Dict, List, Any, Type, Optional
from abc import ABC, abstractmethod

class BasePlugin(ABC):
    """Base class for all SecAudit plugins"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version"""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin with configuration"""
        pass
    
    @abstractmethod
    def process(self, data: Any) -> Any:
        """Process input data"""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup resources"""
        pass

class PluginManager:
    """Manages plugin loading and execution"""
    
    def __init__(self, config):
        self.config = config
        self.plugins = {}
        self.plugin_paths = config.get('plugins.paths', ['plugins/'])
        self.sandbox_mode = config.get('plugins.sandbox_mode', False)
    
    def load_plugins(self) -> bool:
        """Load all available plugins"""
        if not self.config.get('plugins.enabled', True):
            return True
        
        for plugin_path in self.plugin_paths:
            if os.path.exists(plugin_path):
                self._load_plugins_from_path(plugin_path)
        
        return True
    
    def _load_plugins_from_path(self, path: str) -> None:
        """Load plugins from a specific directory"""
        # Add path to sys.path if not already there
        if path not in sys.path:
            sys.path.insert(0, path)
        
        for filename in os.listdir(path):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py extension
                try:
                    module = importlib.import_module(module_name)
                    self._register_plugins_from_module(module)
                except ImportError as e:
                    print(f"Failed to import plugin {module_name}: {e}")
    
    def _register_plugins_from_module(self, module) -> None:
        """Register all plugin classes from a module"""
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, BasePlugin) and 
                obj != BasePlugin):
                
                try:
                    plugin_instance = obj()
                    self.plugins[plugin_instance.name] = plugin_instance
                    print(f"Loaded plugin: {plugin_instance.name}")
                except Exception as e:
                    print(f"Failed to instantiate plugin {name}: {e}")
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin by name"""
        return self.plugins.get(name)
    
    def get_plugins_by_type(self, plugin_type: Type) -> List[BasePlugin]:
        """Get all plugins of a specific type"""
        return [p for p in self.plugins.values() if isinstance(p, plugin_type)]
    
    def execute_plugin(self, name: str, data: Any) -> Any:
        """Execute a plugin with given data"""
        plugin = self.get_plugin(name)
        if plugin:
            return plugin.process(data)
        else:
            raise ValueError(f"Plugin {name} not found")
    
    def list_plugins(self) -> List[Dict[str, str]]:
        """List all loaded plugins"""
        return [
            {
                'name': plugin.name,
                'version': plugin.version,
                'type': type(plugin).__name__
            }
            for plugin in self.plugins.values()
        ]
    
    def unload_plugin(self, name: str) -> bool:
        """Unload a plugin"""
        if name in self.plugins:
            plugin = self.plugins.pop(name)
            try:
                plugin.cleanup()
                return True
            except Exception as e:
                print(f"Error during plugin cleanup: {e}")
                return False
        return False