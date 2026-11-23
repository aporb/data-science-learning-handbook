#!/usr/bin/env python3
"""
CAC/PIV Middleware Abstraction Layer
Provides abstraction for different smart card middleware solutions
"""

import os
import platform
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import subprocess
import glob
if platform.system() == "Windows":
    import winreg
else:
    winreg = None

# Configure logging
logger = logging.getLogger(__name__)

class MiddlewareType(Enum):
    """Types of supported middleware"""
    OPENSC = "OpenSC"
    ACTIVCLIENT = "ActivClient" 
    COOLKEY = "CoolKey"
    PKCS11_SPY = "PKCS11-Spy"
    CACKEY = "CACKey"
    UNKNOWN = "Unknown"

@dataclass
class MiddlewareInfo:
    """Information about detected middleware"""
    name: str
    middleware_type: MiddlewareType
    version: Optional[str]
    pkcs11_path: str
    is_available: bool
    capabilities: List[str]
    priority: int  # Lower number = higher priority
    
class MiddlewareDetector:
    """
    Auto-detect available CAC/PIV middleware on the system
    Supports multiple middleware solutions with prioritization
    """
    
    # Middleware detection configurations
    MIDDLEWARE_CONFIGS = {
        MiddlewareType.OPENSC: {
            'windows_paths': [
                "C:\\Windows\\System32\\opensc-pkcs11.dll",
                "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",
                "C:\\Program Files (x86)\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll"
            ],
            'linux_paths': [
                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
                "/usr/lib/opensc-pkcs11.so",
                "/usr/local/lib/opensc-pkcs11.so",
                "/usr/lib64/opensc-pkcs11.so"
            ],
            'macos_paths': [
                "/usr/local/lib/opensc-pkcs11.so",
                "/opt/homebrew/lib/opensc-pkcs11.so",
                "/usr/lib/opensc-pkcs11.so"
            ],
            'registry_keys': [
                r"SOFTWARE\OpenSC Project\OpenSC"
            ],
            'version_command': ['opensc-tool', '--version'],
            'capabilities': ['basic_auth', 'digital_signature', 'key_generation'],
            'priority': 2
        },
        
        MiddlewareType.ACTIVCLIENT: {
            'windows_paths': [
                "C:\\Windows\\System32\\acpkcs211.dll",
                "C:\\Program Files\\ActivIdentity\\ActivClient\\acpkcs211.dll",
                "C:\\Program Files (x86)\\ActivIdentity\\ActivClient\\acpkcs211.dll",
                "C:\\Program Files\\HID Global\\ActivClient\\acpkcs211.dll"
            ],
            'linux_paths': [
                "/usr/lib/libacpkcs211.so",
                "/opt/ActivIdentity/ActivClient/lib/libacpkcs211.so"
            ],
            'macos_paths': [
                "/usr/local/lib/libacpkcs211.so",
                "/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib"
            ],
            'registry_keys': [
                r"SOFTWARE\ActivIdentity\ActivClient",
                r"SOFTWARE\HID Global\ActivClient"
            ],
            'version_command': None,  # No standard version command
            'capabilities': ['advanced_auth', 'digital_signature', 'encryption', 'middleware_management'],
            'priority': 1  # Highest priority for DoD environments
        },
        
        MiddlewareType.COOLKEY: {
            'windows_paths': [
                "C:\\Windows\\System32\\coolkeypk11.dll"
            ],
            'linux_paths': [
                "/usr/lib/pkcs11/coolkey.so",
                "/usr/lib64/pkcs11/coolkey.so",
                "/usr/lib/x86_64-linux-gnu/pkcs11/coolkey.so"
            ],
            'macos_paths': [
                "/usr/local/lib/coolkey.so"
            ],
            'registry_keys': [],
            'version_command': None,
            'capabilities': ['basic_auth', 'digital_signature'],
            'priority': 3
        },
        
        MiddlewareType.CACKEY: {
            'windows_paths': [
                "C:\\Windows\\System32\\libcackey.dll"
            ],
            'linux_paths': [
                "/usr/lib/libcackey.so",
                "/usr/local/lib/libcackey.so",
                "/usr/lib64/libcackey.so"
            ],
            'macos_paths': [
                "/usr/local/lib/libcackey.so"
            ],
            'registry_keys': [],
            'version_command': None,
            'capabilities': ['cac_specific', 'basic_auth'],
            'priority': 4
        }
    }
    
    def __init__(self):
        """Initialize middleware detector"""
        self.system = platform.system()
        self.detected_middleware = []
        logger.info(f"Middleware detector initialized for {self.system}")
    
    def detect_all_middleware(self) -> List[MiddlewareInfo]:
        """
        Detect all available middleware on the system
        
        Returns:
            List of detected middleware, sorted by priority
        """
        self.detected_middleware.clear()
        
        for middleware_type, config in self.MIDDLEWARE_CONFIGS.items():
            try:
                middleware_info = self._detect_specific_middleware(middleware_type, config)
                if middleware_info and middleware_info.is_available:
                    self.detected_middleware.append(middleware_info)
                    logger.info(f"Detected middleware: {middleware_info.name} at {middleware_info.pkcs11_path}")
            except Exception as e:
                logger.warning(f"Error detecting {middleware_type.value}: {e}")
        
        # Sort by priority (lower number = higher priority)
        self.detected_middleware.sort(key=lambda x: x.priority)
        
        logger.info(f"Total middleware detected: {len(self.detected_middleware)}")
        return self.detected_middleware.copy()
    
    def _detect_specific_middleware(self, middleware_type: MiddlewareType, 
                                  config: Dict) -> Optional[MiddlewareInfo]:
        """Detect specific middleware type"""
        
        # Get paths for current OS
        if self.system == "Windows":
            search_paths = config.get('windows_paths', [])
        elif self.system == "Linux":
            search_paths = config.get('linux_paths', [])
        elif self.system == "Darwin":  # macOS
            search_paths = config.get('macos_paths', [])
        else:
            logger.warning(f"Unsupported OS for middleware detection: {self.system}")
            return None
        
        # Check file system paths
        pkcs11_path = None
        for path in search_paths:
            if os.path.exists(path):
                pkcs11_path = path
                break
        
        # For Windows, also check registry
        if self.system == "Windows" and not pkcs11_path:
            pkcs11_path = self._check_windows_registry(config.get('registry_keys', []))
        
        if not pkcs11_path:
            return MiddlewareInfo(
                name=middleware_type.value,
                middleware_type=middleware_type,
                version=None,
                pkcs11_path="",
                is_available=False,
                capabilities=config.get('capabilities', []),
                priority=config.get('priority', 99)
            )
        
        # Get version if possible
        version = self._get_middleware_version(config.get('version_command'))
        
        return MiddlewareInfo(
            name=middleware_type.value,
            middleware_type=middleware_type,
            version=version,
            pkcs11_path=pkcs11_path,
            is_available=True,
            capabilities=config.get('capabilities', []),
            priority=config.get('priority', 99)
        )
    
    def _check_windows_registry(self, registry_keys: List[str]) -> Optional[str]:
        """Check Windows registry for middleware installation"""
        if self.system != "Windows" or not winreg:
            return None
        
        for key_path in registry_keys:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    # Look for installation path
                    install_path = winreg.QueryValueEx(key, "InstallPath")[0]
                    
                    # Look for PKCS#11 library in installation directory
                    possible_libs = [
                        os.path.join(install_path, "acpkcs211.dll"),
                        os.path.join(install_path, "pkcs11", "opensc-pkcs11.dll"),
                        os.path.join(install_path, "lib", "opensc-pkcs11.dll")
                    ]
                    
                    for lib_path in possible_libs:
                        if os.path.exists(lib_path):
                            return lib_path
                            
            except (WindowsError, FileNotFoundError, KeyError):
                continue
        
        return None
    
    def _get_middleware_version(self, version_command: Optional[List[str]]) -> Optional[str]:
        """Get middleware version using command line tool"""
        if not version_command:
            return None
        
        try:
            result = subprocess.run(
                version_command, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse version from output (implementation depends on tool)
                output_lines = result.stdout.strip().split('\n')
                if output_lines:
                    return output_lines[0].strip()
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return None
    
    def get_best_middleware(self) -> Optional[MiddlewareInfo]:
        """Get the best available middleware (highest priority)"""
        if not self.detected_middleware:
            self.detect_all_middleware()
        
        return self.detected_middleware[0] if self.detected_middleware else None
    
    def get_middleware_by_type(self, middleware_type: MiddlewareType) -> Optional[MiddlewareInfo]:
        """Get specific middleware by type"""
        if not self.detected_middleware:
            self.detect_all_middleware()
        
        for middleware in self.detected_middleware:
            if middleware.middleware_type == middleware_type:
                return middleware
        
        return None

class PKCS11ProviderManager:
    """
    Manages PKCS#11 providers with fallback and abstraction
    Provides unified interface regardless of underlying middleware
    """
    
    def __init__(self, auto_detect: bool = True, preferred_middleware: MiddlewareType = None):
        """
        Initialize PKCS#11 provider manager
        
        Args:
            auto_detect: Whether to auto-detect middleware
            preferred_middleware: Preferred middleware type
        """
        self.detector = MiddlewareDetector()
        self.available_middleware = []
        self.current_provider = None
        self.preferred_middleware = preferred_middleware
        
        if auto_detect:
            self.available_middleware = self.detector.detect_all_middleware()
        
        logger.info("PKCS#11 Provider Manager initialized")
    
    def initialize_provider(self, specific_middleware: MiddlewareType = None) -> bool:
        """
        Initialize PKCS#11 provider
        
        Args:
            specific_middleware: Use specific middleware type
            
        Returns:
            True if provider initialized successfully
        """
        target_middleware = None
        
        if specific_middleware:
            target_middleware = self.detector.get_middleware_by_type(specific_middleware)
        elif self.preferred_middleware:
            target_middleware = self.detector.get_middleware_by_type(self.preferred_middleware)
        else:
            target_middleware = self.detector.get_best_middleware()
        
        if not target_middleware or not target_middleware.is_available:
            logger.error("No suitable middleware found")
            return False
        
        try:
            # Import PyKCS11 here to avoid circular imports
            import PyKCS11
            
            self.current_provider = PyKCS11.PyKCS11Lib()
            self.current_provider.load(target_middleware.pkcs11_path)
            
            logger.info(f"Initialized PKCS#11 provider: {target_middleware.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize PKCS#11 provider: {e}")
            self.current_provider = None
            return False
    
    def initialize_with_fallback(self) -> bool:
        """
        Initialize provider with automatic fallback to other middleware

        Returns:
            True if any provider initialized successfully
        """
        if not self.available_middleware:
            logger.error("No middleware available for fallback")
            return False

        # Try each middleware in priority order
        for middleware in self.available_middleware:
            logger.info(f"Trying to initialize {middleware.name}...")

            if self.initialize_provider(middleware.middleware_type):
                logger.info(f"Successfully initialized {middleware.name}")
                return True
            else:
                logger.warning(f"Failed to initialize {middleware.name}, trying next...")

        logger.error("All middleware initialization attempts failed")
        return False

    def get_current_provider_info(self) -> Optional[MiddlewareInfo]:
        """Get information about currently active provider"""
        if not self.current_provider:
            return None

        # Find middleware info for current provider
        for middleware in self.available_middleware:
            if middleware.is_available:
                try:
                    # Try to match by checking if the library is loaded
                    test_lib = PyKCS11.PyKCS11Lib()
                    test_lib.load(middleware.pkcs11_path)
                    # If we get here, this might be our current provider
                    # (This is a simplified check - in practice you'd want more robust matching)
                    return middleware
                except:
                    continue

        return None

    def get_provider_capabilities(self) -> List[str]:
        """Get capabilities of current provider"""
        provider_info = self.get_current_provider_info()
        return provider_info.capabilities if provider_info else []

    def supports_capability(self, capability: str) -> bool:
        """Check if current provider supports specific capability"""
        return capability in self.get_provider_capabilities()

    def get_available_middleware_summary(self) -> Dict[str, Any]:
        """Get summary of all available middleware"""
        summary = {
            'total_detected': len(self.available_middleware),
            'middleware_list': [],
            'best_available': None
        }

        for middleware in self.available_middleware:
            summary['middleware_list'].append({
                'name': middleware.name,
                'type': middleware.middleware_type.value,
                'version': middleware.version,
                'path': middleware.pkcs11_path,
                'capabilities': middleware.capabilities,
                'priority': middleware.priority
            })

        best = self.detector.get_best_middleware()
        if best:
            summary['best_available'] = {
                'name': best.name,
                'type': best.middleware_type.value,
                'path': best.pkcs11_path
            }

        return summary

    def cleanup(self):
        """Cleanup provider resources"""
        if self.current_provider:
            try:
                # Note: PyKCS11 doesn't have an explicit cleanup method
                # but we can set it to None to release the reference
                self.current_provider = None
                logger.info("PKCS#11 provider cleaned up")
            except Exception as e:
                logger.warning(f"Error during provider cleanup: {e}")

class MiddlewareCompatibilityLayer:
    """
    Compatibility layer to handle differences between middleware implementations
    Provides normalized interface for common operations
    """

    def __init__(self, provider_manager: PKCS11ProviderManager):
        """
        Initialize compatibility layer

        Args:
            provider_manager: PKCS#11 provider manager
        """
        self.provider_manager = provider_manager
        self.middleware_specific_quirks = {
            MiddlewareType.ACTIVCLIENT: {
                'requires_pin_pad': True,
                'supports_key_generation': True,
                'max_pin_length': 8,
                'session_timeout': 1800  # 30 minutes
            },
            MiddlewareType.OPENSC: {
                'requires_pin_pad': False,
                'supports_key_generation': False,
                'max_pin_length': 12,
                'session_timeout': 3600  # 1 hour
            },
            MiddlewareType.COOLKEY: {
                'requires_pin_pad': False,
                'supports_key_generation': False,
                'max_pin_length': 8,
                'session_timeout': 1800
            }
        }

    def get_middleware_quirks(self) -> Dict[str, Any]:
        """Get middleware-specific quirks and limitations"""
        provider_info = self.provider_manager.get_current_provider_info()
        if not provider_info:
            return {}

        return self.middleware_specific_quirks.get(provider_info.middleware_type, {})

    def normalize_error_message(self, error_message: str, middleware_type: MiddlewareType) -> str:
        """Normalize error messages across different middleware"""
        # Common error message mappings
        error_mappings = {
            MiddlewareType.ACTIVCLIENT: {
                'CKR_PIN_INCORRECT': 'Invalid PIN entered',
                'CKR_PIN_LOCKED': 'Card is locked due to too many incorrect PIN attempts',
                'CKR_TOKEN_NOT_PRESENT': 'Smart card not detected'
            },
            MiddlewareType.OPENSC: {
                'CKR_PIN_INCORRECT': 'PIN verification failed',
                'CKR_PIN_LOCKED': 'PIN is locked',
                'CKR_TOKEN_NOT_PRESENT': 'No token present'
            }
        }

        middleware_mappings = error_mappings.get(middleware_type, {})

        for error_code, friendly_message in middleware_mappings.items():
            if error_code in error_message:
                return friendly_message

        return error_message

    def get_recommended_settings(self) -> Dict[str, Any]:
        """Get recommended settings for current middleware"""
        quirks = self.get_middleware_quirks()
        provider_info = self.provider_manager.get_current_provider_info()

        settings = {
            'session_timeout': quirks.get('session_timeout', 3600),
            'max_pin_length': quirks.get('max_pin_length', 12),
            'retry_attempts': 3,
            'enable_pin_caching': not quirks.get('requires_pin_pad', False),
            'middleware_name': provider_info.name if provider_info else 'Unknown'
        }

        return settings
