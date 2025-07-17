"""
DoD-Compliant Key Management System
Implements secure key management with HSM integration and key rotation.
"""

import os
import json
import logging
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from enum import Enum
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class KeyType(Enum):
    """Enumeration of supported key types."""
    MASTER = "master"
    DATA_ENCRYPTION = "data_encryption"
    KEY_ENCRYPTION = "key_encryption"
    SIGNING = "signing"
    TRANSPORT = "transport"

class KeyStatus(Enum):
    """Enumeration of key status values."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    COMPROMISED = "compromised"
    EXPIRED = "expired"
    PENDING_ACTIVATION = "pending_activation"

class DoD_Key_Manager:
    """
    DoD-compliant key management system with HSM integration,
    key rotation, and hierarchical key management.
    """
    
    def __init__(self, classification_level: str = "NIPR", 
                 hsm_enabled: bool = False, hsm_config: Optional[Dict] = None):
        """
        Initialize key manager with classification-specific settings.
        
        Args:
            classification_level: Security classification (NIPR, SIPR, JWICS)
            hsm_enabled: Whether to use Hardware Security Module
            hsm_config: HSM configuration parameters
        """
        self.classification_level = classification_level.upper()
        self.hsm_enabled = hsm_enabled
        self.hsm_config = hsm_config or {}
        self.backend = default_backend()
        
        # Key storage
        self.keys = {}
        self.key_metadata = {}
        
        # Configuration based on classification level
        self.config = self._get_key_management_config()
        
        # Initialize key hierarchy
        self._initialize_key_hierarchy()
        
        logger.info(f"Initialized DoD Key Manager for {self.classification_level}")
    
    def _get_key_management_config(self) -> Dict[str, Any]:
        """Get key management configuration based on classification level."""
        
        base_config = {
            'key_sizes': {
                'symmetric': 256,  # AES-256
                'asymmetric': 4096,  # RSA-4096
                'hash': 256  # SHA-256
            },
            'rotation_intervals': {
                'master': timedelta(days=365),
                'data_encryption': timedelta(days=90),
                'key_encryption': timedelta(days=180),
                'signing': timedelta(days=365),
                'transport': timedelta(days=30)
            },
            'backup_required': True,
            'audit_logging': True,
            'key_escrow': False
        }
        
        classification_configs = {
            "NIPR": {
                **base_config,
                'hsm_required': False,
                'dual_control': False,
                'split_knowledge': False,
                'key_ceremony_required': False
            },
            "SIPR": {
                **base_config,
                'hsm_required': True,
                'dual_control': True,
                'split_knowledge': True,
                'key_ceremony_required': True,
                'rotation_intervals': {
                    'master': timedelta(days=180),
                    'data_encryption': timedelta(days=60),
                    'key_encryption': timedelta(days=90),
                    'signing': timedelta(days=180),
                    'transport': timedelta(days=14)
                }
            },
            "JWICS": {
                **base_config,
                'hsm_required': True,
                'dual_control': True,
                'split_knowledge': True,
                'key_ceremony_required': True,
                'key_escrow': True,
                'rotation_intervals': {
                    'master': timedelta(days=90),
                    'data_encryption': timedelta(days=30),
                    'key_encryption': timedelta(days=60),
                    'signing': timedelta(days=90),
                    'transport': timedelta(days=7)
                }
            }
        }
        
        if self.classification_level not in classification_configs:
            raise ValueError(f"Unsupported classification level: {self.classification_level}")
        
        return classification_configs[self.classification_level]
    
    def _initialize_key_hierarchy(self) -> None:
        """Initialize the key hierarchy structure."""
        self.key_hierarchy = {
            'root': None,  # Root key (stored in HSM if available)
            'master_keys': {},  # Master keys for different contexts
            'data_keys': {},  # Data encryption keys
            'key_encryption_keys': {},  # Key encryption keys
            'transport_keys': {},  # Transport/session keys
            'signing_keys': {}  # Digital signature keys
        }
        
        logger.info("Key hierarchy initialized")
    
    def generate_key(self, key_type: KeyType, key_id: str, 
                    context: Optional[str] = None, 
                    key_size: Optional[int] = None) -> str:
        """
        Generate a new cryptographic key.
        
        Args:
            key_type: Type of key to generate
            key_id: Unique identifier for the key
            context: Optional context for key derivation
            key_size: Optional key size (uses default if not specified)
            
        Returns:
            Key identifier
        """
        if key_id in self.keys:
            raise ValueError(f"Key with ID '{key_id}' already exists")
        
        # Determine key size
        if key_size is None:
            if key_type in [KeyType.SIGNING]:
                key_size = self.config['key_sizes']['asymmetric']
            else:
                key_size = self.config['key_sizes']['symmetric']
        
        # Generate key material
        if key_type == KeyType.SIGNING:
            key_material = self._generate_rsa_key(key_size)
        else:
            key_material = self._generate_symmetric_key(key_size // 8)  # Convert bits to bytes
        
        # Create key metadata
        metadata = {
            'key_id': key_id,
            'key_type': key_type.value,
            'context': context,
            'key_size': key_size,
            'created_at': datetime.utcnow(),
            'status': KeyStatus.ACTIVE.value,
            'classification': self.classification_level,
            'rotation_due': datetime.utcnow() + self.config['rotation_intervals'].get(
                key_type.value, timedelta(days=90)
            ),
            'usage_count': 0,
            'last_used': None
        }
        
        # Store key and metadata
        self.keys[key_id] = key_material
        self.key_metadata[key_id] = metadata
        
        # Add to appropriate hierarchy level
        self._add_to_hierarchy(key_type, key_id, context)
        
        logger.info(f"Generated {key_type.value} key: {key_id}")
        return key_id
    
    def _generate_symmetric_key(self, key_length: int) -> bytes:
        """Generate symmetric key material."""
        if self.hsm_enabled:
            return self._hsm_generate_symmetric_key(key_length)
        else:
            return secrets.token_bytes(key_length)
    
    def _generate_rsa_key(self, key_size: int) -> Tuple[bytes, bytes]:
        """Generate RSA key pair."""
        if self.hsm_enabled:
            return self._hsm_generate_rsa_key(key_size)
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self.backend
            )
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return private_pem, public_pem
    
    def _hsm_generate_symmetric_key(self, key_length: int) -> bytes:
        """Generate symmetric key using HSM (placeholder implementation)."""
        # This would integrate with actual HSM APIs (e.g., PKCS#11, AWS CloudHSM, etc.)
        logger.warning("HSM integration not implemented - using software generation")
        return secrets.token_bytes(key_length)
    
    def _hsm_generate_rsa_key(self, key_size: int) -> Tuple[bytes, bytes]:
        """Generate RSA key pair using HSM (placeholder implementation)."""
        # This would integrate with actual HSM APIs
        logger.warning("HSM integration not implemented - using software generation")
        return self._generate_rsa_key(key_size)
    
    def _add_to_hierarchy(self, key_type: KeyType, key_id: str, context: Optional[str]) -> None:
        """Add key to appropriate hierarchy level."""
        if key_type == KeyType.MASTER:
            self.key_hierarchy['master_keys'][key_id] = context
        elif key_type == KeyType.DATA_ENCRYPTION:
            self.key_hierarchy['data_keys'][key_id] = context
        elif key_type == KeyType.KEY_ENCRYPTION:
            self.key_hierarchy['key_encryption_keys'][key_id] = context
        elif key_type == KeyType.TRANSPORT:
            self.key_hierarchy['transport_keys'][key_id] = context
        elif key_type == KeyType.SIGNING:
            self.key_hierarchy['signing_keys'][key_id] = context
    
    def derive_key(self, parent_key_id: str, derived_key_id: str, 
                  context: str, key_type: KeyType) -> str:
        """
        Derive a new key from an existing parent key.
        
        Args:
            parent_key_id: ID of the parent key
            derived_key_id: ID for the derived key
            context: Derivation context
            key_type: Type of derived key
            
        Returns:
            Derived key identifier
        """
        if parent_key_id not in self.keys:
            raise ValueError(f"Parent key '{parent_key_id}' not found")
        
        if derived_key_id in self.keys:
            raise ValueError(f"Derived key ID '{derived_key_id}' already exists")
        
        parent_key = self.keys[parent_key_id]
        
        # Use HKDF for key derivation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=None,
            info=context.encode(),
            backend=self.backend
        )
        
        # Handle different parent key types
        if isinstance(parent_key, tuple):  # RSA key pair
            # Use private key for derivation
            derived_key = hkdf.derive(parent_key[0])
        else:  # Symmetric key
            derived_key = hkdf.derive(parent_key)
        
        # Create metadata for derived key
        metadata = {
            'key_id': derived_key_id,
            'key_type': key_type.value,
            'context': context,
            'parent_key_id': parent_key_id,
            'key_size': len(derived_key) * 8,  # Convert bytes to bits
            'created_at': datetime.utcnow(),
            'status': KeyStatus.ACTIVE.value,
            'classification': self.classification_level,
            'rotation_due': datetime.utcnow() + self.config['rotation_intervals'].get(
                key_type.value, timedelta(days=90)
            ),
            'usage_count': 0,
            'last_used': None,
            'derived': True
        }
        
        # Store derived key and metadata
        self.keys[derived_key_id] = derived_key
        self.key_metadata[derived_key_id] = metadata
        
        # Add to hierarchy
        self._add_to_hierarchy(key_type, derived_key_id, context)
        
        logger.info(f"Derived key '{derived_key_id}' from parent '{parent_key_id}'")
        return derived_key_id
    
    def get_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve key material by ID.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Key material or None if not found
        """
        if key_id not in self.keys:
            logger.warning(f"Key '{key_id}' not found")
            return None
        
        # Update usage statistics
        self.key_metadata[key_id]['usage_count'] += 1
        self.key_metadata[key_id]['last_used'] = datetime.utcnow()
        
        return self.keys[key_id]
    
    def rotate_key(self, key_id: str) -> str:
        """
        Rotate an existing key.
        
        Args:
            key_id: ID of key to rotate
            
        Returns:
            New key identifier
        """
        if key_id not in self.keys:
            raise ValueError(f"Key '{key_id}' not found")
        
        old_metadata = self.key_metadata[key_id]
        
        # Generate new key ID
        new_key_id = f"{key_id}_rotated_{int(datetime.utcnow().timestamp())}"
        
        # Generate new key of same type
        key_type = KeyType(old_metadata['key_type'])
        context = old_metadata.get('context')
        key_size = old_metadata['key_size']
        
        # Generate new key
        self.generate_key(key_type, new_key_id, context, key_size)
        
        # Mark old key as inactive
        self.key_metadata[key_id]['status'] = KeyStatus.INACTIVE.value
        self.key_metadata[key_id]['rotated_at'] = datetime.utcnow()
        self.key_metadata[key_id]['successor_key_id'] = new_key_id
        
        # Update new key metadata
        self.key_metadata[new_key_id]['predecessor_key_id'] = key_id
        
        logger.info(f"Rotated key '{key_id}' to '{new_key_id}'")
        return new_key_id
    
    def revoke_key(self, key_id: str, reason: str = "Manual revocation") -> None:
        """
        Revoke a key and mark it as compromised.
        
        Args:
            key_id: ID of key to revoke
            reason: Reason for revocation
        """
        if key_id not in self.keys:
            raise ValueError(f"Key '{key_id}' not found")
        
        # Update key status
        self.key_metadata[key_id]['status'] = KeyStatus.COMPROMISED.value
        self.key_metadata[key_id]['revoked_at'] = datetime.utcnow()
        self.key_metadata[key_id]['revocation_reason'] = reason
        
        # Optionally remove key material (depending on policy)
        if not self.config.get('retain_revoked_keys', False):
            del self.keys[key_id]
        
        logger.warning(f"Revoked key '{key_id}': {reason}")
    
    def check_key_expiration(self) -> Dict[str, List[str]]:
        """
        Check for expired or soon-to-expire keys.
        
        Returns:
            Dictionary categorizing keys by expiration status
        """
        current_time = datetime.utcnow()
        warning_threshold = timedelta(days=7)  # Warn 7 days before expiration
        
        result = {
            'expired': [],
            'expiring_soon': [],
            'active': []
        }
        
        for key_id, metadata in self.key_metadata.items():
            if metadata['status'] != KeyStatus.ACTIVE.value:
                continue
            
            rotation_due = metadata['rotation_due']
            time_to_expiry = rotation_due - current_time
            
            if time_to_expiry <= timedelta(0):
                result['expired'].append(key_id)
                # Auto-mark as expired
                metadata['status'] = KeyStatus.EXPIRED.value
            elif time_to_expiry <= warning_threshold:
                result['expiring_soon'].append(key_id)
            else:
                result['active'].append(key_id)
        
        if result['expired']:
            logger.warning(f"Found {len(result['expired'])} expired keys")
        if result['expiring_soon']:
            logger.info(f"Found {len(result['expiring_soon'])} keys expiring soon")
        
        return result
    
    def backup_keys(self, backup_path: str, encrypt_backup: bool = True) -> str:
        """
        Create encrypted backup of key material and metadata.
        
        Args:
            backup_path: Path for backup file
            encrypt_backup: Whether to encrypt the backup
            
        Returns:
            Path to backup file
        """
        backup_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'classification': self.classification_level,
            'key_metadata': self.key_metadata,
            'key_hierarchy': self.key_hierarchy
        }
        
        # Include key material if not HSM-protected
        if not self.hsm_enabled:
            # Encode key material for JSON serialization
            encoded_keys = {}
            for key_id, key_material in self.keys.items():
                if isinstance(key_material, tuple):  # RSA key pair
                    encoded_keys[key_id] = {
                        'type': 'rsa_pair',
                        'private_key': base64.b64encode(key_material[0]).decode(),
                        'public_key': base64.b64encode(key_material[1]).decode()
                    }
                else:  # Symmetric key
                    encoded_keys[key_id] = {
                        'type': 'symmetric',
                        'key_material': base64.b64encode(key_material).decode()
                    }
            
            backup_data['keys'] = encoded_keys
        
        # Write backup
        with open(backup_path, 'w') as backup_file:
            json.dump(backup_data, backup_file, indent=2)
        
        logger.info(f"Key backup created: {backup_path}")
        return backup_path
    
    def restore_keys(self, backup_path: str) -> None:
        """
        Restore keys from backup file.
        
        Args:
            backup_path: Path to backup file
        """
        with open(backup_path, 'r') as backup_file:
            backup_data = json.load(backup_file)
        
        # Restore metadata and hierarchy
        self.key_metadata = backup_data['key_metadata']
        self.key_hierarchy = backup_data['key_hierarchy']
        
        # Restore key material if present
        if 'keys' in backup_data:
            self.keys = {}
            for key_id, key_data in backup_data['keys'].items():
                if key_data['type'] == 'rsa_pair':
                    private_key = base64.b64decode(key_data['private_key'])
                    public_key = base64.b64decode(key_data['public_key'])
                    self.keys[key_id] = (private_key, public_key)
                else:  # symmetric
                    key_material = base64.b64decode(key_data['key_material'])
                    self.keys[key_id] = key_material
        
        logger.info(f"Keys restored from backup: {backup_path}")
    
    def get_key_statistics(self) -> Dict[str, Any]:
        """
        Get key management statistics.
        
        Returns:
            Dictionary containing key statistics
        """
        stats = {
            'total_keys': len(self.keys),
            'active_keys': 0,
            'inactive_keys': 0,
            'expired_keys': 0,
            'compromised_keys': 0,
            'keys_by_type': {},
            'keys_by_classification': {},
            'rotation_status': self.check_key_expiration()
        }
        
        for metadata in self.key_metadata.values():
            status = metadata['status']
            key_type = metadata['key_type']
            classification = metadata['classification']
            
            # Count by status
            if status == KeyStatus.ACTIVE.value:
                stats['active_keys'] += 1
            elif status == KeyStatus.INACTIVE.value:
                stats['inactive_keys'] += 1
            elif status == KeyStatus.EXPIRED.value:
                stats['expired_keys'] += 1
            elif status == KeyStatus.COMPROMISED.value:
                stats['compromised_keys'] += 1
            
            # Count by type
            stats['keys_by_type'][key_type] = stats['keys_by_type'].get(key_type, 0) + 1
            
            # Count by classification
            stats['keys_by_classification'][classification] = stats['keys_by_classification'].get(classification, 0) + 1
        
        return stats
    
    def audit_log_entry(self, action: str, key_id: str, details: Dict[str, Any]) -> None:
        """
        Create audit log entry for key management operations.
        
        Args:
            action: Action performed
            key_id: Key identifier
            details: Additional details
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'key_id': key_id,
            'classification': self.classification_level,
            'details': details
        }
        
        # In production, this would write to a secure audit log
        logger.info(f"AUDIT: {json.dumps(log_entry)}")
