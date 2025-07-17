"""
Comprehensive tests for DoD-compliant encryption implementation.
Tests encryption manager, TLS configuration, and key management.
"""

import pytest
import os
import tempfile
import json
import ssl
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from encryption_manager import DoD_Encryption_Manager
from tls_config import DoD_TLS_Manager
from key_manager import DoD_Key_Manager, KeyType, KeyStatus


class TestDoD_Encryption_Manager:
    """Test suite for DoD Encryption Manager."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.encryption_manager = DoD_Encryption_Manager("NIPR")
        self.test_password = "TestPassword123!"
        self.test_data = "This is sensitive test data"
    
    def test_initialization(self):
        """Test encryption manager initialization."""
        assert self.encryption_manager.classification_level == "NIPR"
        assert self.encryption_manager.encryption_params['kdf_iterations'] == 100000
        assert self.encryption_manager.encryption_params['key_rotation_days'] == 90
    
    def test_classification_levels(self):
        """Test different classification level configurations."""
        # Test SIPR
        sipr_manager = DoD_Encryption_Manager("SIPR")
        assert sipr_manager.classification_level == "SIPR"
        assert sipr_manager.encryption_params['kdf_iterations'] == 150000
        assert sipr_manager.encryption_params['require_hsm'] == True
        
        # Test JWICS
        jwics_manager = DoD_Encryption_Manager("JWICS")
        assert jwics_manager.classification_level == "JWICS"
        assert jwics_manager.encryption_params['kdf_iterations'] == 200000
        assert jwics_manager.encryption_params['key_rotation_days'] == 30
    
    def test_invalid_classification(self):
        """Test invalid classification level handling."""
        with pytest.raises(ValueError):
            DoD_Encryption_Manager("INVALID")
    
    def test_master_key_generation(self):
        """Test master key generation."""
        master_key = self.encryption_manager.generate_master_key(self.test_password)
        assert master_key is not None
        assert len(master_key) == 32  # 256 bits
        assert self.encryption_manager.master_key == master_key
    
    def test_data_encryption_key_derivation(self):
        """Test data encryption key derivation."""
        self.encryption_manager.generate_master_key(self.test_password)
        
        context = "test_context"
        dek = self.encryption_manager.derive_data_encryption_key(context)
        
        assert dek is not None
        assert len(dek) == 32  # 256 bits
        assert context in self.encryption_manager.data_encryption_keys
        assert self.encryption_manager.data_encryption_keys[context]['key'] == dek
    
    def test_data_encryption_decryption(self):
        """Test data encryption and decryption."""
        self.encryption_manager.generate_master_key(self.test_password)
        
        # Test string encryption
        encrypted_package = self.encryption_manager.encrypt_data(self.test_data)
        
        assert 'ciphertext' in encrypted_package
        assert 'iv' in encrypted_package
        assert 'tag' in encrypted_package
        assert encrypted_package['algorithm'] == 'AES-256-GCM'
        assert encrypted_package['classification'] == 'NIPR'
        
        # Test decryption
        decrypted_data = self.encryption_manager.decrypt_data(encrypted_package)
        assert decrypted_data.decode('utf-8') == self.test_data
    
    def test_data_encryption_with_context(self):
        """Test data encryption with specific context."""
        self.encryption_manager.generate_master_key(self.test_password)
        
        context = "user_data"
        encrypted_package = self.encryption_manager.encrypt_data(self.test_data, context)
        
        assert encrypted_package['context'] == context
        
        decrypted_data = self.encryption_manager.decrypt_data(encrypted_package)
        assert decrypted_data.decode('utf-8') == self.test_data
    
    def test_bytes_encryption(self):
        """Test encryption of bytes data."""
        self.encryption_manager.generate_master_key(self.test_password)
        
        test_bytes = b"Binary test data"
        encrypted_package = self.encryption_manager.encrypt_data(test_bytes)
        
        decrypted_data = self.encryption_manager.decrypt_data(encrypted_package)
        assert decrypted_data == test_bytes
    
    def test_classification_mismatch(self):
        """Test classification level mismatch during decryption."""
        self.encryption_manager.generate_master_key(self.test_password)
        encrypted_package = self.encryption_manager.encrypt_data(self.test_data)
        
        # Modify classification in package
        encrypted_package['classification'] = 'SIPR'
        
        with pytest.raises(ValueError, match="Classification level mismatch"):
            self.encryption_manager.decrypt_data(encrypted_package)
    
    def test_file_encryption_decryption(self):
        """Test file encryption and decryption."""
        self.encryption_manager.generate_master_key(self.test_password)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write(self.test_data)
            temp_file_path = temp_file.name
        
        try:
            # Encrypt file
            encrypted_path = self.encryption_manager.encrypt_file(temp_file_path)
            assert os.path.exists(encrypted_path)
            
            # Verify encrypted file contains JSON
            with open(encrypted_path, 'r') as f:
                encrypted_data = json.load(f)
            assert 'ciphertext' in encrypted_data
            assert 'algorithm' in encrypted_data
            
            # Decrypt file
            decrypted_path = self.encryption_manager.decrypt_file(encrypted_path)
            assert os.path.exists(decrypted_path)
            
            # Verify decrypted content
            with open(decrypted_path, 'r') as f:
                decrypted_content = f.read()
            assert decrypted_content == self.test_data
            
        finally:
            # Cleanup
            for path in [temp_file_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.unlink(path)
    
    def test_rsa_key_generation(self):
        """Test RSA key pair generation."""
        private_pem, public_pem = self.encryption_manager.generate_rsa_keypair()
        
        assert b'-----BEGIN PRIVATE KEY-----' in private_pem
        assert b'-----BEGIN PUBLIC KEY-----' in public_pem
        assert len(private_pem) > 0
        assert len(public_pem) > 0
    
    def test_rsa_encryption_decryption(self):
        """Test RSA encryption and decryption."""
        private_pem, public_pem = self.encryption_manager.generate_rsa_keypair()
        
        test_message = b"RSA test message"
        
        # Encrypt with public key
        ciphertext = self.encryption_manager.rsa_encrypt(test_message, public_pem)
        assert ciphertext != test_message
        assert len(ciphertext) > 0
        
        # Decrypt with private key
        plaintext = self.encryption_manager.rsa_decrypt(ciphertext, private_pem)
        assert plaintext == test_message
    
    def test_key_rotation(self):
        """Test key rotation functionality."""
        self.encryption_manager.generate_master_key(self.test_password)
        
        context = "rotation_test"
        original_key = self.encryption_manager.derive_data_encryption_key(context)
        
        # Rotate key
        self.encryption_manager.rotate_keys(context)
        
        # Verify new key is different
        new_key = self.encryption_manager.data_encryption_keys[context]['key']
        assert new_key != original_key
    
    def test_key_expiration_check(self):
        """Test key expiration checking."""
        self.encryption_manager.generate_master_key(self.test_password)
        
        context = "expiration_test"
        self.encryption_manager.derive_data_encryption_key(context)
        
        # Manually set key as expired
        past_date = datetime.utcnow() - timedelta(days=1)
        self.encryption_manager.data_encryption_keys[context]['created'] = past_date
        
        expiration_status = self.encryption_manager.check_key_expiration()
        assert context in expiration_status
    
    def test_encryption_metadata(self):
        """Test encryption metadata retrieval."""
        metadata = self.encryption_manager.get_encryption_metadata()
        
        assert metadata['classification_level'] == 'NIPR'
        assert 'encryption_params' in metadata
        assert 'algorithms' in metadata
        assert metadata['algorithms']['symmetric'] == 'AES-256-GCM'


class TestDoD_TLS_Manager:
    """Test suite for DoD TLS Manager."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.tls_manager = DoD_TLS_Manager("NIPR")
    
    def test_initialization(self):
        """Test TLS manager initialization."""
        assert self.tls_manager.classification_level == "NIPR"
        assert self.tls_manager.tls_config['minimum_version'] == ssl.TLSVersion.TLSv1_2
        assert self.tls_manager.tls_config['maximum_version'] == ssl.TLSVersion.TLSv1_3
    
    def test_classification_configurations(self):
        """Test different classification level TLS configurations."""
        # Test SIPR
        sipr_manager = DoD_TLS_Manager("SIPR")
        assert sipr_manager.tls_config['require_client_cert'] == True
        assert sipr_manager.tls_config['session_timeout'] == 1800
        assert sipr_manager.tls_config['minimum_version'] == ssl.TLSVersion.TLSv1_3
        
        # Test JWICS
        jwics_manager = DoD_TLS_Manager("JWICS")
        assert jwics_manager.tls_config['session_timeout'] == 900
        assert jwics_manager.tls_config['perfect_forward_secrecy'] == True
    
    def test_ssl_context_creation(self):
        """Test SSL context creation."""
        context = self.tls_manager.create_ssl_context()
        
        assert isinstance(context, ssl.SSLContext)
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2
        assert context.maximum_version == ssl.TLSVersion.TLSv1_3
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname == True
    
    def test_certificate_pinning(self):
        """Test certificate pinning functionality."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as cert_file:
            cert_file.write("-----BEGIN CERTIFICATE-----\ntest_cert_data\n-----END CERTIFICATE-----")
            cert_path = cert_file.name
        
        try:
            hostname = "test.example.com"
            self.tls_manager.pin_certificate(hostname, cert_path)
            
            assert hostname in self.tls_manager.pinned_certificates
            assert 'certificate' in self.tls_manager.pinned_certificates[hostname]
            assert 'pinned_at' in self.tls_manager.pinned_certificates[hostname]
            
        finally:
            os.unlink(cert_path)
    
    def test_certificate_pin_verification(self):
        """Test certificate pin verification."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as cert_file:
            cert_content = "test_certificate_data"
            cert_file.write(cert_content)
            cert_path = cert_file.name
        
        try:
            hostname = "test.example.com"
            self.tls_manager.pin_certificate(hostname, cert_path)
            
            # Test matching certificate
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            assert self.tls_manager.verify_certificate_pin(hostname, cert_data) == True
            
            # Test non-matching certificate
            fake_cert = b"different_certificate_data"
            assert self.tls_manager.verify_certificate_pin(hostname, fake_cert) == False
            
        finally:
            os.unlink(cert_path)
    
    @patch('requests.Session.head')
    def test_security_headers_check(self, mock_head):
        """Test security headers checking."""
        # Mock response with security headers
        mock_response = Mock()
        mock_response.headers = {
            'strict-transport-security': 'max-age=31536000',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY'
        }
        mock_head.return_value = mock_response
        
        result = self.tls_manager.get_security_headers("https://example.com")
        
        assert result['url'] == "https://example.com"
        assert 'strict-transport-security' in result['security_headers']
        assert 'x-content-type-options' in result['security_headers']
        assert len(result['missing_headers']) > 0  # Some headers missing
        assert result['security_score'] > 0
    
    def test_secure_requests_session(self):
        """Test secure requests session creation."""
        session = self.tls_manager.create_secure_requests_session()
        
        assert session.verify == True
        assert 'Strict-Transport-Security' in session.headers
        assert 'X-Content-Type-Options' in session.headers
        assert session.headers['X-Frame-Options'] == 'DENY'
    
    def test_tls_configuration_summary(self):
        """Test TLS configuration summary."""
        summary = self.tls_manager.get_tls_configuration_summary()
        
        assert summary['classification_level'] == 'NIPR'
        assert 'tls_config' in summary
        assert 'supported_protocols' in summary
        assert 'TLS 1.3' in summary['supported_protocols']
        assert 'security_features' in summary


class TestDoD_Key_Manager:
    """Test suite for DoD Key Manager."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.key_manager = DoD_Key_Manager("NIPR")
    
    def test_initialization(self):
        """Test key manager initialization."""
        assert self.key_manager.classification_level == "NIPR"
        assert self.key_manager.hsm_enabled == False
        assert 'key_sizes' in self.key_manager.config
        assert self.key_manager.config['key_sizes']['symmetric'] == 256
    
    def test_classification_configurations(self):
        """Test different classification level configurations."""
        # Test SIPR
        sipr_manager = DoD_Key_Manager("SIPR")
        assert sipr_manager.config['hsm_required'] == True
        assert sipr_manager.config['dual_control'] == True
        
        # Test JWICS
        jwics_manager = DoD_Key_Manager("JWICS")
        assert jwics_manager.config['key_escrow'] == True
        assert jwics_manager.config['split_knowledge'] == True
    
    def test_symmetric_key_generation(self):
        """Test symmetric key generation."""
        key_id = "test_symmetric_key"
        generated_key_id = self.key_manager.generate_key(
            KeyType.DATA_ENCRYPTION, key_id, "test_context"
        )
        
        assert generated_key_id == key_id
        assert key_id in self.key_manager.keys
        assert key_id in self.key_manager.key_metadata
        
        metadata = self.key_manager.key_metadata[key_id]
        assert metadata['key_type'] == KeyType.DATA_ENCRYPTION.value
        assert metadata['status'] == KeyStatus.ACTIVE.value
        assert metadata['classification'] == 'NIPR'
    
    def test_rsa_key_generation(self):
        """Test RSA key generation."""
        key_id = "test_signing_key"
        generated_key_id = self.key_manager.generate_key(
            KeyType.SIGNING, key_id, "signing_context"
        )
        
        assert generated_key_id == key_id
        key_material = self.key_manager.keys[key_id]
        assert isinstance(key_material, tuple)  # RSA key pair
        assert len(key_material) == 2  # Private and public key
    
    def test_key_derivation(self):
        """Test key derivation from parent key."""
        # Generate parent key
        parent_id = "parent_key"
        self.key_manager.generate_key(KeyType.MASTER, parent_id)
        
        # Derive child key
        child_id = "derived_key"
        context = "derivation_context"
        derived_key_id = self.key_manager.derive_key(
            parent_id, child_id, context, KeyType.DATA_ENCRYPTION
        )
        
        assert derived_key_id == child_id
        assert child_id in self.key_manager.keys
        
        child_metadata = self.key_manager.key_metadata[child_id]
        assert child_metadata['parent_key_id'] == parent_id
        assert child_metadata['derived'] == True
        assert child_metadata['context'] == context
    
    def test_key_retrieval(self):
        """Test key retrieval and usage tracking."""
        key_id = "test_retrieval_key"
        self.key_manager.generate_key(KeyType.DATA_ENCRYPTION, key_id)
        
        # Initial usage count should be 0
        assert self.key_manager.key_metadata[key_id]['usage_count'] == 0
        assert self.key_manager.key_metadata[key_id]['last_used'] is None
        
        # Retrieve key
        key_material = self.key_manager.get_key(key_id)
        assert key_material is not None
        
        # Usage should be tracked
        assert self.key_manager.key_metadata[key_id]['usage_count'] == 1
        assert self.key_manager.key_metadata[key_id]['last_used'] is not None
    
    def test_key_rotation(self):
        """Test key rotation."""
        key_id = "rotation_test_key"
        self.key_manager.generate_key(KeyType.DATA_ENCRYPTION, key_id)
        
        original_key = self.key_manager.keys[key_id]
        
        # Rotate key
        new_key_id = self.key_manager.rotate_key(key_id)
        
        assert new_key_id != key_id
        assert new_key_id in self.key_manager.keys
        
        # Original key should be inactive
        assert self.key_manager.key_metadata[key_id]['status'] == KeyStatus.INACTIVE.value
        assert 'successor_key_id' in self.key_manager.key_metadata[key_id]
        
        # New key should reference old key
        assert self.key_manager.key_metadata[new_key_id]['predecessor_key_id'] == key_id
    
    def test_key_revocation(self):
        """Test key revocation."""
        key_id = "revocation_test_key"
        self.key_manager.generate_key(KeyType.DATA_ENCRYPTION, key_id)
        
        reason = "Security breach"
        self.key_manager.revoke_key(key_id, reason)
        
        metadata = self.key_manager.key_metadata[key_id]
        assert metadata['status'] == KeyStatus.COMPROMISED.value
        assert metadata['revocation_reason'] == reason
        assert 'revoked_at' in metadata
    
    def test_key_expiration_check(self):
        """Test key expiration checking."""
        key_id = "expiration_test_key"
        self.key_manager.generate_key(KeyType.DATA_ENCRYPTION, key_id)
        
        # Manually set key as expired
        past_date = datetime.utcnow() - timedelta(days=1)
        self.key_manager.key_metadata[key_id]['rotation_due'] = past_date
        
        expiration_status = self.key_manager.check_key_expiration()
        
        assert key_id in expiration_status['expired']
        assert self.key_manager.key_metadata[key_id]['status'] == KeyStatus.EXPIRED.value
    
    def test_key_backup_restore(self):
        """Test key backup and restore functionality."""
        # Generate test keys
        key1_id = "backup_test_key1"
        key2_id = "backup_test_key2"
        self.key_manager.generate_key(KeyType.DATA_ENCRYPTION, key1_id)
        self.key_manager.generate_key(KeyType.SIGNING, key2_id)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as backup_file:
            backup_path = backup_file.name
        
        try:
            # Create backup
            returned_path = self.key_manager.backup_keys(backup_path)
            assert returned_path == backup_path
            assert os.path.exists(backup_path)
            
            # Verify backup content
            with open(backup_path, 'r') as f:
                backup_data = json.load(f)
            
            assert 'timestamp' in backup_data
            assert 'classification' in backup_data
            assert 'key_metadata' in backup_data
            assert 'keys' in backup_data
            
            # Clear current keys
            original_keys = self.key_manager.keys.copy()
            original_metadata = self.key_manager.key_metadata.copy()
            self.key_manager.keys.clear()
            self.key_manager.key_metadata.clear()
            
            # Restore from backup
            self.key_manager.restore_keys(backup_path)
            
            # Verify restoration
            assert len(self.key_manager.keys) == len(original_keys)
            assert len(self.key_manager.key_metadata) == len(original_metadata)
            assert key1_id in self.key_manager.keys
            assert key2_id in self.key_manager.keys
            
        finally:
            if os.path.exists(backup_path):
                os.unlink(backup_path)
    
    def test_key_statistics(self):
        """Test key statistics generation."""
        # Generate various keys
        self.key_manager.generate_key(KeyType.DATA_ENCRYPTION, "stats_key1")
        self.key_manager.generate_key(KeyType.SIGNING, "stats_key2")
        self.key_manager.generate_key(KeyType.TRANSPORT, "stats_key3")
        
        # Revoke one key
        self.key_manager.revoke_key("stats_key3")
        
        stats = self.key_manager.get_key_statistics()
        
        assert stats['total_keys'] == 3
        assert stats['active_keys'] == 2
        assert stats['compromised_keys'] == 1
        assert 'keys_by_type' in stats
        assert 'rotation_status' in stats
    
    def test_duplicate_key_id(self):
        """Test handling of duplicate key IDs."""
        key_id = "duplicate_test_key"
        self.key_manager.generate_key(KeyType.DATA_ENCRYPTION, key_id)
        
        with pytest.raises(ValueError, match="already exists"):
            self.key_manager.generate_key(KeyType.DATA_ENCRYPTION, key_id)
    
    def test_nonexistent_key_operations(self):
        """Test operations on non-existent keys."""
        nonexistent_id = "nonexistent_key"
        
        # Test key retrieval
        assert self.key_manager.get_key(nonexistent_id) is None
        
        # Test key rotation
        with pytest.raises(ValueError, match="not found"):
            self.key_manager.rotate_key(nonexistent_id)
        
        # Test key revocation
        with pytest.raises(ValueError, match="not found"):
            self.key_manager.revoke_key(nonexistent_id)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
