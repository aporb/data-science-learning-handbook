"""
Test Data Generation Engine
==========================

Main engine for generating comprehensive test data for penetration testing scenarios.
Integrates with the multi-classification engine to ensure classification-appropriate
data generation while providing realistic test scenarios.

Key Features:
- Classification-aware data generation (UNCLASSIFIED through TOP SECRET)
- Synthetic user accounts and credentials with realistic patterns
- Database records with configurable volume and complexity
- Document generation with embedded metadata
- Network traffic patterns and service simulation
- Integration with existing audit and monitoring systems

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import secrets
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import random
import string
from faker import Faker
from concurrent.futures import ThreadPoolExecutor
import aiofiles

# Import existing infrastructure  
from ...multi_classification.enhanced_classification_engine import (
    EnhancedClassificationEngine,
    ClassificationLevel,
    SecurityLabel
)
from ...rbac.models.classification import SecurityClearance
from ...audits.audit_logger import AuditLogger
from ...rbac.models.data_classification import DataSensitivity, NetworkDomain

logger = logging.getLogger(__name__)

class TestDataType(Enum):
    """Types of test data that can be generated."""
    USERS = "users"
    CREDENTIALS = "credentials"  
    DOCUMENTS = "documents"
    DATABASE_RECORDS = "database_records"
    NETWORK_TRAFFIC = "network_traffic"
    FILE_SYSTEM = "file_system"
    APPLICATIONS = "applications"

@dataclass
class TestDataConfiguration:
    """Configuration for test data generation."""
    data_type: TestDataType
    classification_level: ClassificationLevel
    volume: int = 100
    complexity: str = "medium"  # low, medium, high
    network_domain: NetworkDomain = NetworkDomain.NIPR
    include_vulnerabilities: bool = True
    realistic_patterns: bool = True
    audit_enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass 
class GeneratedTestData:
    """Container for generated test data with metadata."""
    data_id: str
    data_type: TestDataType
    classification: ClassificationLevel
    content: Dict[str, Any]
    metadata: Dict[str, Any]
    generated_at: datetime
    expires_at: Optional[datetime] = None
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)

class TestDataGenerator:
    """
    Main test data generation engine with classification awareness.
    
    Provides comprehensive test data generation capabilities while
    integrating with existing security infrastructure.
    """
    
    def __init__(self, 
                 classification_engine: Optional[EnhancedClassificationEngine] = None,
                 audit_logger: Optional[AuditLogger] = None):
        """Initialize the test data generator."""
        self.classification_engine = classification_engine
        self.audit_logger = audit_logger
        self.fake = Faker()
        self.generated_data: Dict[str, GeneratedTestData] = {}
        self.generation_statistics = {
            'total_generated': 0,
            'by_type': {},
            'by_classification': {},
            'generation_errors': []
        }
        
        # Seed for reproducible testing if needed
        self.random_seed = None
        
        logger.info("TestDataGenerator initialized")
    
    def set_random_seed(self, seed: int) -> None:
        """Set random seed for reproducible test data generation."""
        self.random_seed = seed
        random.seed(seed)
        self.fake.seed_instance(seed)
        logger.info(f"Random seed set to {seed}")
    
    async def generate_test_data(self, 
                               config: TestDataConfiguration) -> GeneratedTestData:
        """
        Generate test data based on configuration.
        
        Args:
            config: Test data generation configuration
            
        Returns:
            Generated test data with metadata
        """
        try:
            data_id = str(uuid.uuid4())
            
            # Audit the generation request
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="test_data_generation_request",
                    data={
                        'data_id': data_id,
                        'data_type': config.data_type.value,
                        'classification': config.classification_level.value,
                        'volume': config.volume
                    },
                    classification=config.classification_level
                )
            
            # Generate data based on type
            content = await self._generate_by_type(config)
            
            # Apply classification markings
            if self.classification_engine:
                content = await self._apply_classification_markings(
                    content, config.classification_level
                )
            
            # Create generated data object
            generated_data = GeneratedTestData(
                data_id=data_id,
                data_type=config.data_type,
                classification=config.classification_level,
                content=content,
                metadata={
                    'generation_config': asdict(config),
                    'generation_time': datetime.now(timezone.utc).isoformat(),
                    'generator_version': '1.0',
                    'seed': self.random_seed
                },
                generated_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
            )
            
            # Store generated data
            self.generated_data[data_id] = generated_data
            
            # Update statistics
            self._update_statistics(config.data_type, config.classification_level)
            
            logger.info(f"Generated test data {data_id} of type {config.data_type.value}")
            
            return generated_data
            
        except Exception as e:
            error_msg = f"Failed to generate test data: {str(e)}"
            logger.error(error_msg)
            self.generation_statistics['generation_errors'].append({
                'error': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'config': asdict(config)
            })
            raise
    
    async def _generate_by_type(self, config: TestDataConfiguration) -> Dict[str, Any]:
        """Generate content based on data type."""
        
        generators = {
            TestDataType.USERS: self._generate_users,
            TestDataType.CREDENTIALS: self._generate_credentials,
            TestDataType.DOCUMENTS: self._generate_documents,
            TestDataType.DATABASE_RECORDS: self._generate_database_records,
            TestDataType.NETWORK_TRAFFIC: self._generate_network_traffic,
            TestDataType.FILE_SYSTEM: self._generate_file_system,
            TestDataType.APPLICATIONS: self._generate_applications
        }
        
        generator_func = generators.get(config.data_type)
        if not generator_func:
            raise ValueError(f"Unsupported data type: {config.data_type}")
        
        return await generator_func(config)
    
    async def _generate_users(self, config: TestDataConfiguration) -> Dict[str, Any]:
        """Generate synthetic user accounts."""
        users = []
        
        for i in range(config.volume):
            # Generate realistic user data
            first_name = self.fake.first_name()
            last_name = self.fake.last_name()
            username = f"{first_name.lower()}.{last_name.lower()}{random.randint(1, 999)}"
            
            # Classification-appropriate email domains
            domain_map = {
                ClassificationLevel.UNCLASSIFIED: ["example.com", "test.mil", "contractor.gov"],
                ClassificationLevel.CONFIDENTIAL: ["secure.mil", "classified.gov"],
                ClassificationLevel.SECRET: ["secret.mil", "intel.gov"],
                ClassificationLevel.TOP_SECRET: ["topsecret.mil", "nsa.gov"]
            }
            
            email_domain = random.choice(domain_map.get(config.classification_level, ["example.com"]))
            
            user = {
                'user_id': str(uuid.uuid4()),
                'username': username,
                'email': f"{username}@{email_domain}",
                'first_name': first_name,
                'last_name': last_name,
                'full_name': f"{first_name} {last_name}",
                'department': self.fake.company_suffix(),
                'job_title': self.fake.job(),
                'phone': self.fake.phone_number(),
                'created_at': self.fake.date_time_between(start_date='-2y', end_date='now'),
                'last_login': self.fake.date_time_between(start_date='-30d', end_date='now'),
                'security_clearance': self._generate_security_clearance(config.classification_level),
                'account_status': random.choice(['active', 'inactive', 'suspended']),
                'classification_level': config.classification_level.value
            }
            
            # Add vulnerabilities if requested
            if config.include_vulnerabilities:
                user.update({
                    'weak_password_hints': True,
                    'password_reuse_pattern': True,
                    'security_questions_weak': True,
                    'mfa_disabled': random.choice([True, False])
                })
            
            users.append(user)
        
        return {
            'users': users,
            'total_count': len(users),
            'generation_method': 'synthetic',
            'includes_vulnerabilities': config.include_vulnerabilities
        }
    
    async def _generate_credentials(self, config: TestDataConfiguration) -> Dict[str, Any]:
        """Generate synthetic credentials with realistic patterns."""
        credentials = []
        
        # Common weak password patterns for testing
        weak_patterns = [
            "Password123!", "Summer2024!", "Company123", "Welcome1!",
            "P@ssw0rd", "123456789", "password", "admin123"
        ]
        
        strong_patterns = [
            "Tr0ub4dor&3", "correct-horse-battery-staple", "MyP@ssw0rd2024!",
            "Secure#Pass123", "C0mpl3x!ty2024"
        ]
        
        for i in range(config.volume):
            # Mix of weak and strong passwords for realistic testing
            if config.include_vulnerabilities and random.random() < 0.3:
                password = random.choice(weak_patterns)
                strength = "weak"
            else:
                if config.complexity == "low":
                    password = self.fake.password(length=8, special_chars=False)
                elif config.complexity == "high":
                    password = random.choice(strong_patterns)
                else:
                    password = self.fake.password(length=12, special_chars=True)
                strength = "medium"
            
            credential = {
                'credential_id': str(uuid.uuid4()),
                'username': f"testuser{i}",
                'password': password,
                'password_hash': hashlib.sha256(password.encode()).hexdigest(),
                'password_strength': strength,
                'created_at': self.fake.date_time_between(start_date='-1y', end_date='now'),
                'last_changed': self.fake.date_time_between(start_date='-90d', end_date='now'),
                'expires_at': self.fake.date_time_between(start_date='now', end_date='+90d'),
                'classification_level': config.classification_level.value,
                'api_key': secrets.token_urlsafe(32),
                'mfa_secret': secrets.token_urlsafe(16) if random.choice([True, False]) else None
            }
            
            # Add vulnerability patterns
            if config.include_vulnerabilities:
                credential.update({
                    'password_reused': random.choice([True, False]),
                    'stored_plaintext': random.choice([True, False]),
                    'weak_encryption': random.choice([True, False]),
                    'default_credential': random.choice([True, False])
                })
            
            credentials.append(credential)
        
        return {
            'credentials': credentials,
            'total_count': len(credentials),
            'weak_password_count': sum(1 for c in credentials if c.get('password_strength') == 'weak'),
            'includes_vulnerabilities': config.include_vulnerabilities
        }
    
    async def _generate_documents(self, config: TestDataConfiguration) -> Dict[str, Any]:
        """Generate synthetic documents with classification markings."""
        documents = []
        
        # Document types based on classification level
        doc_types_map = {
            ClassificationLevel.UNCLASSIFIED: ["memo", "report", "presentation", "manual"],
            ClassificationLevel.CONFIDENTIAL: ["briefing", "analysis", "intelligence", "operational"],
            ClassificationLevel.SECRET: ["assessment", "strategy", "classified_report"],
            ClassificationLevel.TOP_SECRET: ["intelligence_brief", "operational_plan", "threat_analysis"]
        }
        
        doc_types = doc_types_map.get(config.classification_level, ["document"])
        
        for i in range(config.volume):
            doc_type = random.choice(doc_types)
            
            # Generate realistic content based on classification
            if config.classification_level == ClassificationLevel.UNCLASSIFIED:
                content = self.fake.text(max_nb_chars=2000)
            else:
                # More structured content for classified documents
                content = self._generate_classified_content(config.classification_level)
            
            document = {
                'document_id': str(uuid.uuid4()),
                'title': f"{doc_type.title()} - {self.fake.catch_phrase()}",
                'document_type': doc_type,
                'content': content,
                'author': self.fake.name(),
                'classification': config.classification_level.value,
                'created_at': self.fake.date_time_between(start_date='-1y', end_date='now'),
                'modified_at': self.fake.date_time_between(start_date='-30d', end_date='now'),
                'file_size': len(content.encode('utf-8')),
                'file_format': random.choice(['pdf', 'docx', 'txt', 'rtf']),
                'metadata': {
                    'classification_marking': self._get_classification_marking(config.classification_level),
                    'handling_instructions': self._get_handling_instructions(config.classification_level),
                    'distribution_list': self._generate_distribution_list(),
                    'keywords': self.fake.words(nb=5)
                }
            }
            
            # Add security vulnerabilities
            if config.include_vulnerabilities:
                document.update({
                    'encryption_weak': random.choice([True, False]),
                    'access_controls_missing': random.choice([True, False]),
                    'metadata_leakage': random.choice([True, False]),
                    'classification_mismatch': random.choice([True, False])
                })
            
            documents.append(document)
        
        return {
            'documents': documents,
            'total_count': len(documents),
            'classification_distribution': self._get_classification_distribution(documents),
            'includes_vulnerabilities': config.include_vulnerabilities
        }
    
    async def _generate_database_records(self, config: TestDataConfiguration) -> Dict[str, Any]:
        """Generate database records for testing."""
        records = []
        
        # Different record types based on classification
        if config.classification_level == ClassificationLevel.UNCLASSIFIED:
            record_schemas = ["customer", "inventory", "employee", "transaction"]
        elif config.classification_level == ClassificationLevel.CONFIDENTIAL:
            record_schemas = ["personnel", "contract", "financial", "operational"]
        else:
            record_schemas = ["intelligence", "threat", "assessment", "classified_operation"]
        
        for i in range(config.volume):
            schema = random.choice(record_schemas)
            record = self._generate_record_by_schema(schema, config)
            records.append(record)
        
        return {
            'records': records,
            'total_count': len(records),
            'schemas': list(set(r['record_type'] for r in records)),
            'includes_vulnerabilities': config.include_vulnerabilities
        }
    
    async def _generate_network_traffic(self, config: TestDataConfiguration) -> Dict[str, Any]:
        """Generate network traffic patterns for testing."""
        traffic_patterns = []
        
        for i in range(config.volume):
            pattern = {
                'flow_id': str(uuid.uuid4()),
                'source_ip': self.fake.ipv4(),
                'destination_ip': self.fake.ipv4(),
                'source_port': random.randint(1024, 65535),
                'destination_port': random.choice([80, 443, 22, 21, 23, 25, 53]),
                'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                'packet_count': random.randint(1, 1000),
                'byte_count': random.randint(64, 65536),
                'duration': random.uniform(0.1, 300.0),
                'timestamp': self.fake.date_time_between(start_date='-1d', end_date='now'),
                'classification_level': config.classification_level.value
            }
            
            # Add suspicious patterns for vulnerability testing
            if config.include_vulnerabilities:
                pattern.update({
                    'suspicious_activity': random.choice([True, False]),
                    'port_scan_indicator': random.choice([True, False]),
                    'data_exfiltration_pattern': random.choice([True, False]),
                    'anomalous_volume': random.choice([True, False])
                })
            
            traffic_patterns.append(pattern)
        
        return {
            'traffic_patterns': traffic_patterns,
            'total_flows': len(traffic_patterns),
            'network_domain': config.network_domain.value,
            'includes_vulnerabilities': config.include_vulnerabilities
        }
    
    async def _generate_file_system(self, config: TestDataConfiguration) -> Dict[str, Any]:
        """Generate file system structures for testing."""
        file_systems = []
        
        # Generate directory structure
        base_paths = ["/home", "/var", "/opt", "/etc", "/tmp"]
        
        for i in range(config.volume):
            base_path = random.choice(base_paths)
            file_entry = {
                'path': f"{base_path}/{self.fake.file_path()}",
                'file_type': random.choice(['file', 'directory', 'symlink']),
                'size': random.randint(0, 1024*1024*10),  # Up to 10MB
                'permissions': random.choice(['755', '644', '600', '777']),
                'owner': self.fake.user_name(),
                'group': random.choice(['users', 'admin', 'wheel', 'staff']),
                'created_at': self.fake.date_time_between(start_date='-1y', end_date='now'),
                'modified_at': self.fake.date_time_between(start_date='-30d', end_date='now'),
                'classification_level': config.classification_level.value
            }
            
            # Add security vulnerabilities
            if config.include_vulnerabilities:
                file_entry.update({
                    'world_writable': random.choice([True, False]),
                    'suid_bit_set': random.choice([True, False]),
                    'contains_secrets': random.choice([True, False]),
                    'weak_permissions': random.choice([True, False])
                })
            
            file_systems.append(file_entry)
        
        return {
            'file_system_entries': file_systems,
            'total_entries': len(file_systems),
            'directory_count': sum(1 for f in file_systems if f['file_type'] == 'directory'),
            'includes_vulnerabilities': config.include_vulnerabilities
        }
    
    async def _generate_applications(self, config: TestDataConfiguration) -> Dict[str, Any]:
        """Generate application configurations for testing."""
        applications = []
        
        app_types = ["web_app", "database", "api_service", "file_server", "auth_service"]
        
        for i in range(config.volume):
            app_type = random.choice(app_types)
            
            application = {
                'application_id': str(uuid.uuid4()),
                'name': f"{app_type}_{i}",
                'type': app_type,
                'version': f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
                'host': self.fake.ipv4(),
                'port': random.randint(8000, 9999),
                'status': random.choice(['running', 'stopped', 'error']),
                'configuration': self._generate_app_config(app_type),
                'classification_level': config.classification_level.value,
                'deployed_at': self.fake.date_time_between(start_date='-6m', end_date='now')
            }
            
            # Add vulnerabilities
            if config.include_vulnerabilities:
                application.update({
                    'default_credentials': random.choice([True, False]),
                    'outdated_version': random.choice([True, False]),
                    'insecure_config': random.choice([True, False]),
                    'missing_encryption': random.choice([True, False])
                })
            
            applications.append(application)
        
        return {
            'applications': applications,
            'total_count': len(applications),
            'app_types': list(set(a['type'] for a in applications)),
            'includes_vulnerabilities': config.include_vulnerabilities
        }
    
    def _generate_security_clearance(self, classification_level: ClassificationLevel) -> str:
        """Generate appropriate security clearance for classification level."""
        clearance_map = {
            ClassificationLevel.UNCLASSIFIED: "Public Trust",
            ClassificationLevel.CONFIDENTIAL: "Confidential",
            ClassificationLevel.SECRET: "Secret", 
            ClassificationLevel.TOP_SECRET: "Top Secret"
        }
        return clearance_map.get(classification_level, "None")
    
    def _generate_classified_content(self, classification_level: ClassificationLevel) -> str:
        """Generate realistic classified content."""
        templates = {
            ClassificationLevel.CONFIDENTIAL: [
                "This briefing contains information regarding operational procedures...",
                "Personnel assessment indicates the following security considerations...",
                "Contractual arrangements with external entities require..."
            ],
            ClassificationLevel.SECRET: [
                "Intelligence analysis reveals potential threats to...",
                "Operational security assessment identifies vulnerabilities in...",
                "Strategic planning document outlines classified objectives..."
            ],
            ClassificationLevel.TOP_SECRET: [
                "Highly sensitive intelligence indicates imminent threats...",
                "Covert operational parameters require immediate attention...",
                "National security implications of this analysis..."
            ]
        }
        
        template = random.choice(templates.get(classification_level, ["Standard document content..."]))
        return template + " " + self.fake.text(max_nb_chars=1500)
    
    def _get_classification_marking(self, classification_level: ClassificationLevel) -> str:
        """Get appropriate classification marking."""
        markings = {
            ClassificationLevel.UNCLASSIFIED: "UNCLASSIFIED",
            ClassificationLevel.CONFIDENTIAL: "CONFIDENTIAL",
            ClassificationLevel.SECRET: "SECRET",
            ClassificationLevel.TOP_SECRET: "TOP SECRET"
        }
        return markings.get(classification_level, "UNCLASSIFIED")
    
    def _get_handling_instructions(self, classification_level: ClassificationLevel) -> List[str]:
        """Get handling instructions for classification level."""
        instructions = {
            ClassificationLevel.UNCLASSIFIED: ["FOR OFFICIAL USE ONLY"],
            ClassificationLevel.CONFIDENTIAL: ["CONFIDENTIAL//NOFORN"],
            ClassificationLevel.SECRET: ["SECRET//NOFORN", "HANDLE VIA SPECIAL ACCESS CHANNELS"],
            ClassificationLevel.TOP_SECRET: ["TOP SECRET//NOFORN", "SPECIAL ACCESS REQUIRED"]
        }
        return instructions.get(classification_level, [])
    
    def _generate_distribution_list(self) -> List[str]:
        """Generate realistic distribution list."""
        return [self.fake.email() for _ in range(random.randint(2, 8))]
    
    def _get_classification_distribution(self, documents: List[Dict]) -> Dict[str, int]:
        """Get distribution of classifications in document set."""
        distribution = {}
        for doc in documents:
            classification = doc['classification']
            distribution[classification] = distribution.get(classification, 0) + 1
        return distribution
    
    def _generate_record_by_schema(self, schema: str, config: TestDataConfiguration) -> Dict[str, Any]:
        """Generate database record based on schema type."""
        base_record = {
            'record_id': str(uuid.uuid4()),
            'record_type': schema,
            'created_at': self.fake.date_time_between(start_date='-1y', end_date='now'),
            'classification_level': config.classification_level.value
        }
        
        schema_generators = {
            'customer': self._generate_customer_record,
            'employee': self._generate_employee_record,
            'transaction': self._generate_transaction_record,
            'personnel': self._generate_personnel_record,
            'intelligence': self._generate_intelligence_record
        }
        
        generator = schema_generators.get(schema, self._generate_generic_record)
        record_data = generator()
        
        base_record.update(record_data)
        
        # Add vulnerabilities
        if config.include_vulnerabilities:
            base_record.update({
                'pii_exposed': random.choice([True, False]),
                'encryption_missing': random.choice([True, False]),
                'access_controls_weak': random.choice([True, False])
            })
        
        return base_record
    
    def _generate_customer_record(self) -> Dict[str, Any]:
        """Generate customer record."""
        return {
            'customer_id': random.randint(10000, 99999),
            'name': self.fake.name(),
            'email': self.fake.email(),
            'phone': self.fake.phone_number(),
            'address': self.fake.address(),
            'account_balance': round(random.uniform(0, 10000), 2)
        }
    
    def _generate_employee_record(self) -> Dict[str, Any]:
        """Generate employee record."""
        return {
            'employee_id': random.randint(1000, 9999),
            'name': self.fake.name(),
            'department': self.fake.company_suffix(),
            'position': self.fake.job(),
            'salary': random.randint(30000, 150000),
            'hire_date': self.fake.date_between(start_date='-5y', end_date='now')
        }
    
    def _generate_transaction_record(self) -> Dict[str, Any]:
        """Generate transaction record."""
        return {
            'transaction_id': str(uuid.uuid4()),
            'amount': round(random.uniform(1, 5000), 2),
            'currency': 'USD',
            'transaction_type': random.choice(['debit', 'credit', 'transfer']),
            'merchant': self.fake.company(),
            'timestamp': self.fake.date_time_between(start_date='-30d', end_date='now')
        }
    
    def _generate_personnel_record(self) -> Dict[str, Any]:
        """Generate personnel record for classified systems."""
        return {
            'personnel_id': random.randint(100000, 999999),
            'name': self.fake.name(),
            'clearance_level': random.choice(['Confidential', 'Secret', 'Top Secret']),
            'unit': f"Unit {random.randint(1, 100)}",
            'position': self.fake.military_rank(),
            'assignment_date': self.fake.date_between(start_date='-2y', end_date='now')
        }
    
    def _generate_intelligence_record(self) -> Dict[str, Any]:
        """Generate intelligence record for top secret systems."""
        return {
            'intel_id': str(uuid.uuid4()),
            'source_type': random.choice(['HUMINT', 'SIGINT', 'IMINT', 'OSINT']),
            'reliability': random.choice(['A', 'B', 'C', 'D', 'E', 'F']),
            'threat_level': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
            'region': self.fake.country(),
            'collection_date': self.fake.date_between(start_date='-60d', end_date='now')
        }
    
    def _generate_generic_record(self) -> Dict[str, Any]:
        """Generate generic record when no specific schema matches."""
        return {
            'data': self.fake.pydict(nb_elements=5),
            'description': self.fake.text(max_nb_chars=200)
        }
    
    def _generate_app_config(self, app_type: str) -> Dict[str, Any]:
        """Generate application configuration."""
        base_config = {
            'debug_mode': random.choice([True, False]),
            'log_level': random.choice(['DEBUG', 'INFO', 'WARN', 'ERROR']),
            'max_connections': random.randint(50, 1000)
        }
        
        type_configs = {
            'web_app': {
                'session_timeout': random.randint(300, 3600),
                'ssl_enabled': random.choice([True, False]),
                'cors_enabled': random.choice([True, False])
            },
            'database': {
                'max_pool_size': random.randint(10, 100),
                'connection_timeout': random.randint(5, 30),
                'auto_vacuum': random.choice([True, False])
            },
            'api_service': {
                'rate_limit': random.randint(100, 10000),
                'auth_required': random.choice([True, False]),
                'api_version': f"v{random.randint(1, 3)}"
            }
        }
        
        base_config.update(type_configs.get(app_type, {}))
        return base_config
    
    async def _apply_classification_markings(self, 
                                           content: Dict[str, Any], 
                                           classification: ClassificationLevel) -> Dict[str, Any]:
        """Apply classification markings to generated content."""
        if self.classification_engine:
            # Use the classification engine to apply proper markings
            # This would integrate with the existing enhanced classification engine
            pass
        
        # Basic classification marking
        content['classification_markings'] = {
            'level': classification.value,
            'marking': self._get_classification_marking(classification),
            'handling': self._get_handling_instructions(classification),
            'applied_at': datetime.now(timezone.utc).isoformat()
        }
        
        return content
    
    def _update_statistics(self, data_type: TestDataType, classification: ClassificationLevel) -> None:
        """Update generation statistics."""
        self.generation_statistics['total_generated'] += 1
        
        type_key = data_type.value
        self.generation_statistics['by_type'][type_key] = \
            self.generation_statistics['by_type'].get(type_key, 0) + 1
        
        class_key = classification.value
        self.generation_statistics['by_classification'][class_key] = \
            self.generation_statistics['by_classification'].get(class_key, 0) + 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generation statistics."""
        return self.generation_statistics.copy()
    
    def get_generated_data(self, data_id: str) -> Optional[GeneratedTestData]:
        """Retrieve generated test data by ID."""
        return self.generated_data.get(data_id)
    
    def list_generated_data(self, 
                          data_type: Optional[TestDataType] = None,
                          classification: Optional[ClassificationLevel] = None) -> List[GeneratedTestData]:
        """List generated test data with optional filtering."""
        results = []
        
        for data in self.generated_data.values():
            if data_type and data.data_type != data_type:
                continue
            if classification and data.classification != classification:
                continue
            results.append(data)
        
        return results
    
    async def cleanup_expired_data(self) -> int:
        """Clean up expired test data."""
        now = datetime.now(timezone.utc)
        expired_ids = []
        
        for data_id, data in self.generated_data.items():
            if data.expires_at and data.expires_at < now:
                expired_ids.append(data_id)
        
        for data_id in expired_ids:
            del self.generated_data[data_id]
            
            # Audit cleanup
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="test_data_cleanup",
                    data={'data_id': data_id, 'reason': 'expired'},
                    classification=ClassificationLevel.UNCLASSIFIED
                )
        
        logger.info(f"Cleaned up {len(expired_ids)} expired test data entries")
        return len(expired_ids)
    
    async def export_test_data(self, 
                             data_id: str, 
                             format: str = 'json') -> Optional[str]:
        """Export test data in specified format."""
        data = self.get_generated_data(data_id)
        if not data:
            return None
        
        if format.lower() == 'json':
            return json.dumps(asdict(data), indent=2, default=str)
        elif format.lower() == 'csv':
            # Implementation for CSV export would go here
            pass
        elif format.lower() == 'xml':
            # Implementation for XML export would go here  
            pass
        
        return None