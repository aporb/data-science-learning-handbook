"""
Advanced Result Filtering and Masking System
============================================

Comprehensive result filtering and masking system for classification-aware queries
with support for dynamic content redaction, field-level security, and context-aware masking.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Created: 2025-07-17
Version: 1.0
"""

import logging
import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Any, Union, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import threading
from collections import defaultdict
import copy

try:
    import pandas as pd
    import numpy as np
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from ...models.bell_lapadula import SecurityLabel, ClassificationLevel, NetworkDomain

# Configure logging
logger = logging.getLogger(__name__)


class FilterLevel(Enum):
    """Levels of result filtering intensity."""
    NONE = "NONE"
    MINIMAL = "MINIMAL"
    STANDARD = "STANDARD"
    STRICT = "STRICT"
    MAXIMUM = "MAXIMUM"


class RedactionStrategy(Enum):
    """Strategies for redacting sensitive content."""
    FULL_REDACTION = "FULL_REDACTION"
    PARTIAL_REDACTION = "PARTIAL_REDACTION"
    HASH_REPLACEMENT = "HASH_REPLACEMENT"
    TOKEN_REPLACEMENT = "TOKEN_REPLACEMENT"
    ENCRYPTION = "ENCRYPTION"
    SUPPRESSION = "SUPPRESSION"
    BLUR = "BLUR"
    GENERALIZATION = "GENERALIZATION"


class DataType(Enum):
    """Types of data for specialized handling."""
    TEXT = "TEXT"
    NUMERIC = "NUMERIC"
    DATE = "DATE"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    IP_ADDRESS = "IP_ADDRESS"
    GEOLOCATION = "GEOLOCATION"
    CLASSIFICATION_MARKING = "CLASSIFICATION_MARKING"


@dataclass
class FilterRule:
    """Rule for filtering and masking data."""
    rule_id: str
    name: str
    data_type: DataType
    classification_trigger: ClassificationLevel
    redaction_strategy: RedactionStrategy
    pattern: Optional[str] = None
    compartments: Set[str] = field(default_factory=set)
    caveats: Set[str] = field(default_factory=set)
    network_restrictions: Set[NetworkDomain] = field(default_factory=set)
    priority: int = 50
    active: bool = True
    context_dependent: bool = False
    
    def matches(self, data: Any, context: Dict[str, Any]) -> bool:
        """Check if rule matches the data and context."""
        if not self.active:
            return False
        
        # Check data type
        if self.data_type != DataType.TEXT and not self._matches_data_type(data):
            return False
        
        # Check pattern if specified
        if self.pattern and isinstance(data, str):
            if not re.search(self.pattern, data, re.IGNORECASE):
                return False
        
        # Check context dependencies
        if self.context_dependent:
            return self._matches_context(context)
        
        return True
    
    def _matches_data_type(self, data: Any) -> bool:
        """Check if data matches the expected type."""
        if self.data_type == DataType.NUMERIC:
            return isinstance(data, (int, float))
        elif self.data_type == DataType.DATE:
            return isinstance(data, datetime) or self._looks_like_date(str(data))
        elif self.data_type == DataType.EMAIL:
            return self._looks_like_email(str(data))
        elif self.data_type == DataType.PHONE:
            return self._looks_like_phone(str(data))
        elif self.data_type == DataType.SSN:
            return self._looks_like_ssn(str(data))
        elif self.data_type == DataType.CREDIT_CARD:
            return self._looks_like_credit_card(str(data))
        elif self.data_type == DataType.IP_ADDRESS:
            return self._looks_like_ip(str(data))
        else:
            return True
    
    def _looks_like_date(self, data: str) -> bool:
        """Check if string looks like a date."""
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',
            r'\d{2}/\d{2}/\d{4}',
            r'\d{2}-\d{2}-\d{4}'
        ]
        return any(re.search(pattern, data) for pattern in date_patterns)
    
    def _looks_like_email(self, data: str) -> bool:
        """Check if string looks like an email."""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return bool(re.search(email_pattern, data))
    
    def _looks_like_phone(self, data: str) -> bool:
        """Check if string looks like a phone number."""
        phone_pattern = r'(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
        return bool(re.search(phone_pattern, data))
    
    def _looks_like_ssn(self, data: str) -> bool:
        """Check if string looks like an SSN."""
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        return bool(re.search(ssn_pattern, data))
    
    def _looks_like_credit_card(self, data: str) -> bool:
        """Check if string looks like a credit card number."""
        cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        return bool(re.search(cc_pattern, data))
    
    def _looks_like_ip(self, data: str) -> bool:
        """Check if string looks like an IP address."""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, data))
    
    def _matches_context(self, context: Dict[str, Any]) -> bool:
        """Check if rule matches the current context."""
        # Check network restrictions
        if self.network_restrictions:
            current_network = context.get('network_domain')
            if current_network not in self.network_restrictions:
                return False
        
        # Check compartment requirements
        user_compartments = context.get('user_compartments', set())
        if self.compartments and not self.compartments.issubset(user_compartments):
            return False
        
        return True


@dataclass
class MaskingResult:
    """Result of masking operation."""
    original_data: Any
    masked_data: Any
    mask_applied: bool
    redaction_strategy: RedactionStrategy
    rules_applied: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TokenManager:
    """Manages tokenization and detokenization for sensitive data."""
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        self.token_map = {}
        self.reverse_token_map = {}
        self.token_counter = 0
        self.lock = threading.Lock()
        
        if CRYPTO_AVAILABLE and encryption_key:
            self.cipher = Fernet(encryption_key)
        else:
            self.cipher = None
    
    def tokenize(self, value: str) -> str:
        """Create a token for sensitive value."""
        with self.lock:
            if value in self.token_map:
                return self.token_map[value]
            
            token = f"TOKEN_{self.token_counter:08d}"
            self.token_counter += 1
            
            self.token_map[value] = token
            self.reverse_token_map[token] = value
            
            return token
    
    def detokenize(self, token: str) -> Optional[str]:
        """Retrieve original value from token."""
        with self.lock:
            return self.reverse_token_map.get(token)
    
    def encrypt_value(self, value: str) -> str:
        """Encrypt sensitive value."""
        if self.cipher:
            encrypted = self.cipher.encrypt(value.encode())
            return encrypted.decode()
        else:
            return hashlib.sha256(value.encode()).hexdigest()
    
    def decrypt_value(self, encrypted_value: str) -> Optional[str]:
        """Decrypt sensitive value."""
        if self.cipher:
            try:
                decrypted = self.cipher.decrypt(encrypted_value.encode())
                return decrypted.decode()
            except Exception:
                return None
        else:
            return None


class ContentRedactor:
    """Handles content redaction using various strategies."""
    
    def __init__(self, token_manager: TokenManager):
        self.token_manager = token_manager
        self.redaction_cache = {}
        self.cache_lock = threading.Lock()
    
    def redact_content(self, data: Any, strategy: RedactionStrategy, 
                      context: Dict[str, Any] = None) -> MaskingResult:
        """Apply redaction strategy to content."""
        context = context or {}
        
        # Check cache first
        cache_key = self._generate_cache_key(data, strategy, context)
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            return cached_result
        
        # Apply redaction strategy
        if strategy == RedactionStrategy.FULL_REDACTION:
            result = self._full_redaction(data, context)
        elif strategy == RedactionStrategy.PARTIAL_REDACTION:
            result = self._partial_redaction(data, context)
        elif strategy == RedactionStrategy.HASH_REPLACEMENT:
            result = self._hash_replacement(data, context)
        elif strategy == RedactionStrategy.TOKEN_REPLACEMENT:
            result = self._token_replacement(data, context)
        elif strategy == RedactionStrategy.ENCRYPTION:
            result = self._encryption(data, context)
        elif strategy == RedactionStrategy.SUPPRESSION:
            result = self._suppression(data, context)
        elif strategy == RedactionStrategy.BLUR:
            result = self._blur(data, context)
        elif strategy == RedactionStrategy.GENERALIZATION:
            result = self._generalization(data, context)
        else:
            result = MaskingResult(data, data, False, strategy)
        
        # Cache result
        self._cache_result(cache_key, result)
        
        return result
    
    def _full_redaction(self, data: Any, context: Dict[str, Any]) -> MaskingResult:
        """Apply full redaction - replace with [REDACTED]."""
        if isinstance(data, str):
            masked_data = "[REDACTED]"
        elif isinstance(data, (int, float)):
            masked_data = 0
        elif isinstance(data, bool):
            masked_data = False
        else:
            masked_data = "[REDACTED]"
        
        return MaskingResult(
            original_data=data,
            masked_data=masked_data,
            mask_applied=True,
            redaction_strategy=RedactionStrategy.FULL_REDACTION
        )
    
    def _partial_redaction(self, data: Any, context: Dict[str, Any]) -> MaskingResult:
        """Apply partial redaction - show beginning and end."""
        if isinstance(data, str) and len(data) > 6:
            masked_data = data[:2] + "*" * (len(data) - 4) + data[-2:]
        else:
            masked_data = "*" * len(str(data))
        
        return MaskingResult(
            original_data=data,
            masked_data=masked_data,
            mask_applied=True,
            redaction_strategy=RedactionStrategy.PARTIAL_REDACTION
        )
    
    def _hash_replacement(self, data: Any, context: Dict[str, Any]) -> MaskingResult:
        """Replace with hash of original data."""
        hash_value = hashlib.sha256(str(data).encode()).hexdigest()[:8]
        masked_data = f"HASH_{hash_value}"
        
        return MaskingResult(
            original_data=data,
            masked_data=masked_data,
            mask_applied=True,
            redaction_strategy=RedactionStrategy.HASH_REPLACEMENT
        )
    
    def _token_replacement(self, data: Any, context: Dict[str, Any]) -> MaskingResult:
        """Replace with reversible token."""
        token = self.token_manager.tokenize(str(data))
        
        return MaskingResult(
            original_data=data,
            masked_data=token,
            mask_applied=True,
            redaction_strategy=RedactionStrategy.TOKEN_REPLACEMENT
        )
    
    def _encryption(self, data: Any, context: Dict[str, Any]) -> MaskingResult:
        """Encrypt the data."""
        encrypted_data = self.token_manager.encrypt_value(str(data))
        
        return MaskingResult(
            original_data=data,
            masked_data=encrypted_data,
            mask_applied=True,
            redaction_strategy=RedactionStrategy.ENCRYPTION
        )
    
    def _suppression(self, data: Any, context: Dict[str, Any]) -> MaskingResult:
        """Suppress the data completely."""
        return MaskingResult(
            original_data=data,
            masked_data=None,
            mask_applied=True,
            redaction_strategy=RedactionStrategy.SUPPRESSION
        )
    
    def _blur(self, data: Any, context: Dict[str, Any]) -> MaskingResult:
        """Apply blur effect to numeric data."""
        if isinstance(data, (int, float)):
            # Add noise to numeric data
            noise_factor = 0.1
            noise = np.random.normal(0, abs(data) * noise_factor)
            masked_data = data + noise
        else:
            masked_data = self._partial_redaction(data, context).masked_data
        
        return MaskingResult(
            original_data=data,
            masked_data=masked_data,
            mask_applied=True,
            redaction_strategy=RedactionStrategy.BLUR
        )
    
    def _generalization(self, data: Any, context: Dict[str, Any]) -> MaskingResult:
        """Generalize the data to reduce specificity."""
        if isinstance(data, str):
            # Example: Replace specific values with categories
            if self._looks_like_email(data):
                masked_data = "[EMAIL_ADDRESS]"
            elif self._looks_like_phone(data):
                masked_data = "[PHONE_NUMBER]"
            elif self._looks_like_date(data):
                masked_data = "[DATE]"
            else:
                masked_data = "[TEXT]"
        elif isinstance(data, (int, float)):
            # Round to nearest range
            if data < 100:
                masked_data = "< 100"
            elif data < 1000:
                masked_data = "100-1000"
            else:
                masked_data = "> 1000"
        else:
            masked_data = "[DATA]"
        
        return MaskingResult(
            original_data=data,
            masked_data=masked_data,
            mask_applied=True,
            redaction_strategy=RedactionStrategy.GENERALIZATION
        )
    
    def _looks_like_email(self, data: str) -> bool:
        """Check if string looks like an email."""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return bool(re.search(email_pattern, data))
    
    def _looks_like_phone(self, data: str) -> bool:
        """Check if string looks like a phone number."""
        phone_pattern = r'(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
        return bool(re.search(phone_pattern, data))
    
    def _looks_like_date(self, data: str) -> bool:
        """Check if string looks like a date."""
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',
            r'\d{2}/\d{2}/\d{4}',
            r'\d{2}-\d{2}-\d{4}'
        ]
        return any(re.search(pattern, data) for pattern in date_patterns)
    
    def _generate_cache_key(self, data: Any, strategy: RedactionStrategy, 
                           context: Dict[str, Any]) -> str:
        """Generate cache key for redaction result."""
        cache_data = {
            'data_hash': hashlib.md5(str(data).encode()).hexdigest(),
            'strategy': strategy.value,
            'context_hash': hashlib.md5(str(sorted(context.items())).encode()).hexdigest()
        }
        return hashlib.md5(json.dumps(cache_data, sort_keys=True).encode()).hexdigest()
    
    def _get_cached_result(self, cache_key: str) -> Optional[MaskingResult]:
        """Get cached redaction result."""
        with self.cache_lock:
            return self.redaction_cache.get(cache_key)
    
    def _cache_result(self, cache_key: str, result: MaskingResult):
        """Cache redaction result."""
        with self.cache_lock:
            self.redaction_cache[cache_key] = result
            
            # Simple cache size management
            if len(self.redaction_cache) > 1000:
                # Remove oldest entries (simple FIFO)
                oldest_keys = list(self.redaction_cache.keys())[:100]
                for key in oldest_keys:
                    del self.redaction_cache[key]


class FieldLevelSecurityManager:
    """Manages field-level security and access controls."""
    
    def __init__(self):
        self.field_security_rules = {}
        self.field_classifications = {}
        self.access_matrix = {}
        self.lock = threading.Lock()
    
    def register_field_security(self, field_path: str, classification: SecurityLabel, 
                              access_rules: List[str]):
        """Register security configuration for a field."""
        with self.lock:
            self.field_classifications[field_path] = classification
            self.field_security_rules[field_path] = access_rules
    
    def get_field_classification(self, field_path: str) -> Optional[SecurityLabel]:
        """Get classification for a specific field."""
        with self.lock:
            return self.field_classifications.get(field_path)
    
    def can_access_field(self, field_path: str, user_clearance: SecurityLabel, 
                        context: Dict[str, Any]) -> bool:
        """Check if user can access specific field."""
        field_classification = self.get_field_classification(field_path)
        
        if not field_classification:
            return True  # No restrictions if not classified
        
        # Check Bell-LaPadula rules
        if not user_clearance.dominates(field_classification):
            return False
        
        # Check additional access rules
        with self.lock:
            access_rules = self.field_security_rules.get(field_path, [])
            return self._evaluate_access_rules(access_rules, context)
    
    def _evaluate_access_rules(self, rules: List[str], context: Dict[str, Any]) -> bool:
        """Evaluate additional access rules."""
        for rule in rules:
            if rule == "NEED_TO_KNOW":
                if not context.get('need_to_know_approved', False):
                    return False
            elif rule == "EXECUTIVE_ACCESS_ONLY":
                if not context.get('executive_access', False):
                    return False
            elif rule == "AUDIT_REQUIRED":
                if not context.get('audit_logged', False):
                    return False
        
        return True


class AdvancedResultFilter:
    """
    Advanced result filtering and masking system for classification-aware queries.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the advanced result filter.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Initialize components
        encryption_key = self.config.get('encryption_key')
        self.token_manager = TokenManager(encryption_key)
        self.content_redactor = ContentRedactor(self.token_manager)
        self.field_security_manager = FieldLevelSecurityManager()
        
        # Load filter rules
        self.filter_rules = self._load_filter_rules()
        
        # Filter settings
        self.default_filter_level = FilterLevel(
            self.config.get('default_filter_level', FilterLevel.STANDARD.value)
        )
        
        # Performance tracking
        self.filter_metrics = defaultdict(list)
        self.metrics_lock = threading.Lock()
    
    def _load_filter_rules(self) -> List[FilterRule]:
        """Load default filter rules."""
        rules = [
            # SSN filtering
            FilterRule(
                rule_id="ssn_filter",
                name="Social Security Number Filter",
                data_type=DataType.SSN,
                classification_trigger=ClassificationLevel.CONFIDENTIAL,
                redaction_strategy=RedactionStrategy.HASH_REPLACEMENT,
                pattern=r'\b\d{3}-\d{2}-\d{4}\b',
                compartments={'PII'},
                priority=90
            ),
            
            # Credit card filtering
            FilterRule(
                rule_id="credit_card_filter",
                name="Credit Card Filter",
                data_type=DataType.CREDIT_CARD,
                classification_trigger=ClassificationLevel.CONFIDENTIAL,
                redaction_strategy=RedactionStrategy.TOKEN_REPLACEMENT,
                pattern=r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                compartments={'PII', 'FINANCIAL'},
                priority=90
            ),
            
            # Email filtering
            FilterRule(
                rule_id="email_filter",
                name="Email Address Filter",
                data_type=DataType.EMAIL,
                classification_trigger=ClassificationLevel.UNCLASSIFIED,
                redaction_strategy=RedactionStrategy.PARTIAL_REDACTION,
                pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                compartments={'PII'},
                priority=70
            ),
            
            # Classification marking filter
            FilterRule(
                rule_id="classification_marking_filter",
                name="Classification Marking Filter",
                data_type=DataType.CLASSIFICATION_MARKING,
                classification_trigger=ClassificationLevel.SECRET,
                redaction_strategy=RedactionStrategy.FULL_REDACTION,
                pattern=r'\b(SECRET|CONFIDENTIAL|TOP SECRET|CLASSIFIED)\b',
                priority=100
            ),
            
            # Phone number filtering
            FilterRule(
                rule_id="phone_filter",
                name="Phone Number Filter",
                data_type=DataType.PHONE,
                classification_trigger=ClassificationLevel.CONFIDENTIAL,
                redaction_strategy=RedactionStrategy.BLUR,
                pattern=r'(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
                compartments={'PII'},
                priority=80
            ),
            
            # IP address filtering
            FilterRule(
                rule_id="ip_filter",
                name="IP Address Filter",
                data_type=DataType.IP_ADDRESS,
                classification_trigger=ClassificationLevel.CONFIDENTIAL,
                redaction_strategy=RedactionStrategy.GENERALIZATION,
                pattern=r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                compartments={'NETWORK'},
                priority=75
            )
        ]
        
        return rules
    
    def filter_result(self, data: Any, user_clearance: SecurityLabel, 
                     data_classification: SecurityLabel, 
                     context: Dict[str, Any] = None) -> Tuple[Any, Dict[str, Any]]:
        """
        Filter and mask query results based on user clearance and data classification.
        
        Args:
            data: Query result data
            user_clearance: User's security clearance
            data_classification: Classification of the data
            context: Additional context information
            
        Returns:
            Tuple of (filtered_data, filter_metadata)
        """
        context = context or {}
        start_time = datetime.now()
        
        # Determine filter level
        filter_level = self._determine_filter_level(user_clearance, data_classification, context)
        
        # Initialize filter metadata
        filter_metadata = {
            'filter_level': filter_level.value,
            'rules_applied': [],
            'fields_masked': [],
            'records_suppressed': 0,
            'redaction_strategies': []
        }
        
        # Apply filtering based on data type
        if PANDAS_AVAILABLE and isinstance(data, pd.DataFrame):
            filtered_data = self._filter_dataframe(data, user_clearance, data_classification, 
                                                 filter_level, context, filter_metadata)
        elif isinstance(data, list):
            filtered_data = self._filter_list(data, user_clearance, data_classification, 
                                            filter_level, context, filter_metadata)
        elif isinstance(data, dict):
            filtered_data = self._filter_dict(data, user_clearance, data_classification, 
                                            filter_level, context, filter_metadata)
        else:
            filtered_data = self._filter_scalar(data, user_clearance, data_classification, 
                                              filter_level, context, filter_metadata)
        
        # Record performance metrics
        execution_time = (datetime.now() - start_time).total_seconds()
        self._record_filter_metrics(filter_level, execution_time, filter_metadata)
        
        return filtered_data, filter_metadata
    
    def _determine_filter_level(self, user_clearance: SecurityLabel, 
                               data_classification: SecurityLabel, 
                               context: Dict[str, Any]) -> FilterLevel:
        """Determine appropriate filter level based on clearance and classification."""
        # Check if user has sufficient clearance
        if not user_clearance.dominates(data_classification):
            return FilterLevel.MAXIMUM
        
        # Check network domain restrictions
        network_domain = context.get('network_domain', NetworkDomain.NIPR)
        if network_domain == NetworkDomain.NIPR and data_classification.classification > ClassificationLevel.UNCLASSIFIED:
            return FilterLevel.STRICT
        
        # Check compartment access
        missing_compartments = data_classification.compartments - user_clearance.compartments
        if missing_compartments:
            return FilterLevel.STRICT
        
        # Check for special access requirements
        if data_classification.caveats:
            return FilterLevel.STANDARD
        
        return self.default_filter_level
    
    def _filter_dataframe(self, df: 'pd.DataFrame', user_clearance: SecurityLabel, 
                         data_classification: SecurityLabel, filter_level: FilterLevel, 
                         context: Dict[str, Any], metadata: Dict[str, Any]) -> 'pd.DataFrame':
        """Filter pandas DataFrame."""
        filtered_df = df.copy()
        
        # Apply row-level filtering
        if filter_level == FilterLevel.MAXIMUM:
            # Return empty DataFrame with same structure
            filtered_df = pd.DataFrame(columns=df.columns)
            metadata['records_suppressed'] = len(df)
            return filtered_df
        
        # Apply column-level filtering
        for column in df.columns:
            column_path = f"column.{column}"
            
            # Check field-level security
            if not self.field_security_manager.can_access_field(column_path, user_clearance, context):
                filtered_df = filtered_df.drop(columns=[column])
                metadata['fields_masked'].append(column)
                continue
            
            # Apply content filtering to column
            filtered_df[column] = filtered_df[column].apply(
                lambda x: self._filter_cell_value(x, user_clearance, data_classification, 
                                                filter_level, context, metadata)
            )
        
        # Apply row-level suppression based on filter rules
        if filter_level in [FilterLevel.STRICT, FilterLevel.MAXIMUM]:
            # Remove rows that might cause inference issues
            original_length = len(filtered_df)
            filtered_df = self._apply_row_suppression(filtered_df, context)
            metadata['records_suppressed'] = original_length - len(filtered_df)
        
        return filtered_df
    
    def _filter_list(self, data: List[Any], user_clearance: SecurityLabel, 
                    data_classification: SecurityLabel, filter_level: FilterLevel, 
                    context: Dict[str, Any], metadata: Dict[str, Any]) -> List[Any]:
        """Filter list data."""
        if filter_level == FilterLevel.MAXIMUM:
            metadata['records_suppressed'] = len(data)
            return []
        
        filtered_data = []
        for i, item in enumerate(data):
            filtered_item = self._filter_item(item, user_clearance, data_classification, 
                                            filter_level, context, metadata, f"item_{i}")
            if filtered_item is not None:  # None indicates suppression
                filtered_data.append(filtered_item)
            else:
                metadata['records_suppressed'] += 1
        
        return filtered_data
    
    def _filter_dict(self, data: Dict[str, Any], user_clearance: SecurityLabel, 
                    data_classification: SecurityLabel, filter_level: FilterLevel, 
                    context: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Filter dictionary data."""
        if filter_level == FilterLevel.MAXIMUM:
            metadata['records_suppressed'] = len(data)
            return {}
        
        filtered_data = {}
        for key, value in data.items():
            field_path = f"field.{key}"
            
            # Check field-level security
            if not self.field_security_manager.can_access_field(field_path, user_clearance, context):
                metadata['fields_masked'].append(key)
                continue
            
            filtered_value = self._filter_item(value, user_clearance, data_classification, 
                                             filter_level, context, metadata, field_path)
            if filtered_value is not None:
                filtered_data[key] = filtered_value
            else:
                metadata['fields_masked'].append(key)
        
        return filtered_data
    
    def _filter_scalar(self, data: Any, user_clearance: SecurityLabel, 
                      data_classification: SecurityLabel, filter_level: FilterLevel, 
                      context: Dict[str, Any], metadata: Dict[str, Any]) -> Any:
        """Filter scalar data."""
        if filter_level == FilterLevel.MAXIMUM:
            metadata['records_suppressed'] = 1
            return None
        
        return self._filter_cell_value(data, user_clearance, data_classification, 
                                     filter_level, context, metadata)
    
    def _filter_item(self, item: Any, user_clearance: SecurityLabel, 
                    data_classification: SecurityLabel, filter_level: FilterLevel, 
                    context: Dict[str, Any], metadata: Dict[str, Any], 
                    path: str) -> Any:
        """Filter individual item."""
        if isinstance(item, dict):
            return self._filter_dict(item, user_clearance, data_classification, 
                                   filter_level, context, metadata)
        elif isinstance(item, list):
            return self._filter_list(item, user_clearance, data_classification, 
                                   filter_level, context, metadata)
        else:
            return self._filter_cell_value(item, user_clearance, data_classification, 
                                         filter_level, context, metadata)
    
    def _filter_cell_value(self, value: Any, user_clearance: SecurityLabel, 
                          data_classification: SecurityLabel, filter_level: FilterLevel, 
                          context: Dict[str, Any], metadata: Dict[str, Any]) -> Any:
        """Filter individual cell value."""
        if value is None:
            return None
        
        # Find applicable filter rules
        applicable_rules = self._find_applicable_rules(value, user_clearance, 
                                                     data_classification, context)
        
        if not applicable_rules:
            return value
        
        # Apply highest priority rule
        rule = max(applicable_rules, key=lambda r: r.priority)
        
        # Apply redaction
        redaction_result = self.content_redactor.redact_content(
            value, rule.redaction_strategy, context
        )
        
        # Update metadata
        if redaction_result.mask_applied:
            metadata['rules_applied'].append(rule.rule_id)
            metadata['redaction_strategies'].append(rule.redaction_strategy.value)
        
        return redaction_result.masked_data
    
    def _find_applicable_rules(self, value: Any, user_clearance: SecurityLabel, 
                              data_classification: SecurityLabel, 
                              context: Dict[str, Any]) -> List[FilterRule]:
        """Find filter rules applicable to the value."""
        applicable_rules = []
        
        for rule in self.filter_rules:
            # Check if rule applies based on classification
            if user_clearance.classification < rule.classification_trigger:
                if rule.matches(value, context):
                    applicable_rules.append(rule)
            
            # Check compartment restrictions
            if rule.compartments and not rule.compartments.issubset(user_clearance.compartments):
                if rule.matches(value, context):
                    applicable_rules.append(rule)
        
        return applicable_rules
    
    def _apply_row_suppression(self, df: 'pd.DataFrame', context: Dict[str, Any]) -> 'pd.DataFrame':
        """Apply row-level suppression to prevent inference."""
        # Simple implementation - in practice, this would be more sophisticated
        if len(df) < 5:  # Minimum group size
            return pd.DataFrame(columns=df.columns)
        
        # Remove rows that might enable inference
        # This is a simplified example
        return df.head(int(len(df) * 0.9))  # Remove 10% of rows
    
    def _record_filter_metrics(self, filter_level: FilterLevel, execution_time: float, 
                              metadata: Dict[str, Any]):
        """Record filter performance metrics."""
        with self.metrics_lock:
            metrics = self.filter_metrics[filter_level.value]
            metrics.append({
                'execution_time': execution_time,
                'timestamp': datetime.now(),
                'rules_applied': len(metadata['rules_applied']),
                'fields_masked': len(metadata['fields_masked']),
                'records_suppressed': metadata['records_suppressed']
            })
            
            # Keep only recent metrics
            if len(metrics) > 1000:
                metrics.pop(0)
    
    def add_filter_rule(self, rule: FilterRule):
        """Add a new filter rule."""
        self.filter_rules.append(rule)
        self.filter_rules.sort(key=lambda r: r.priority, reverse=True)
    
    def remove_filter_rule(self, rule_id: str):
        """Remove a filter rule."""
        self.filter_rules = [r for r in self.filter_rules if r.rule_id != rule_id]
    
    def get_filter_rules(self) -> List[FilterRule]:
        """Get all filter rules."""
        return self.filter_rules.copy()
    
    def get_filter_metrics(self) -> Dict[str, Any]:
        """Get filter performance metrics."""
        with self.metrics_lock:
            metrics_summary = {}
            
            for filter_level, metrics in self.filter_metrics.items():
                if metrics:
                    execution_times = [m['execution_time'] for m in metrics]
                    metrics_summary[filter_level] = {
                        'avg_execution_time': sum(execution_times) / len(execution_times),
                        'max_execution_time': max(execution_times),
                        'min_execution_time': min(execution_times),
                        'total_filters': len(execution_times),
                        'avg_rules_applied': sum(m['rules_applied'] for m in metrics) / len(metrics),
                        'avg_fields_masked': sum(m['fields_masked'] for m in metrics) / len(metrics)
                    }
            
            return metrics_summary
    
    def clear_cache(self):
        """Clear all caches."""
        self.content_redactor.redaction_cache.clear()
        logger.info("Filter caches cleared")


# Utility functions for external integration

def create_result_filter(config_path: Optional[str] = None) -> AdvancedResultFilter:
    """Create and configure an advanced result filter."""
    config = {}
    
    if config_path:
        with open(config_path, 'r') as f:
            config = json.load(f)
    
    return AdvancedResultFilter(config)


def filter_query_result(data: Any, user_clearance: SecurityLabel, 
                       data_classification: SecurityLabel, 
                       context: Dict[str, Any] = None) -> Tuple[Any, Dict[str, Any]]:
    """Filter query result with default settings."""
    filter_engine = create_result_filter()
    return filter_engine.filter_result(data, user_clearance, data_classification, context)


# Example usage
def example_usage():
    """Demonstrate advanced result filter usage."""
    # Create filter
    filter_engine = create_result_filter()
    
    # Create sample data
    if PANDAS_AVAILABLE:
        sample_data = pd.DataFrame({
            'id': [1, 2, 3, 4, 5],
            'name': ['John Doe', 'Jane Smith', 'Bob Johnson', 'Alice Brown', 'Charlie Davis'],
            'email': ['john@example.com', 'jane@example.com', 'bob@example.com', 'alice@example.com', 'charlie@example.com'],
            'ssn': ['123-45-6789', '987-65-4321', '555-44-3333', '111-22-3333', '999-88-7777'],
            'salary': [50000, 60000, 55000, 65000, 70000],
            'classification': ['U', 'C', 'U', 'S', 'C']
        })
    else:
        sample_data = {
            'records': [
                {'id': 1, 'name': 'John Doe', 'email': 'john@example.com', 'ssn': '123-45-6789'},
                {'id': 2, 'name': 'Jane Smith', 'email': 'jane@example.com', 'ssn': '987-65-4321'}
            ]
        }
    
    # Create user clearance
    user_clearance = SecurityLabel(
        classification=ClassificationLevel.CONFIDENTIAL,
        compartments={'PII'},
        caveats=set()
    )
    
    # Create data classification
    data_classification = SecurityLabel(
        classification=ClassificationLevel.SECRET,
        compartments={'PII'},
        caveats=set()
    )
    
    # Create context
    context = {
        'network_domain': NetworkDomain.SIPR,
        'user_compartments': {'PII'},
        'need_to_know_approved': True
    }
    
    # Filter result
    try:
        filtered_data, metadata = filter_engine.filter_result(
            sample_data, user_clearance, data_classification, context
        )
        
        print(f"Filter level: {metadata['filter_level']}")
        print(f"Rules applied: {metadata['rules_applied']}")
        print(f"Fields masked: {metadata['fields_masked']}")
        print(f"Records suppressed: {metadata['records_suppressed']}")
        print(f"Redaction strategies: {metadata['redaction_strategies']}")
        
        if PANDAS_AVAILABLE and isinstance(filtered_data, pd.DataFrame):
            print(f"Filtered data shape: {filtered_data.shape}")
            print(filtered_data.head())
        else:
            print(f"Filtered data: {filtered_data}")
    
    except Exception as e:
        print(f"Filtering failed: {e}")


if __name__ == "__main__":
    example_usage()