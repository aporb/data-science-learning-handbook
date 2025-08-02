"""
Pattern-based Data Spillage Detection System
===========================================

This module provides comprehensive pattern-based detection capabilities for identifying
sensitive data patterns in unauthorized locations. It integrates with the real-time
spillage detection engine to provide specialized pattern matching and content analysis
for DoD classification and security requirements.

Key Features:
- Advanced regex-based pattern matching for classification markings
- NLP-powered content analysis for contextual spillage detection
- File format-specific pattern detection (documents, emails, databases)
- Cross-reference analysis with authorized location mappings
- Real-time content scanning with <50ms processing targets
- Integration with automated data labeling and classification systems

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Initial Implementation
Author: Security Compliance Team
Date: 2025-07-29
"""

import asyncio
import json
import logging
import time
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Pattern
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import numpy as np
from threading import Lock
import aiofiles
from collections import defaultdict, deque
import mimetypes
import base64

# NLP and content analysis
try:
    import spacy
    from spacy.matcher import Matcher
    NLP_AVAILABLE = True
except ImportError:
    NLP_AVAILABLE = False
    spacy = None
    Matcher = None

# Document processing
try:
    import python_docx
    import pypdf2
    import openpyxl
    DOCUMENT_PROCESSING_AVAILABLE = True
except ImportError:
    DOCUMENT_PROCESSING_AVAILABLE = False

# Import existing infrastructure
from .spillage_detection_engine import (
    SpillageEvent, SpillageEventType, SpillageRiskLevel, DetectionMethod
)
from .enhanced_classification_engine import ClassificationLevel
from .models.bell_lapadula import NetworkDomain
from .automated_data_labeler import AutomatedDataLabeler


class PatternType(Enum):
    """Types of patterns that can be detected"""
    CLASSIFICATION_MARKING = "classification_marking"
    PII_PATTERN = "pii_pattern"
    PROPRIETARY_MARKING = "proprietary_marking"
    CONTROL_MARKING = "control_marking"
    FOREIGN_DISCLOSURE = "foreign_disclosure"
    COMPARTMENTED_INFO = "compartmented_info"
    CAVEAT_MARKING = "caveat_marking"
    HANDLING_INSTRUCTION = "handling_instruction"
    SIGNATURE_BLOCK = "signature_block"
    DOCUMENT_METADATA = "document_metadata"


class ContentType(Enum):
    """Types of content being analyzed"""
    PLAIN_TEXT = "plain_text"
    HTML = "html"
    XML = "xml"
    JSON = "json"
    EMAIL = "email"
    DOCUMENT = "document"
    SPREADSHEET = "spreadsheet"
    PRESENTATION = "presentation"
    PDF = "pdf"
    IMAGE = "image"
    DATABASE = "database"
    BINARY = "binary"


class LocationType(Enum):
    """Types of locations where content is found"""
    FILE_SYSTEM = "file_system"
    DATABASE = "database"
    EMAIL_SYSTEM = "email_system"
    WEB_APPLICATION = "web_application"
    CLOUD_STORAGE = "cloud_storage"
    REMOVABLE_MEDIA = "removable_media"
    NETWORK_SHARE = "network_share"
    COLLABORATION_TOOL = "collaboration_tool"
    VERSION_CONTROL = "version_control"
    BACKUP_SYSTEM = "backup_system"


@dataclass
class PatternMatch:
    """Represents a detected pattern match"""
    match_id: str = field(default_factory=lambda: str(uuid4()))
    pattern_type: PatternType = PatternType.CLASSIFICATION_MARKING
    pattern_name: str = ""
    
    # Match details
    content_snippet: str = ""
    full_match: str = ""
    start_position: int = 0
    end_position: int = 0
    line_number: Optional[int] = None
    
    # Context information
    surrounding_context: str = ""
    confidence_score: float = 0.0
    severity_score: float = 0.0
    
    # Classification details
    detected_classification: Optional[ClassificationLevel] = None
    expected_classification: Optional[ClassificationLevel] = None
    classification_mismatch: bool = False
    
    # Location context
    location_type: LocationType = LocationType.FILE_SYSTEM
    location_path: str = ""
    authorized_location: bool = False
    
    # Processing metadata
    detection_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    processing_time_ms: float = 0.0


@dataclass
class PatternRule:
    """Configuration for pattern detection rules"""
    rule_id: str
    rule_name: str
    pattern_type: PatternType
    
    # Pattern definition
    regex_pattern: str
    case_sensitive: bool = False
    multiline: bool = False
    word_boundary: bool = True
    
    # Context requirements
    required_context: List[str] = field(default_factory=list)
    forbidden_context: List[str] = field(default_factory=list)
    context_window_size: int = 200
    
    # Classification mapping
    classification_mapping: Dict[str, ClassificationLevel] = field(default_factory=dict)
    default_classification: Optional[ClassificationLevel] = None
    
    # Risk assessment
    base_risk_level: SpillageRiskLevel = SpillageRiskLevel.MEDIUM
    risk_multipliers: Dict[str, float] = field(default_factory=dict)
    
    # Rule metadata
    enabled: bool = True
    priority: int = 100
    description: str = ""
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    match_count: int = 0


@dataclass
class LocationMapping:
    """Mapping of authorized locations for different classification levels"""
    location_id: str
    location_type: LocationType
    location_path: str
    
    # Authorization details
    authorized_classifications: Set[ClassificationLevel] = field(default_factory=set)
    authorized_networks: Set[NetworkDomain] = field(default_factory=set)
    authorized_users: Set[str] = field(default_factory=set)
    authorized_roles: Set[str] = field(default_factory=set)
    
    # Restrictions
    time_restrictions: Dict[str, Any] = field(default_factory=dict)
    access_controls: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    created_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_verified: Optional[datetime] = None
    verification_required: bool = True


class SpillagePatternDetector:
    """
    Advanced pattern-based detection system for identifying sensitive data patterns
    in unauthorized locations.
    
    This detector provides:
    - Comprehensive pattern matching for classification markings and sensitive content
    - Context-aware analysis to reduce false positives
    - Integration with location authorization mappings
    - Support for multiple content types and formats
    - Real-time processing with performance optimization
    """
    
    def __init__(
        self,
        data_labeler: AutomatedDataLabeler,
        config: Dict[str, Any] = None
    ):
        """Initialize the pattern detector"""
        self.data_labeler = data_labeler
        self.config = config or {}
        
        # Processing configuration
        self.max_content_size = self.config.get('max_content_size', 10 * 1024 * 1024)  # 10MB
        self.context_window_size = self.config.get('context_window_size', 200)
        self.max_matches_per_content = self.config.get('max_matches_per_content', 100)
        self.processing_timeout_seconds = self.config.get('processing_timeout_seconds', 30)
        
        # Pattern rules and mappings
        self.pattern_rules = {}
        self.location_mappings = {}
        self.compiled_patterns = {}
        
        # NLP components
        self.nlp_model = None
        self.matcher = None
        if NLP_AVAILABLE:
            self._init_nlp_components()
        
        # Performance tracking
        self.metrics = {
            'patterns_processed': 0,
            'matches_found': 0,
            'false_positives': 0,
            'processing_time_total': 0.0,
            'average_processing_time': 0.0,
            'last_updated': datetime.now(timezone.utc)
        }
        
        # Thread pool for intensive operations
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.config.get('max_worker_threads', 5),
            thread_name_prefix='pattern_detection'
        )
        
        # Caching for performance
        self.pattern_cache = {}
        self.cache_max_size = self.config.get('cache_max_size', 1000)
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("SpillagePatternDetector initialized")
        
        # Initialize default patterns
        asyncio.create_task(self._initialize_default_patterns())
    
    def _init_nlp_components(self):
        """Initialize NLP components if available"""
        try:
            # Load English model (install with: python -m spacy download en_core_web_sm)
            self.nlp_model = spacy.load("en_core_web_sm")
            self.matcher = Matcher(self.nlp_model.vocab)
            
            # Add custom patterns for classification markings
            self._add_nlp_patterns()
            
            self.logger.info("NLP components initialized successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to initialize NLP components: {e}")
            self.nlp_model = None
            self.matcher = None
    
    def _add_nlp_patterns(self):
        """Add NLP patterns for better context understanding"""
        if not self.matcher:
            return
        
        try:
            # Classification marking patterns
            classification_patterns = [
                [{"LOWER": "classified"}, {"LOWER": "by"}],
                [{"LOWER": "secret"}, {"ORTH": "//"}, {"LOWER": "noforn"}],
                [{"LOWER": "top"}, {"LOWER": "secret"}, {"ORTH": "//"}, {"LOWER": "sci"}],
                [{"LOWER": "confidential"}, {"ORTH": "//"}, {"LOWER": "rel"}]
            ]
            
            self.matcher.add("CLASSIFICATION_CONTEXT", classification_patterns)
            
            # Control marking patterns
            control_patterns = [
                [{"LOWER": "for"}, {"LOWER": "official"}, {"LOWER": "use"}, {"LOWER": "only"}],
                [{"LOWER": "controlled"}, {"LOWER": "unclassified"}, {"LOWER": "information"}],
                [{"LOWER": "law"}, {"LOWER": "enforcement"}, {"LOWER": "sensitive"}]
            ]
            
            self.matcher.add("CONTROL_MARKINGS", control_patterns)
            
        except Exception as e:
            self.logger.error(f"Error adding NLP patterns: {e}")
    
    async def _initialize_default_patterns(self):
        """Initialize default pattern rules"""
        try:
            default_patterns = [
                # Classification markings
                PatternRule(
                    rule_id="secret_marking",
                    rule_name="SECRET Classification Marking",
                    pattern_type=PatternType.CLASSIFICATION_MARKING,
                    regex_pattern=r'\b(?:SECRET(?:\s*//\s*(?:NOFORN|REL\s+TO\s+[A-Z,\s]+|ORCON|IMCON))?)\b',
                    case_sensitive=False,
                    classification_mapping={"SECRET": ClassificationLevel.SECRET},
                    base_risk_level=SpillageRiskLevel.CRITICAL,
                    description="Detects SECRET classification markings with handling caveats"
                ),
                PatternRule(
                    rule_id="top_secret_marking",
                    rule_name="TOP SECRET Classification Marking",
                    pattern_type=PatternType.CLASSIFICATION_MARKING,
                    regex_pattern=r'\b(?:TOP\s+SECRET(?:\s*//\s*(?:SCI|TK|SI|COMINT|HCS|ORCON|NOFORN|REL\s+TO\s+[A-Z,\s]+))?)\b',
                    case_sensitive=False,
                    classification_mapping={"TOP SECRET": ClassificationLevel.TOP_SECRET},
                    base_risk_level=SpillageRiskLevel.CRITICAL,
                    description="Detects TOP SECRET classification markings with SCI and other caveats"
                ),
                PatternRule(
                    rule_id="confidential_marking",
                    rule_name="CONFIDENTIAL Classification Marking",
                    pattern_type=PatternType.CLASSIFICATION_MARKING,
                    regex_pattern=r'\b(?:CONFIDENTIAL(?:\s*//\s*(?:NOFORN|REL\s+TO\s+[A-Z,\s]+|ORCON))?)\b',
                    case_sensitive=False,
                    classification_mapping={"CONFIDENTIAL": ClassificationLevel.CONFIDENTIAL},
                    base_risk_level=SpillageRiskLevel.HIGH,
                    description="Detects CONFIDENTIAL classification markings"
                ),
                # Control markings
                PatternRule(
                    rule_id="fouo_marking",
                    rule_name="For Official Use Only Marking",
                    pattern_type=PatternType.CONTROL_MARKING,
                    regex_pattern=r'\b(?:FOR\s+OFFICIAL\s+USE\s+ONLY|FOUO)\b',
                    case_sensitive=False,
                    classification_mapping={"FOUO": ClassificationLevel.FOR_OFFICIAL_USE_ONLY},
                    base_risk_level=SpillageRiskLevel.MEDIUM,
                    description="Detects For Official Use Only control markings"
                ),
                PatternRule(
                    rule_id="cui_marking",
                    rule_name="Controlled Unclassified Information Marking",
                    pattern_type=PatternType.CONTROL_MARKING,
                    regex_pattern=r'\b(?:CONTROLLED\s+UNCLASSIFIED\s+INFORMATION|CUI(?:\s*//\s*[A-Z]+)?)\b',
                    case_sensitive=False,
                    classification_mapping={"CUI": ClassificationLevel.FOR_OFFICIAL_USE_ONLY},
                    base_risk_level=SpillageRiskLevel.MEDIUM,
                    description="Detects Controlled Unclassified Information markings"
                ),
                # PII patterns
                PatternRule(
                    rule_id="ssn_pattern",
                    rule_name="Social Security Number Pattern",
                    pattern_type=PatternType.PII_PATTERN,
                    regex_pattern=r'\b\d{3}-\d{2}-\d{4}\b',
                    base_risk_level=SpillageRiskLevel.HIGH,
                    description="Detects Social Security Number patterns"
                ),
                PatternRule(
                    rule_id="email_pattern",
                    rule_name="Email Address Pattern",
                    pattern_type=PatternType.PII_PATTERN,
                    regex_pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                    base_risk_level=SpillageRiskLevel.LOW,
                    description="Detects email address patterns"
                ),
                # Foreign disclosure patterns
                PatternRule(
                    rule_id="foreign_rel_pattern",
                    rule_name="Foreign Release Pattern",
                    pattern_type=PatternType.FOREIGN_DISCLOSURE,
                    regex_pattern=r'\b(?:REL\s+TO\s+([A-Z]{2,4}(?:,\s*[A-Z]{2,4})*)|NOFORN|FVEY)\b',
                    case_sensitive=False,
                    base_risk_level=SpillageRiskLevel.HIGH,
                    description="Detects foreign release and disclosure markings"
                ),
                # Compartmented information
                PatternRule(
                    rule_id="sci_pattern",
                    rule_name="Sensitive Compartmented Information Pattern",
                    pattern_type=PatternType.COMPARTMENTED_INFO,
                    regex_pattern=r'\b(?:SCI|TK|SI|COMINT|HCS|KLIEG|GAMMA|TALENT|KEYHOLE)\b',
                    case_sensitive=False,
                    base_risk_level=SpillageRiskLevel.CRITICAL,
                    description="Detects SCI and other compartmented information indicators"
                )
            ]
            
            for pattern in default_patterns:
                await self.add_pattern_rule(pattern)
            
            self.logger.info(f"Initialized {len(default_patterns)} default pattern rules")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize default patterns: {e}")
    
    async def add_pattern_rule(self, rule: PatternRule):
        """Add a new pattern rule"""
        try:
            # Validate and compile regex pattern
            try:
                flags = 0
                if not rule.case_sensitive:
                    flags |= re.IGNORECASE
                if rule.multiline:
                    flags |= re.MULTILINE
                
                compiled_pattern = re.compile(rule.regex_pattern, flags)
                self.compiled_patterns[rule.rule_id] = compiled_pattern
                
            except re.error as e:
                self.logger.error(f"Invalid regex pattern in rule {rule.rule_id}: {e}")
                return False
            
            # Store rule
            self.pattern_rules[rule.rule_id] = rule
            
            # Clear cache to ensure new patterns are used
            self.pattern_cache.clear()
            
            self.logger.info(f"Added pattern rule: {rule.rule_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding pattern rule {rule.rule_id}: {e}")
            return False
    
    async def detect_patterns(
        self,
        content: str,
        content_type: ContentType = ContentType.PLAIN_TEXT,
        location_path: str = "",
        location_type: LocationType = LocationType.FILE_SYSTEM,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[PatternMatch]:
        """
        Detect patterns in content and return matches
        
        Args:
            content: Content to analyze
            content_type: Type of content being analyzed
            location_path: Path where content was found
            location_type: Type of location
            metadata: Additional metadata about the content
            
        Returns:
            List of pattern matches found
        """
        start_time = time.time()
        matches = []
        
        try:
            if not content or len(content) > self.max_content_size:
                return matches
            
            # Check cache first
            content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
            cache_key = f"{content_hash}_{content_type.value}_{location_type.value}"
            
            if cache_key in self.pattern_cache:
                return self.pattern_cache[cache_key]
            
            # Preprocess content based on type
            processed_content = await self._preprocess_content(content, content_type)
            
            # Apply pattern rules
            for rule_id, rule in self.pattern_rules.items():
                if not rule.enabled:
                    continue
                
                try:
                    rule_matches = await self._apply_pattern_rule(
                        rule, processed_content, location_path, location_type, metadata
                    )
                    matches.extend(rule_matches)
                    
                    # Update rule statistics
                    rule.match_count += len(rule_matches)
                    
                except Exception as e:
                    self.logger.error(f"Error applying rule {rule_id}: {e}")
            
            # Post-process matches
            matches = await self._post_process_matches(matches, processed_content, metadata)
            
            # Limit matches to prevent overwhelming results
            if len(matches) > self.max_matches_per_content:
                matches = sorted(matches, key=lambda m: m.severity_score, reverse=True)
                matches = matches[:self.max_matches_per_content]
                self.logger.warning(f"Limited matches to {self.max_matches_per_content} for content")
            
            # Cache results
            if len(self.pattern_cache) < self.cache_max_size:
                self.pattern_cache[cache_key] = matches
            
            # Update metrics
            processing_time = (time.time() - start_time) * 1000
            self.metrics['patterns_processed'] += 1
            self.metrics['matches_found'] += len(matches)
            self.metrics['processing_time_total'] += processing_time
            self.metrics['average_processing_time'] = (
                self.metrics['processing_time_total'] / self.metrics['patterns_processed']
            )
            
            # Set processing metadata for each match
            for match in matches:
                match.processing_time_ms = processing_time
            
        except Exception as e:
            self.logger.error(f"Error in pattern detection: {e}")
        
        return matches
    
    async def _preprocess_content(self, content: str, content_type: ContentType) -> str:
        """Preprocess content based on its type"""
        try:
            if content_type == ContentType.HTML:
                # Remove HTML tags but preserve text content
                import re
                content = re.sub(r'<[^>]+>', ' ', content)
                content = re.sub(r'\s+', ' ', content).strip()
                
            elif content_type == ContentType.XML:
                # Similar to HTML but preserve some structure
                import re
                content = re.sub(r'<[^>]+>', '\n', content)
                content = re.sub(r'\n+', '\n', content).strip()
                
            elif content_type == ContentType.JSON:
                # Extract text values from JSON
                try:
                    import json
                    data = json.loads(content)
                    content = self._extract_json_text(data)
                except json.JSONDecodeError:
                    pass  # Keep original content if JSON parsing fails
                
            elif content_type == ContentType.EMAIL:
                # Extract email body and headers
                content = self._extract_email_content(content)
            
            # Normalize whitespace
            content = re.sub(r'\s+', ' ', content).strip()
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error preprocessing content: {e}")
            return content
    
    def _extract_json_text(self, data: Any) -> str:
        """Extract text values from JSON data recursively"""
        text_values = []
        
        if isinstance(data, dict):
            for value in data.values():
                text_values.append(self._extract_json_text(value))
        elif isinstance(data, list):
            for item in data:
                text_values.append(self._extract_json_text(item))
        elif isinstance(data, str):
            text_values.append(data)
        elif data is not None:
            text_values.append(str(data))
        
        return ' '.join(text_values)
    
    def _extract_email_content(self, content: str) -> str:
        """Extract relevant content from email"""
        try:
            # Simple email parsing - in production, use proper email parsing libraries
            lines = content.split('\n')
            body_lines = []
            in_body = False
            
            for line in lines:
                if not in_body:
                    # Look for end of headers
                    if line.strip() == '':
                        in_body = True
                    continue
                
                # Skip quoted text and signatures
                if line.startswith('>') or line.startswith('--'):
                    continue
                
                body_lines.append(line)
            
            return '\n'.join(body_lines)
            
        except Exception as e:
            self.logger.error(f"Error extracting email content: {e}")
            return content
    
    async def _apply_pattern_rule(
        self,
        rule: PatternRule,
        content: str,
        location_path: str,
        location_type: LocationType,
        metadata: Optional[Dict[str, Any]]
    ) -> List[PatternMatch]:
        """Apply a single pattern rule to content"""
        matches = []
        
        try:
            compiled_pattern = self.compiled_patterns.get(rule.rule_id)
            if not compiled_pattern:
                return matches
            
            # Find all matches
            for match in compiled_pattern.finditer(content):
                start_pos = match.start()
                end_pos = match.end()
                matched_text = match.group()
                
                # Extract surrounding context
                context_start = max(0, start_pos - rule.context_window_size)
                context_end = min(len(content), end_pos + rule.context_window_size)
                surrounding_context = content[context_start:context_end]
                
                # Check context requirements
                if not self._check_context_requirements(rule, surrounding_context):
                    continue
                
                # Determine classification level
                detected_classification = self._determine_classification(rule, matched_text)
                
                # Check if location is authorized
                authorized_location = await self._check_location_authorization(
                    location_path, location_type, detected_classification
                )
                
                # Calculate confidence and severity scores
                confidence_score = self._calculate_confidence_score(
                    rule, matched_text, surrounding_context
                )
                severity_score = self._calculate_severity_score(
                    rule, detected_classification, authorized_location
                )
                
                # Create pattern match
                pattern_match = PatternMatch(
                    pattern_type=rule.pattern_type,
                    pattern_name=rule.rule_name,
                    content_snippet=matched_text,
                    full_match=matched_text,
                    start_position=start_pos,
                    end_position=end_pos,
                    surrounding_context=surrounding_context[:400],  # Limit context size
                    confidence_score=confidence_score,
                    severity_score=severity_score,
                    detected_classification=detected_classification,
                    location_type=location_type,
                    location_path=location_path,
                    authorized_location=authorized_location
                )
                
                # Calculate line number if needed
                if '\n' in content:
                    pattern_match.line_number = content[:start_pos].count('\n') + 1
                
                matches.append(pattern_match)
            
        except Exception as e:
            self.logger.error(f"Error applying pattern rule {rule.rule_id}: {e}")
        
        return matches
    
    def _check_context_requirements(self, rule: PatternRule, context: str) -> bool:
        """Check if context requirements are met"""
        try:
            # Check required context
            if rule.required_context:
                for required in rule.required_context:
                    if required.lower() not in context.lower():
                        return False
            
            # Check forbidden context
            if rule.forbidden_context:
                for forbidden in rule.forbidden_context:
                    if forbidden.lower() in context.lower():
                        return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking context requirements: {e}")
            return True  # Default to allowing if error occurs
    
    def _determine_classification(
        self,
        rule: PatternRule,
        matched_text: str
    ) -> Optional[ClassificationLevel]:
        """Determine classification level from matched text"""
        try:
            # Check rule-specific mapping first
            for pattern, classification in rule.classification_mapping.items():
                if pattern.lower() in matched_text.lower():
                    return classification
            
            # Use default classification
            if rule.default_classification:
                return rule.default_classification
            
            # Pattern-based inference
            text_upper = matched_text.upper()
            
            if 'TOP SECRET' in text_upper:
                return ClassificationLevel.TOP_SECRET
            elif 'SECRET' in text_upper:
                return ClassificationLevel.SECRET
            elif 'CONFIDENTIAL' in text_upper:
                return ClassificationLevel.CONFIDENTIAL
            elif any(marker in text_upper for marker in ['FOUO', 'CUI', 'FOR OFFICIAL USE ONLY']):
                return ClassificationLevel.FOR_OFFICIAL_USE_ONLY
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error determining classification: {e}")
            return None
    
    async def _check_location_authorization(
        self,
        location_path: str,
        location_type: LocationType,
        classification: Optional[ClassificationLevel]
    ) -> bool:
        """Check if location is authorized for the classification level"""
        try:
            if not classification:
                return True  # Unclassified content allowed everywhere
            
            # Check against location mappings
            for mapping_id, mapping in self.location_mappings.items():
                if (mapping.location_type == location_type and
                    (not location_path or location_path.startswith(mapping.location_path))):
                    
                    return classification in mapping.authorized_classifications
            
            # Default authorization check based on location type and classification
            return self._default_location_authorization(location_type, classification)
            
        except Exception as e:
            self.logger.error(f"Error checking location authorization: {e}")
            return False  # Default to unauthorized if error occurs
    
    def _default_location_authorization(
        self,
        location_type: LocationType,
        classification: ClassificationLevel
    ) -> bool:
        """Default location authorization logic"""
        # Define basic authorization rules
        authorization_rules = {
            LocationType.FILE_SYSTEM: {
                ClassificationLevel.UNCLASSIFIED,
                ClassificationLevel.FOR_OFFICIAL_USE_ONLY,
                ClassificationLevel.CONFIDENTIAL,
                ClassificationLevel.SECRET,
                ClassificationLevel.TOP_SECRET
            },
            LocationType.EMAIL_SYSTEM: {
                ClassificationLevel.UNCLASSIFIED,
                ClassificationLevel.FOR_OFFICIAL_USE_ONLY
            },
            LocationType.WEB_APPLICATION: {
                ClassificationLevel.UNCLASSIFIED,
                ClassificationLevel.FOR_OFFICIAL_USE_ONLY
            },
            LocationType.CLOUD_STORAGE: {
                ClassificationLevel.UNCLASSIFIED
            },
            LocationType.REMOVABLE_MEDIA: set(),  # No classified on removable media by default
            LocationType.COLLABORATION_TOOL: {
                ClassificationLevel.UNCLASSIFIED,
                ClassificationLevel.FOR_OFFICIAL_USE_ONLY
            }
        }
        
        allowed_classifications = authorization_rules.get(location_type, set())
        return classification in allowed_classifications
    
    def _calculate_confidence_score(
        self,
        rule: PatternRule,
        matched_text: str,
        context: str
    ) -> float:
        """Calculate confidence score for the match"""
        base_confidence = 0.8
        
        try:
            # Adjust based on pattern specificity
            if rule.word_boundary and not re.search(r'\b' + re.escape(matched_text) + r'\b', context):
                base_confidence -= 0.2
            
            # Adjust based on context quality
            if rule.required_context:
                context_matches = sum(1 for req in rule.required_context if req.lower() in context.lower())
                context_quality = context_matches / len(rule.required_context)
                base_confidence = base_confidence * 0.5 + context_quality * 0.5
            
            # NLP-based confidence adjustment
            if self.nlp_model and self.matcher:
                nlp_confidence = self._calculate_nlp_confidence(context)
                base_confidence = base_confidence * 0.7 + nlp_confidence * 0.3
            
            return max(0.0, min(1.0, base_confidence))
            
        except Exception as e:
            self.logger.error(f"Error calculating confidence score: {e}")
            return 0.5
    
    def _calculate_nlp_confidence(self, context: str) -> float:
        """Calculate confidence using NLP analysis"""
        try:
            if not self.nlp_model or not self.matcher:
                return 0.5
            
            doc = self.nlp_model(context)
            matches = self.matcher(doc)
            
            # More context matches = higher confidence
            if matches:
                return min(1.0, 0.6 + len(matches) * 0.1)
            
            return 0.4
            
        except Exception as e:
            self.logger.error(f"Error in NLP confidence calculation: {e}")
            return 0.5
    
    def _calculate_severity_score(
        self,
        rule: PatternRule,
        classification: Optional[ClassificationLevel],
        authorized_location: bool
    ) -> float:
        """Calculate severity score for the match"""
        try:
            # Base severity from rule
            severity_mapping = {
                SpillageRiskLevel.CRITICAL: 1.0,
                SpillageRiskLevel.HIGH: 0.8,
                SpillageRiskLevel.MEDIUM: 0.6,
                SpillageRiskLevel.LOW: 0.4,
                SpillageRiskLevel.INFO: 0.2
            }
            
            base_severity = severity_mapping.get(rule.base_risk_level, 0.6)
            
            # Adjust for classification level
            if classification:
                classification_multipliers = {
                    ClassificationLevel.TOP_SECRET: 1.0,
                    ClassificationLevel.SECRET: 0.8,
                    ClassificationLevel.CONFIDENTIAL: 0.6,
                    ClassificationLevel.FOR_OFFICIAL_USE_ONLY: 0.4,
                    ClassificationLevel.UNCLASSIFIED: 0.2
                }
                classification_multiplier = classification_multipliers.get(classification, 0.6)
                base_severity *= classification_multiplier
            
            # Significantly increase severity if location is unauthorized
            if not authorized_location:
                base_severity = min(1.0, base_severity * 1.5)
            
            # Apply rule-specific multipliers
            for condition, multiplier in rule.risk_multipliers.items():
                # This would check specific conditions - placeholder for now
                if condition == "unauthorized_location" and not authorized_location:
                    base_severity = min(1.0, base_severity * multiplier)
            
            return max(0.0, min(1.0, base_severity))
            
        except Exception as e:
            self.logger.error(f"Error calculating severity score: {e}")
            return 0.5
    
    async def _post_process_matches(
        self,
        matches: List[PatternMatch],
        content: str,
        metadata: Optional[Dict[str, Any]]
    ) -> List[PatternMatch]:
        """Post-process matches to improve quality and reduce false positives"""
        try:
            processed_matches = []
            
            for match in matches:
                # Skip very low confidence matches
                if match.confidence_score < 0.3:
                    self.metrics['false_positives'] += 1
                    continue
                
                # Check for overlapping matches and keep the best one
                is_duplicate = False
                for existing_match in processed_matches:
                    if self._matches_overlap(match, existing_match):
                        if match.severity_score > existing_match.severity_score:
                            processed_matches.remove(existing_match)
                            break
                        else:
                            is_duplicate = True
                            break
                
                if not is_duplicate:
                    processed_matches.append(match)
            
            # Sort by severity score
            processed_matches.sort(key=lambda m: m.severity_score, reverse=True)
            
            return processed_matches
            
        except Exception as e:
            self.logger.error(f"Error post-processing matches: {e}")
            return matches
    
    def _matches_overlap(self, match1: PatternMatch, match2: PatternMatch) -> bool:
        """Check if two matches overlap significantly"""
        try:
            # Check position overlap
            overlap_start = max(match1.start_position, match2.start_position)
            overlap_end = min(match1.end_position, match2.end_position)
            
            if overlap_end <= overlap_start:
                return False  # No overlap
            
            overlap_length = overlap_end - overlap_start
            match1_length = match1.end_position - match1.start_position
            match2_length = match2.end_position - match2.start_position
            
            # Consider overlapping if overlap is > 50% of either match
            overlap_ratio1 = overlap_length / match1_length
            overlap_ratio2 = overlap_length / match2_length
            
            return overlap_ratio1 > 0.5 or overlap_ratio2 > 0.5
            
        except Exception as e:
            self.logger.error(f"Error checking match overlap: {e}")
            return False
    
    async def add_location_mapping(self, mapping: LocationMapping):
        """Add a location authorization mapping"""
        try:
            self.location_mappings[mapping.location_id] = mapping
            self.logger.info(f"Added location mapping: {mapping.location_path}")
            
        except Exception as e:
            self.logger.error(f"Error adding location mapping: {e}")
    
    async def create_spillage_events(
        self,
        matches: List[PatternMatch],
        context: Optional[Dict[str, Any]] = None
    ) -> List[SpillageEvent]:
        """Convert pattern matches to spillage events"""
        spillage_events = []
        
        try:
            for match in matches:
                # Determine event type and risk level
                event_type = self._map_pattern_to_event_type(match.pattern_type)
                risk_level = self._map_severity_to_risk_level(match.severity_score)
                
                # Create spillage event
                spillage_event = SpillageEvent(
                    event_type=event_type,
                    risk_level=risk_level,
                    detection_method=DetectionMethod.PATTERN_ANALYSIS,
                    description=f"Pattern match detected: {match.pattern_name}",
                    evidence={
                        'pattern_match_id': match.match_id,
                        'pattern_type': match.pattern_type.value,
                        'pattern_name': match.pattern_name,
                        'matched_content': match.content_snippet,
                        'location_path': match.location_path,
                        'location_type': match.location_type.value,
                        'authorized_location': match.authorized_location,
                        'detected_classification': match.detected_classification.value if match.detected_classification else None,
                        'start_position': match.start_position,
                        'end_position': match.end_position,
                        'line_number': match.line_number,
                        'surrounding_context': match.surrounding_context[:200]  # Limit context
                    },
                    confidence_score=match.confidence_score,
                    anomaly_score=match.severity_score,
                    detection_latency_ms=match.processing_time_ms,
                    source_network=context.get('source_network') if context else None,
                    target_network=context.get('target_network') if context else None,
                    classification_level=match.detected_classification
                )
                
                spillage_events.append(spillage_event)
            
        except Exception as e:
            self.logger.error(f"Error creating spillage events: {e}")
        
        return spillage_events
    
    def _map_pattern_to_event_type(self, pattern_type: PatternType) -> SpillageEventType:
        """Map pattern type to spillage event type"""
        mapping = {
            PatternType.CLASSIFICATION_MARKING: SpillageEventType.CLASSIFICATION_VIOLATION,
            PatternType.PII_PATTERN: SpillageEventType.PATTERN_MATCH,
            PatternType.PROPRIETARY_MARKING: SpillageEventType.PATTERN_MATCH,
            PatternType.CONTROL_MARKING: SpillageEventType.POLICY_VIOLATION,
            PatternType.FOREIGN_DISCLOSURE: SpillageEventType.CLASSIFICATION_VIOLATION,
            PatternType.COMPARTMENTED_INFO: SpillageEventType.CLASSIFICATION_VIOLATION,
            PatternType.CAVEAT_MARKING: SpillageEventType.CLASSIFICATION_VIOLATION,
            PatternType.HANDLING_INSTRUCTION: SpillageEventType.POLICY_VIOLATION,
            PatternType.SIGNATURE_BLOCK: SpillageEventType.PATTERN_MATCH,
            PatternType.DOCUMENT_METADATA: SpillageEventType.PATTERN_MATCH
        }
        return mapping.get(pattern_type, SpillageEventType.PATTERN_MATCH)
    
    def _map_severity_to_risk_level(self, severity_score: float) -> SpillageRiskLevel:
        """Map severity score to risk level"""
        if severity_score >= 0.9:
            return SpillageRiskLevel.CRITICAL
        elif severity_score >= 0.7:
            return SpillageRiskLevel.HIGH
        elif severity_score >= 0.5:
            return SpillageRiskLevel.MEDIUM
        elif severity_score >= 0.3:
            return SpillageRiskLevel.LOW
        else:
            return SpillageRiskLevel.INFO
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get current performance and detection metrics"""
        try:
            return {
                **self.metrics,
                'active_pattern_rules': len([r for r in self.pattern_rules.values() if r.enabled]),
                'total_pattern_rules': len(self.pattern_rules),
                'location_mappings': len(self.location_mappings),
                'cache_size': len(self.pattern_cache),
                'nlp_available': NLP_AVAILABLE,
                'document_processing_available': DOCUMENT_PROCESSING_AVAILABLE,
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error getting metrics: {e}")
            return {'error': str(e)}
    
    def shutdown(self):
        """Shutdown the pattern detector"""
        try:
            self.thread_pool.shutdown(wait=True)
            self.pattern_cache.clear()
            self.logger.info("SpillagePatternDetector shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


# Export main classes
__all__ = [
    'SpillagePatternDetector',
    'PatternMatch',
    'PatternRule',
    'LocationMapping',
    'PatternType',
    'ContentType',
    'LocationType'
]