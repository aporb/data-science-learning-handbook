"""
Data Classification Engine
=========================

Automatic content analysis and classification system for multi-level security.
Implements ML-based classification, pattern recognition, and human-in-the-loop workflows.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Created: 2025-07-17
Version: 1.0
"""

import re
import json
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any, Union
from datetime import datetime
import hashlib
import nltk
from collections import Counter
import pickle
import numpy as np
from pathlib import Path

# Try to import ML libraries (optional dependencies)
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    import torch
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    
try:
    import spacy
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False

from ..models.bell_lapadula import SecurityLabel, ClassificationLevel, Compartment

# Configure logging
logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    """Confidence levels for classification decisions."""
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


class ClassificationMethod(Enum):
    """Methods used for classification."""
    PATTERN_MATCHING = "PATTERN_MATCHING"
    KEYWORD_ANALYSIS = "KEYWORD_ANALYSIS"
    ML_MODEL = "ML_MODEL"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    HYBRID = "HYBRID"


@dataclass
class ClassificationPattern:
    """Represents a classification pattern for content analysis."""
    pattern_id: str
    name: str
    regex_pattern: str
    classification_level: ClassificationLevel
    compartments: Set[str] = field(default_factory=set)
    confidence_score: float = 0.8
    description: str = ""
    active: bool = True
    
    def matches(self, content: str) -> List[Dict[str, Any]]:
        """Check if pattern matches content and return match details."""
        matches = []
        compiled_pattern = re.compile(self.regex_pattern, re.IGNORECASE | re.MULTILINE)
        
        for match in compiled_pattern.finditer(content):
            matches.append({
                'start': match.start(),
                'end': match.end(),
                'text': match.group(),
                'pattern_id': self.pattern_id,
                'confidence': self.confidence_score
            })
        
        return matches


@dataclass
class ClassificationRule:
    """Rule-based classification logic."""
    rule_id: str
    name: str
    conditions: List[Dict[str, Any]]
    classification_level: ClassificationLevel
    compartments: Set[str] = field(default_factory=set)
    priority: int = 50
    active: bool = True
    
    def evaluate(self, content_features: Dict[str, Any]) -> bool:
        """Evaluate rule conditions against content features."""
        for condition in self.conditions:
            if not self._evaluate_condition(condition, content_features):
                return False
        return True
    
    def _evaluate_condition(self, condition: Dict[str, Any], 
                          features: Dict[str, Any]) -> bool:
        """Evaluate a single condition."""
        feature_name = condition['feature']
        operator = condition['operator']
        threshold = condition['value']
        
        if feature_name not in features:
            return False
        
        feature_value = features[feature_name]
        
        if operator == 'gt':
            return feature_value > threshold
        elif operator == 'gte':
            return feature_value >= threshold
        elif operator == 'lt':
            return feature_value < threshold
        elif operator == 'lte':
            return feature_value <= threshold
        elif operator == 'eq':
            return feature_value == threshold
        elif operator == 'ne':
            return feature_value != threshold
        elif operator == 'contains':
            return threshold in str(feature_value).lower()
        elif operator == 'regex':
            return bool(re.search(threshold, str(feature_value), re.IGNORECASE))
        
        return False


@dataclass
class ClassificationResult:
    """Result of content classification analysis."""
    content_id: str
    recommended_classification: SecurityLabel
    confidence: ConfidenceLevel
    method: ClassificationMethod
    reasoning: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    requires_human_review: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'content_id': self.content_id,
            'recommended_classification': self.recommended_classification.to_dict(),
            'confidence': self.confidence.value,
            'method': self.method.value,
            'reasoning': self.reasoning,
            'evidence': self.evidence,
            'requires_human_review': self.requires_human_review,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }


class KeywordClassifier:
    """Keyword-based classification using predefined lists."""
    
    def __init__(self):
        self.classified_keywords = self._load_classified_keywords()
    
    def _load_classified_keywords(self) -> Dict[ClassificationLevel, Set[str]]:
        """Load classified keyword lists."""
        keywords = {
            ClassificationLevel.CONFIDENTIAL: {
                'proprietary', 'internal use only', 'company confidential',
                'restricted', 'sensitive', 'confidential'
            },
            ClassificationLevel.SECRET: {
                'secret', 'classified', 'national security', 'intelligence',
                'covert', 'sensitive compartmented information', 'special access'
            },
            ClassificationLevel.TOP_SECRET: {
                'top secret', 'ts', 'sci', 'special intelligence',
                'compartmented', 'codeword', 'talent keyhole', 'humint'
            }
        }
        return keywords
    
    def classify(self, content: str) -> Tuple[ClassificationLevel, float, List[str]]:
        """
        Classify content based on keyword analysis.
        
        Returns:
            Tuple of (classification_level, confidence_score, found_keywords)
        """
        content_lower = content.lower()
        found_keywords = []
        classification_scores = Counter()
        
        for level, keywords in self.classified_keywords.items():
            for keyword in keywords:
                if keyword in content_lower:
                    found_keywords.append(keyword)
                    classification_scores[level] += 1
        
        if not classification_scores:
            return ClassificationLevel.UNCLASSIFIED, 1.0, []
        
        # Get highest scoring classification
        max_level = classification_scores.most_common(1)[0][0]
        confidence = min(classification_scores[max_level] * 0.2, 1.0)
        
        return max_level, confidence, found_keywords


class PatternClassifier:
    """Pattern-based classification using regular expressions."""
    
    def __init__(self):
        self.patterns = self._load_classification_patterns()
    
    def _load_classification_patterns(self) -> List[ClassificationPattern]:
        """Load predefined classification patterns."""
        patterns = [
            # SSN patterns
            ClassificationPattern(
                pattern_id="ssn_pattern",
                name="Social Security Number",
                regex_pattern=r'\b\d{3}-\d{2}-\d{4}\b',
                classification_level=ClassificationLevel.CONFIDENTIAL,
                compartments={'PII'},
                confidence_score=0.9,
                description="Detects Social Security Numbers"
            ),
            
            # Credit card patterns
            ClassificationPattern(
                pattern_id="credit_card_pattern",
                name="Credit Card Number",
                regex_pattern=r'\b(?:\d[ -]*?){13,16}\b',
                classification_level=ClassificationLevel.CONFIDENTIAL,
                compartments={'PII', 'FINANCIAL'},
                confidence_score=0.8,
                description="Detects credit card numbers"
            ),
            
            # Classification markings
            ClassificationPattern(
                pattern_id="secret_marking",
                name="Secret Classification Marking",
                regex_pattern=r'\b(SECRET|CONFIDENTIAL|TOP SECRET)\b',
                classification_level=ClassificationLevel.SECRET,
                confidence_score=0.95,
                description="Detects classification markings"
            ),
            
            # Intelligence compartments
            ClassificationPattern(
                pattern_id="sci_marking",
                name="SCI Marking",
                regex_pattern=r'\b(SI|TK|HCS|ORCON)\b',
                classification_level=ClassificationLevel.TOP_SECRET,
                compartments={'SCI'},
                confidence_score=0.9,
                description="Detects SCI compartment markings"
            ),
            
            # FOUO/CUI markings
            ClassificationPattern(
                pattern_id="fouo_marking",
                name="FOUO/CUI Marking",
                regex_pattern=r'\b(FOUO|FOR OFFICIAL USE ONLY|CUI)\b',
                classification_level=ClassificationLevel.UNCLASSIFIED,
                compartments={'CUI'},
                confidence_score=0.85,
                description="Detects FOUO/CUI markings"
            )
        ]
        
        return patterns
    
    def classify(self, content: str) -> List[ClassificationResult]:
        """
        Classify content using pattern matching.
        
        Returns:
            List of classification results for each matched pattern
        """
        results = []
        content_id = hashlib.md5(content.encode()).hexdigest()[:8]
        
        for pattern in self.patterns:
            if not pattern.active:
                continue
                
            matches = pattern.matches(content)
            if matches:
                confidence = self._calculate_confidence(matches, pattern)
                
                result = ClassificationResult(
                    content_id=content_id,
                    recommended_classification=SecurityLabel(
                        classification=pattern.classification_level,
                        compartments=pattern.compartments
                    ),
                    confidence=self._map_confidence(confidence),
                    method=ClassificationMethod.PATTERN_MATCHING,
                    reasoning=f"Pattern '{pattern.name}' matched {len(matches)} times",
                    evidence=matches,
                    requires_human_review=(confidence < 0.7),
                    metadata={'pattern_id': pattern.pattern_id}
                )
                
                results.append(result)
        
        return results
    
    def _calculate_confidence(self, matches: List[Dict[str, Any]], 
                            pattern: ClassificationPattern) -> float:
        """Calculate confidence based on matches."""
        base_confidence = pattern.confidence_score
        match_count = len(matches)
        
        # Adjust confidence based on number of matches
        if match_count == 1:
            return base_confidence
        elif match_count <= 3:
            return min(base_confidence + 0.1, 1.0)
        else:
            return min(base_confidence + 0.2, 1.0)
    
    def _map_confidence(self, score: float) -> ConfidenceLevel:
        """Map numeric confidence to confidence level."""
        if score >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif score >= 0.7:
            return ConfidenceLevel.HIGH
        elif score >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW


class MLClassifier:
    """Machine learning-based content classifier."""
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.model = None
        self.tokenizer = None
        self.is_loaded = False
        
        if ML_AVAILABLE:
            self._load_model()
    
    def _load_model(self):
        """Load pre-trained classification model."""
        try:
            if self.model_path and Path(self.model_path).exists():
                # Load custom trained model
                self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            else:
                # Use general text classification model as baseline
                self.classifier = pipeline(
                    "text-classification",
                    model="distilbert-base-uncased-finetuned-sst-2-english"
                )
            
            self.is_loaded = True
            logger.info("ML classification model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self.is_loaded = False
    
    def classify(self, content: str) -> ClassificationResult:
        """
        Classify content using ML model.
        
        Returns:
            ClassificationResult with ML-based classification
        """
        if not self.is_loaded or not ML_AVAILABLE:
            return ClassificationResult(
                content_id=hashlib.md5(content.encode()).hexdigest()[:8],
                recommended_classification=SecurityLabel(ClassificationLevel.UNCLASSIFIED),
                confidence=ConfidenceLevel.LOW,
                method=ClassificationMethod.ML_MODEL,
                reasoning="ML model not available",
                requires_human_review=True
            )
        
        try:
            # This is a simplified example - in practice, you would use
            # a model specifically trained for classification levels
            features = self._extract_features(content)
            prediction = self._predict_classification(features)
            
            return ClassificationResult(
                content_id=hashlib.md5(content.encode()).hexdigest()[:8],
                recommended_classification=prediction['classification'],
                confidence=prediction['confidence'],
                method=ClassificationMethod.ML_MODEL,
                reasoning=prediction['reasoning'],
                evidence=prediction['evidence'],
                requires_human_review=(prediction['confidence'] == ConfidenceLevel.LOW),
                metadata=prediction['metadata']
            )
            
        except Exception as e:
            logger.error(f"ML classification failed: {e}")
            return ClassificationResult(
                content_id=hashlib.md5(content.encode()).hexdigest()[:8],
                recommended_classification=SecurityLabel(ClassificationLevel.UNCLASSIFIED),
                confidence=ConfidenceLevel.LOW,
                method=ClassificationMethod.ML_MODEL,
                reasoning=f"ML classification error: {str(e)}",
                requires_human_review=True
            )
    
    def _extract_features(self, content: str) -> Dict[str, Any]:
        """Extract features from content for ML classification."""
        features = {
            'length': len(content),
            'word_count': len(content.split()),
            'has_classification_keywords': bool(re.search(
                r'\b(secret|confidential|classified|restricted)\b', 
                content, re.IGNORECASE
            )),
            'has_government_terms': bool(re.search(
                r'\b(government|federal|agency|department)\b',
                content, re.IGNORECASE
            )),
            'has_sensitive_data': bool(re.search(
                r'\b(\d{3}-\d{2}-\d{4}|\d{16})\b',
                content
            ))
        }
        
        return features
    
    def _predict_classification(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Predict classification based on features."""
        # Simplified rule-based prediction for demonstration
        # In practice, this would use the trained ML model
        
        if features['has_classification_keywords']:
            classification = SecurityLabel(ClassificationLevel.SECRET)
            confidence = ConfidenceLevel.HIGH
            reasoning = "Contains classification keywords"
        elif features['has_sensitive_data']:
            classification = SecurityLabel(
                ClassificationLevel.CONFIDENTIAL,
                compartments={'PII'}
            )
            confidence = ConfidenceLevel.MEDIUM
            reasoning = "Contains sensitive data patterns"
        elif features['has_government_terms']:
            classification = SecurityLabel(
                ClassificationLevel.UNCLASSIFIED,
                compartments={'CUI'}
            )
            confidence = ConfidenceLevel.MEDIUM
            reasoning = "Contains government-related terms"
        else:
            classification = SecurityLabel(ClassificationLevel.UNCLASSIFIED)
            confidence = ConfidenceLevel.HIGH
            reasoning = "No classified indicators found"
        
        return {
            'classification': classification,
            'confidence': confidence,
            'reasoning': reasoning,
            'evidence': features,
            'metadata': {'model': 'rule_based_demo'}
        }


class DataClassificationEngine:
    """
    Main data classification engine that coordinates multiple classifiers.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize classification engine.
        
        Args:
            config: Configuration dictionary with classifier settings
        """
        self.config = config or {}
        
        # Initialize classifiers
        self.keyword_classifier = KeywordClassifier()
        self.pattern_classifier = PatternClassifier()
        self.ml_classifier = MLClassifier(
            model_path=self.config.get('ml_model_path')
        )
        
        # Classification thresholds
        self.confidence_threshold = self.config.get('confidence_threshold', 0.7)
        self.human_review_threshold = self.config.get('human_review_threshold', 0.5)
        
        # Feature extractors
        self.nlp = None
        if SPACY_AVAILABLE:
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                logger.warning("spaCy model not found. Install with: python -m spacy download en_core_web_sm")
    
    def classify_content(self, content: str, content_type: str = "text",
                        content_id: Optional[str] = None) -> ClassificationResult:
        """
        Classify content using multiple classification methods.
        
        Args:
            content: Content to classify
            content_type: Type of content (text, document, etc.)
            content_id: Optional content identifier
            
        Returns:
            Comprehensive classification result
        """
        if content_id is None:
            content_id = hashlib.md5(content.encode()).hexdigest()[:8]
        
        logger.info(f"Classifying content {content_id} of type {content_type}")
        
        # Run all classifiers
        keyword_level, keyword_confidence, keywords = self.keyword_classifier.classify(content)
        pattern_results = self.pattern_classifier.classify(content)
        ml_result = self.ml_classifier.classify(content)
        
        # Combine results
        final_result = self._combine_results(
            content_id, content_type, keyword_level, keyword_confidence, 
            keywords, pattern_results, ml_result
        )
        
        # Apply post-processing rules
        final_result = self._apply_post_processing(final_result, content)
        
        logger.info(
            f"Classification complete for {content_id}: "
            f"{final_result.recommended_classification.classification.to_string()} "
            f"(confidence: {final_result.confidence.value})"
        )
        
        return final_result
    
    def _combine_results(self, content_id: str, content_type: str,
                        keyword_level: ClassificationLevel, keyword_confidence: float,
                        keywords: List[str], pattern_results: List[ClassificationResult],
                        ml_result: ClassificationResult) -> ClassificationResult:
        """Combine results from multiple classifiers."""
        
        # Determine highest classification level
        max_level = keyword_level
        evidence = []
        reasoning_parts = []
        compartments = set()
        
        # Factor in keyword analysis
        if keywords:
            evidence.append({
                'type': 'keywords',
                'data': keywords,
                'confidence': keyword_confidence
            })
            reasoning_parts.append(f"Keywords found: {', '.join(keywords)}")
        
        # Factor in pattern results
        for result in pattern_results:
            pattern_level = result.recommended_classification.classification
            if pattern_level > max_level:
                max_level = pattern_level
            
            compartments.update(result.recommended_classification.compartments)
            evidence.extend(result.evidence)
            reasoning_parts.append(result.reasoning)
        
        # Factor in ML result
        ml_level = ml_result.recommended_classification.classification
        if ml_level > max_level:
            max_level = ml_level
        
        compartments.update(ml_result.recommended_classification.compartments)
        evidence.append({
            'type': 'ml_analysis',
            'data': ml_result.evidence,
            'confidence': ml_result.confidence.value
        })
        reasoning_parts.append(ml_result.reasoning)
        
        # Calculate combined confidence
        confidences = [keyword_confidence]
        if pattern_results:
            confidences.extend([
                self._confidence_to_numeric(r.confidence) for r in pattern_results
            ])
        confidences.append(self._confidence_to_numeric(ml_result.confidence))
        
        avg_confidence = sum(confidences) / len(confidences)
        
        # Determine if human review is required
        requires_review = (
            avg_confidence < self.human_review_threshold or
            max_level >= ClassificationLevel.SECRET or
            any(result.requires_human_review for result in pattern_results) or
            ml_result.requires_human_review
        )
        
        return ClassificationResult(
            content_id=content_id,
            recommended_classification=SecurityLabel(
                classification=max_level,
                compartments=compartments
            ),
            confidence=self._numeric_to_confidence(avg_confidence),
            method=ClassificationMethod.HYBRID,
            reasoning='; '.join(reasoning_parts),
            evidence=evidence,
            requires_human_review=requires_review,
            metadata={
                'content_type': content_type,
                'classifiers_used': ['keyword', 'pattern', 'ml'],
                'pattern_matches': len(pattern_results)
            }
        )
    
    def _apply_post_processing(self, result: ClassificationResult, 
                             content: str) -> ClassificationResult:
        """Apply post-processing rules to classification result."""
        
        # Rule: If content is very short, reduce confidence
        if len(content) < 50:
            if result.confidence != ConfidenceLevel.VERY_LOW:
                result.confidence = ConfidenceLevel.LOW
                result.reasoning += "; Content too short for high confidence"
                result.requires_human_review = True
        
        # Rule: If multiple high-level indicators, increase confidence
        high_level_indicators = sum(
            1 for evidence in result.evidence
            if evidence.get('confidence', 0) > 0.8
        )
        
        if high_level_indicators >= 3 and result.confidence == ConfidenceLevel.MEDIUM:
            result.confidence = ConfidenceLevel.HIGH
            result.reasoning += "; Multiple strong indicators found"
        
        # Rule: Foreign language content requires review
        if self.nlp:
            doc = self.nlp(content[:1000])  # Analyze first 1000 chars
            non_english_ratio = sum(
                1 for token in doc if not token.is_alpha or token.lang_ != 'en'
            ) / len(doc)
            
            if non_english_ratio > 0.3:
                result.requires_human_review = True
                result.reasoning += "; Contains significant non-English content"
        
        return result
    
    def _confidence_to_numeric(self, confidence: ConfidenceLevel) -> float:
        """Convert ConfidenceLevel to numeric value."""
        mapping = {
            ConfidenceLevel.VERY_LOW: 0.1,
            ConfidenceLevel.LOW: 0.3,
            ConfidenceLevel.MEDIUM: 0.5,
            ConfidenceLevel.HIGH: 0.7,
            ConfidenceLevel.VERY_HIGH: 0.9
        }
        return mapping[confidence]
    
    def _numeric_to_confidence(self, score: float) -> ConfidenceLevel:
        """Convert numeric score to ConfidenceLevel."""
        if score >= 0.8:
            return ConfidenceLevel.VERY_HIGH
        elif score >= 0.6:
            return ConfidenceLevel.HIGH
        elif score >= 0.4:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.2:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def batch_classify(self, contents: List[Tuple[str, str]]) -> List[ClassificationResult]:
        """
        Classify multiple content items in batch.
        
        Args:
            contents: List of (content, content_type) tuples
            
        Returns:
            List of classification results
        """
        results = []
        
        for i, (content, content_type) in enumerate(contents):
            content_id = f"batch_{i:04d}"
            result = self.classify_content(content, content_type, content_id)
            results.append(result)
        
        return results
    
    def validate_classification(self, content_id: str, 
                              human_classification: SecurityLabel,
                              original_result: ClassificationResult) -> Dict[str, Any]:
        """
        Validate human-provided classification against automatic result.
        
        Args:
            content_id: Content identifier
            human_classification: Human-assigned classification
            original_result: Original automatic classification result
            
        Returns:
            Validation report
        """
        validation = {
            'content_id': content_id,
            'timestamp': datetime.now().isoformat(),
            'agreement': self._check_classification_agreement(
                human_classification, original_result.recommended_classification
            ),
            'human_classification': human_classification.to_dict(),
            'automatic_classification': original_result.recommended_classification.to_dict(),
            'confidence_level': original_result.confidence.value,
            'discrepancies': []
        }
        
        # Check for discrepancies
        if human_classification.classification != original_result.recommended_classification.classification:
            validation['discrepancies'].append({
                'type': 'classification_level',
                'human': human_classification.classification.to_string(),
                'automatic': original_result.recommended_classification.classification.to_string()
            })
        
        missing_compartments = human_classification.compartments - original_result.recommended_classification.compartments
        extra_compartments = original_result.recommended_classification.compartments - human_classification.compartments
        
        if missing_compartments:
            validation['discrepancies'].append({
                'type': 'missing_compartments',
                'compartments': list(missing_compartments)
            })
        
        if extra_compartments:
            validation['discrepancies'].append({
                'type': 'extra_compartments',
                'compartments': list(extra_compartments)
            })
        
        return validation
    
    def _check_classification_agreement(self, human: SecurityLabel, 
                                      automatic: SecurityLabel) -> str:
        """Check agreement level between human and automatic classification."""
        if (human.classification == automatic.classification and
            human.compartments == automatic.compartments):
            return "FULL_AGREEMENT"
        elif human.classification == automatic.classification:
            return "PARTIAL_AGREEMENT"
        elif abs(human.classification - automatic.classification) <= 1:
            return "CLOSE_AGREEMENT"
        else:
            return "DISAGREEMENT"
    
    def get_classification_statistics(self) -> Dict[str, Any]:
        """Get statistics about classification engine performance."""
        # This would typically query a database of past classifications
        # For now, return sample statistics
        return {
            'total_classifications': 0,
            'accuracy_rate': 0.0,
            'human_review_rate': 0.0,
            'classification_distribution': {
                'UNCLASSIFIED': 0,
                'CONFIDENTIAL': 0,
                'SECRET': 0,
                'TOP_SECRET': 0
            },
            'confidence_distribution': {
                'VERY_LOW': 0,
                'LOW': 0,
                'MEDIUM': 0,
                'HIGH': 0,
                'VERY_HIGH': 0
            }
        }


# Utility functions for external integration

def create_classification_engine(config_path: Optional[str] = None) -> DataClassificationEngine:
    """Create and configure a classification engine."""
    config = {}
    
    if config_path and Path(config_path).exists():
        with open(config_path, 'r') as f:
            config = json.load(f)
    
    return DataClassificationEngine(config)


def quick_classify(content: str) -> str:
    """Quick classification for simple use cases."""
    engine = create_classification_engine()
    result = engine.classify_content(content)
    return result.recommended_classification.classification.to_string()


# Example usage
def example_usage():
    """Demonstrate classification engine usage."""
    engine = DataClassificationEngine()
    
    # Example content with various classification indicators
    test_content = """
    This document contains SECRET information about national security operations.
    The operation codenamed TALENT KEYHOLE involves intelligence gathering.
    Contact information: John Doe, SSN: 123-45-6789
    Credit Card: 4111 1111 1111 1111
    """
    
    result = engine.classify_content(test_content, "document")
    
    print(f"Classification: {result.recommended_classification.classification.to_string()}")
    print(f"Compartments: {', '.join(result.recommended_classification.compartments)}")
    print(f"Confidence: {result.confidence.value}")
    print(f"Reasoning: {result.reasoning}")
    print(f"Requires Review: {result.requires_human_review}")
    
    for evidence in result.evidence:
        print(f"Evidence: {evidence}")


if __name__ == "__main__":
    example_usage()