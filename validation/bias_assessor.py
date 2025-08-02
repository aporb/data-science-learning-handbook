#!/usr/bin/env python3
"""
Bias Assessment Module for Chapter Content Management System
===========================================================

Comprehensive bias assessment framework that analyzes:
- Methodology balance (traditional vs modern approaches)
- Platform neutrality and tool diversity
- Inclusive language and accessibility
- Context diversity analysis
- Geographic and cultural representation
- Demographic bias detection

Author: Claude Code Implementation
Created: 2025-07-28
Version: 1.0.0
"""

import re
import json
import logging
import nltk
import spacy
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
import yaml
import pandas as pd
import numpy as np
from textstat import flesch_reading_ease, gunning_fog
from wordcloud import WordCloud
import matplotlib.pyplot as plt

# Download required NLTK data
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('vader_lexicon', quiet=True)
    nltk.download('wordnet', quiet=True)
except:
    pass

from nltk.sentiment.vader import SentimentIntensityAnalyzer
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize, sent_tokenize

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BiasAssessmentResult:
    """Result of bias assessment analysis"""
    overall_bias_score: float  # 0-100, where 50 is perfectly balanced
    component_scores: Dict[str, float]
    passed: bool
    bias_indicators: List[str]
    balance_issues: List[str]
    recommendations: List[str]
    methodology_analysis: Dict[str, Any]
    platform_analysis: Dict[str, Any]
    language_analysis: Dict[str, Any]
    diversity_analysis: Dict[str, Any]
    timestamp: str
    processing_time: float


@dataclass
class MethodologyBalance:
    """Analysis of methodology balance"""
    traditional_count: int
    modern_count: int
    balance_ratio: float
    traditional_terms: List[str]
    modern_terms: List[str]
    imbalance_severity: str


@dataclass
class PlatformAnalysis:
    """Analysis of platform representation"""
    platform_mentions: Dict[str, int]
    dominant_platform: str
    diversity_score: float
    missing_platforms: List[str]
    recommendations: List[str]


@dataclass
class LanguageInclusivenessResult:
    """Result of inclusive language analysis"""
    inclusiveness_score: float
    issues_found: List[str]
    suggestions: List[str]
    readability_score: float
    complexity_analysis: Dict[str, Any]


class BiasAssessor:
    """
    Comprehensive bias assessment system for educational content
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Bias Assessor
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.sentiment_analyzer = SentimentIntensityAnalyzer()
        
        # Initialize spaCy model for NLP analysis
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            logger.warning("spaCy model not found. Some features may be limited.")
            self.nlp = None
        
        # Load bias detection patterns
        self.bias_patterns = self._load_bias_patterns()
        self.methodology_terms = self._load_methodology_terms()
        self.platform_terms = self._load_platform_terms()
        self.inclusive_language_terms = self._load_inclusive_language_terms()
        
        logger.info("Bias Assessor initialized")
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load bias assessor configuration"""
        default_config = {
            "assessment": {
                "target_balance_score": 50.0,  # Perfect balance
                "tolerance_threshold": 10.0,   # ±10 from perfect balance
                "minimum_pass_score": 40.0,    # Minimum acceptable bias score
                "maximum_pass_score": 60.0     # Maximum acceptable bias score
            },
            "methodology": {
                "balance_target": 0.5,  # 50/50 traditional vs modern
                "tolerance": 0.2,       # ±20% tolerance
                "weight": 0.3          # 30% of overall score
            },
            "platform": {
                "minimum_platforms": 3,  # Minimum platforms to mention
                "diversity_threshold": 0.7,  # 70% diversity requirement
                "dominant_platform_threshold": 0.6,  # Max 60% dominance
                "weight": 0.25          # 25% of overall score
            },
            "language": {
                "inclusiveness_threshold": 85.0,  # 85% inclusiveness requirement
                "readability_min": 60.0,          # Minimum readability score
                "readability_max": 80.0,          # Maximum readability score
                "weight": 0.25                    # 25% of overall score
            },
            "diversity": {
                "context_variety_threshold": 0.7,  # 70% context variety
                "geographic_representation": 3,    # Minimum geographic contexts
                "demographic_balance": 0.6,        # 60% demographic balance
                "weight": 0.2                     # 20% of overall score
            }
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    self._deep_merge(default_config, user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def _deep_merge(self, base: Dict, update: Dict) -> None:
        """Deep merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _load_bias_patterns(self) -> Dict[str, List[str]]:
        """Load bias detection patterns"""
        return {
            "gender_bias": [
                r'\bmankind\b', r'\bmanpower\b', r'\bmanmade\b',
                r'\bchairman\b', r'\bfireman\b', r'\bpoliceman\b',
                r'\bhe/she\b', r'\bhis/her\b', r'\bhimself/herself\b'
            ],
            "racial_bias": [
                r'\bwhitelist\b', r'\bblacklist\b', r'\bmaster/slave\b',
                r'\bnative\b(?=\s+(?:to|speaker))', r'\bprimitive\b'
            ],
            "ableism": [
                r'\bblind\s+to\b', r'\bdeaf\s+to\b', r'\bdumb\b(?!\s+terminal)',
                r'\blame\b(?=\s+(?:excuse|attempt))', r'\bcrippl\w+\b'
            ],
            "ageism": [
                r'\bold\s+(?:school|fashioned)\b', r'\byoung\s+blood\b',
                r'\bover\s+the\s+hill\b'
            ],
            "technical_elitism": [
                r'\bobviously\b', r'\bsimply\b', r'\bjust\b(?=\s+(?:do|use|run))',
                r'\beasily\b', r'\btrivial(?:ly)?\b'
            ]
        }
    
    def _load_methodology_terms(self) -> Dict[str, List[str]]:
        """Load methodology classification terms"""
        return {
            "traditional": [
                # Statistical methods
                "t-test", "anova", "chi-square", "correlation", "regression",
                "hypothesis testing", "p-value", "significance", "confidence interval",
                "normal distribution", "parametric", "frequentist",
                # Traditional ML
                "linear regression", "logistic regression", "decision tree",
                "svm", "support vector", "k-means", "hierarchical clustering",
                # Traditional tools
                "excel", "spss", "sas", "stata", "matlab", "tableau classic",
                # Traditional approaches
                "waterfall", "structured", "sequential", "batch processing"
            ],
            "modern": [
                # Modern ML/AI
                "neural network", "deep learning", "transformer", "bert", "gpt",
                "convolution", "lstm", "gan", "reinforcement learning",
                "gradient boosting", "xgboost", "lightgbm", "catboost",
                "ensemble", "bagging", "boosting", "random forest",
                # Modern stats
                "bayesian", "mcmc", "bootstrap", "cross-validation",
                "regularization", "lasso", "ridge", "elastic net",
                # Modern tools
                "python", "r", "tensorflow", "pytorch", "keras", "scikit-learn",
                "pandas", "numpy", "jupyter", "colab", "databricks", "mlflow",
                "docker", "kubernetes", "spark", "hadoop", "cloud",
                # Modern approaches
                "agile", "devops", "mlops", "continuous", "streaming",
                "real-time", "microservices", "api", "rest", "graphql"
            ]
        }
    
    def _load_platform_terms(self) -> Dict[str, List[str]]:
        """Load platform classification terms"""
        return {
            "python": [
                "python", "pandas", "numpy", "scikit-learn", "tensorflow",
                "pytorch", "keras", "matplotlib", "seaborn", "plotly",
                "jupyter", "ipython", "anaconda", "pip", "conda"
            ],
            "r": [
                "r", "ggplot2", "dplyr", "tidyr", "caret", "randomforest",
                "rstudio", "cran", "tidyverse", "shiny", "knitr", "rmarkdown"
            ],
            "sql": [
                "sql", "mysql", "postgresql", "sqlite", "oracle", "mssql",
                "bigquery", "redshift", "snowflake", "databricks sql"
            ],
            "cloud_platforms": [
                "aws", "azure", "gcp", "google cloud", "amazon web services",
                "microsoft azure", "databricks", "snowflake", "redshift"
            ],
            "analytics_tools": [
                "tableau", "power bi", "qlik", "looker", "spotfire",
                "sas", "spss", "stata", "matlab"
            ],
            "big_data": [
                "spark", "hadoop", "kafka", "storm", "flink", "hive",
                "impala", "presto", "drill"
            ]
        }
    
    def _load_inclusive_language_terms(self) -> Dict[str, Dict[str, str]]:
        """Load inclusive language recommendations"""
        return {
            "replacements": {
                # Gender-neutral alternatives
                "mankind": "humanity",
                "manpower": "workforce",
                "manmade": "artificial",
                "chairman": "chairperson",
                "fireman": "firefighter",
                "policeman": "police officer",
                # Racial sensitivity
                "whitelist": "allowlist",
                "blacklist": "blocklist",
                "master/slave": "primary/secondary",
                # Disability sensitivity
                "blind to": "unaware of",
                "deaf to": "ignoring",
                "lame": "weak",
                # Technical elitism
                "obviously": "as shown",
                "simply": "directly",
                "just": "then",
                "easily": "straightforwardly",
                "trivially": "directly"
            },
            "avoid_terms": {
                "sanity check": "validation check",
                "crazy": "unexpected",
                "insane": "extreme",
                "retarded": "delayed",
                "handicapped": "limited"
            }
        }
    
    async def assess_bias(self, content: str, file_path: Optional[str] = None) -> BiasAssessmentResult:
        """
        Perform comprehensive bias assessment of content
        
        Args:
            content: Text content to analyze
            file_path: Optional file path for context
            
        Returns:
            BiasAssessmentResult with comprehensive analysis
        """
        start_time = datetime.now()
        
        logger.info(f"Starting bias assessment for {file_path or 'content'}")
        
        # Initialize result structure
        result = BiasAssessmentResult(
            overall_bias_score=50.0,
            component_scores={},
            passed=False,
            bias_indicators=[],
            balance_issues=[],
            recommendations=[],
            methodology_analysis={},
            platform_analysis={},
            language_analysis={},
            diversity_analysis={},
            timestamp=start_time.isoformat(),
            processing_time=0.0
        )
        
        try:
            # Perform individual bias assessments
            methodology_result = self._assess_methodology_balance(content)
            platform_result = self._assess_platform_neutrality(content)
            language_result = self._assess_language_inclusiveness(content)
            diversity_result = self._assess_context_diversity(content)
            
            # Store detailed analysis
            result.methodology_analysis = asdict(methodology_result)
            result.platform_analysis = asdict(platform_result)
            result.language_analysis = asdict(language_result)
            result.diversity_analysis = diversity_result
            
            # Calculate component scores
            result.component_scores = {
                "methodology_balance": self._score_methodology_balance(methodology_result),
                "platform_neutrality": self._score_platform_neutrality(platform_result),
                "language_inclusiveness": language_result.inclusiveness_score,
                "context_diversity": self._score_context_diversity(diversity_result)
            }
            
            # Calculate overall bias score
            result.overall_bias_score = self._calculate_overall_bias_score(result.component_scores)
            
            # Determine pass/fail
            result.passed = (
                self.config["assessment"]["minimum_pass_score"] <= 
                result.overall_bias_score <= 
                self.config["assessment"]["maximum_pass_score"]
            )
            
            # Collect bias indicators and recommendations
            result.bias_indicators = self._collect_bias_indicators(
                methodology_result, platform_result, language_result, diversity_result
            )
            
            result.balance_issues = self._collect_balance_issues(
                methodology_result, platform_result, language_result, diversity_result
            )
            
            result.recommendations = self._generate_recommendations(
                methodology_result, platform_result, language_result, diversity_result
            )
            
            # Record processing time
            result.processing_time = (datetime.now() - start_time).total_seconds()
            
            logger.info(
                f"Bias assessment completed. Score: {result.overall_bias_score:.2f}, "
                f"Passed: {result.passed}"
            )
            
        except Exception as e:
            logger.error(f"Bias assessment failed: {e}")
            result.bias_indicators.append(f"Assessment error: {str(e)}")
            result.processing_time = (datetime.now() - start_time).total_seconds()
        
        return result
    
    def _assess_methodology_balance(self, content: str) -> MethodologyBalance:
        """Assess balance between traditional and modern methodologies"""
        content_lower = content.lower()
        
        traditional_matches = []
        modern_matches = []
        
        # Count methodology term occurrences
        for term in self.methodology_terms["traditional"]:
            count = len(re.findall(r'\b' + re.escape(term.lower()) + r'\b', content_lower))
            if count > 0:
                traditional_matches.extend([term] * count)
        
        for term in self.methodology_terms["modern"]:
            count = len(re.findall(r'\b' + re.escape(term.lower()) + r'\b', content_lower))
            if count > 0:
                modern_matches.extend([term] * count)
        
        traditional_count = len(traditional_matches)
        modern_count = len(modern_matches)
        total_count = traditional_count + modern_count
        
        # Calculate balance ratio (0.0 = all traditional, 1.0 = all modern)
        if total_count > 0:
            balance_ratio = modern_count / total_count
        else:
            balance_ratio = 0.5  # Neutral if no terms found
        
        # Determine imbalance severity
        target_ratio = self.config["methodology"]["balance_target"]
        tolerance = self.config["methodology"]["tolerance"]
        
        if abs(balance_ratio - target_ratio) <= tolerance:
            imbalance_severity = "none"
        elif abs(balance_ratio - target_ratio) <= tolerance * 2:
            imbalance_severity = "mild"
        elif abs(balance_ratio - target_ratio) <= tolerance * 3:
            imbalance_severity = "moderate"
        else:
            imbalance_severity = "severe"
        
        return MethodologyBalance(
            traditional_count=traditional_count,
            modern_count=modern_count,
            balance_ratio=balance_ratio,
            traditional_terms=list(set(traditional_matches)),
            modern_terms=list(set(modern_matches)),
            imbalance_severity=imbalance_severity
        )
    
    def _assess_platform_neutrality(self, content: str) -> PlatformAnalysis:
        """Assess platform representation and neutrality"""
        content_lower = content.lower()
        platform_mentions = {}
        
        # Count platform mentions
        for platform, terms in self.platform_terms.items():
            count = 0
            for term in terms:
                count += len(re.findall(r'\b' + re.escape(term.lower()) + r'\b', content_lower))
            platform_mentions[platform] = count
        
        # Find dominant platform
        total_mentions = sum(platform_mentions.values())
        if total_mentions > 0:
            dominant_platform = max(platform_mentions, key=platform_mentions.get)
            dominance_ratio = platform_mentions[dominant_platform] / total_mentions
        else:
            dominant_platform = "none"
            dominance_ratio = 0.0
        
        # Calculate diversity score
        mentioned_platforms = sum(1 for count in platform_mentions.values() if count > 0)
        total_platforms = len(self.platform_terms)
        diversity_score = mentioned_platforms / total_platforms
        
        # Identify missing important platforms
        missing_platforms = [
            platform for platform, count in platform_mentions.items() 
            if count == 0 and platform in ["python", "r", "sql"]
        ]
        
        # Generate recommendations
        recommendations = []
        if dominance_ratio > self.config["platform"]["dominant_platform_threshold"]:
            recommendations.append(f"Reduce emphasis on {dominant_platform} (currently {dominance_ratio:.1%})")
        
        if mentioned_platforms < self.config["platform"]["minimum_platforms"]:
            recommendations.append(f"Include more platform diversity (currently {mentioned_platforms} platforms)")
        
        if missing_platforms:
            recommendations.append(f"Consider including: {', '.join(missing_platforms)}")
        
        return PlatformAnalysis(
            platform_mentions=platform_mentions,
            dominant_platform=dominant_platform,
            diversity_score=diversity_score,
            missing_platforms=missing_platforms,
            recommendations=recommendations
        )
    
    def _assess_language_inclusiveness(self, content: str) -> LanguageInclusivenessResult:
        """Assess language inclusiveness and accessibility"""
        issues_found = []
        suggestions = []
        
        # Check for biased language patterns
        for bias_type, patterns in self.bias_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    issues_found.append(f"{bias_type}: {', '.join(matches)}")
        
        # Check for non-inclusive terms
        content_lower = content.lower()
        replacements = self.inclusive_language_terms["replacements"]
        avoid_terms = self.inclusive_language_terms["avoid_terms"]
        
        for term, replacement in replacements.items():
            if term.lower() in content_lower:
                suggestions.append(f"Replace '{term}' with '{replacement}'")
        
        for term, replacement in avoid_terms.items():
            if term.lower() in content_lower:
                suggestions.append(f"Avoid '{term}', consider '{replacement}'")
        
        # Calculate readability
        try:
            readability_score = flesch_reading_ease(content)
        except:
            readability_score = 50.0  # Default if calculation fails
        
        # Analyze complexity
        complexity_analysis = self._analyze_text_complexity(content)
        
        # Calculate inclusiveness score
        total_checks = len(self.bias_patterns) * 10  # Assume 10 potential issues per category
        issues_count = len(issues_found)
        inclusiveness_score = max(0, 100 - (issues_count / total_checks * 100))
        
        return LanguageInclusivenessResult(
            inclusiveness_score=inclusiveness_score,
            issues_found=issues_found,
            suggestions=suggestions,
            readability_score=readability_score,
            complexity_analysis=complexity_analysis
        )
    
    def _analyze_text_complexity(self, content: str) -> Dict[str, Any]:
        """Analyze text complexity metrics"""
        try:
            sentences = sent_tokenize(content)
            words = word_tokenize(content)
            
            # Basic metrics
            avg_sentence_length = len(words) / len(sentences) if sentences else 0
            
            # Vocabulary complexity
            unique_words = set(word.lower() for word in words if word.isalpha())
            vocabulary_richness = len(unique_words) / len(words) if words else 0
            
            # Technical term density
            technical_terms = []
            for category_terms in self.methodology_terms.values():
                technical_terms.extend(category_terms)
            
            technical_count = sum(
                1 for word in words 
                if word.lower() in [term.lower() for term in technical_terms]
            )
            technical_density = technical_count / len(words) if words else 0
            
            return {
                "avg_sentence_length": avg_sentence_length,
                "vocabulary_richness": vocabulary_richness,
                "technical_density": technical_density,
                "total_sentences": len(sentences),
                "total_words": len(words),
                "unique_words": len(unique_words)
            }
        except Exception as e:
            logger.warning(f"Failed to analyze text complexity: {e}")
            return {}
    
    def _assess_context_diversity(self, content: str) -> Dict[str, Any]:
        """Assess diversity of contexts and examples"""
        diversity_analysis = {
            "example_contexts": [],
            "geographic_mentions": [],
            "demographic_representation": {},
            "industry_contexts": [],
            "scale_contexts": [],
            "diversity_score": 0.0
        }
        
        # Define context patterns
        context_patterns = {
            "geographic": [
                r'\b(america|usa|europe|asia|africa|australia|canada|uk|germany|france|japan|china|india)\b',
                r'\b(new york|london|tokyo|berlin|paris|sydney|toronto|mumbai|beijing|moscow)\b'
            ],
            "industries": [
                r'\b(healthcare|finance|retail|manufacturing|education|government|military|dod)\b',
                r'\b(banking|insurance|pharmaceutical|automotive|aerospace|telecom)\b'
            ],
            "demographics": [
                r'\b(student|researcher|analyst|scientist|engineer|manager|executive)\b',
                r'\b(beginner|intermediate|advanced|expert|professional)\b'
            ],
            "scale": [
                r'\b(startup|enterprise|corporation|small business|large scale|global)\b',
                r'\b(individual|team|department|organization|company)\b'
            ]
        }
        
        content_lower = content.lower()
        
        # Extract context mentions
        for context_type, patterns in context_patterns.items():
            mentions = []
            for pattern in patterns:
                matches = re.findall(pattern, content_lower)
                mentions.extend(matches)
            
            if context_type == "geographic":
                diversity_analysis["geographic_mentions"] = list(set(mentions))
            elif context_type == "industries":
                diversity_analysis["industry_contexts"] = list(set(mentions))
            elif context_type == "demographics":
                diversity_analysis["demographic_representation"] = dict(Counter(mentions))
            elif context_type == "scale":
                diversity_analysis["scale_contexts"] = list(set(mentions))
        
        # Calculate diversity score
        geographic_diversity = min(len(diversity_analysis["geographic_mentions"]) / 3, 1.0)
        industry_diversity = min(len(diversity_analysis["industry_contexts"]) / 3, 1.0)
        demographic_diversity = min(len(diversity_analysis["demographic_representation"]) / 3, 1.0)
        scale_diversity = min(len(diversity_analysis["scale_contexts"]) / 2, 1.0)
        
        diversity_analysis["diversity_score"] = (
            geographic_diversity + industry_diversity + 
            demographic_diversity + scale_diversity
        ) / 4 * 100
        
        return diversity_analysis
    
    def _score_methodology_balance(self, methodology: MethodologyBalance) -> float:
        """Score methodology balance (50 = perfect balance)"""
        target_ratio = self.config["methodology"]["balance_target"]
        
        # Convert balance ratio to bias score (50 = perfect balance)
        if methodology.balance_ratio == target_ratio:
            return 50.0
        elif methodology.balance_ratio < target_ratio:
            # Traditional bias (score < 50)
            deviation = target_ratio - methodology.balance_ratio
            return max(0.0, 50.0 - (deviation / target_ratio * 50.0))
        else:
            # Modern bias (score > 50)
            deviation = methodology.balance_ratio - target_ratio
            return min(100.0, 50.0 + (deviation / (1.0 - target_ratio) * 50.0))
    
    def _score_platform_neutrality(self, platform: PlatformAnalysis) -> float:
        """Score platform neutrality (50 = perfect neutrality)"""
        # Base score from diversity
        diversity_score = platform.diversity_score * 50  # 0-50 points
        
        # Penalty for platform dominance
        total_mentions = sum(platform.platform_mentions.values())
        if total_mentions > 0:
            max_mentions = max(platform.platform_mentions.values())
            dominance_ratio = max_mentions / total_mentions
            
            # Penalty increases with dominance
            dominance_penalty = max(0, (dominance_ratio - 0.4) * 50)  # Start penalty at 40% dominance
        else:
            dominance_penalty = 0
        
        return max(0.0, min(100.0, diversity_score + (50 - dominance_penalty)))
    
    def _score_context_diversity(self, diversity: Dict[str, Any]) -> float:
        """Score context diversity"""
        return diversity.get("diversity_score", 0.0)
    
    def _calculate_overall_bias_score(self, component_scores: Dict[str, float]) -> float:
        """Calculate weighted overall bias score"""
        weights = {
            "methodology_balance": self.config["methodology"]["weight"],
            "platform_neutrality": self.config["platform"]["weight"],
            "language_inclusiveness": self.config["language"]["weight"],
            "context_diversity": self.config["diversity"]["weight"]
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for component, score in component_scores.items():
            if component in weights:
                # Convert inclusiveness and diversity scores to bias scale (50 = perfect)
                if component in ["language_inclusiveness", "context_diversity"]:
                    # These are 0-100 scales, convert to bias scale
                    bias_score = 50.0 + (score - 50.0) * 0.5  # Compress to bias scale
                else:
                    bias_score = score
                
                weight = weights[component]
                total_score += bias_score * weight
                total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 50.0
    
    def _collect_bias_indicators(self, methodology: MethodologyBalance, 
                                platform: PlatformAnalysis,
                                language: LanguageInclusivenessResult,
                                diversity: Dict[str, Any]) -> List[str]:
        """Collect all bias indicators found"""
        indicators = []
        
        # Methodology bias indicators
        if methodology.imbalance_severity != "none":
            if methodology.balance_ratio < 0.3:
                indicators.append(f"Strong traditional methodology bias ({methodology.traditional_count} vs {methodology.modern_count})")
            elif methodology.balance_ratio > 0.7:
                indicators.append(f"Strong modern methodology bias ({methodology.modern_count} vs {methodology.traditional_count})")
        
        # Platform bias indicators
        total_mentions = sum(platform.platform_mentions.values())
        if total_mentions > 0:
            max_platform = max(platform.platform_mentions, key=platform.platform_mentions.get)
            dominance = platform.platform_mentions[max_platform] / total_mentions
            if dominance > 0.6:
                indicators.append(f"Platform bias toward {max_platform} ({dominance:.1%} of mentions)")
        
        # Language bias indicators
        indicators.extend(language.issues_found)
        
        # Diversity bias indicators
        if diversity["diversity_score"] < 50:
            indicators.append(f"Limited context diversity ({diversity['diversity_score']:.1f}%)")
        
        return indicators
    
    def _collect_balance_issues(self, methodology: MethodologyBalance,
                               platform: PlatformAnalysis,
                               language: LanguageInclusivenessResult,
                               diversity: Dict[str, Any]) -> List[str]:
        """Collect balance-related issues"""
        issues = []
        
        # Methodology balance issues
        if methodology.imbalance_severity in ["moderate", "severe"]:
            issues.append(f"Methodology imbalance: {methodology.imbalance_severity}")
        
        # Platform balance issues
        if platform.diversity_score < 0.5:
            issues.append("Limited platform diversity")
        
        # Language balance issues
        if language.readability_score < 40 or language.readability_score > 80:
            issues.append(f"Readability imbalance (score: {language.readability_score:.1f})")
        
        # Context balance issues
        if len(diversity.get("geographic_mentions", [])) < 2:
            issues.append("Limited geographic context diversity")
        
        return issues
    
    def _generate_recommendations(self, methodology: MethodologyBalance,
                                 platform: PlatformAnalysis,
                                 language: LanguageInclusivenessResult,
                                 diversity: Dict[str, Any]) -> List[str]:
        """Generate recommendations for bias mitigation"""
        recommendations = []
        
        # Methodology recommendations
        if methodology.balance_ratio < 0.4:
            recommendations.append("Include more modern methodologies and tools")
            recommendations.append("Add examples using contemporary data science approaches")
        elif methodology.balance_ratio > 0.6:
            recommendations.append("Include more traditional statistical methods")
            recommendations.append("Provide foundational statistical context")
        
        # Platform recommendations
        recommendations.extend(platform.recommendations)
        
        # Language recommendations
        recommendations.extend(language.suggestions[:5])  # Limit to top 5
        
        if language.readability_score < 60:
            recommendations.append("Simplify language for better accessibility")
        elif language.readability_score > 80:
            recommendations.append("Add more technical depth while maintaining clarity")
        
        # Diversity recommendations
        if diversity["diversity_score"] < 70:
            recommendations.append("Include more diverse examples and contexts")
            recommendations.append("Add examples from different industries and scales")
        
        if len(diversity.get("geographic_mentions", [])) < 2:
            recommendations.append("Include examples from different geographic regions")
        
        return recommendations
    
    def generate_bias_report(self, results: List[BiasAssessmentResult]) -> Dict[str, Any]:
        """Generate comprehensive bias assessment report"""
        if not results:
            return {"error": "No results to analyze"}
        
        report = {
            "summary": {
                "total_files": len(results),
                "passed": sum(1 for r in results if r.passed),
                "failed": sum(1 for r in results if not r.passed),
                "average_bias_score": sum(r.overall_bias_score for r in results) / len(results),
                "bias_score_range": {
                    "min": min(r.overall_bias_score for r in results),
                    "max": max(r.overall_bias_score for r in results)
                }
            },
            "component_analysis": {},
            "common_bias_indicators": {},
            "frequent_recommendations": {},
            "methodology_analysis": {
                "average_balance": 0.0,
                "common_imbalances": []
            },
            "platform_analysis": {
                "platform_mentions": {},
                "diversity_scores": []
            },
            "timestamp": datetime.now().isoformat()
        }
        
        # Analyze component scores
        components = set()
        for result in results:
            components.update(result.component_scores.keys())
        
        for component in components:
            scores = [r.component_scores.get(component, 0) for r in results]
            report["component_analysis"][component] = {
                "average": sum(scores) / len(scores),
                "min": min(scores),
                "max": max(scores),
                "std_dev": np.std(scores) if len(scores) > 1 else 0.0
            }
        
        # Collect common bias indicators
        all_indicators = []
        for result in results:
            all_indicators.extend(result.bias_indicators)
        
        indicator_counts = Counter(all_indicators)
        report["common_bias_indicators"] = dict(indicator_counts.most_common(10))
        
        # Collect frequent recommendations
        all_recommendations = []
        for result in results:
            all_recommendations.extend(result.recommendations)
        
        rec_counts = Counter(all_recommendations)
        report["frequent_recommendations"] = dict(rec_counts.most_common(10))
        
        # Methodology analysis
        balance_ratios = []
        for result in results:
            if "balance_ratio" in result.methodology_analysis:
                balance_ratios.append(result.methodology_analysis["balance_ratio"])
        
        if balance_ratios:
            report["methodology_analysis"]["average_balance"] = sum(balance_ratios) / len(balance_ratios)
        
        # Platform analysis
        all_platform_mentions = {}
        diversity_scores = []
        
        for result in results:
            if "platform_mentions" in result.platform_analysis:
                for platform, count in result.platform_analysis["platform_mentions"].items():
                    all_platform_mentions[platform] = all_platform_mentions.get(platform, 0) + count
            
            if "diversity_score" in result.platform_analysis:
                diversity_scores.append(result.platform_analysis["diversity_score"])
        
        report["platform_analysis"]["platform_mentions"] = all_platform_mentions
        report["platform_analysis"]["diversity_scores"] = diversity_scores
        
        return report
    
    def create_bias_visualization(self, results: List[BiasAssessmentResult], 
                                 output_dir: Optional[Path] = None) -> Dict[str, str]:
        """Create visualizations for bias assessment results"""
        if not results:
            return {}
        
        output_dir = output_dir or Path("bias_visualizations")
        output_dir.mkdir(exist_ok=True)
        
        created_files = {}
        
        try:
            # Bias score distribution
            bias_scores = [r.overall_bias_score for r in results]
            
            plt.figure(figsize=(10, 6))
            plt.hist(bias_scores, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            plt.axvline(x=50, color='red', linestyle='--', label='Perfect Balance')
            plt.axvline(x=np.mean(bias_scores), color='green', linestyle='-', label='Average')
            plt.xlabel('Bias Score')
            plt.ylabel('Frequency')
            plt.title('Distribution of Bias Scores')
            plt.legend()
            plt.grid(True, alpha=0.3)
            
            score_dist_path = output_dir / "bias_score_distribution.png"
            plt.savefig(score_dist_path, dpi=300, bbox_inches='tight')
            plt.close()
            created_files["bias_score_distribution"] = str(score_dist_path)
            
            # Component analysis
            component_data = {}
            for result in results:
                for component, score in result.component_scores.items():
                    if component not in component_data:
                        component_data[component] = []
                    component_data[component].append(score)
            
            if component_data:
                plt.figure(figsize=(12, 8))
                components = list(component_data.keys())
                averages = [np.mean(component_data[comp]) for comp in components]
                
                bars = plt.bar(components, averages, color='lightcoral', alpha=0.7)
                plt.axhline(y=50, color='red', linestyle='--', label='Perfect Balance')
                plt.ylabel('Average Score')
                plt.title('Component Analysis')
                plt.xticks(rotation=45, ha='right')
                plt.legend()
                plt.grid(True, alpha=0.3)
                
                # Add value labels on bars
                for bar, avg in zip(bars, averages):
                    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                           f'{avg:.1f}', ha='center', va='bottom')
                
                component_path = output_dir / "component_analysis.png"
                plt.savefig(component_path, dpi=300, bbox_inches='tight')
                plt.close()
                created_files["component_analysis"] = str(component_path)
            
        except Exception as e:
            logger.warning(f"Failed to create visualizations: {e}")
        
        return created_files


async def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Bias Assessor")
    parser.add_argument("--file", required=True, help="File to assess")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--visualize", action="store_true", help="Create visualizations")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    assessor = BiasAssessor(args.config)
    
    try:
        # Read content
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Perform assessment
        result = await assessor.assess_bias(content, args.file)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(asdict(result), f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            print(f"Bias Score: {result.overall_bias_score:.2f}")
            print(f"Passed: {result.passed}")
            
            if result.bias_indicators:
                print("\nBias Indicators:")
                for indicator in result.bias_indicators:
                    print(f"  - {indicator}")
            
            if result.recommendations:
                print("\nRecommendations:")
                for rec in result.recommendations[:5]:  # Show top 5
                    print(f"  - {rec}")
        
        # Create visualizations if requested
        if args.visualize:
            viz_files = assessor.create_bias_visualization([result])
            if viz_files:
                print(f"\nVisualizations created:")
                for name, path in viz_files.items():
                    print(f"  - {name}: {path}")
    
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        exit(1)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())