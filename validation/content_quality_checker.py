#!/usr/bin/env python3
"""
Content Quality Checker Module for Chapter Content Management System
==================================================================

Comprehensive content quality assessment system that evaluates:
- Learning objectives alignment and clarity
- Content completeness and structure
- Educational effectiveness and progression
- Accessibility and inclusive design
- Assessment criteria and validation
- Knowledge transfer optimization

Author: Claude Code Implementation
Created: 2025-07-28
Version: 1.0.0
"""

import re
import json
import logging
import nltk
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
import yaml
import numpy as np
from textstat import flesch_reading_ease, flesch_kincaid_grade, automated_readability_index
import spacy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Download required NLTK data
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)
    nltk.download('wordnet', quiet=True)
except:
    pass

from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
from nltk import pos_tag

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ContentQualityResult:
    """Result of content quality assessment"""
    overall_quality_score: float
    component_scores: Dict[str, float]
    passed: bool
    quality_issues: List[str]
    strengths: List[str]
    recommendations: List[str]
    learning_objectives_analysis: Dict[str, Any]
    content_structure_analysis: Dict[str, Any]
    educational_effectiveness: Dict[str, Any]
    accessibility_analysis: Dict[str, Any]
    completeness_analysis: Dict[str, Any]
    timestamp: str
    processing_time: float


@dataclass
class LearningObjective:
    """Represents a learning objective"""
    text: str
    bloom_level: str
    measurable: bool
    specific: bool
    achievable: bool
    relevant: bool
    time_bound: bool
    keywords: List[str]
    assessment_alignment: float


@dataclass
class ContentStructure:
    """Analysis of content structure"""
    has_introduction: bool
    has_learning_objectives: bool
    has_prerequisites: bool
    has_examples: bool
    has_exercises: bool
    has_assessment: bool
    has_summary: bool
    has_references: bool
    logical_flow_score: float
    section_balance: Dict[str, float]


@dataclass
class AccessibilityMetrics:
    """Accessibility assessment metrics"""
    readability_score: float
    reading_grade_level: float
    vocabulary_complexity: float
    sentence_complexity: float
    has_alt_text: bool
    has_captions: bool
    color_contrast_issues: int
    navigation_clarity: float
    inclusive_design_score: float


class ContentQualityChecker:
    """
    Comprehensive content quality assessment system
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Content Quality Checker
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        
        # Initialize NLP components
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            logger.warning("spaCy model not found. Some features may be limited.")
            self.nlp = None
        
        self.stop_words = set(stopwords.words('english'))
        
        # Load educational frameworks and patterns
        self.bloom_taxonomy = self._load_bloom_taxonomy()
        self.learning_verbs = self._load_learning_verbs()
        self.content_patterns = self._load_content_patterns()
        self.assessment_patterns = self._load_assessment_patterns()
        
        logger.info("Content Quality Checker initialized")
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load content quality checker configuration"""
        default_config = {
            "quality_assessment": {
                "minimum_pass_score": 80.0,
                "excellence_threshold": 90.0,
                "component_weights": {
                    "learning_objectives": 0.25,
                    "content_structure": 0.20,
                    "educational_effectiveness": 0.25,
                    "accessibility": 0.15,
                    "completeness": 0.15
                }
            },
            "learning_objectives": {
                "minimum_count": 3,
                "maximum_count": 8,
                "smart_criteria_weight": 0.4,
                "bloom_distribution_weight": 0.3,
                "alignment_weight": 0.3
            },
            "content_structure": {
                "required_sections": [
                    "introduction", "learning_objectives", "content", 
                    "examples", "exercises", "summary"
                ],
                "logical_flow_weight": 0.4,
                "section_balance_weight": 0.3,
                "completeness_weight": 0.3
            },
            "educational_effectiveness": {
                "engagement_weight": 0.3,
                "clarity_weight": 0.3,
                "practical_application_weight": 0.2,
                "knowledge_transfer_weight": 0.2
            },
            "accessibility": {
                "readability_target_min": 60.0,
                "readability_target_max": 80.0,
                "grade_level_max": 12.0,
                "vocabulary_complexity_max": 0.7,
                "inclusive_design_min": 85.0
            },
            "completeness": {
                "topic_coverage_weight": 0.4,
                "example_adequacy_weight": 0.3,
                "resource_availability_weight": 0.3
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
    
    def _load_bloom_taxonomy(self) -> Dict[str, List[str]]:
        """Load Bloom's taxonomy levels and associated verbs"""
        return {
            "remember": [
                "define", "describe", "identify", "list", "name", "recall",
                "recognize", "select", "state", "tell", "who", "what", "when", "where"
            ],
            "understand": [
                "classify", "comprehend", "describe", "discuss", "explain",
                "express", "identify", "indicate", "locate", "recognize",
                "report", "restate", "review", "select", "translate"
            ],
            "apply": [
                "apply", "choose", "demonstrate", "dramatize", "employ",
                "illustrate", "interpret", "operate", "practice", "schedule",
                "sketch", "solve", "use", "write"
            ],
            "analyze": [
                "analyze", "appraise", "calculate", "categorize", "compare",
                "contrast", "criticize", "differentiate", "discriminate",
                "distinguish", "examine", "experiment", "question", "test"
            ],
            "evaluate": [
                "appraise", "argue", "assess", "attach", "choose", "compare",
                "defend", "estimate", "judge", "predict", "rate", "core",
                "select", "support", "value", "evaluate"
            ],
            "create": [
                "arrange", "assemble", "collect", "compose", "construct",
                "create", "design", "develop", "formulate", "manage",
                "organize", "plan", "prepare", "propose", "set up", "write"
            ]
        }
    
    def _load_learning_verbs(self) -> Set[str]:
        """Load all learning action verbs"""
        all_verbs = set()
        for verbs in self.bloom_taxonomy.values():
            all_verbs.update(verbs)
        return all_verbs
    
    def _load_content_patterns(self) -> Dict[str, List[str]]:
        """Load content section identification patterns"""
        return {
            "introduction": [
                r"(?i)^#\s*introduction",
                r"(?i)^##\s*introduction",
                r"(?i)^#\s*overview",
                r"(?i)this\s+chapter\s+(?:will\s+)?(?:cover|introduce|discuss)"
            ],
            "learning_objectives": [
                r"(?i)learning\s+objectives?",
                r"(?i)objectives?",
                r"(?i)by\s+the\s+end\s+of\s+this",
                r"(?i)you\s+will\s+(?:be\s+able\s+to|learn|understand)"
            ],
            "prerequisites": [
                r"(?i)prerequisites?",
                r"(?i)requirements?",
                r"(?i)before\s+(?:starting|beginning)",
                r"(?i)you\s+should\s+(?:have|know|understand)"
            ],
            "examples": [
                r"(?i)example[s:]",
                r"(?i)for\s+(?:example|instance)",
                r"(?i)let'?s\s+(?:look\s+at|consider|examine)",
                r"```\w*\n"  # Code blocks
            ],
            "exercises": [
                r"(?i)exercise[s:]",
                r"(?i)practice",
                r"(?i)try\s+(?:this|it)",
                r"(?i)your\s+turn",
                r"(?i)hands-on"
            ],
            "assessment": [
                r"(?i)assessment",
                r"(?i)quiz",
                r"(?i)test\s+your",
                r"(?i)check\s+your\s+understanding"
            ],
            "summary": [
                r"(?i)summary",
                r"(?i)conclusion",
                r"(?i)key\s+(?:points|takeaways)",
                r"(?i)in\s+this\s+(?:chapter|section).*(?:learned|covered)"
            ],
            "references": [
                r"(?i)references?",
                r"(?i)bibliography",
                r"(?i)further\s+reading",
                r"(?i)resources?"
            ]
        }
    
    def _load_assessment_patterns(self) -> Dict[str, List[str]]:
        """Load assessment criteria patterns"""
        return {
            "formative": [
                r"(?i)check\s+your\s+understanding",
                r"(?i)quick\s+(?:check|quiz)",
                r"(?i)think\s+about",
                r"(?i)reflect\s+on"
            ],
            "summative": [
                r"(?i)final\s+(?:assessment|quiz|test)",
                r"(?i)chapter\s+(?:assessment|quiz)",
                r"(?i)comprehensive\s+(?:review|test)"
            ],
            "practical": [
                r"(?i)hands-on\s+(?:exercise|activity)",
                r"(?i)build\s+(?:a|your)",
                r"(?i)implement",
                r"(?i)create\s+(?:a|your)"
            ]
        }
    
    async def assess_content_quality(self, content: str, 
                                   metadata: Optional[Dict] = None,
                                   file_path: Optional[str] = None) -> ContentQualityResult:
        """
        Perform comprehensive content quality assessment
        
        Args:
            content: Text content to analyze
            metadata: Optional metadata about the content
            file_path: Optional file path for context
            
        Returns:
            ContentQualityResult with comprehensive analysis
        """
        start_time = datetime.now()
        
        logger.info(f"Starting content quality assessment for {file_path or 'content'}")
        
        # Initialize result structure
        result = ContentQualityResult(
            overall_quality_score=0.0,
            component_scores={},
            passed=False,
            quality_issues=[],
            strengths=[],
            recommendations=[],
            learning_objectives_analysis={},
            content_structure_analysis={},
            educational_effectiveness={},
            accessibility_analysis={},
            completeness_analysis={},
            timestamp=start_time.isoformat(),
            processing_time=0.0
        )
        
        try:
            # Perform individual quality assessments
            objectives_result = self._assess_learning_objectives(content, metadata)
            structure_result = self._assess_content_structure(content)
            effectiveness_result = self._assess_educational_effectiveness(content)
            accessibility_result = self._assess_accessibility(content)
            completeness_result = self._assess_completeness(content, metadata)
            
            # Store detailed analysis
            result.learning_objectives_analysis = asdict(objectives_result) if objectives_result else {}
            result.content_structure_analysis = asdict(structure_result)
            result.educational_effectiveness = effectiveness_result
            result.accessibility_analysis = asdict(accessibility_result)
            result.completeness_analysis = completeness_result
            
            # Calculate component scores
            result.component_scores = {
                "learning_objectives": self._score_learning_objectives(objectives_result),
                "content_structure": self._score_content_structure(structure_result),
                "educational_effectiveness": self._score_educational_effectiveness(effectiveness_result),
                "accessibility": self._score_accessibility(accessibility_result),
                "completeness": self._score_completeness(completeness_result)
            }
            
            # Calculate overall quality score
            result.overall_quality_score = self._calculate_overall_quality_score(result.component_scores)
            
            # Determine pass/fail
            result.passed = result.overall_quality_score >= self.config["quality_assessment"]["minimum_pass_score"]
            
            # Collect quality issues, strengths, and recommendations
            result.quality_issues = self._collect_quality_issues(
                objectives_result, structure_result, effectiveness_result,
                accessibility_result, completeness_result
            )
            
            result.strengths = self._collect_strengths(
                objectives_result, structure_result, effectiveness_result,
                accessibility_result, completeness_result
            )
            
            result.recommendations = self._generate_quality_recommendations(
                objectives_result, structure_result, effectiveness_result,
                accessibility_result, completeness_result
            )
            
            # Record processing time
            result.processing_time = (datetime.now() - start_time).total_seconds()
            
            logger.info(
                f"Content quality assessment completed. Score: {result.overall_quality_score:.2f}, "
                f"Passed: {result.passed}"
            )
            
        except Exception as e:
            logger.error(f"Content quality assessment failed: {e}")
            result.quality_issues.append(f"Assessment error: {str(e)}")
            result.processing_time = (datetime.now() - start_time).total_seconds()
        
        return result
    
    def _assess_learning_objectives(self, content: str, 
                                   metadata: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
        """Assess learning objectives quality and alignment"""
        objectives_analysis = {
            "objectives_found": [],
            "count": 0,
            "smart_compliance": 0.0,
            "bloom_distribution": {},
            "measurability_score": 0.0,
            "alignment_score": 0.0,
            "issues": [],
            "strengths": []
        }
        
        # Extract learning objectives from content
        objectives_text = self._extract_learning_objectives(content)
        
        if not objectives_text:
            objectives_analysis["issues"].append("No learning objectives found")
            return objectives_analysis
        
        # Parse individual objectives
        objectives = self._parse_objectives(objectives_text)
        objectives_analysis["objectives_found"] = [obj.text for obj in objectives]
        objectives_analysis["count"] = len(objectives)
        
        # Check count appropriateness
        min_count = self.config["learning_objectives"]["minimum_count"]
        max_count = self.config["learning_objectives"]["maximum_count"]
        
        if len(objectives) < min_count:
            objectives_analysis["issues"].append(f"Too few objectives ({len(objectives)} < {min_count})")
        elif len(objectives) > max_count:
            objectives_analysis["issues"].append(f"Too many objectives ({len(objectives)} > {max_count})")
        else:
            objectives_analysis["strengths"].append("Appropriate number of objectives")
        
        # Assess SMART criteria compliance
        smart_scores = []
        for obj in objectives:
            smart_score = self._evaluate_smart_criteria(obj)
            smart_scores.append(smart_score)
        
        objectives_analysis["smart_compliance"] = np.mean(smart_scores) if smart_scores else 0.0
        
        # Analyze Bloom's taxonomy distribution
        bloom_counts = defaultdict(int)
        for obj in objectives:
            bloom_counts[obj.bloom_level] += 1
        
        objectives_analysis["bloom_distribution"] = dict(bloom_counts)
        
        # Assess measurability
        measurable_count = sum(1 for obj in objectives if obj.measurable)
        objectives_analysis["measurability_score"] = (
            measurable_count / len(objectives) * 100 if objectives else 0.0
        )
        
        # Assess alignment with content
        alignment_scores = []
        for obj in objectives:
            alignment = self._assess_objective_content_alignment(obj, content)
            alignment_scores.append(alignment)
        
        objectives_analysis["alignment_score"] = np.mean(alignment_scores) if alignment_scores else 0.0
        
        return objectives_analysis
    
    def _extract_learning_objectives(self, content: str) -> str:
        """Extract learning objectives section from content"""
        patterns = self.content_patterns["learning_objectives"]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
            if match:
                # Extract text from match to next major heading or end
                start_pos = match.end()
                
                # Look for next major section
                next_section_pattern = r'\n\s*#{1,3}\s+(?!.*(?:objective|goal))'
                next_match = re.search(next_section_pattern, content[start_pos:], re.IGNORECASE)
                
                if next_match:
                    end_pos = start_pos + next_match.start()
                    return content[start_pos:end_pos].strip()
                else:
                    # Take reasonable chunk (next 500 chars or to end)
                    return content[start_pos:start_pos + 500].strip()
        
        return ""
    
    def _parse_objectives(self, objectives_text: str) -> List[LearningObjective]:
        """Parse individual learning objectives from text"""
        objectives = []
        
        # Split by bullet points, numbers, or line breaks
        lines = re.split(r'\n\s*(?:[-*•]|\d+\.)\s*', objectives_text)
        
        for line in lines:
            line = line.strip()
            if len(line) > 10:  # Minimum length for meaningful objective
                obj = self._analyze_objective(line)
                if obj:
                    objectives.append(obj)
        
        return objectives
    
    def _analyze_objective(self, text: str) -> Optional[LearningObjective]:
        """Analyze a single learning objective"""
        text = text.strip()
        if not text:
            return None
        
        # Determine Bloom's taxonomy level
        bloom_level = self._classify_bloom_level(text)
        
        # Assess SMART criteria
        measurable = self._is_measurable(text)
        specific = self._is_specific(text)
        achievable = self._is_achievable(text)
        relevant = self._is_relevant(text)
        time_bound = self._is_time_bound(text)
        
        # Extract keywords
        keywords = self._extract_objective_keywords(text)
        
        return LearningObjective(
            text=text,
            bloom_level=bloom_level,
            measurable=measurable,
            specific=specific,
            achievable=achievable,
            relevant=relevant,
            time_bound=time_bound,
            keywords=keywords,
            assessment_alignment=0.0  # Will be calculated separately
        )
    
    def _classify_bloom_level(self, text: str) -> str:
        """Classify objective according to Bloom's taxonomy"""
        text_lower = text.lower()
        
        # Count verbs for each level
        level_scores = {}
        for level, verbs in self.bloom_taxonomy.items():
            score = sum(1 for verb in verbs if verb in text_lower)
            level_scores[level] = score
        
        # Return level with highest score, default to 'understand'
        if any(level_scores.values()):
            return max(level_scores, key=level_scores.get)
        else:
            return "understand"
    
    def _is_measurable(self, text: str) -> bool:
        """Check if objective is measurable"""
        measurable_indicators = [
            r'\b(?:identify|list|describe|explain|demonstrate|calculate|analyze|evaluate|create)\b',
            r'\b(?:will\s+be\s+able\s+to)\b',
            r'\b(?:students?\s+(?:will|can|should))\b',
            r'\b(?:by\s+the\s+end)\b'
        ]
        
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in measurable_indicators)
    
    def _is_specific(self, text: str) -> bool:
        """Check if objective is specific"""
        # Look for specific topics, tools, or contexts
        specific_indicators = [
            r'\busing\s+\w+',
            r'\bwith\s+\w+',
            r'\bin\s+(?:python|r|sql|databricks|qlik)',
            r'\b(?:dataset|data|algorithm|model|analysis)\b'
        ]
        
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in specific_indicators)
    
    def _is_achievable(self, text: str) -> bool:
        """Check if objective seems achievable"""
        # This is subjective, but we can check for overly ambitious language
        unrealistic_indicators = [
            r'\b(?:master|expert|perfect|complete|total)\b',
            r'\ball\s+(?:aspects|elements|components)',
            r'\beverything\s+about'
        ]
        
        # Return True if no unrealistic indicators found
        return not any(re.search(pattern, text, re.IGNORECASE) for pattern in unrealistic_indicators)
    
    def _is_relevant(self, text: str) -> bool:
        """Check if objective is relevant to data science"""
        relevant_topics = [
            'data', 'analysis', 'statistics', 'machine learning', 'visualization',
            'python', 'r', 'sql', 'model', 'algorithm', 'database', 'analytics'
        ]
        
        text_lower = text.lower()
        return any(topic in text_lower for topic in relevant_topics)
    
    def _is_time_bound(self, text: str) -> bool:
        """Check if objective has time boundaries"""
        time_indicators = [
            r'\bby\s+the\s+end\s+of',
            r'\bafter\s+(?:this|completing)',
            r'\bwithin\s+\d+\s+(?:hours?|days?|weeks?)',
            r'\bduring\s+this\s+(?:chapter|section|module)'
        ]
        
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in time_indicators)
    
    def _extract_objective_keywords(self, text: str) -> List[str]:
        """Extract key terms from objective"""
        # Remove common stop words and extract meaningful terms
        words = word_tokenize(text.lower())
        keywords = [
            word for word in words 
            if word.isalpha() and word not in self.stop_words and len(word) > 3
        ]
        
        return keywords[:5]  # Return top 5 keywords
    
    def _evaluate_smart_criteria(self, objective: LearningObjective) -> float:
        """Evaluate SMART criteria compliance (0-100)"""
        criteria_scores = [
            100 if objective.specific else 0,
            100 if objective.measurable else 0,
            100 if objective.achievable else 0,
            100 if objective.relevant else 0,
            100 if objective.time_bound else 0
        ]
        
        return np.mean(criteria_scores)
    
    def _assess_objective_content_alignment(self, objective: LearningObjective, content: str) -> float:
        """Assess how well objective aligns with content"""
        content_lower = content.lower()
        
        # Check if objective keywords appear in content
        keyword_matches = sum(
            1 for keyword in objective.keywords 
            if keyword in content_lower
        )
        
        keyword_alignment = (
            keyword_matches / len(objective.keywords) * 100 
            if objective.keywords else 0
        )
        
        # Check if action verbs from objective appear in content
        verb_pattern = rf'\b{re.escape(objective.bloom_level)}\b'
        verb_matches = len(re.findall(verb_pattern, content_lower))
        verb_alignment = min(verb_matches * 20, 100)  # Cap at 100
        
        return (keyword_alignment + verb_alignment) / 2
    
    def _assess_content_structure(self, content: str) -> ContentStructure:
        """Assess overall content structure and organization"""
        structure = ContentStructure(
            has_introduction=False,
            has_learning_objectives=False,
            has_prerequisites=False,
            has_examples=False,
            has_exercises=False,
            has_assessment=False,
            has_summary=False,
            has_references=False,
            logical_flow_score=0.0,
            section_balance={}
        )
        
        # Check for required sections
        for section, patterns in self.content_patterns.items():
            section_found = any(
                re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
                for pattern in patterns
            )
            setattr(structure, f"has_{section}", section_found)
        
        # Assess logical flow
        structure.logical_flow_score = self._assess_logical_flow(content)
        
        # Assess section balance
        structure.section_balance = self._assess_section_balance(content)
        
        return structure
    
    def _assess_logical_flow(self, content: str) -> float:
        """Assess logical flow and organization of content"""
        flow_score = 100.0
        
        # Check for proper heading hierarchy
        headings = re.findall(r'^(#{1,6})\s+(.+)$', content, re.MULTILINE)
        
        if headings:
            prev_level = 0
            for heading_marks, title in headings:
                current_level = len(heading_marks)
                
                # Penalize for skipping levels (e.g., # to ###)
                if current_level > prev_level + 1:
                    flow_score -= 5
                
                prev_level = current_level
        
        # Check for introduction before main content
        intro_pattern = self.content_patterns["introduction"][0]
        intro_match = re.search(intro_pattern, content, re.IGNORECASE)
        
        if intro_match and intro_match.start() > len(content) * 0.3:
            flow_score -= 10  # Introduction should be early
        
        # Check for summary near the end
        summary_patterns = self.content_patterns["summary"]
        summary_found = False
        
        for pattern in summary_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match and match.start() > len(content) * 0.7:
                summary_found = True
                break
        
        if not summary_found:
            flow_score -= 10
        
        return max(0.0, flow_score)
    
    def _assess_section_balance(self, content: str) -> Dict[str, float]:
        """Assess balance between different content sections"""
        sections = {}
        total_length = len(content)
        
        if total_length == 0:
            return sections
        
        # Split content by major headings
        heading_splits = re.split(r'^#{1,3}\s+.+$', content, flags=re.MULTILINE)
        
        if len(heading_splits) > 1:
            for i, section in enumerate(heading_splits[1:], 1):  # Skip first empty split
                section_length = len(section.strip())
                sections[f"section_{i}"] = section_length / total_length * 100
        
        return sections
    
    def _assess_educational_effectiveness(self, content: str) -> Dict[str, Any]:
        """Assess educational effectiveness of content"""
        effectiveness = {
            "engagement_score": 0.0,
            "clarity_score": 0.0,
            "practical_application_score": 0.0,
            "knowledge_transfer_score": 0.0,
            "interactive_elements": 0,
            "visual_aids": 0,
            "real_world_examples": 0,
            "progressive_complexity": 0.0
        }
        
        # Assess engagement
        effectiveness["engagement_score"] = self._assess_engagement(content)
        
        # Assess clarity
        effectiveness["clarity_score"] = self._assess_clarity(content)
        
        # Assess practical application
        effectiveness["practical_application_score"] = self._assess_practical_application(content)
        
        # Assess knowledge transfer
        effectiveness["knowledge_transfer_score"] = self._assess_knowledge_transfer(content)
        
        # Count interactive and visual elements
        effectiveness["interactive_elements"] = self._count_interactive_elements(content)
        effectiveness["visual_aids"] = self._count_visual_aids(content)
        effectiveness["real_world_examples"] = self._count_real_world_examples(content)
        
        # Assess progressive complexity
        effectiveness["progressive_complexity"] = self._assess_progressive_complexity(content)
        
        return effectiveness
    
    def _assess_engagement(self, content: str) -> float:
        """Assess content engagement level"""
        engagement_score = 0.0
        
        # Look for engaging language patterns
        engaging_patterns = [
            r'\b(?:imagine|consider|think about|what if|let\'s)\b',
            r'\b(?:you|your)\b',  # Direct address
            r'\?',  # Questions
            r'\b(?:discover|explore|learn|master)\b'
        ]
        
        total_sentences = len(sent_tokenize(content))
        if total_sentences == 0:
            return 0.0
        
        engaging_sentences = 0
        for pattern in engaging_patterns:
            engaging_sentences += len(re.findall(pattern, content, re.IGNORECASE))
        
        engagement_score = min(engaging_sentences / total_sentences * 100, 100.0)
        
        return engagement_score
    
    def _assess_clarity(self, content: str) -> float:
        """Assess content clarity and comprehensibility"""
        clarity_score = 100.0
        
        # Penalize overly complex sentences
        sentences = sent_tokenize(content)
        if sentences:
            avg_sentence_length = np.mean([len(word_tokenize(s)) for s in sentences])
            if avg_sentence_length > 25:  # Very long sentences
                clarity_score -= (avg_sentence_length - 25) * 2
        
        # Penalize excessive jargon without explanation
        jargon_terms = [
            'algorithm', 'paradigm', 'framework', 'methodology', 'architecture',
            'optimization', 'implementation', 'instantiation', 'polymorphism'
        ]
        
        jargon_count = sum(
            len(re.findall(rf'\b{term}\b', content, re.IGNORECASE))
            for term in jargon_terms
        )
        
        # Look for explanations or definitions
        explanation_patterns = [
            r'(?:is defined as|means|refers to|is when)',
            r'(?:in other words|that is|i\.e\.)',
            r'\([^)]*\)'  # Parenthetical explanations
        ]
        
        explanations = sum(
            len(re.findall(pattern, content, re.IGNORECASE))
            for pattern in explanation_patterns
        )
        
        # Penalize if jargon is used without sufficient explanation
        if jargon_count > explanations * 2:
            clarity_score -= (jargon_count - explanations * 2) * 5
        
        return max(0.0, clarity_score)
    
    def _assess_practical_application(self, content: str) -> float:
        """Assess practical application and hands-on elements"""
        practical_score = 0.0
        
        # Count code examples
        code_blocks = len(re.findall(r'```[\w]*\n', content))
        
        # Count practical activity indicators
        practical_patterns = [
            r'(?i)\b(?:try|practice|implement|build|create|exercise)\b',
            r'(?i)\bhands-on\b',
            r'(?i)\bstep-by-step\b',
            r'(?i)\bexample\b'
        ]
        
        practical_indicators = sum(
            len(re.findall(pattern, content))
            for pattern in practical_patterns
        )
        
        # Score based on practical elements
        practical_score = min((code_blocks * 10) + (practical_indicators * 2), 100.0)
        
        return practical_score
    
    def _assess_knowledge_transfer(self, content: str) -> float:
        """Assess knowledge transfer effectiveness"""
        transfer_score = 0.0
        
        # Look for knowledge transfer patterns
        transfer_patterns = [
            r'(?i)\b(?:remember|recall|apply|use|transfer)\b',
            r'(?i)\bin\s+(?:real\s+world|practice|industry)\b',
            r'(?i)\b(?:scenario|situation|case\s+study)\b',
            r'(?i)\b(?:connection|relationship|similarity)\b'
        ]
        
        transfer_indicators = sum(
            len(re.findall(pattern, content))
            for pattern in transfer_patterns
        )
        
        # Look for explicit connections to prior knowledge
        connection_patterns = [
            r'(?i)\b(?:as\s+we\s+learned|previously|earlier|remember)\b',
            r'(?i)\b(?:building\s+on|extends|relates\s+to)\b'
        ]
        
        connections = sum(
            len(re.findall(pattern, content))
            for pattern in connection_patterns
        )
        
        transfer_score = min((transfer_indicators * 5) + (connections * 10), 100.0)
        
        return transfer_score
    
    def _count_interactive_elements(self, content: str) -> int:
        """Count interactive elements in content"""
        interactive_patterns = [
            r'(?i)\b(?:quiz|poll|survey|interactive)\b',
            r'(?i)\b(?:click|drag|select|choose)\b',
            r'\[.*\]\(.*\)',  # Links
            r'(?i)\b(?:video|animation|simulation)\b'
        ]
        
        return sum(
            len(re.findall(pattern, content))
            for pattern in interactive_patterns
        )
    
    def _count_visual_aids(self, content: str) -> int:
        """Count visual aids and multimedia elements"""
        visual_patterns = [
            r'!\[.*\]\(.*\)',  # Images
            r'(?i)\b(?:figure|chart|graph|diagram|illustration)\b',
            r'(?i)\b(?:table|visualization|plot)\b'
        ]
        
        return sum(
            len(re.findall(pattern, content))
            for pattern in visual_patterns
        )
    
    def _count_real_world_examples(self, content: str) -> int:
        """Count real-world examples and case studies"""
        example_patterns = [
            r'(?i)\b(?:real[-\s]world|industry|business|case\s+study)\b',
            r'(?i)\b(?:company|organization|enterprise)\b.*(?:example|case)',
            r'(?i)\b(?:netflix|amazon|google|microsoft|facebook)\b'  # Well-known companies
        ]
        
        return sum(
            len(re.findall(pattern, content))
            for pattern in example_patterns
        )
    
    def _assess_progressive_complexity(self, content: str) -> float:
        """Assess whether content builds complexity progressively"""
        # This is a simplified heuristic - could be enhanced with more sophisticated analysis
        sections = re.split(r'^#{1,3}\s+.+$', content, flags=re.MULTILINE)
        
        if len(sections) < 3:
            return 50.0  # Neutral score for short content
        
        # Analyze vocabulary complexity progression
        complexity_scores = []
        for section in sections[1:]:  # Skip first empty section
            if section.strip():
                words = word_tokenize(section.lower())
                # Simple complexity measure: average word length
                if words:
                    avg_word_length = np.mean([len(word) for word in words if word.isalpha()])
                    complexity_scores.append(avg_word_length)
        
        if len(complexity_scores) < 2:
            return 50.0
        
        # Check if complexity generally increases
        increasing_trend = 0
        for i in range(1, len(complexity_scores)):
            if complexity_scores[i] >= complexity_scores[i-1]:
                increasing_trend += 1
        
        progression_score = (increasing_trend / (len(complexity_scores) - 1)) * 100
        return progression_score
    
    def _assess_accessibility(self, content: str) -> AccessibilityMetrics:
        """Assess content accessibility and inclusive design"""
        try:
            readability_score = flesch_reading_ease(content)
            grade_level = flesch_kincaid_grade(content)
        except:
            readability_score = 50.0
            grade_level = 10.0
        
        # Assess vocabulary complexity
        words = word_tokenize(content.lower())
        if words:
            avg_word_length = np.mean([len(word) for word in words if word.isalpha()])
            vocab_complexity = min(avg_word_length / 8.0, 1.0)  # Normalize to 0-1
        else:
            vocab_complexity = 0.5
        
        # Assess sentence complexity
        sentences = sent_tokenize(content)
        if sentences:
            avg_sentence_length = np.mean([len(word_tokenize(s)) for s in sentences])
            sentence_complexity = min(avg_sentence_length / 30.0, 1.0)  # Normalize to 0-1
        else:
            sentence_complexity = 0.5
        
        # Check for alt text in images
        has_alt_text = bool(re.search(r'!\[.+\]\(.+\)', content))
        
        # Check for captions (simplified check)
        has_captions = bool(re.search(r'(?i)\bcaption\b', content))
        
        # Assess navigation clarity (headings structure)
        headings = re.findall(r'^(#{1,6})\s+(.+)$', content, re.MULTILINE)
        navigation_clarity = min(len(headings) / 5.0 * 100, 100.0)  # Up to 5 headings is good
        
        # Calculate inclusive design score
        inclusive_design_score = self._calculate_inclusive_design_score(
            readability_score, vocab_complexity, sentence_complexity,
            has_alt_text, has_captions, navigation_clarity
        )
        
        return AccessibilityMetrics(
            readability_score=readability_score,
            reading_grade_level=grade_level,
            vocabulary_complexity=vocab_complexity * 100,
            sentence_complexity=sentence_complexity * 100,
            has_alt_text=has_alt_text,
            has_captions=has_captions,
            color_contrast_issues=0,  # Would need actual color analysis
            navigation_clarity=navigation_clarity,
            inclusive_design_score=inclusive_design_score
        )
    
    def _calculate_inclusive_design_score(self, readability: float, vocab_complexity: float,
                                        sentence_complexity: float, has_alt_text: bool,
                                        has_captions: bool, navigation_clarity: float) -> float:
        """Calculate overall inclusive design score"""
        # Weight different accessibility factors
        readability_weight = 0.3
        complexity_weight = 0.2
        multimedia_weight = 0.2
        navigation_weight = 0.3
        
        # Normalize readability (60-80 is ideal)
        if 60 <= readability <= 80:
            readability_score = 100
        else:
            readability_score = max(0, 100 - abs(readability - 70) * 2)
        
        # Complexity penalties (lower is better for accessibility)
        complexity_score = 100 - ((vocab_complexity + sentence_complexity) * 50)
        
        # Multimedia accessibility
        multimedia_score = ((has_alt_text * 50) + (has_captions * 50))
        
        # Calculate weighted score
        inclusive_score = (
            readability_score * readability_weight +
            complexity_score * complexity_weight +
            multimedia_score * multimedia_weight +
            navigation_clarity * navigation_weight
        )
        
        return max(0.0, min(100.0, inclusive_score))
    
    def _assess_completeness(self, content: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """Assess content completeness and coverage"""
        completeness = {
            "topic_coverage_score": 0.0,
            "example_adequacy_score": 0.0,
            "resource_availability_score": 0.0,
            "expected_topics": [],
            "covered_topics": [],
            "missing_topics": [],
            "example_count": 0,
            "reference_count": 0
        }
        
        # Determine expected topics based on metadata or content analysis
        expected_topics = self._determine_expected_topics(content, metadata)
        completeness["expected_topics"] = expected_topics
        
        # Identify covered topics
        covered_topics = self._identify_covered_topics(content, expected_topics)
        completeness["covered_topics"] = covered_topics
        completeness["missing_topics"] = list(set(expected_topics) - set(covered_topics))
        
        # Calculate topic coverage score
        if expected_topics:
            coverage_ratio = len(covered_topics) / len(expected_topics)
            completeness["topic_coverage_score"] = coverage_ratio * 100
        else:
            completeness["topic_coverage_score"] = 100.0
        
        # Assess example adequacy
        example_count = len(re.findall(r'(?i)\bexample\b', content))
        code_blocks = len(re.findall(r'```[\w]*\n', content))
        completeness["example_count"] = example_count + code_blocks
        
        # Score based on content length and complexity
        content_length = len(content)
        expected_examples = max(1, content_length // 1000)  # 1 example per 1000 chars
        example_ratio = min(completeness["example_count"] / expected_examples, 1.0)
        completeness["example_adequacy_score"] = example_ratio * 100
        
        # Assess resource availability
        reference_patterns = [
            r'(?i)\b(?:reference|source|link|url)\b',
            r'\[.*\]\(http.*\)',  # Markdown links
            r'https?://[^\s\)]+',  # URLs
        ]
        
        reference_count = sum(
            len(re.findall(pattern, content))
            for pattern in reference_patterns
        )
        completeness["reference_count"] = reference_count
        
        # Score based on expected references
        expected_references = max(1, len(expected_topics))
        reference_ratio = min(reference_count / expected_references, 1.0)
        completeness["resource_availability_score"] = reference_ratio * 100
        
        return completeness
    
    def _determine_expected_topics(self, content: str, metadata: Optional[Dict] = None) -> List[str]:
        """Determine expected topics based on content and metadata"""
        expected_topics = []
        
        # Extract from metadata if available
        if metadata:
            if 'topics' in metadata:
                expected_topics.extend(metadata['topics'])
            if 'chapter_id' in metadata:
                # Infer topics from chapter ID
                chapter_topics = self._infer_topics_from_chapter(metadata['chapter_id'])
                expected_topics.extend(chapter_topics)
        
        # Extract from content headings
        headings = re.findall(r'^#{2,6}\s+(.+)$', content, re.MULTILINE)
        expected_topics.extend([h.strip().lower() for h in headings])
        
        # Remove duplicates and return
        return list(set(expected_topics))
    
    def _infer_topics_from_chapter(self, chapter_id: str) -> List[str]:
        """Infer expected topics from chapter identifier"""
        topic_mapping = {
            'python': ['syntax', 'data types', 'functions', 'classes', 'modules'],
            'statistics': ['descriptive', 'inferential', 'hypothesis testing', 'correlation'],
            'machine-learning': ['supervised', 'unsupervised', 'evaluation', 'algorithms'],
            'visualization': ['plots', 'charts', 'dashboards', 'interactive'],
            'data-cleaning': ['missing values', 'outliers', 'transformation', 'validation']
        }
        
        chapter_lower = chapter_id.lower()
        for key, topics in topic_mapping.items():
            if key in chapter_lower:
                return topics
        
        return []
    
    def _identify_covered_topics(self, content: str, expected_topics: List[str]) -> List[str]:
        """Identify which expected topics are covered in content"""
        content_lower = content.lower()
        covered_topics = []
        
        for topic in expected_topics:
            topic_lower = topic.lower()
            # Simple check - could be enhanced with semantic similarity
            if topic_lower in content_lower:
                covered_topics.append(topic)
            else:
                # Check for related terms
                topic_words = topic_lower.split()
                if any(word in content_lower for word in topic_words if len(word) > 3):
                    covered_topics.append(topic)
        
        return covered_topics
    
    # Scoring methods
    def _score_learning_objectives(self, objectives_analysis: Optional[Dict[str, Any]]) -> float:
        """Score learning objectives component"""
        if not objectives_analysis:
            return 0.0
        
        weights = self.config["learning_objectives"]
        
        # SMART compliance score
        smart_score = objectives_analysis.get("smart_compliance", 0.0)
        
        # Count appropriateness score
        count = objectives_analysis.get("count", 0)
        min_count = weights["minimum_count"]
        max_count = weights["maximum_count"]
        
        if min_count <= count <= max_count:
            count_score = 100.0
        else:
            # Penalize deviation from ideal range
            ideal_count = (min_count + max_count) / 2
            deviation = abs(count - ideal_count)
            count_score = max(0, 100 - deviation * 10)
        
        # Bloom distribution score (diversity bonus)
        bloom_dist = objectives_analysis.get("bloom_distribution", {})
        bloom_diversity = len(bloom_dist) / 6 * 100  # 6 levels in Bloom's taxonomy
        
        # Alignment score
        alignment_score = objectives_analysis.get("alignment_score", 0.0)
        
        # Calculate weighted score
        total_score = (
            smart_score * weights["smart_criteria_weight"] +
            bloom_diversity * weights["bloom_distribution_weight"] +
            alignment_score * weights["alignment_weight"] +
            count_score * 0.1  # Small weight for count appropriateness
        )
        
        return min(100.0, total_score)
    
    def _score_content_structure(self, structure: ContentStructure) -> float:
        """Score content structure component"""
        weights = self.config["content_structure"]
        
        # Required sections score
        required_sections = self.config["content_structure"]["required_sections"]
        present_sections = sum(
            1 for section in required_sections
            if getattr(structure, f"has_{section}", False)
        )
        
        section_score = (present_sections / len(required_sections)) * 100
        
        # Logical flow score
        flow_score = structure.logical_flow_score
        
        # Section balance score (penalize extreme imbalances)
        balance_scores = list(structure.section_balance.values())
        if balance_scores:
            balance_variance = np.var(balance_scores)
            balance_score = max(0, 100 - balance_variance)  # Lower variance is better
        else:
            balance_score = 50.0  # Neutral if no sections detected
        
        # Calculate weighted score
        total_score = (
            section_score * weights["completeness_weight"] +
            flow_score * weights["logical_flow_weight"] +
            balance_score * weights["section_balance_weight"]
        )
        
        return min(100.0, total_score)
    
    def _score_educational_effectiveness(self, effectiveness: Dict[str, Any]) -> float:
        """Score educational effectiveness component"""
        weights = self.config["educational_effectiveness"]
        
        engagement_score = effectiveness.get("engagement_score", 0.0)
        clarity_score = effectiveness.get("clarity_score", 0.0)
        practical_score = effectiveness.get("practical_application_score", 0.0)
        transfer_score = effectiveness.get("knowledge_transfer_score", 0.0)
        
        # Calculate weighted score
        total_score = (
            engagement_score * weights["engagement_weight"] +
            clarity_score * weights["clarity_weight"] +
            practical_score * weights["practical_application_weight"] +
            transfer_score * weights["knowledge_transfer_weight"]
        )
        
        return min(100.0, total_score)
    
    def _score_accessibility(self, accessibility: AccessibilityMetrics) -> float:
        """Score accessibility component"""
        return accessibility.inclusive_design_score
    
    def _score_completeness(self, completeness: Dict[str, Any]) -> float:
        """Score completeness component"""
        weights = self.config["completeness"]
        
        topic_score = completeness.get("topic_coverage_score", 0.0)
        example_score = completeness.get("example_adequacy_score", 0.0)
        resource_score = completeness.get("resource_availability_score", 0.0)
        
        # Calculate weighted score
        total_score = (
            topic_score * weights["topic_coverage_weight"] +
            example_score * weights["example_adequacy_weight"] +
            resource_score * weights["resource_availability_weight"]
        )
        
        return min(100.0, total_score)
    
    def _calculate_overall_quality_score(self, component_scores: Dict[str, float]) -> float:
        """Calculate weighted overall quality score"""
        weights = self.config["quality_assessment"]["component_weights"]
        
        total_score = 0.0
        total_weight = 0.0
        
        for component, score in component_scores.items():
            if component in weights:
                weight = weights[component]
                total_score += score * weight
                total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    # Collection methods for issues, strengths, and recommendations
    def _collect_quality_issues(self, objectives_result, structure_result, 
                               effectiveness_result, accessibility_result, 
                               completeness_result) -> List[str]:
        """Collect all quality issues identified"""
        issues = []
        
        # Learning objectives issues
        if objectives_result and "issues" in objectives_result:
            issues.extend(objectives_result["issues"])
        
        # Structure issues
        required_sections = self.config["content_structure"]["required_sections"]
        missing_sections = [
            section for section in required_sections
            if not getattr(structure_result, f"has_{section}", False)
        ]
        if missing_sections:
            issues.append(f"Missing required sections: {', '.join(missing_sections)}")
        
        # Accessibility issues
        if accessibility_result.readability_score < 40:
            issues.append(f"Very low readability score: {accessibility_result.readability_score:.1f}")
        elif accessibility_result.readability_score > 90:
            issues.append(f"Text may be too simple: {accessibility_result.readability_score:.1f}")
        
        if accessibility_result.reading_grade_level > 15:
            issues.append(f"Grade level too high: {accessibility_result.reading_grade_level:.1f}")
        
        # Completeness issues
        missing_topics = completeness_result.get("missing_topics", [])
        if missing_topics:
            issues.append(f"Missing expected topics: {', '.join(missing_topics[:3])}")
        
        if completeness_result.get("example_count", 0) == 0:
            issues.append("No examples or code blocks found")
        
        return issues
    
    def _collect_strengths(self, objectives_result, structure_result,
                          effectiveness_result, accessibility_result,
                          completeness_result) -> List[str]:
        """Collect content strengths"""
        strengths = []
        
        # Learning objectives strengths
        if objectives_result and "strengths" in objectives_result:
            strengths.extend(objectives_result["strengths"])
        
        # Structure strengths
        if structure_result.logical_flow_score > 80:
            strengths.append("Well-organized logical flow")
        
        if all(getattr(structure_result, f"has_{section}", False) 
               for section in ["introduction", "examples", "summary"]):
            strengths.append("Complete section structure")
        
        # Effectiveness strengths
        if effectiveness_result.get("engagement_score", 0) > 70:
            strengths.append("Highly engaging content")
        
        if effectiveness_result.get("practical_application_score", 0) > 80:
            strengths.append("Strong practical focus")
        
        # Accessibility strengths
        if 60 <= accessibility_result.readability_score <= 80:
            strengths.append("Optimal readability level")
        
        if accessibility_result.inclusive_design_score > 85:
            strengths.append("Excellent accessibility design")
        
        # Completeness strengths
        if completeness_result.get("topic_coverage_score", 0) > 90:
            strengths.append("Comprehensive topic coverage")
        
        return strengths
    
    def _generate_quality_recommendations(self, objectives_result, structure_result,
                                        effectiveness_result, accessibility_result,
                                        completeness_result) -> List[str]:
        """Generate quality improvement recommendations"""
        recommendations = []
        
        # Learning objectives recommendations
        if not objectives_result or objectives_result.get("count", 0) < 3:
            recommendations.append("Add more specific learning objectives (minimum 3)")
        
        if objectives_result and objectives_result.get("smart_compliance", 0) < 60:
            recommendations.append("Improve SMART criteria compliance in learning objectives")
        
        # Structure recommendations
        if not structure_result.has_examples:
            recommendations.append("Add practical examples and code demonstrations")
        
        if not structure_result.has_exercises:
            recommendations.append("Include hands-on exercises and practice activities")
        
        if structure_result.logical_flow_score < 70:
            recommendations.append("Improve content organization and logical flow")
        
        # Effectiveness recommendations
        if effectiveness_result.get("engagement_score", 0) < 50:
            recommendations.append("Increase engagement with interactive elements and direct address")
        
        if effectiveness_result.get("clarity_score", 0) < 70:
            recommendations.append("Simplify complex concepts and add more explanations")
        
        if effectiveness_result.get("practical_application_score", 0) < 60:
            recommendations.append("Add more hands-on activities and real-world applications")
        
        # Accessibility recommendations
        if accessibility_result.readability_score < 60:
            recommendations.append("Improve readability by simplifying language and sentence structure")
        
        if not accessibility_result.has_alt_text:
            recommendations.append("Add alt text descriptions for images and visual content")
        
        # Completeness recommendations
        missing_topics = completeness_result.get("missing_topics", [])
        if missing_topics:
            recommendations.append(f"Consider covering missing topics: {', '.join(missing_topics[:2])}")
        
        if completeness_result.get("reference_count", 0) < 3:
            recommendations.append("Add more references and external resources")
        
        # Limit to top recommendations
        return recommendations[:8]


async def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Content Quality Checker")
    parser.add_argument("--file", required=True, help="File to assess")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    checker = ContentQualityChecker(args.config)
    
    try:
        # Read content
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Perform assessment
        result = await checker.assess_content_quality(content, file_path=args.file)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(asdict(result), f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            print(f"Quality Score: {result.overall_quality_score:.2f}")
            print(f"Passed: {result.passed}")
            
            if result.quality_issues:
                print("\nQuality Issues:")
                for issue in result.quality_issues:
                    print(f"  - {issue}")
            
            if result.strengths:
                print("\nStrengths:")
                for strength in result.strengths:
                    print(f"  + {strength}")
            
            if result.recommendations:
                print("\nRecommendations:")
                for rec in result.recommendations[:5]:  # Show top 5
                    print(f"  → {rec}")
    
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        exit(1)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())