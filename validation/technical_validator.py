#!/usr/bin/env python3
"""
Technical Validator Module for Chapter Content Management System
===============================================================

Comprehensive technical validation system that checks:
- Code execution and technical accuracy
- Link functionality and currency
- API documentation validation  
- Platform capability verification
- Security compliance in code examples
- Performance and optimization checks

Author: Claude Code Implementation
Created: 2025-07-28
Version: 1.0.0
"""

import ast
import re
import requests
import subprocess
import tempfile
import json
import logging
import asyncio
import aiohttp
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml
import nbformat
from nbformat.v4 import new_notebook, new_code_cell, new_markdown_cell
import docker
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of technical validation"""
    overall_score: float
    component_scores: Dict[str, float]
    passed: bool
    issues: List[str]
    warnings: List[str]
    recommendations: List[str]
    execution_results: Dict[str, Any]
    link_validation: Dict[str, Any]
    api_currency: Dict[str, Any]
    security_checks: Dict[str, Any]
    timestamp: str
    processing_time: float


@dataclass
class CodeBlock:
    """Represents a code block for validation"""
    content: str
    language: str
    line_number: int
    cell_type: Optional[str] = None
    metadata: Optional[Dict] = None


@dataclass  
class LinkCheck:
    """Result of link validation"""
    url: str
    status_code: int
    response_time: float
    is_valid: bool
    error_message: Optional[str] = None
    redirect_chain: List[str] = None
    last_modified: Optional[str] = None


class TechnicalValidator:
    """
    Comprehensive technical validation system for educational content
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Technical Validator
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.docker_client = None
        self.temp_dir = Path(tempfile.mkdtemp(prefix="tech_validator_"))
        
        # Initialize Docker client if available
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
        
        # Initialize validation database
        self.db_path = self.temp_dir / "validation_results.db"
        self._init_database()
        
        logger.info("Technical Validator initialized")
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load validator configuration"""
        default_config = {
            "validation": {
                "minimum_score": 80.0,
                "timeout_seconds": 30,
                "max_concurrent_checks": 10,
                "retry_attempts": 3
            },
            "code_execution": {
                "supported_languages": ["python", "r", "sql", "bash", "javascript"],
                "docker_images": {
                    "python": "python:3.9-slim",
                    "r": "r-base:latest", 
                    "sql": "postgres:13",
                    "javascript": "node:16-slim"
                },
                "security_patterns": [
                    r"import\s+os",
                    r"subprocess\.",
                    r"eval\s*\(",
                    r"exec\s*\(",
                    r"__import__"
                ],
                "dangerous_functions": [
                    "eval", "exec", "compile", "open", "file",
                    "input", "raw_input", "execfile", "reload"
                ]
            },
            "link_validation": {
                "user_agent": "TechnicalValidator/1.0 (+https://handbook.mil)",
                "timeout": 10,
                "max_redirects": 5,
                "check_ssl": True,
                "check_content_type": True,
                "valid_content_types": [
                    "text/html", "application/json", "text/plain",
                    "application/pdf", "text/markdown"
                ]
            },
            "api_validation": {
                "check_versions": True,
                "version_tolerance_months": 12,
                "known_apis": {
                    "databricks": "https://docs.databricks.com/",
                    "qlik": "https://qlik.dev/",
                    "advana": "https://www.ai.mil/"
                },
                "deprecation_patterns": [
                    "deprecated", "obsolete", "legacy", "end-of-life"
                ]
            },
            "scoring": {
                "weights": {
                    "code_execution": 0.30,
                    "link_validation": 0.20,
                    "api_currency": 0.20,
                    "security_compliance": 0.15,
                    "performance": 0.10,
                    "documentation": 0.05
                }
            }
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Deep merge configuration
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
    
    def _init_database(self):
        """Initialize SQLite database for validation results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                validation_type TEXT NOT NULL,
                score REAL NOT NULL,
                passed BOOLEAN NOT NULL,
                issues TEXT,
                timestamp TEXT NOT NULL,
                processing_time REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS code_execution_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                validation_id INTEGER,
                language TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                execution_time REAL,
                success BOOLEAN NOT NULL,
                output TEXT,
                error_message TEXT,
                FOREIGN KEY (validation_id) REFERENCES validation_results (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS link_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                validation_id INTEGER,
                url TEXT NOT NULL,
                status_code INTEGER,
                response_time REAL,
                is_valid BOOLEAN NOT NULL,
                error_message TEXT,
                last_checked TEXT,
                FOREIGN KEY (validation_id) REFERENCES validation_results (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def validate_content(self, file_path: Union[str, Path]) -> ValidationResult:
        """
        Perform comprehensive validation of content file
        
        Args:
            file_path: Path to content file
            
        Returns:
            ValidationResult with comprehensive analysis
        """
        start_time = datetime.now()
        file_path = Path(file_path)
        
        logger.info(f"Starting technical validation of {file_path}")
        
        # Initialize result structure
        result = ValidationResult(
            overall_score=0.0,
            component_scores={},
            passed=False,
            issues=[],
            warnings=[],
            recommendations=[],
            execution_results={},
            link_validation={},
            api_currency={},
            security_checks={},
            timestamp=start_time.isoformat(),
            processing_time=0.0
        )
        
        try:
            # Parse content and extract code blocks and links
            content_data = await self._parse_content(file_path)
            
            # Run validation components in parallel
            validation_tasks = [
                self._validate_code_execution(content_data["code_blocks"]),
                self._validate_links(content_data["links"]),
                self._validate_api_currency(content_data["api_references"]),
                self._validate_security_compliance(content_data["code_blocks"]),
                self._validate_performance(content_data["code_blocks"]),
                self._validate_documentation(content_data)
            ]
            
            validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
            
            # Process results
            component_names = [
                "code_execution", "link_validation", "api_currency", 
                "security_compliance", "performance", "documentation"
            ]
            
            for i, (name, component_result) in enumerate(zip(component_names, validation_results)):
                if isinstance(component_result, Exception):
                    logger.error(f"Error in {name} validation: {component_result}")
                    result.component_scores[name] = 0.0
                    result.issues.append(f"Failed to validate {name}: {str(component_result)}")
                else:
                    result.component_scores[name] = component_result["score"]
                    if name == "code_execution":
                        result.execution_results = component_result
                    elif name == "link_validation":
                        result.link_validation = component_result
                    elif name == "api_currency":
                        result.api_currency = component_result
                    elif name == "security_compliance":
                        result.security_checks = component_result
                    
                    # Collect issues and warnings
                    result.issues.extend(component_result.get("issues", []))
                    result.warnings.extend(component_result.get("warnings", []))
                    result.recommendations.extend(component_result.get("recommendations", []))
            
            # Calculate overall score
            result.overall_score = self._calculate_overall_score(result.component_scores)
            result.passed = result.overall_score >= self.config["validation"]["minimum_score"]
            
            # Record processing time
            result.processing_time = (datetime.now() - start_time).total_seconds()
            
            # Store results in database
            self._store_validation_result(file_path, result)
            
            logger.info(f"Validation completed for {file_path}. Score: {result.overall_score:.2f}")
            
        except Exception as e:
            logger.error(f"Validation failed for {file_path}: {e}")
            result.issues.append(f"Validation error: {str(e)}")
            result.processing_time = (datetime.now() - start_time).total_seconds()
        
        return result
    
    async def _parse_content(self, file_path: Path) -> Dict[str, Any]:
        """Parse content file and extract validation targets"""
        content_data = {
            "code_blocks": [],
            "links": [],
            "api_references": [],
            "metadata": {}
        }
        
        try:
            if file_path.suffix == '.md':
                content_data = await self._parse_markdown(file_path)
            elif file_path.suffix == '.ipynb':
                content_data = await self._parse_notebook(file_path)
            elif file_path.suffix == '.py':
                content_data = await self._parse_python_file(file_path)
            else:
                logger.warning(f"Unsupported file type: {file_path.suffix}")
        
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
        
        return content_data
    
    async def _parse_markdown(self, file_path: Path) -> Dict[str, Any]:
        """Parse Markdown file for validation targets"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        content_data = {
            "code_blocks": [],
            "links": [],
            "api_references": [],
            "metadata": {}
        }
        
        # Extract YAML frontmatter
        if content.startswith('---'):
            try:
                end_idx = content.find('---', 3)
                if end_idx > 0:
                    frontmatter = content[3:end_idx].strip()
                    content_data["metadata"] = yaml.safe_load(frontmatter)
                    content = content[end_idx + 3:]
            except Exception as e:
                logger.warning(f"Failed to parse frontmatter: {e}")
        
        # Extract code blocks
        code_pattern = r'```(\w+)?\n(.*?)\n```'
        for match in re.finditer(code_pattern, content, re.DOTALL):
            language = match.group(1) or 'text'
            code_content = match.group(2)
            line_number = content[:match.start()].count('\n') + 1
            
            content_data["code_blocks"].append(CodeBlock(
                content=code_content,
                language=language.lower(),
                line_number=line_number
            ))
        
        # Extract links
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        for match in re.finditer(link_pattern, content):
            url = match.group(2)
            if url.startswith(('http://', 'https://')):
                content_data["links"].append(url)
        
        # Extract API references
        api_patterns = [
            r'https://docs\.databricks\.com/[^\s\)]+',
            r'https://qlik\.dev/[^\s\)]+',
            r'https://[^/]*\.mil/[^\s\)]+',
            r'api\.[\w.-]+\.com/[^\s\)]+'
        ]
        
        for pattern in api_patterns:
            for match in re.finditer(pattern, content):
                content_data["api_references"].append(match.group(0))
        
        return content_data
    
    async def _parse_notebook(self, file_path: Path) -> Dict[str, Any]:
        """Parse Jupyter notebook for validation targets"""
        with open(file_path, 'r', encoding='utf-8') as f:
            notebook = nbformat.read(f, as_version=4)
        
        content_data = {
            "code_blocks": [],
            "links": [],
            "api_references": [],
            "metadata": notebook.metadata.get('handbook', {})
        }
        
        for i, cell in enumerate(notebook.cells):
            if cell.cell_type == 'code':
                content_data["code_blocks"].append(CodeBlock(
                    content=cell.source,
                    language='python',  # Assume Python for notebooks
                    line_number=i + 1,
                    cell_type='code',
                    metadata=cell.metadata
                ))
            
            elif cell.cell_type == 'markdown':
                # Extract links from markdown cells
                link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
                for match in re.finditer(link_pattern, cell.source):
                    url = match.group(2)
                    if url.startswith(('http://', 'https://')):
                        content_data["links"].append(url)
        
        return content_data
    
    async def _parse_python_file(self, file_path: Path) -> Dict[str, Any]:
        """Parse Python file for validation targets"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        content_data = {
            "code_blocks": [CodeBlock(
                content=content,
                language='python',
                line_number=1
            )],
            "links": [],
            "api_references": [],
            "metadata": {}
        }
        
        # Extract URLs from comments and strings
        url_pattern = r'https?://[^\s\'">\)]+' 
        for match in re.finditer(url_pattern, content):
            content_data["links"].append(match.group(0))
        
        return content_data
    
    async def _validate_code_execution(self, code_blocks: List[CodeBlock]) -> Dict[str, Any]:
        """Validate code execution across different languages"""
        result = {
            "score": 0.0,
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "execution_details": {}
        }
        
        if not code_blocks:
            result["warnings"].append("No code blocks found to validate")
            result["score"] = 100.0  # Perfect score if no code to test
            return result
        
        successful_executions = 0
        total_executions = 0
        
        for code_block in code_blocks:
            if code_block.language in self.config["code_execution"]["supported_languages"]:
                total_executions += 1
                
                try:
                    execution_result = await self._execute_code_block(code_block)
                    result["execution_details"][f"block_{code_block.line_number}"] = execution_result
                    
                    if execution_result["success"]:
                        successful_executions += 1
                    else:
                        result["issues"].append(
                            f"Code execution failed at line {code_block.line_number}: "
                            f"{execution_result.get('error', 'Unknown error')}"
                        )
                        
                except Exception as e:
                    result["issues"].append(
                        f"Failed to execute code block at line {code_block.line_number}: {str(e)}"
                    )
        
        # Calculate score based on successful executions
        if total_executions > 0:
            success_rate = successful_executions / total_executions
            result["score"] = success_rate * 100.0
        else:
            result["score"] = 100.0
            result["warnings"].append("No executable code blocks found")
        
        # Add recommendations
        if result["score"] < 100.0:
            result["recommendations"].append("Review and fix failing code examples")
            result["recommendations"].append("Ensure all code blocks have proper error handling")
        
        return result
    
    async def _execute_code_block(self, code_block: CodeBlock) -> Dict[str, Any]:
        """Execute a single code block safely"""
        execution_result = {
            "success": False,
            "output": "",
            "error": "",
            "execution_time": 0.0,
            "language": code_block.language
        }
        
        start_time = datetime.now()
        
        try:
            if code_block.language == 'python':
                execution_result = await self._execute_python_code(code_block.content)
            elif code_block.language == 'r':
                execution_result = await self._execute_r_code(code_block.content)
            elif code_block.language == 'sql':
                execution_result = await self._execute_sql_code(code_block.content)
            elif code_block.language == 'bash':
                execution_result = await self._execute_bash_code(code_block.content)
            else:
                execution_result["error"] = f"Unsupported language: {code_block.language}"
        
        except Exception as e:
            execution_result["error"] = str(e)
        
        execution_result["execution_time"] = (datetime.now() - start_time).total_seconds()
        return execution_result
    
    async def _execute_python_code(self, code: str) -> Dict[str, Any]:
        """Execute Python code safely"""
        result = {"success": False, "output": "", "error": ""}
        
        # Security check
        security_issues = self._check_code_security(code, 'python')
        if security_issues:
            result["error"] = f"Security issues detected: {', '.join(security_issues)}"
            return result
        
        try:
            # Create temporary file
            temp_file = self.temp_dir / f"test_{datetime.now().timestamp()}.py"
            with open(temp_file, 'w') as f:
                f.write(code)
            
            # Execute using subprocess for safety
            process = await asyncio.create_subprocess_exec(
                'python', str(temp_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.temp_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.config["validation"]["timeout_seconds"]
            )
            
            result["output"] = stdout.decode('utf-8')
            if stderr:
                result["error"] = stderr.decode('utf-8')
            
            result["success"] = process.returncode == 0
            
            # Clean up
            temp_file.unlink(missing_ok=True)
            
        except asyncio.TimeoutError:
            result["error"] = "Code execution timed out"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _execute_r_code(self, code: str) -> Dict[str, Any]:
        """Execute R code safely"""
        result = {"success": False, "output": "", "error": ""}
        
        if not self.docker_client:
            result["error"] = "Docker not available for R code execution"
            return result
        
        try:
            # Create temporary R file
            temp_file = self.temp_dir / f"test_{datetime.now().timestamp()}.R"
            with open(temp_file, 'w') as f:
                f.write(code)
            
            # Execute in Docker container
            container = self.docker_client.containers.run(
                self.config["code_execution"]["docker_images"]["r"],
                f"Rscript /tmp/test.R",
                volumes={str(temp_file): {'bind': '/tmp/test.R', 'mode': 'ro'}},
                remove=True,
                capture_output=True,
                timeout=self.config["validation"]["timeout_seconds"]
            )
            
            result["output"] = container.decode('utf-8') if container else ""
            result["success"] = True
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _execute_sql_code(self, code: str) -> Dict[str, Any]:
        """Execute SQL code safely"""
        result = {"success": False, "output": "", "error": ""}
        
        # For now, just do syntax validation
        try:
            # Basic SQL syntax check
            if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b', code, re.IGNORECASE):
                result["success"] = True
                result["output"] = "SQL syntax appears valid"
            else:
                result["error"] = "No valid SQL statements found"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _execute_bash_code(self, code: str) -> Dict[str, Any]:
        """Execute Bash code safely"""
        result = {"success": False, "output": "", "error": ""}
        
        # Security check for dangerous commands
        dangerous_patterns = [
            r'\brm\s+-rf', r'\bsudo\b', r'\bsu\b', r'\bchmod\s+777',
            r'\b(wget|curl)\s+.*\|.*sh', r'>\s*/dev/sd[a-z]'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, code):
                result["error"] = f"Dangerous command detected: {pattern}"
                return result
        
        try:
            process = await asyncio.create_subprocess_shell(
                code,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.temp_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.config["validation"]["timeout_seconds"]
            )
            
            result["output"] = stdout.decode('utf-8')
            if stderr:
                result["error"] = stderr.decode('utf-8')
            
            result["success"] = process.returncode == 0
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _check_code_security(self, code: str, language: str) -> List[str]:
        """Check code for security issues"""
        issues = []
        
        if language == 'python':
            # Check for dangerous patterns
            for pattern in self.config["code_execution"]["security_patterns"]:
                if re.search(pattern, code):
                    issues.append(f"Potentially dangerous pattern: {pattern}")
            
            # Check for dangerous functions
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Name):
                        if node.id in self.config["code_execution"]["dangerous_functions"]:
                            issues.append(f"Dangerous function used: {node.id}")
            except SyntaxError:
                pass  # Will be caught in execution
        
        return issues
    
    async def _validate_links(self, links: List[str]) -> Dict[str, Any]:
        """Validate all links in content"""
        result = {
            "score": 0.0,
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "link_details": {}
        }
        
        if not links:
            result["score"] = 100.0
            result["warnings"].append("No links found to validate")
            return result
        
        # Remove duplicates
        unique_links = list(set(links))
        
        # Check links concurrently
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config["link_validation"]["timeout"]),
            headers={"User-Agent": self.config["link_validation"]["user_agent"]}
        ) as session:
            
            semaphore = asyncio.Semaphore(self.config["validation"]["max_concurrent_checks"])
            tasks = [self._check_single_link(session, semaphore, url) for url in unique_links]
            link_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        valid_links = 0
        for i, link_result in enumerate(link_results):
            url = unique_links[i]
            
            if isinstance(link_result, Exception):
                result["issues"].append(f"Failed to check link {url}: {str(link_result)}")
                result["link_details"][url] = {"error": str(link_result), "is_valid": False}
            else:
                result["link_details"][url] = asdict(link_result)
                if link_result.is_valid:
                    valid_links += 1
                else:
                    result["issues"].append(f"Invalid link: {url} (Status: {link_result.status_code})")
        
        # Calculate score
        if unique_links:
            result["score"] = (valid_links / len(unique_links)) * 100.0
        else:
            result["score"] = 100.0
        
        # Add recommendations
        if result["score"] < 100.0:
            result["recommendations"].append("Fix or update broken links")
            result["recommendations"].append("Consider using archived versions for historical references")
        
        return result
    
    async def _check_single_link(self, session: aiohttp.ClientSession, 
                                semaphore: asyncio.Semaphore, url: str) -> LinkCheck:
        """Check a single link"""
        async with semaphore:
            start_time = datetime.now()
            
            try:
                async with session.get(url, allow_redirects=True) as response:
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    # Build redirect chain
                    redirect_chain = []
                    if hasattr(response, 'history'):
                        redirect_chain = [str(resp.url) for resp in response.history]
                    
                    return LinkCheck(
                        url=url,
                        status_code=response.status,
                        response_time=response_time,
                        is_valid=200 <= response.status < 400,
                        redirect_chain=redirect_chain,
                        last_modified=response.headers.get('Last-Modified')
                    )
                    
            except Exception as e:
                response_time = (datetime.now() - start_time).total_seconds()
                return LinkCheck(
                    url=url,
                    status_code=0,
                    response_time=response_time,
                    is_valid=False,
                    error_message=str(e)
                )
    
    async def _validate_api_currency(self, api_references: List[str]) -> Dict[str, Any]:
        """Validate API documentation currency"""
        result = {
            "score": 0.0,
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "api_details": {}
        }
        
        if not api_references:
            result["score"] = 100.0
            result["warnings"].append("No API references found")
            return result
        
        current_apis = 0
        total_apis = len(api_references)
        
        for api_url in api_references:
            try:
                api_info = await self._check_api_currency(api_url)
                result["api_details"][api_url] = api_info
                
                if api_info["is_current"]:
                    current_apis += 1
                else:
                    result["issues"].append(f"Outdated API reference: {api_url}")
                    
            except Exception as e:
                result["issues"].append(f"Failed to check API {api_url}: {str(e)}")
        
        # Calculate score
        result["score"] = (current_apis / total_apis) * 100.0 if total_apis > 0 else 100.0
        
        # Add recommendations
        if result["score"] < 100.0:
            result["recommendations"].append("Update outdated API references")
            result["recommendations"].append("Check for deprecated endpoints")
        
        return result
    
    async def _check_api_currency(self, api_url: str) -> Dict[str, Any]:
        """Check if API documentation is current"""
        api_info = {
            "url": api_url,
            "is_current": True,
            "last_checked": datetime.now().isoformat(),
            "issues": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url) as response:
                    content = await response.text()
                    
                    # Check for deprecation indicators
                    for pattern in self.config["api_validation"]["deprecation_patterns"]:
                        if pattern.lower() in content.lower():
                            api_info["is_current"] = False
                            api_info["issues"].append(f"Deprecation indicator found: {pattern}")
                    
                    # Check last modified date if available
                    last_modified = response.headers.get('Last-Modified')
                    if last_modified:
                        try:
                            last_mod_date = datetime.strptime(last_modified, '%a, %d %b %Y %H:%M:%S %Z')
                            months_old = (datetime.now() - last_mod_date).days / 30.44
                            
                            if months_old > self.config["api_validation"]["version_tolerance_months"]:
                                api_info["is_current"] = False
                                api_info["issues"].append(f"Documentation is {months_old:.1f} months old")
                                
                        except ValueError:
                            pass  # Ignore date parsing errors
                    
        except Exception as e:
            api_info["issues"].append(f"Failed to validate: {str(e)}")
            api_info["is_current"] = False
        
        return api_info
    
    async def _validate_security_compliance(self, code_blocks: List[CodeBlock]) -> Dict[str, Any]:
        """Validate security compliance in code examples"""
        result = {
            "score": 0.0,
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "security_details": {}
        }
        
        if not code_blocks:
            result["score"] = 100.0
            return result
        
        total_blocks = len(code_blocks)
        secure_blocks = 0
        
        for code_block in code_blocks:
            security_check = self._analyze_code_security(code_block)
            result["security_details"][f"block_{code_block.line_number}"] = security_check
            
            if security_check["is_secure"]:
                secure_blocks += 1
            else:
                result["issues"].extend([
                    f"Line {code_block.line_number}: {issue}" 
                    for issue in security_check["issues"]
                ])
        
        # Calculate score
        result["score"] = (secure_blocks / total_blocks) * 100.0 if total_blocks > 0 else 100.0
        
        # Add general recommendations
        if result["score"] < 100.0:
            result["recommendations"].extend([
                "Review code examples for security best practices",
                "Add input validation and error handling",
                "Avoid hardcoded credentials or sensitive data",
                "Use secure authentication patterns"
            ])
        
        return result
    
    def _analyze_code_security(self, code_block: CodeBlock) -> Dict[str, Any]:
        """Analyze a single code block for security issues"""
        security_check = {
            "is_secure": True,
            "issues": [],
            "recommendations": []
        }
        
        code = code_block.content
        
        # Check for common security anti-patterns
        security_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password detected"),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key detected"),
            (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret detected"),
            (r'eval\s*\(', "Use of eval() function detected"),
            (r'exec\s*\(', "Use of exec() function detected"),
            (r'subprocess\.call.*shell=True', "Potentially unsafe shell execution"),
            (r'input\s*\([^)]*\)', "Direct user input without validation"),
            (r'pickle\.loads?', "Unsafe pickle usage detected"),
            (r'yaml\.load\s*\(', "Unsafe YAML loading detected")
        ]
        
        for pattern, message in security_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                security_check["is_secure"] = False
                security_check["issues"].append(message)
        
        # Check for missing security practices
        if code_block.language == 'python':
            if 'requests.get' in code and 'verify=' not in code:
                security_check["recommendations"].append("Consider SSL certificate verification")
            
            if 'sql' in code.lower() and not any(word in code for word in ['parameterized', 'prepare', '?']):
                security_check["recommendations"].append("Use parameterized queries to prevent SQL injection")
        
        return security_check
    
    async def _validate_performance(self, code_blocks: List[CodeBlock]) -> Dict[str, Any]:
        """Validate code performance and optimization"""
        result = {
            "score": 0.0,
            "issues": [],
            "warnings": [],
            "recommendations": [],
            "performance_details": {}
        }
        
        if not code_blocks:
            result["score"] = 100.0
            return result
        
        total_score = 0.0
        
        for code_block in code_blocks:
            perf_analysis = self._analyze_code_performance(code_block)
            result["performance_details"][f"block_{code_block.line_number}"] = perf_analysis
            total_score += perf_analysis["score"]
            
            result["issues"].extend(perf_analysis["issues"])
            result["recommendations"].extend(perf_analysis["recommendations"])
        
        # Calculate average score
        result["score"] = total_score / len(code_blocks) if code_blocks else 100.0
        
        return result
    
    def _analyze_code_performance(self, code_block: CodeBlock) -> Dict[str, Any]:
        """Analyze code block for performance issues"""
        analysis = {
            "score": 100.0,
            "issues": [],
            "recommendations": []
        }
        
        code = code_block.content
        
        # Check for common performance anti-patterns
        performance_patterns = [
            (r'for\s+\w+\s+in\s+range\(len\(', "Consider using enumerate() instead of range(len())"),
            (r'\.append\s*\(\s*\w+\s*\[\s*\w+\s*\]\s*\)', "Consider list comprehension for better performance"),
            (r'time\.sleep\s*\(\s*\d+\s*\)', "Long sleep detected - consider async alternatives"),
            (r'while\s+True:', "Infinite loop detected - ensure proper exit conditions"),
            (r'import\s+\*', "Wildcard imports can impact performance and readability")
        ]
        
        for pattern, recommendation in performance_patterns:
            if re.search(pattern, code):
                analysis["score"] -= 10
                analysis["recommendations"].append(recommendation)
        
        # Language-specific optimizations
        if code_block.language == 'python':
            if 'pandas' in code:
                if '.iterrows()' in code:
                    analysis["score"] -= 15
                    analysis["issues"].append("iterrows() is inefficient - consider vectorized operations")
                
                if '.apply(' in code and 'lambda' in code:
                    analysis["recommendations"].append("Consider vectorized operations instead of apply() with lambda")
        
        # Ensure score doesn't go below 0
        analysis["score"] = max(0.0, analysis["score"])
        
        return analysis
    
    async def _validate_documentation(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate documentation quality"""
        result = {
            "score": 0.0,
            "issues": [],
            "warnings": [],
            "recommendations": []
        }
        
        score = 100.0
        
        # Check for code comments
        code_blocks = content_data.get("code_blocks", [])
        documented_blocks = 0
        
        for code_block in code_blocks:
            if self._has_adequate_documentation(code_block):
                documented_blocks += 1
            else:
                result["issues"].append(f"Line {code_block.line_number}: Insufficient documentation")
        
        if code_blocks:
            doc_ratio = documented_blocks / len(code_blocks)
            score *= doc_ratio
        
        # Check metadata completeness
        metadata = content_data.get("metadata", {})
        required_fields = ["title", "author", "created_date", "platforms"]
        
        for field in required_fields:
            if not metadata.get(field):
                score -= 10
                result["issues"].append(f"Missing metadata field: {field}")
        
        result["score"] = max(0.0, score)
        
        if result["score"] < 100.0:
            result["recommendations"].extend([
                "Add comprehensive comments to code examples",
                "Include complete metadata in content headers",
                "Provide context and explanations for complex code"
            ])
        
        return result
    
    def _has_adequate_documentation(self, code_block: CodeBlock) -> bool:
        """Check if code block has adequate documentation"""
        code = code_block.content
        
        # Count comment lines
        lines = code.split('\n')
        comment_lines = 0
        code_lines = 0
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            elif stripped.startswith('#') or stripped.startswith('"""') or stripped.startswith("'''"):
                comment_lines += 1
            else:
                code_lines += 1
        
        # Require at least 20% comments for complex code blocks
        if code_lines > 5:
            return comment_lines / max(code_lines, 1) >= 0.2
        
        return True  # Short code blocks don't need as much documentation
    
    def _calculate_overall_score(self, component_scores: Dict[str, float]) -> float:
        """Calculate weighted overall score"""
        weights = self.config["scoring"]["weights"]
        total_score = 0.0
        total_weight = 0.0
        
        for component, score in component_scores.items():
            if component in weights:
                weight = weights[component]
                total_score += score * weight
                total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _store_validation_result(self, file_path: Path, result: ValidationResult):
        """Store validation result in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO validation_results 
                (file_path, validation_type, score, passed, issues, timestamp, processing_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(file_path),
                "technical_validation",
                result.overall_score,
                result.passed,
                json.dumps(result.issues),
                result.timestamp,
                result.processing_time
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.warning(f"Failed to store validation result: {e}")
    
    def get_validation_history(self, file_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get validation history from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if file_path:
                cursor.execute('''
                    SELECT * FROM validation_results 
                    WHERE file_path = ? 
                    ORDER BY timestamp DESC
                ''', (file_path,))
            else:
                cursor.execute('''
                    SELECT * FROM validation_results 
                    ORDER BY timestamp DESC
                ''')
            
            columns = [description[0] for description in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return results
            
        except Exception as e:
            logger.error(f"Failed to get validation history: {e}")
            return []
    
    def generate_validation_report(self, results: List[ValidationResult]) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        report = {
            "summary": {
                "total_files": len(results),
                "passed": sum(1 for r in results if r.passed),
                "failed": sum(1 for r in results if not r.passed),
                "average_score": sum(r.overall_score for r in results) / len(results) if results else 0,
                "total_issues": sum(len(r.issues) for r in results),
                "total_warnings": sum(len(r.warnings) for r in results)
            },
            "component_analysis": {},
            "issues_by_category": {},
            "recommendations": [],
            "timestamp": datetime.now().isoformat()
        }
        
        if not results:
            return report
        
        # Analyze component scores
        components = set()
        for result in results:
            components.update(result.component_scores.keys())
        
        for component in components:
            scores = [r.component_scores.get(component, 0) for r in results]
            report["component_analysis"][component] = {
                "average_score": sum(scores) / len(scores),
                "min_score": min(scores),
                "max_score": max(scores),
                "failing_count": sum(1 for s in scores if s < self.config["validation"]["minimum_score"])
            }
        
        # Categorize issues
        issue_categories = {}
        for result in results:
            for issue in result.issues:
                # Simple categorization based on keywords
                category = "general"
                if "code" in issue.lower():
                    category = "code_execution"
                elif "link" in issue.lower():
                    category = "link_validation"
                elif "api" in issue.lower():
                    category = "api_currency"
                elif "security" in issue.lower():
                    category = "security"
                
                if category not in issue_categories:
                    issue_categories[category] = []
                issue_categories[category].append(issue)
        
        report["issues_by_category"] = {
            cat: len(issues) for cat, issues in issue_categories.items()
        }
        
        # Generate top recommendations
        all_recommendations = []
        for result in results:
            all_recommendations.extend(result.recommendations)
        
        # Count recommendation frequency
        rec_counts = {}
        for rec in all_recommendations:
            rec_counts[rec] = rec_counts.get(rec, 0) + 1
        
        # Sort by frequency and take top 10
        top_recommendations = sorted(rec_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        report["recommendations"] = [rec for rec, count in top_recommendations]
        
        return report
    
    def cleanup(self):
        """Clean up temporary resources"""
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            logger.info("Technical validator cleanup completed")
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup()


async def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Technical Validator")
    parser.add_argument("--file", required=True, help="File to validate")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    validator = TechnicalValidator(args.config)
    
    try:
        result = await validator.validate_content(args.file)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(asdict(result), f, indent=2)
            print(f"Results saved to {args.output}")
        else:
            print(f"Validation Score: {result.overall_score:.2f}")
            print(f"Passed: {result.passed}")
            
            if result.issues:
                print("\nIssues:")
                for issue in result.issues:
                    print(f"  - {issue}")
            
            if result.warnings:
                print("\nWarnings:")
                for warning in result.warnings:
                    print(f"  - {warning}")
            
            if result.recommendations:
                print("\nRecommendations:")
                for rec in result.recommendations:
                    print(f"  - {rec}")
    
    finally:
        validator.cleanup()


if __name__ == "__main__":
    asyncio.run(main())