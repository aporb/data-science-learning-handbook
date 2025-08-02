#!/usr/bin/env python3
"""
Automated Testing Framework for Chapter Content Management System
================================================================

Comprehensive multi-platform testing system that provides:
- Multi-language code execution testing (Python, R, SQL, JavaScript)
- Environment isolation and containerization
- Test case generation and validation
- Performance benchmarking and optimization
- Cross-platform compatibility verification
- Automated debugging and error analysis

Author: Claude Code Implementation
Created: 2025-07-28
Version: 1.0.0
"""

import ast
import re
import json
import logging
import asyncio
import tempfile
import subprocess
import shutil
import time
import hashlib
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml
import docker
import psutil
import requests
import nbformat
from nbformat.v4 import new_notebook, new_code_cell

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TestCase:
    """Represents a single test case"""
    id: str
    name: str
    language: str
    code: str
    expected_output: Optional[str]
    setup_code: Optional[str]
    cleanup_code: Optional[str]
    timeout_seconds: int
    environment_requirements: Dict[str, Any]
    tags: List[str]
    priority: str  # "high", "medium", "low"


@dataclass
class TestResult:
    """Result of a single test execution"""
    test_case_id: str
    success: bool
    execution_time: float
    output: str
    error_message: Optional[str]
    exit_code: int
    environment_info: Dict[str, Any]
    resource_usage: Dict[str, Any]
    warnings: List[str]
    timestamp: str


@dataclass
class TestSuiteResult:
    """Result of entire test suite execution"""
    suite_name: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    total_execution_time: float
    success_rate: float
    test_results: List[TestResult]
    platform_summary: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    issues_summary: List[str]
    recommendations: List[str]
    timestamp: str


@dataclass
class PlatformEnvironment:
    """Platform environment configuration"""
    name: str
    language: str
    docker_image: str
    version: str
    dependencies: List[str]
    environment_variables: Dict[str, str]
    setup_commands: List[str]
    validation_commands: List[str]


class AutomatedTestingFramework:
    """
    Comprehensive automated testing framework for multi-platform code validation
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Automated Testing Framework
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.temp_dir = Path(tempfile.mkdtemp(prefix="testing_framework_"))
        self.db_path = self.temp_dir / "test_results.db"
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized successfully")
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            self.docker_client = None
        
        # Initialize platform environments
        self.environments = self._initialize_environments()
        
        # Initialize test database
        self._init_test_database()
        
        # Test case cache
        self.test_cache = {}
        
        logger.info("Automated Testing Framework initialized")
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load testing framework configuration"""
        default_config = {
            "testing": {
                "default_timeout": 30,
                "max_parallel_tests": 5,
                "retry_attempts": 2,
                "memory_limit_mb": 512,
                "cpu_limit_percent": 50,
                "enable_performance_profiling": True
            },
            "environments": {
                "python": {
                    "docker_image": "python:3.9-slim",
                    "version": "3.9",
                    "dependencies": ["pandas", "numpy", "matplotlib", "scikit-learn"],
                    "setup_commands": ["pip install --no-cache-dir -r requirements.txt"]
                },
                "r": {
                    "docker_image": "r-base:4.1.0",
                    "version": "4.1.0", 
                    "dependencies": ["ggplot2", "dplyr", "tidyr", "caret"],
                    "setup_commands": ["R -e \"install.packages(c('ggplot2', 'dplyr', 'tidyr', 'caret'))\""]
                },
                "sql": {
                    "docker_image": "postgres:13",
                    "version": "13",
                    "dependencies": [],
                    "setup_commands": ["createdb testdb"]
                },
                "javascript": {
                    "docker_image": "node:16-slim",
                    "version": "16",
                    "dependencies": ["@observablehq/plot", "d3"],
                    "setup_commands": ["npm install"]
                }
            },
            "validation": {
                "syntax_check": True,
                "security_scan": True,
                "performance_benchmark": True,
                "compatibility_check": True,
                "output_validation": True
            },
            "reporting": {
                "generate_html_report": True,
                "generate_json_report": True,
                "include_performance_charts": True,
                "include_error_analysis": True
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
    
    def _initialize_environments(self) -> Dict[str, PlatformEnvironment]:
        """Initialize platform environments from configuration"""
        environments = {}
        
        for name, config in self.config["environments"].items():
            env = PlatformEnvironment(
                name=name,
                language=name,
                docker_image=config["docker_image"],
                version=config["version"],
                dependencies=config.get("dependencies", []),
                environment_variables=config.get("environment_variables", {}),
                setup_commands=config.get("setup_commands", []),
                validation_commands=config.get("validation_commands", [])
            )
            environments[name] = env
        
        return environments
    
    def _init_test_database(self):
        """Initialize SQLite database for test results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_suites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                suite_name TEXT NOT NULL,
                total_tests INTEGER,
                passed_tests INTEGER,
                failed_tests INTEGER,
                success_rate REAL,
                execution_time REAL,
                timestamp TEXT,
                config_hash TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                suite_id INTEGER,
                test_case_id TEXT,
                language TEXT,
                success BOOLEAN,
                execution_time REAL,
                output TEXT,
                error_message TEXT,
                resource_usage TEXT,
                timestamp TEXT,
                FOREIGN KEY (suite_id) REFERENCES test_suites (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_result_id INTEGER,
                metric_name TEXT,
                metric_value REAL,
                unit TEXT,
                timestamp TEXT,
                FOREIGN KEY (test_result_id) REFERENCES test_results (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def extract_test_cases_from_content(self, content: str, 
                                            file_path: Optional[str] = None) -> List[TestCase]:
        """
        Extract test cases from content (markdown, notebooks, etc.)
        
        Args:
            content: Source content to extract tests from
            file_path: Optional file path for context
            
        Returns:
            List of TestCase objects
        """
        test_cases = []
        
        try:
            if file_path and file_path.endswith('.ipynb'):
                test_cases = await self._extract_from_notebook(content)
            elif file_path and file_path.endswith('.md'):
                test_cases = await self._extract_from_markdown(content)
            elif file_path and file_path.endswith('.py'):
                test_cases = await self._extract_from_python(content)
            else:
                # Try to auto-detect format
                test_cases = await self._auto_extract_test_cases(content)
            
            logger.info(f"Extracted {len(test_cases)} test cases from {file_path or 'content'}")
            
        except Exception as e:
            logger.error(f"Failed to extract test cases: {e}")
        
        return test_cases
    
    async def _extract_from_markdown(self, content: str) -> List[TestCase]:
        """Extract test cases from Markdown content"""
        test_cases = []
        
        # Find code blocks with language specification
        code_pattern = r'```(\w+)(?:\s+(.*)?)?\n(.*?)\n```'
        matches = re.finditer(code_pattern, content, re.DOTALL)
        
        for i, match in enumerate(matches):
            language = match.group(1).lower()
            attributes = match.group(2) or ""
            code = match.group(3).strip()
            
            if language in self.environments and code:
                test_case = TestCase(
                    id=f"markdown_test_{i}",
                    name=f"Test from markdown block {i+1}",
                    language=language,
                    code=code,
                    expected_output=self._extract_expected_output(attributes),
                    setup_code=self._extract_setup_code(attributes),
                    cleanup_code=None,
                    timeout_seconds=self.config["testing"]["default_timeout"],
                    environment_requirements={},
                    tags=self._extract_tags(attributes),
                    priority="medium"
                )
                test_cases.append(test_case)
        
        return test_cases
    
    async def _extract_from_notebook(self, content: str) -> List[TestCase]:
        """Extract test cases from Jupyter notebook"""
        test_cases = []
        
        try:
            notebook = nbformat.reads(content, as_version=4)
            
            for i, cell in enumerate(notebook.cells):
                if cell.cell_type == 'code' and cell.source.strip():
                    # Determine language (default to Python for notebooks)
                    language = 'python'
                    if 'kernel' in notebook.metadata:
                        kernel_name = notebook.metadata['kernel'].get('name', 'python')
                        if 'r' in kernel_name.lower():
                            language = 'r'
                    
                    test_case = TestCase(
                        id=f"notebook_cell_{i}",
                        name=f"Notebook cell {i+1}",
                        language=language,
                        code=cell.source,
                        expected_output=self._extract_cell_expected_output(cell),
                        setup_code=None,
                        cleanup_code=None,
                        timeout_seconds=self.config["testing"]["default_timeout"],
                        environment_requirements={},
                        tags=self._extract_cell_tags(cell),
                        priority="medium"
                    )
                    test_cases.append(test_case)
        
        except Exception as e:
            logger.error(f"Failed to parse notebook: {e}")
        
        return test_cases
    
    async def _extract_from_python(self, content: str) -> List[TestCase]:
        """Extract test cases from Python file"""
        test_cases = []
        
        try:
            tree = ast.parse(content)
            
            # Look for functions that look like tests or examples
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_name = node.name
                    if any(keyword in func_name.lower() 
                          for keyword in ['test', 'example', 'demo', 'sample']):
                        
                        # Extract function code
                        func_code = ast.get_source_segment(content, node)
                        if func_code:
                            test_case = TestCase(
                                id=f"python_func_{func_name}",
                                name=f"Python function: {func_name}",
                                language="python",
                                code=func_code + f"\n\n# Execute function\n{func_name}()",
                                expected_output=None,
                                setup_code=None,
                                cleanup_code=None,
                                timeout_seconds=self.config["testing"]["default_timeout"],
                                environment_requirements={},
                                tags=["function", "python"],
                                priority="medium"
                            )
                            test_cases.append(test_case)
        
        except SyntaxError as e:
            logger.warning(f"Python syntax error: {e}")
        except Exception as e:
            logger.error(f"Failed to parse Python code: {e}")
        
        return test_cases
    
    async def _auto_extract_test_cases(self, content: str) -> List[TestCase]:
        """Auto-detect and extract test cases from content"""
        test_cases = []
        
        # Try markdown extraction first
        markdown_cases = await self._extract_from_markdown(content)
        test_cases.extend(markdown_cases)
        
        # If no markdown cases found, try as Python
        if not markdown_cases:
            python_cases = await self._extract_from_python(content)
            test_cases.extend(python_cases)
        
        return test_cases
    
    def _extract_expected_output(self, attributes: str) -> Optional[str]:
        """Extract expected output from code block attributes"""
        if 'expected:' in attributes:
            return attributes.split('expected:')[1].strip()
        return None
    
    def _extract_setup_code(self, attributes: str) -> Optional[str]:
        """Extract setup code from attributes"""
        if 'setup:' in attributes:
            return attributes.split('setup:')[1].split()[0]
        return None
    
    def _extract_tags(self, attributes: str) -> List[str]:
        """Extract tags from attributes"""
        if 'tags:' in attributes:
            tags_str = attributes.split('tags:')[1].split()[0]
            return [tag.strip() for tag in tags_str.split(',')]
        return []
    
    def _extract_cell_expected_output(self, cell) -> Optional[str]:
        """Extract expected output from notebook cell"""
        if hasattr(cell, 'outputs') and cell.outputs:
            for output in cell.outputs:
                if output.output_type == 'execute_result' and 'data' in output:
                    if 'text/plain' in output.data:
                        return output.data['text/plain']
        return None
    
    def _extract_cell_tags(self, cell) -> List[str]:
        """Extract tags from notebook cell metadata"""
        if hasattr(cell, 'metadata') and 'tags' in cell.metadata:
            return cell.metadata['tags']
        return []
    
    async def run_test_suite(self, test_cases: List[TestCase], 
                           suite_name: str = "default") -> TestSuiteResult:
        """
        Run a complete test suite across multiple platforms
        
        Args:
            test_cases: List of test cases to execute
            suite_name: Name of the test suite
            
        Returns:
            TestSuiteResult with comprehensive results
        """
        start_time = datetime.now()
        
        logger.info(f"Starting test suite '{suite_name}' with {len(test_cases)} tests")
        
        # Initialize result structure
        suite_result = TestSuiteResult(
            suite_name=suite_name,
            total_tests=len(test_cases),
            passed_tests=0,
            failed_tests=0,
            skipped_tests=0,
            total_execution_time=0.0,
            success_rate=0.0,
            test_results=[],
            platform_summary={},
            performance_metrics={},
            issues_summary=[],
            recommendations=[],
            timestamp=start_time.isoformat()
        )
        
        try:
            # Prepare environments
            await self._prepare_environments(test_cases)
            
            # Execute tests with controlled parallelism
            semaphore = asyncio.Semaphore(self.config["testing"]["max_parallel_tests"])
            
            tasks = [
                self._run_single_test_with_semaphore(semaphore, test_case)
                for test_case in test_cases
            ]
            
            test_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(test_results):
                if isinstance(result, Exception):
                    logger.error(f"Test {test_cases[i].id} failed with exception: {result}")
                    # Create failed test result
                    failed_result = TestResult(
                        test_case_id=test_cases[i].id,
                        success=False,
                        execution_time=0.0,
                        output="",
                        error_message=str(result),
                        exit_code=-1,
                        environment_info={},
                        resource_usage={},
                        warnings=[],
                        timestamp=datetime.now().isoformat()
                    )
                    suite_result.test_results.append(failed_result)
                    suite_result.failed_tests += 1
                else:
                    suite_result.test_results.append(result)
                    if result.success:
                        suite_result.passed_tests += 1
                    else:
                        suite_result.failed_tests += 1
            
            # Calculate summary metrics
            suite_result.total_execution_time = (datetime.now() - start_time).total_seconds()
            suite_result.success_rate = (
                suite_result.passed_tests / suite_result.total_tests * 100
                if suite_result.total_tests > 0 else 0.0
            )
            
            # Generate platform summary
            suite_result.platform_summary = self._generate_platform_summary(suite_result.test_results)
            
            # Generate performance metrics
            suite_result.performance_metrics = self._generate_performance_metrics(suite_result.test_results)
            
            # Generate issues and recommendations
            suite_result.issues_summary = self._generate_issues_summary(suite_result.test_results)
            suite_result.recommendations = self._generate_recommendations(suite_result.test_results)
            
            # Store results in database
            self._store_test_suite_result(suite_result)
            
            logger.info(
                f"Test suite '{suite_name}' completed. "
                f"Passed: {suite_result.passed_tests}/{suite_result.total_tests} "
                f"({suite_result.success_rate:.1f}%)"
            )
            
        except Exception as e:
            logger.error(f"Test suite execution failed: {e}")
            suite_result.issues_summary.append(f"Suite execution error: {str(e)}")
        
        return suite_result
    
    async def _prepare_environments(self, test_cases: List[TestCase]):
        """Prepare and validate testing environments"""
        required_languages = set(test_case.language for test_case in test_cases)
        
        for language in required_languages:
            if language in self.environments:
                env = self.environments[language]
                try:
                    await self._prepare_single_environment(env)
                    logger.info(f"Environment '{language}' prepared successfully")
                except Exception as e:
                    logger.error(f"Failed to prepare environment '{language}': {e}")
    
    async def _prepare_single_environment(self, env: PlatformEnvironment):
        """Prepare a single platform environment"""
        if not self.docker_client:
            logger.warning(f"Docker not available, skipping environment preparation for {env.name}")
            return
        
        try:
            # Pull Docker image if not available
            try:
                self.docker_client.images.get(env.docker_image)
            except docker.errors.ImageNotFound:
                logger.info(f"Pulling Docker image: {env.docker_image}")
                self.docker_client.images.pull(env.docker_image)
            
            # Test environment by running a simple command
            test_container = self.docker_client.containers.run(
                env.docker_image,
                command="echo 'Environment test'",
                remove=True,
                detach=False
            )
            
            if test_container:
                logger.debug(f"Environment {env.name} validated successfully")
        
        except Exception as e:
            logger.error(f"Failed to prepare environment {env.name}: {e}")
            raise
    
    async def _run_single_test_with_semaphore(self, semaphore: asyncio.Semaphore, 
                                            test_case: TestCase) -> TestResult:
        """Run a single test case with semaphore control"""
        async with semaphore:
            return await self._run_single_test(test_case)
    
    async def _run_single_test(self, test_case: TestCase) -> TestResult:
        """Execute a single test case"""
        start_time = datetime.now()
        
        logger.debug(f"Running test: {test_case.id} ({test_case.language})")
        
        # Initialize result
        result = TestResult(
            test_case_id=test_case.id,
            success=False,
            execution_time=0.0,
            output="",
            error_message=None,
            exit_code=0,
            environment_info={},
            resource_usage={},
            warnings=[],
            timestamp=start_time.isoformat()
        )
        
        try:
            # Check if environment is available
            if test_case.language not in self.environments:
                result.error_message = f"Environment '{test_case.language}' not available"
                result.exit_code = -1
                return result
            
            env = self.environments[test_case.language]
            
            # Run test based on available execution method
            if self.docker_client:
                result = await self._run_test_in_docker(test_case, env, result)
            else:
                result = await self._run_test_locally(test_case, env, result)
            
            # Validate output if expected output is provided
            if test_case.expected_output and result.success:
                result.success = self._validate_output(result.output, test_case.expected_output)
                if not result.success:
                    result.warnings.append("Output did not match expected result")
            
            # Record execution time
            result.execution_time = (datetime.now() - start_time).total_seconds()
            
        except Exception as e:
            result.error_message = str(e)
            result.execution_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"Test {test_case.id} failed with exception: {e}")
        
        return result
    
    async def _run_test_in_docker(self, test_case: TestCase, env: PlatformEnvironment, 
                                result: TestResult) -> TestResult:
        """Run test case in Docker container"""
        try:
            # Create temporary directory for test files
            test_dir = self.temp_dir / f"test_{test_case.id}"
            test_dir.mkdir(exist_ok=True)
            
            # Prepare test files
            test_files = await self._prepare_test_files(test_case, test_dir)
            
            # Configure container settings
            container_config = {
                'image': env.docker_image,
                'working_dir': '/workspace',
                'volumes': {str(test_dir): {'bind': '/workspace', 'mode': 'rw'}},
                'mem_limit': f"{self.config['testing']['memory_limit_mb']}m",
                'cpu_percent': self.config['testing']['cpu_limit_percent'],
                'network_disabled': True,  # Security: disable network access
                'remove': True,
                'detach': False
            }
            
            # Add environment variables
            if env.environment_variables:
                container_config['environment'] = env.environment_variables
            
            # Determine execution command
            exec_command = self._get_execution_command(test_case.language, test_files['main'])
            
            # Run container
            start_time = time.time()
            try:
                container_output = self.docker_client.containers.run(
                    command=exec_command,
                    timeout=test_case.timeout_seconds,
                    **container_config
                )
                
                result.output = container_output.decode('utf-8') if container_output else ""
                result.success = True
                result.exit_code = 0
                
            except docker.errors.ContainerError as e:
                result.output = e.stderr.decode('utf-8') if e.stderr else ""
                result.error_message = f"Container execution failed: {e}"
                result.exit_code = e.exit_status
                
            except Exception as e:
                result.error_message = f"Docker execution error: {str(e)}"
                result.exit_code = -1
            
            # Record resource usage (simplified)
            execution_time = time.time() - start_time
            result.resource_usage = {
                'execution_time': execution_time,
                'memory_limit_mb': self.config['testing']['memory_limit_mb'],
                'cpu_limit_percent': self.config['testing']['cpu_limit_percent']
            }
            
            # Clean up test directory
            shutil.rmtree(test_dir, ignore_errors=True)
            
        except Exception as e:
            result.error_message = f"Docker test execution failed: {str(e)}"
            result.exit_code = -1
        
        return result
    
    async def _run_test_locally(self, test_case: TestCase, env: PlatformEnvironment,
                              result: TestResult) -> TestResult:
        """Run test case locally (fallback when Docker is not available)"""
        try:
            # Create temporary directory for test files
            test_dir = self.temp_dir / f"test_{test_case.id}"
            test_dir.mkdir(exist_ok=True)
            
            # Prepare test files
            test_files = await self._prepare_test_files(test_case, test_dir)
            
            # Determine execution command
            exec_command = self._get_local_execution_command(test_case.language, test_files['main'])
            
            # Execute command
            start_time = time.time()
            process = await asyncio.create_subprocess_shell(
                exec_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=test_dir
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=test_case.timeout_seconds
                )
                
                result.output = stdout.decode('utf-8')
                if stderr:
                    result.error_message = stderr.decode('utf-8')
                
                result.success = process.returncode == 0
                result.exit_code = process.returncode or 0
                
            except asyncio.TimeoutError:
                process.kill()
                result.error_message = f"Test timed out after {test_case.timeout_seconds} seconds"
                result.exit_code = -1
            
            # Record resource usage
            execution_time = time.time() - start_time
            result.resource_usage = {
                'execution_time': execution_time,
                'local_execution': True
            }
            
            # Clean up test directory
            shutil.rmtree(test_dir, ignore_errors=True)
            
        except Exception as e:
            result.error_message = f"Local test execution failed: {str(e)}"
            result.exit_code = -1
        
        return result
    
    async def _prepare_test_files(self, test_case: TestCase, test_dir: Path) -> Dict[str, str]:
        """Prepare test files in the test directory"""
        files = {}
        
        # Main test file
        main_extension = self._get_file_extension(test_case.language)
        main_file = f"test_main{main_extension}"
        
        # Combine setup, main code, and cleanup
        full_code = ""
        
        if test_case.setup_code:
            full_code += test_case.setup_code + "\n\n"
        
        full_code += test_case.code
        
        if test_case.cleanup_code:
            full_code += "\n\n" + test_case.cleanup_code
        
        # Write main test file
        main_path = test_dir / main_file
        with open(main_path, 'w', encoding='utf-8') as f:
            f.write(full_code)
        
        files['main'] = main_file
        
        # Create requirements/dependencies file if needed
        if test_case.language == 'python' and test_case.environment_requirements:
            req_file = test_dir / "requirements.txt"
            with open(req_file, 'w') as f:
                for req in test_case.environment_requirements.get('packages', []):
                    f.write(f"{req}\n")
            files['requirements'] = "requirements.txt"
        
        return files
    
    def _get_file_extension(self, language: str) -> str:
        """Get appropriate file extension for language"""
        extensions = {
            'python': '.py',
            'r': '.R',
            'sql': '.sql',
            'javascript': '.js',
            'bash': '.sh'
        }
        return extensions.get(language, '.txt')
    
    def _get_execution_command(self, language: str, filename: str) -> str:
        """Get Docker execution command for language"""
        commands = {
            'python': f"python {filename}",
            'r': f"Rscript {filename}",
            'sql': f"psql -f {filename}",
            'javascript': f"node {filename}",
            'bash': f"bash {filename}"
        }
        return commands.get(language, f"cat {filename}")
    
    def _get_local_execution_command(self, language: str, filename: str) -> str:
        """Get local execution command for language"""
        # Same as Docker commands for now, but could be customized
        return self._get_execution_command(language, filename)
    
    def _validate_output(self, actual_output: str, expected_output: str) -> bool:
        """Validate actual output against expected output"""
        # Simple string comparison - could be enhanced with fuzzy matching
        actual_clean = actual_output.strip()
        expected_clean = expected_output.strip()
        
        # Try exact match first
        if actual_clean == expected_clean:
            return True
        
        # Try ignoring whitespace differences
        actual_normalized = re.sub(r'\s+', ' ', actual_clean)
        expected_normalized = re.sub(r'\s+', ' ', expected_clean)
        
        return actual_normalized == expected_normalized
    
    def _generate_platform_summary(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Generate platform-wise summary of test results"""
        platform_summary = {}
        
        # Group results by language/platform
        platform_results = {}
        for result in test_results:
            # Extract language from test_case_id or use environment info
            language = self._extract_language_from_result(result)
            if language not in platform_results:
                platform_results[language] = []
            platform_results[language].append(result)
        
        # Calculate statistics for each platform
        for platform, results in platform_results.items():
            total = len(results)
            passed = sum(1 for r in results if r.success)
            failed = total - passed
            
            avg_execution_time = (
                sum(r.execution_time for r in results) / total
                if total > 0 else 0.0
            )
            
            platform_summary[platform] = {
                'total_tests': total,
                'passed_tests': passed,
                'failed_tests': failed,
                'success_rate': (passed / total * 100) if total > 0 else 0.0,
                'average_execution_time': avg_execution_time,
                'issues': [r.error_message for r in results if r.error_message]
            }
        
        return platform_summary
    
    def _extract_language_from_result(self, result: TestResult) -> str:
        """Extract language from test result"""
        # Try to extract from test_case_id
        if '_' in result.test_case_id:
            parts = result.test_case_id.split('_')
            for part in parts:
                if part in self.environments:
                    return part
        
        # Default fallback
        return 'unknown'
    
    def _generate_performance_metrics(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Generate performance metrics from test results"""
        if not test_results:
            return {}
        
        execution_times = [r.execution_time for r in test_results if r.execution_time > 0]
        
        metrics = {
            'total_execution_time': sum(execution_times),
            'average_execution_time': sum(execution_times) / len(execution_times) if execution_times else 0.0,
            'min_execution_time': min(execution_times) if execution_times else 0.0,
            'max_execution_time': max(execution_times) if execution_times else 0.0,
            'execution_time_std': np.std(execution_times) if len(execution_times) > 1 else 0.0
        }
        
        # Performance classification
        if metrics['average_execution_time'] < 1.0:
            metrics['performance_rating'] = 'excellent'
        elif metrics['average_execution_time'] < 5.0:
            metrics['performance_rating'] = 'good'
        elif metrics['average_execution_time'] < 15.0:
            metrics['performance_rating'] = 'acceptable'
        else:
            metrics['performance_rating'] = 'poor'
        
        return metrics
    
    def _generate_issues_summary(self, test_results: List[TestResult]) -> List[str]:
        """Generate summary of common issues from test results"""
        issues = []
        
        # Count error types
        error_types = {}
        for result in test_results:
            if not result.success and result.error_message:
                # Categorize error
                error_type = self._categorize_error(result.error_message)
                error_types[error_type] = error_types.get(error_type, 0) + 1
        
        # Generate issue summaries
        for error_type, count in error_types.items():
            issues.append(f"{error_type}: {count} occurrences")
        
        # Add timeout issues
        timeout_count = sum(1 for r in test_results if 'timeout' in (r.error_message or '').lower())
        if timeout_count > 0:
            issues.append(f"Timeout issues: {timeout_count} tests")
        
        return issues
    
    def _categorize_error(self, error_message: str) -> str:
        """Categorize error message into types"""
        error_lower = error_message.lower()
        
        if 'syntax' in error_lower:
            return 'Syntax Error'
        elif 'import' in error_lower or 'module' in error_lower:
            return 'Import/Module Error'
        elif 'timeout' in error_lower:
            return 'Timeout Error'
        elif 'permission' in error_lower or 'access' in error_lower:
            return 'Permission Error'
        elif 'memory' in error_lower:
            return 'Memory Error'
        elif 'network' in error_lower or 'connection' in error_lower:
            return 'Network Error'
        else:
            return 'Runtime Error'
    
    def _generate_recommendations(self, test_results: List[TestResult]) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        # Analyze failure patterns
        failed_results = [r for r in test_results if not r.success]
        total_results = len(test_results)
        
        if not failed_results:
            recommendations.append("All tests passed successfully! Consider adding more comprehensive test cases.")
            return recommendations
        
        failure_rate = len(failed_results) / total_results
        
        if failure_rate > 0.5:
            recommendations.append("High failure rate detected. Review code quality and syntax validation.")
        
        # Check for timeout issues
        timeout_failures = [r for r in failed_results if 'timeout' in (r.error_message or '').lower()]
        if timeout_failures:
            recommendations.append(f"Optimize performance for {len(timeout_failures)} slow-running tests.")
        
        # Check for syntax errors
        syntax_failures = [r for r in failed_results if 'syntax' in (r.error_message or '').lower()]
        if syntax_failures:
            recommendations.append("Fix syntax errors in code examples before publication.")
        
        # Check for import errors
        import_failures = [r for r in failed_results if any(term in (r.error_message or '').lower() 
                                                          for term in ['import', 'module'])]
        if import_failures:
            recommendations.append("Ensure all required dependencies are properly documented and available.")
        
        # Performance recommendations
        slow_tests = [r for r in test_results if r.execution_time > 10.0]
        if slow_tests:
            recommendations.append(f"Consider optimizing {len(slow_tests)} slow-running code examples.")
        
        # Platform-specific recommendations
        platform_failures = {}
        for result in failed_results:
            lang = self._extract_language_from_result(result)
            platform_failures[lang] = platform_failures.get(lang, 0) + 1
        
        for platform, count in platform_failures.items():
            if count > 1:
                recommendations.append(f"Review {platform} code examples - {count} failures detected.")
        
        return recommendations[:8]  # Limit to top 8 recommendations
    
    def _store_test_suite_result(self, suite_result: TestSuiteResult):
        """Store test suite result in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert test suite record
            cursor.execute('''
                INSERT INTO test_suites 
                (suite_name, total_tests, passed_tests, failed_tests, success_rate, 
                 execution_time, timestamp, config_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                suite_result.suite_name,
                suite_result.total_tests,
                suite_result.passed_tests,
                suite_result.failed_tests,
                suite_result.success_rate,
                suite_result.total_execution_time,
                suite_result.timestamp,
                self._calculate_config_hash()
            ))
            
            suite_id = cursor.lastrowid
            
            # Insert individual test results
            for result in suite_result.test_results:
                cursor.execute('''
                    INSERT INTO test_results
                    (suite_id, test_case_id, language, success, execution_time,
                     output, error_message, resource_usage, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    suite_id,
                    result.test_case_id,
                    self._extract_language_from_result(result),
                    result.success,
                    result.execution_time,
                    result.output,
                    result.error_message,
                    json.dumps(result.resource_usage),
                    result.timestamp
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.warning(f"Failed to store test results: {e}")
    
    def _calculate_config_hash(self) -> str:
        """Calculate hash of current configuration"""
        config_str = json.dumps(self.config, sort_keys=True)
        return hashlib.md5(config_str.encode()).hexdigest()[:8]
            
    def generate_test_report(self, suite_result: TestSuiteResult,
                           output_path: Optional[Path] = None) -> Dict[str, str]:
        """Generate comprehensive test report"""
        if not output_path:
            output_path = self.temp_dir / "reports"
        
        output_path.mkdir(exist_ok=True)
        generated_files = {}
        
        try:
            # Generate JSON report
            json_report_path = output_path / f"{suite_result.suite_name}_report.json"
            with open(json_report_path, 'w') as f:
                json.dump(asdict(suite_result), f, indent=2, default=str)
            generated_files['json_report'] = str(json_report_path)
            
            # Generate HTML report if configured
            if self.config["reporting"]["generate_html_report"]:
                html_report_path = output_path / f"{suite_result.suite_name}_report.html"
                html_content = self._generate_html_report(suite_result)
                with open(html_report_path, 'w') as f:
                    f.write(html_content)
                generated_files['html_report'] = str(html_report_path)
            
            logger.info(f"Test reports generated in {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate test report: {e}")
        
        return generated_files
    
    def _generate_html_report(self, suite_result: TestSuiteResult) -> str:
        """Generate HTML test report"""
        html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Test Report - {suite_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .metric {{ background-color: #e9ecef; padding: 10px; border-radius: 5px; flex: 1; }}
        .passed {{ color: #28a745; }}
        .failed {{ color: #dc3545; }}
        .test-result {{ margin: 10px 0; padding: 10px; border-left: 4px solid #007bff; }}
        .test-result.failed {{ border-left-color: #dc3545; }}
        .recommendations {{ background-color: #fff3cd; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Test Report: {suite_name}</h1>
        <p>Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <div class="metric">
            <h3>Total Tests</h3>
            <p>{total_tests}</p>
        </div>
        <div class="metric">
            <h3>Passed</h3>
            <p class="passed">{passed_tests}</p>
        </div>
        <div class="metric">
            <h3>Failed</h3>
            <p class="failed">{failed_tests}</p>
        </div>
        <div class="metric">
            <h3>Success Rate</h3>
            <p>{success_rate:.1f}%</p>
        </div>
    </div>
    
    <h2>Platform Summary</h2>
    {platform_summary_html}
    
    <h2>Test Results</h2>
    {test_results_html}
    
    <div class="recommendations">
        <h2>Recommendations</h2>
        <ul>
            {recommendations_html}
        </ul>
    </div>
</body>
</html>
        '''
        
        # Generate platform summary HTML
        platform_html = ""
        for platform, summary in suite_result.platform_summary.items():
            platform_html += f'''
                <div class="metric">
                    <h4>{platform.title()}</h4>
                    <p>Passed: {summary['passed_tests']}/{summary['total_tests']}</p>
                    <p>Success Rate: {summary['success_rate']:.1f}%</p>
                </div>
            '''
        
        # Generate test results HTML
        results_html = ""
        for result in suite_result.test_results:
            status_class = "passed" if result.success else "failed"
            results_html += f'''
                <div class="test-result {status_class}">
                    <h4>{result.test_case_id}</h4>
                    <p>Status: <span class="{status_class}">{'PASSED' if result.success else 'FAILED'}</span></p>
                    <p>Execution Time: {result.execution_time:.2f}s</p>
                    {f'<p>Error: {result.error_message}</p>' if result.error_message else ''}
                </div>
            '''
        
        # Generate recommendations HTML
        recommendations_html = ""
        for rec in suite_result.recommendations:
            recommendations_html += f"<li>{rec}</li>"
        
        return html_template.format(
            suite_name=suite_result.suite_name,
            timestamp=suite_result.timestamp,
            total_tests=suite_result.total_tests,
            passed_tests=suite_result.passed_tests,
            failed_tests=suite_result.failed_tests,
            success_rate=suite_result.success_rate,
            platform_summary_html=platform_html,
            test_results_html=results_html,
            recommendations_html=recommendations_html
        )
    
    def get_test_history(self, suite_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get historical test results"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if suite_name:
                cursor.execute('''
                    SELECT * FROM test_suites 
                    WHERE suite_name = ? 
                    ORDER BY timestamp DESC
                    LIMIT 10
                ''', (suite_name,))
            else:
                cursor.execute('''
                    SELECT * FROM test_suites 
                    ORDER BY timestamp DESC
                    LIMIT 10
                ''')
            
            columns = [description[0] for description in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return results
            
        except Exception as e:
            logger.error(f"Failed to get test history: {e}")
            return []
    
    def cleanup(self):
        """Clean up temporary resources"""
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            logger.info("Automated testing framework cleanup completed")
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup()


async def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Automated Testing Framework")
    parser.add_argument("--file", required=True, help="File to extract tests from")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", help="Output directory for reports")
    parser.add_argument("--suite-name", default="default", help="Test suite name")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    framework = AutomatedTestingFramework(args.config)
    
    try:
        # Read content
        with open(args.file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract test cases
        test_cases = await framework.extract_test_cases_from_content(content, args.file)
        
        if not test_cases:
            print("No test cases found in the provided file")
            return
        
        print(f"Extracted {len(test_cases)} test cases")
        
        # Run test suite
        suite_result = await framework.run_test_suite(test_cases, args.suite_name)
        
        # Generate reports
        output_path = Path(args.output) if args.output else None
        reports = framework.generate_test_report(suite_result, output_path)
        
        # Print summary
        print(f"\nTest Suite Results:")
        print(f"  Suite: {suite_result.suite_name}")
        print(f"  Total Tests: {suite_result.total_tests}")
        print(f"  Passed: {suite_result.passed_tests}")
        print(f"  Failed: {suite_result.failed_tests}")
        print(f"  Success Rate: {suite_result.success_rate:.1f}%")
        print(f"  Execution Time: {suite_result.total_execution_time:.2f}s")
        
        if suite_result.issues_summary:
            print(f"\nIssues:")
            for issue in suite_result.issues_summary:
                print(f"  - {issue}")
        
        if suite_result.recommendations:
            print(f"\nRecommendations:")
            for rec in suite_result.recommendations[:3]:  # Show top 3
                print(f"  → {rec}")
        
        if reports:
            print(f"\nReports generated:")
            for report_type, path in reports.items():
                print(f"  - {report_type}: {path}")
    
    finally:
        framework.cleanup()


if __name__ == "__main__":
    import asyncio
    import numpy as np
    asyncio.run(main())