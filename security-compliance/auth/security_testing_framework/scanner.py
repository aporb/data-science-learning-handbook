"""
Security Scanner Module
Implements automated security scanning pipeline with SAST and DAST capabilities.
"""

import os
import subprocess
import json
import yaml
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Result from a security scan"""
    scan_type: str
    tool: str
    timestamp: datetime
    target: str
    findings: List[Dict[str, Any]]
    severity_counts: Dict[str, int]
    scan_duration: float
    status: str
    metadata: Dict[str, Any]

@dataclass 
class ScanConfig:
    """Configuration for security scans"""
    sast_tools: List[str]
    dast_tools: List[str] 
    code_paths: List[str]
    exclusions: List[str]
    severity_threshold: str
    output_formats: List[str]
    parallel_execution: bool
    timeout_minutes: int

class SecurityScanner:
    """Comprehensive security scanner with SAST and DAST capabilities"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.results_dir = Path("security_test_results")
        self.results_dir.mkdir(exist_ok=True)
        
        # SAST Tools mapping
        self.sast_tools = {
            'bandit': self._run_bandit,
            'semgrep': self._run_semgrep,
            'safety': self._run_safety,
            'pylint': self._run_pylint_security,
            'sonarqube': self._run_sonarqube
        }
        
        # DAST Tools mapping
        self.dast_tools = {
            'zap': self._run_zap,
            'nikto': self._run_nikto,
            'nmap': self._run_nmap,
            'ssl_test': self._run_ssl_test
        }
    
    def _load_config(self, config_path: Optional[str]) -> ScanConfig:
        """Load scanner configuration"""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            return ScanConfig(**config_data)
        
        # Default configuration
        return ScanConfig(
            sast_tools=['bandit', 'semgrep', 'safety'],
            dast_tools=['zap', 'nmap', 'ssl_test'],
            code_paths=['.'],
            exclusions=['__pycache__', '.git', 'node_modules', 'venv', '.env'],
            severity_threshold='medium',
            output_formats=['json', 'sarif'],
            parallel_execution=True,
            timeout_minutes=30
        )
    
    def run_comprehensive_scan(self, target: str) -> Dict[str, ScanResult]:
        """Run comprehensive security scan with both SAST and DAST"""
        logger.info(f"Starting comprehensive security scan for: {target}")
        
        results = {}
        
        # Run SAST scans
        if os.path.isdir(target):
            logger.info("Running SAST scans...")
            for tool in self.config.sast_tools:
                if tool in self.sast_tools:
                    try:
                        result = self.sast_tools[tool](target)
                        results[f"sast_{tool}"] = result
                    except Exception as e:
                        logger.error(f"SAST scan with {tool} failed: {e}")
        
        # Run DAST scans
        if target.startswith(('http://', 'https://')):
            logger.info("Running DAST scans...")
            for tool in self.config.dast_tools:
                if tool in self.dast_tools:
                    try:
                        result = self.dast_tools[tool](target)
                        results[f"dast_{tool}"] = result
                    except Exception as e:
                        logger.error(f"DAST scan with {tool} failed: {e}")
        
        # Save combined results
        self._save_scan_results(results, target)
        return results
    
    def _run_bandit(self, target: str) -> ScanResult:
        """Run Bandit SAST scan for Python security issues"""
        start_time = datetime.now(timezone.utc)
        
        cmd = [
            'bandit', '-r', target,
            '-f', 'json',
            '-o', str(self.results_dir / 'bandit_results.json')
        ]
        
        # Add exclusions
        for exclusion in self.config.exclusions:
            cmd.extend(['--exclude', f"*/{exclusion}/*"])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_minutes*60)
            
            # Parse JSON output
            findings = []
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            if os.path.exists(self.results_dir / 'bandit_results.json'):
                with open(self.results_dir / 'bandit_results.json', 'r') as f:
                    data = json.load(f)
                    findings = data.get('results', [])
                    
                    for finding in findings:
                        severity = finding.get('issue_severity', 'low').lower()
                        if severity in severity_counts:
                            severity_counts[severity] += 1
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return ScanResult(
                scan_type='SAST',
                tool='bandit',
                timestamp=start_time,
                target=target,
                findings=findings,
                severity_counts=severity_counts,
                scan_duration=duration,
                status='completed' if result.returncode in [0, 1] else 'failed',
                metadata={'command': ' '.join(cmd), 'return_code': result.returncode}
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_type='SAST',
                tool='bandit', 
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=self.config.timeout_minutes * 60,
                status='timeout',
                metadata={'error': 'Scan timed out'}
            )
    
    def _run_semgrep(self, target: str) -> ScanResult:
        """Run Semgrep SAST scan"""
        start_time = datetime.now(timezone.utc)
        
        cmd = [
            'semgrep', '--config=auto',
            '--json',
            '--output', str(self.results_dir / 'semgrep_results.json'),
            target
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_minutes*60)
            
            findings = []
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            if os.path.exists(self.results_dir / 'semgrep_results.json'):
                with open(self.results_dir / 'semgrep_results.json', 'r') as f:
                    data = json.load(f)
                    findings = data.get('results', [])
                    
                    for finding in findings:
                        severity = finding.get('extra', {}).get('severity', 'low').lower()
                        if severity in severity_counts:
                            severity_counts[severity] += 1
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return ScanResult(
                scan_type='SAST',
                tool='semgrep',
                timestamp=start_time,
                target=target,
                findings=findings,
                severity_counts=severity_counts,
                scan_duration=duration,
                status='completed' if result.returncode == 0 else 'failed',
                metadata={'command': ' '.join(cmd), 'return_code': result.returncode}
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_type='SAST',
                tool='semgrep',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=self.config.timeout_minutes * 60,
                status='timeout',
                metadata={'error': 'Scan timed out'}
            )
    
    def _run_safety(self, target: str) -> ScanResult:
        """Run Safety scan for vulnerable dependencies"""
        start_time = datetime.now(timezone.utc)
        
        # Look for requirements files
        req_files = []
        for root, dirs, files in os.walk(target):
            for file in files:
                if file in ['requirements.txt', 'requirements-dev.txt', 'Pipfile']:
                    req_files.append(os.path.join(root, file))
        
        findings = []
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for req_file in req_files:
            cmd = ['safety', 'check', '-r', req_file, '--json']
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.stdout:
                    data = json.loads(result.stdout)
                    for vuln in data:
                        findings.append(vuln)
                        # Safety doesn't provide severity, assume medium for vulnerabilities
                        severity_counts['medium'] += 1
                        
            except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
                logger.error(f"Safety scan failed for {req_file}: {e}")
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        return ScanResult(
            scan_type='SAST',
            tool='safety',
            timestamp=start_time,
            target=target,
            findings=findings,
            severity_counts=severity_counts,
            scan_duration=duration,
            status='completed',
            metadata={'requirements_files': req_files}
        )
    
    def _run_pylint_security(self, target: str) -> ScanResult:
        """Run Pylint with security-focused checks"""
        start_time = datetime.now(timezone.utc)
        
        cmd = [
            'pylint', target,
            '--load-plugins=pylint.extensions.check_elif',
            '--output-format=json',
            '--reports=no'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_minutes*60)
            
            findings = []
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for issue in data:
                        if any(keyword in issue.get('message', '').lower() 
                              for keyword in ['security', 'sql', 'injection', 'xss', 'csrf']):
                            findings.append(issue)
                            severity_counts['medium'] += 1
                except json.JSONDecodeError:
                    pass
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return ScanResult(
                scan_type='SAST',
                tool='pylint_security',
                timestamp=start_time,
                target=target,
                findings=findings,
                severity_counts=severity_counts,
                scan_duration=duration,
                status='completed',
                metadata={'command': ' '.join(cmd)}
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_type='SAST',
                tool='pylint_security',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=self.config.timeout_minutes * 60,
                status='timeout',
                metadata={'error': 'Scan timed out'}
            )
    
    def _run_sonarqube(self, target: str) -> ScanResult:
        """Run SonarQube scan (requires SonarQube server)"""
        start_time = datetime.now(timezone.utc)
        
        # This is a placeholder - actual implementation would require SonarQube server
        logger.info("SonarQube scan would require server setup - skipping")
        
        return ScanResult(
            scan_type='SAST',
            tool='sonarqube',
            timestamp=start_time,
            target=target,
            findings=[],
            severity_counts={'high': 0, 'medium': 0, 'low': 0},
            scan_duration=0,
            status='skipped',
            metadata={'note': 'Requires SonarQube server configuration'}
        )
    
    def _run_zap(self, target: str) -> ScanResult:
        """Run OWASP ZAP DAST scan"""
        start_time = datetime.now(timezone.utc)
        
        # ZAP command for baseline scan
        cmd = [
            'zap-baseline.py',
            '-t', target,
            '-J', str(self.results_dir / 'zap_results.json')
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_minutes*60)
            
            findings = []
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            # Parse ZAP JSON output
            if os.path.exists(self.results_dir / 'zap_results.json'):
                with open(self.results_dir / 'zap_results.json', 'r') as f:
                    data = json.load(f)
                    for site in data.get('site', []):
                        for alert in site.get('alerts', []):
                            findings.append(alert)
                            risk = alert.get('riskdesc', 'Low').lower()
                            if 'high' in risk:
                                severity_counts['high'] += 1
                            elif 'medium' in risk:
                                severity_counts['medium'] += 1
                            else:
                                severity_counts['low'] += 1
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return ScanResult(
                scan_type='DAST',
                tool='zap',
                timestamp=start_time,
                target=target,
                findings=findings,
                severity_counts=severity_counts,
                scan_duration=duration,
                status='completed' if result.returncode == 0 else 'failed',
                metadata={'command': ' '.join(cmd)}
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_type='DAST',
                tool='zap',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=self.config.timeout_minutes * 60,
                status='timeout',
                metadata={'error': 'Scan timed out'}
            )
        except FileNotFoundError:
            return ScanResult(
                scan_type='DAST',
                tool='zap',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=0,
                status='tool_not_found',
                metadata={'error': 'ZAP not installed or not in PATH'}
            )
    
    def _run_nikto(self, target: str) -> ScanResult:
        """Run Nikto web vulnerability scan"""
        start_time = datetime.now(timezone.utc)
        
        cmd = [
            'nikto',
            '-h', target,
            '-output', str(self.results_dir / 'nikto_results.txt')
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_minutes*60)
            
            findings = []
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            # Parse Nikto output (text-based)
            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '+ ' in line and any(keyword in line.lower() for keyword in 
                                          ['vulnerability', 'security', 'risk', 'exploit']):
                        findings.append({'description': line.strip(), 'type': 'web_vulnerability'})
                        severity_counts['medium'] += 1
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return ScanResult(
                scan_type='DAST',
                tool='nikto',
                timestamp=start_time,
                target=target,
                findings=findings,
                severity_counts=severity_counts,
                scan_duration=duration,
                status='completed' if result.returncode == 0 else 'failed',
                metadata={'command': ' '.join(cmd)}
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_type='DAST',
                tool='nikto',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=self.config.timeout_minutes * 60,
                status='timeout',
                metadata={'error': 'Scan timed out'}
            )
        except FileNotFoundError:
            return ScanResult(
                scan_type='DAST',
                tool='nikto',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=0,
                status='tool_not_found',
                metadata={'error': 'Nikto not installed or not in PATH'}
            )
    
    def _run_nmap(self, target: str) -> ScanResult:
        """Run Nmap port scan and service detection"""
        start_time = datetime.now(timezone.utc)
        
        # Extract host from URL if needed
        if target.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname
        else:
            host = target
        
        cmd = [
            'nmap',
            '-sV',  # Version detection
            '-sC',  # Default scripts
            '--script=vuln',  # Vulnerability scripts
            '-oX', str(self.results_dir / 'nmap_results.xml'),
            host
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_minutes*60)
            
            findings = []
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            # Parse nmap output for vulnerabilities
            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in 
                          ['vulnerability', 'exploit', 'cve-', 'security']):
                        findings.append({'description': line.strip(), 'type': 'network_vulnerability'})
                        if 'critical' in line.lower() or 'high' in line.lower():
                            severity_counts['high'] += 1
                        elif 'medium' in line.lower():
                            severity_counts['medium'] += 1
                        else:
                            severity_counts['low'] += 1
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return ScanResult(
                scan_type='DAST',
                tool='nmap',
                timestamp=start_time,
                target=target,
                findings=findings,
                severity_counts=severity_counts,
                scan_duration=duration,
                status='completed' if result.returncode == 0 else 'failed',
                metadata={'command': ' '.join(cmd)}
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_type='DAST',
                tool='nmap',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=self.config.timeout_minutes * 60,
                status='timeout',
                metadata={'error': 'Scan timed out'}
            )
        except FileNotFoundError:
            return ScanResult(
                scan_type='DAST',
                tool='nmap',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=0,
                status='tool_not_found',
                metadata={'error': 'Nmap not installed or not in PATH'}
            )
    
    def _run_ssl_test(self, target: str) -> ScanResult:
        """Run SSL/TLS configuration test"""
        start_time = datetime.now(timezone.utc)
        
        if not target.startswith(('https://')):
            return ScanResult(
                scan_type='DAST',
                tool='ssl_test',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=0,
                status='skipped',
                metadata={'note': 'Target is not HTTPS'}
            )
        
        # Use testssl.sh if available, otherwise use openssl
        cmd = ['testssl.sh', '--jsonfile', str(self.results_dir / 'ssl_results.json'), target]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config.timeout_minutes*60)
            
            findings = []
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            # Parse testssl.sh JSON output
            if os.path.exists(self.results_dir / 'ssl_results.json'):
                with open(self.results_dir / 'ssl_results.json', 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if data.get('severity') in ['HIGH', 'CRITICAL']:
                                findings.append(data)
                                severity_counts['high'] += 1
                            elif data.get('severity') == 'MEDIUM':
                                findings.append(data)
                                severity_counts['medium'] += 1
                            elif data.get('severity') in ['LOW', 'INFO']:
                                findings.append(data)
                                severity_counts['low'] += 1
                        except json.JSONDecodeError:
                            continue
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return ScanResult(
                scan_type='DAST',
                tool='ssl_test',
                timestamp=start_time,
                target=target,
                findings=findings,
                severity_counts=severity_counts,
                scan_duration=duration,
                status='completed' if result.returncode == 0 else 'failed',
                metadata={'command': ' '.join(cmd)}
            )
            
        except FileNotFoundError:
            # Fallback to basic openssl test
            return self._basic_ssl_test(target, start_time)
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_type='DAST',
                tool='ssl_test',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=self.config.timeout_minutes * 60,
                status='timeout',
                metadata={'error': 'SSL test timed out'}
            )
    
    def _basic_ssl_test(self, target: str, start_time: datetime) -> ScanResult:
        """Basic SSL test using openssl"""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443
        
        cmd = ['openssl', 's_client', '-connect', f'{host}:{port}', '-servername', host]
        
        try:
            result = subprocess.run(cmd, input='\n', capture_output=True, text=True, timeout=30)
            
            findings = []
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            # Basic SSL analysis
            if 'SSLv2' in result.stdout or 'SSLv3' in result.stdout:
                findings.append({'issue': 'Weak SSL version detected', 'severity': 'high'})
                severity_counts['high'] += 1
            
            if 'RC4' in result.stdout:
                findings.append({'issue': 'Weak cipher RC4 detected', 'severity': 'medium'})
                severity_counts['medium'] += 1
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            return ScanResult(
                scan_type='DAST',
                tool='ssl_test',
                timestamp=start_time,
                target=target,
                findings=findings,
                severity_counts=severity_counts,
                scan_duration=duration,
                status='completed',
                metadata={'method': 'basic_openssl'}
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_type='DAST',
                tool='ssl_test',
                timestamp=start_time,
                target=target,
                findings=[],
                severity_counts={'high': 0, 'medium': 0, 'low': 0},
                scan_duration=30,
                status='timeout',
                metadata={'error': 'Basic SSL test timed out'}
            )
    
    def _save_scan_results(self, results: Dict[str, ScanResult], target: str):
        """Save scan results to files"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        
        # Create consolidated report
        report = {
            'scan_metadata': {
                'target': target,
                'timestamp': timestamp,
                'total_scans': len(results)
            },
            'results': {name: asdict(result) for name, result in results.items()}
        }
        
        # Save JSON report
        report_file = self.results_dir / f"security_scan_report_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Security scan results saved to: {report_file}")
        
        # Generate summary
        self._generate_summary_report(results, target, timestamp)
    
    def _generate_summary_report(self, results: Dict[str, ScanResult], target: str, timestamp: str):
        """Generate human-readable summary report"""
        summary_file = self.results_dir / f"security_scan_summary_{timestamp}.md"
        
        total_findings = sum(len(result.findings) for result in results.values())
        total_high = sum(result.severity_counts.get('high', 0) for result in results.values())
        total_medium = sum(result.severity_counts.get('medium', 0) for result in results.values())
        total_low = sum(result.severity_counts.get('low', 0) for result in results.values())
        
        with open(summary_file, 'w') as f:
            f.write(f"# Security Scan Summary Report\n\n")
            f.write(f"**Target:** {target}\n")
            f.write(f"**Scan Date:** {timestamp}\n")
            f.write(f"**Total Findings:** {total_findings}\n\n")
            
            f.write(f"## Severity Breakdown\n\n")
            f.write(f"- 🔴 High: {total_high}\n")
            f.write(f"- 🟡 Medium: {total_medium}\n") 
            f.write(f"- 🟢 Low: {total_low}\n\n")
            
            f.write(f"## Scan Results by Tool\n\n")
            
            for name, result in results.items():
                f.write(f"### {result.tool.upper()} ({result.scan_type})\n\n")
                f.write(f"- **Status:** {result.status}\n")
                f.write(f"- **Duration:** {result.scan_duration:.2f}s\n")
                f.write(f"- **Findings:** {len(result.findings)}\n")
                f.write(f"- **High:** {result.severity_counts.get('high', 0)}\n")
                f.write(f"- **Medium:** {result.severity_counts.get('medium', 0)}\n")
                f.write(f"- **Low:** {result.severity_counts.get('low', 0)}\n\n")
        
        logger.info(f"Security scan summary saved to: {summary_file}")