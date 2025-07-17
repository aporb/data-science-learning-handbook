#!/bin/bash

# Security Scanner Script for Data Science Learning Handbook
# This script runs comprehensive security scans across the project

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

# Configuration
REPORT_DIR="/app/reports"
SECURITY_DIR="/app/security-compliance"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create report directory
mkdir -p "$REPORT_DIR/$TIMESTAMP"

log "Starting security scan for Data Science Learning Handbook"
log "Reports will be saved to: $REPORT_DIR/$TIMESTAMP"

# 1. Python Security Scanning
log "Running Python security scans..."
cd /app

# Bandit - Python security linter
if command -v bandit &> /dev/null; then
    log "Running Bandit security scan..."
    bandit -r . -f json -o "$REPORT_DIR/$TIMESTAMP/bandit_report.json" || warning "Bandit scan failed"
    bandit -r . -f txt -o "$REPORT_DIR/$TIMESTAMP/bandit_report.txt" || warning "Bandit scan failed"
else
    warning "Bandit not found, skipping Python security scan"
fi

# Safety - Python dependency vulnerability scanner
if command -v safety &> /dev/null; then
    log "Running Safety vulnerability scan..."
    safety check --json > "$REPORT_DIR/$TIMESTAMP/safety_report.json" || warning "Safety scan failed"
    safety check > "$REPORT_DIR/$TIMESTAMP/safety_report.txt" || warning "Safety scan failed"
else
    warning "Safety not found, skipping dependency vulnerability scan"
fi

# Pip-audit - Python package vulnerability scanner
if command -v pip-audit &> /dev/null; then
    log "Running pip-audit scan..."
    pip-audit --format=json --output="$REPORT_DIR/$TIMESTAMP/pip_audit_report.json" || warning "pip-audit scan failed"
    pip-audit --format=markdown --output="$REPORT_DIR/$TIMESTAMP/pip_audit_report.md" || warning "pip-audit scan failed"
else
    warning "pip-audit not found, skipping package vulnerability scan"
fi

# 2. Infrastructure Security Scanning
log "Running infrastructure security scans..."

# Dockerfile linting
if command -v dockerfile-lint &> /dev/null; then
    log "Running Dockerfile linting..."
    find . -name "Dockerfile*" -type f | while read -r dockerfile; do
        dockerfile-lint "$dockerfile" > "$REPORT_DIR/$TIMESTAMP/dockerfile_lint_$(basename "$dockerfile").txt" || warning "Dockerfile lint failed for $dockerfile"
    done
else
    warning "dockerfile-lint not found, skipping Dockerfile linting"
fi

# YAML linting
if command -v yamllint &> /dev/null; then
    log "Running YAML linting..."
    find . -name "*.yml" -o -name "*.yaml" | while read -r yamlfile; do
        yamllint "$yamlfile" > "$REPORT_DIR/$TIMESTAMP/yamllint_$(basename "$yamlfile").txt" || warning "YAML lint failed for $yamlfile"
    done
else
    warning "yamllint not found, skipping YAML linting"
fi

# 3. Container Security Scanning
log "Running container security scans..."

# Check for secrets in code
log "Scanning for secrets..."
grep -r -i "password\|secret\|key\|token" --include="*.py" --include="*.js" --include="*.sh" --include="*.yml" --include="*.yaml" . > "$REPORT_DIR/$TIMESTAMP/secret_scan.txt" || true

# Check for hardcoded credentials
log "Checking for hardcoded credentials..."
grep -r -E "(password|passwd|pwd|secret|key|token)\s*=\s*['\"][^'\"]+['\"]" --include="*.py" --include="*.js" --include="*.sh" --include="*.yml" --include="*.yaml" . > "$REPORT_DIR/$TIMESTAMP/hardcoded_credentials.txt" || true

# 4. Network Security Scanning
log "Running network security scans..."

# Nmap scan for open ports
if command -v nmap &> /dev/null; then
    log "Running Nmap scan..."
    nmap -sT -O localhost > "$REPORT_DIR/$TIMESTAMP/nmap_scan.txt" || warning "Nmap scan failed"
else
    warning "nmap not found, skipping network scan"
fi

# 5. Web Application Security Scanning
log "Running web application security scans..."

# Nikto scan
if command -v nikto &> /dev/null; then
    log "Running Nikto scan..."
    nikto -h localhost -p 80,443,8888,5000,3000,5601 -o "$REPORT_DIR/$TIMESTAMP/nikto_scan.txt" || warning "Nikto scan failed"
else
    warning "nikto not found, skipping web application scan"
fi

# 6. SQL Injection Testing
log "Running SQL injection tests..."

# SQLMap scan
if command -v sqlmap &> /dev/null; then
    log "Running SQLMap scan..."
    sqlmap -u "http://localhost:5000" --batch --output-dir="$REPORT_DIR/$TIMESTAMP/sqlmap" || warning "SQLMap scan failed"
else
    warning "sqlmap not found, skipping SQL injection scan"
fi

# 7. Malware Scanning
log "Running malware scans..."

# ClamAV scan
if command -v clamscan &> /dev/null; then
    log "Running ClamAV scan..."
    clamscan -r -i --log="$REPORT_DIR/$TIMESTAMP/clamav_scan.log" . || warning "ClamAV scan failed"
else
    warning "clamscan not found, skipping malware scan"
fi

# 8. Generate Security Report Summary
log "Generating security report summary..."

cat > "$REPORT_DIR/$TIMESTAMP/security_summary.md" << EOF
# Security Scan Summary Report
**Generated:** $(date)

## Overview
This report contains the results of comprehensive security scanning for the Data Science Learning Handbook project.

## Scan Results
- **Python Security:** Bandit, Safety, pip-audit
- **Infrastructure:** Dockerfile linting, YAML validation
- **Container Security:** Secret scanning, credential checks
- **Network Security:** Port scanning, web application testing
- **Malware Detection:** ClamAV scanning

## Files Generated
$(ls -la "$REPORT_DIR/$TIMESTAMP")

## Next Steps
1. Review all security reports
2. Address any high-severity vulnerabilities
3. Update security policies as needed
4. Schedule regular security scans

## Contact
For questions about this security scan, contact the security team.
EOF

log "Security scan completed successfully"
log "All reports saved to: $REPORT_DIR/$TIMESTAMP"
log "Summary report: $REPORT_DIR/$TIMESTAMP/security_summary.md"

# Display summary
echo ""
echo "============================================"
echo "Security Scan Summary"
echo "============================================"
echo "Reports location: $REPORT_DIR/$TIMESTAMP"
echo "Summary file: $REPORT_DIR/$TIMESTAMP/security_summary.md"
echo "============================================"
