# CAC/PIV Security Monitoring and Audit System

## Overview

This comprehensive security monitoring and audit system provides advanced monitoring, threat detection, and compliance capabilities for CAC/PIV smart card infrastructure in DoD environments. The system ensures real-time security monitoring, automated threat detection, failover capabilities, and comprehensive compliance reporting.

## Architecture

The monitoring system consists of several integrated components:

### Core Components

1. **Security Monitor** (`cac_piv_security_monitor.py`)
   - Real-time security event detection and correlation
   - Advanced threat analytics and pattern recognition
   - Performance monitoring and metrics collection
   - Integration with audit logging system

2. **Failover Detector** (`failover_detector.py`)
   - Health monitoring for CAC/PIV components
   - Predictive failure detection
   - Automated failover mechanisms
   - Performance degradation monitoring

3. **Security Alerting** (`security_alerting.py`)
   - Multi-channel alert delivery (email, SMS, dashboard, SIEM)
   - Intelligent alert correlation and deduplication
   - Escalation procedures with time-based triggers
   - Alert severity classification and prioritization

4. **Prometheus Integration** (`prometheus_integration.py`)
   - Metrics collection and exposition for Prometheus
   - Integration with existing monitoring infrastructure
   - Custom security metrics for CAC/PIV systems
   - Health check endpoints and service discovery

5. **Compliance Reporting** (`compliance_reporting.py`)
   - Automated DoD compliance report generation
   - NIST SP 800-53 control implementation tracking
   - Real-time compliance metrics and dashboards
   - Audit trail generation and preservation

## Key Features

### Security Monitoring
- **Real-time Event Detection**: Continuous monitoring of security events across CAC/PIV infrastructure
- **Threat Analytics**: Advanced pattern recognition and behavioral analysis
- **Multi-layer Security**: Detection at authentication, card reader, and system levels
- **Correlation Engine**: Intelligent event correlation to reduce false positives

### Health Monitoring
- **Predictive Failure Detection**: Early warning system for component failures
- **Card Reader Health**: Comprehensive monitoring of smart card readers
- **Performance Metrics**: Real-time performance monitoring and alerting
- **Automated Failover**: Seamless failover to backup systems

### Alerting System
- **Multi-channel Delivery**: Email, SMS, webhook, dashboard, and SIEM integration
- **Intelligent Deduplication**: Reduces alert noise through correlation
- **Escalation Procedures**: Automated escalation based on time and severity
- **Rate Limiting**: Prevents alert flooding during incidents

### Compliance Monitoring
- **DoD Standards**: Full compliance with DoD 8500.01E and related standards
- **NIST Framework**: Implementation of NIST SP 800-53 controls
- **Automated Reporting**: Scheduled generation of compliance reports
- **Evidence Collection**: Automated evidence gathering for audits

## Installation and Setup

### Prerequisites

```bash
# Python dependencies
pip install -r requirements.txt

# System dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install sqlite3 prometheus grafana

# Create monitoring user
sudo useradd -r -s /bin/false monitoring
sudo mkdir -p /var/log/security-monitoring
sudo chown monitoring:monitoring /var/log/security-monitoring
```

### Configuration

1. **Environment Variables**:
```bash
# Security monitoring
export SECURITY_MONITOR_PROMETHEUS=true
export SECURITY_MONITOR_PROMETHEUS_PORT=8080
export SECURITY_MONITOR_WORKERS=4
export SECURITY_MONITOR_RETENTION_DAYS=2555

# Alerting configuration
export ALERT_SMTP_SERVER=smtp.company.com
export ALERT_SMTP_USERNAME=alerts@company.com
export ALERT_SMTP_PASSWORD=your_password
export ALERT_EMAIL_FROM=security-alerts@company.com

# Compliance reporting
export COMPLIANCE_AUTO_REPORTS=true
export COMPLIANCE_REPORTS_DIR=/var/reports/compliance
export COMPLIANCE_THRESHOLD=90.0
export COMPLIANCE_RETENTION_YEARS=7

# Prometheus integration
export PROMETHEUS_METRICS_PORT=8080
export PROMETHEUS_BIND_ADDRESS=0.0.0.0
export PROMETHEUS_COLLECTION_INTERVAL=15.0
export PROMETHEUS_SERVICE_NAME=cac-piv-security-monitor
```

2. **Database Setup**:
```bash
# Create database directories
sudo mkdir -p /var/lib/security-monitoring
sudo chown monitoring:monitoring /var/lib/security-monitoring

# Initialize databases (automatically created on first run)
```

3. **TLS Configuration**:
```bash
# Generate TLS certificates for secure communication
openssl req -x509 -newkey rsa:4096 -keyout monitoring.key -out monitoring.crt -days 365 -nodes

# Place certificates in secure location
sudo mkdir -p /etc/security-monitoring/certs
sudo mv monitoring.* /etc/security-monitoring/certs/
sudo chown -R monitoring:monitoring /etc/security-monitoring/
sudo chmod 600 /etc/security-monitoring/certs/*
```

### Service Configuration

1. **systemd Service** (`/etc/systemd/system/security-monitoring.service`):
```ini
[Unit]
Description=CAC/PIV Security Monitoring System
After=network.target
Wants=network.target

[Service]
Type=notify
User=monitoring
Group=monitoring
WorkingDirectory=/opt/security-monitoring
ExecStart=/usr/bin/python3 -m security_compliance.monitoring.main
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/log/security-monitoring /var/lib/security-monitoring

# Environment
EnvironmentFile=/etc/security-monitoring/environment

[Install]
WantedBy=multi-user.target
```

2. **Enable and Start Service**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable security-monitoring
sudo systemctl start security-monitoring
sudo systemctl status security-monitoring
```

## Usage

### Starting the Monitoring System

```python
from security_compliance.monitoring import (
    CACPIVSecurityMonitor, 
    FailoverDetector, 
    SecurityAlerting,
    PrometheusIntegration,
    ComplianceReporting
)

# Initialize components
security_monitor = CACPIVSecurityMonitor()
failover_detector = FailoverDetector()
alerting_system = SecurityAlerting()
prometheus_integration = PrometheusIntegration()
compliance_reporting = ComplianceReporting()

# Register integrations
prometheus_integration.register_security_monitor(security_monitor)
prometheus_integration.register_failover_detector(failover_detector)
prometheus_integration.register_alerting_system(alerting_system)

# Start all components
security_monitor.start()
failover_detector.start()
alerting_system.start()
prometheus_integration.start()
compliance_reporting.start()

# Monitor system status
status = security_monitor.get_monitoring_status()
print(f"Security Monitor Status: {status}")
```

### Recording Security Events

```python
from security_compliance.monitoring.cac_piv_security_monitor import (
    SecurityEvent, SecurityEventCategory, SecurityThreatLevel
)

# Record authentication event
event = SecurityEvent(
    event_id="auth_001",
    category=SecurityEventCategory.AUTHENTICATION_FAILURE,
    threat_level=SecurityThreatLevel.HIGH,
    title="Multiple Failed Authentication Attempts",
    description="User attempted authentication 5 times with invalid credentials",
    source_system="cac_piv_auth",
    source_component="authenticator",
    user_id="john.doe",
    source_ip="192.168.1.100"
)

security_monitor._record_security_event(event)
```

### Generating Compliance Reports

```python
from security_compliance.monitoring.compliance_reporting import (
    ReportType, ComplianceFramework
)

# Generate daily compliance report
report_id = compliance_reporting.generate_compliance_report(
    report_type=ReportType.DAILY_POSTURE,
    framework=ComplianceFramework.NIST_SP_800_53
)

# Get compliance status
status = compliance_reporting.get_compliance_status(
    framework=ComplianceFramework.DOD_8500_01E
)
print(f"DoD Compliance: {status['compliance_percentage']:.1f}%")
```

### Configuring Alerts

```python
from security_compliance.monitoring.security_alerting import (
    AlertRule, AlertChannel, AlertSeverity, SecurityEventCategory
)

# Create custom alert rule
rule = AlertRule(
    rule_id="custom_auth_failure",
    name="High Authentication Failure Rate",
    description="Alert when authentication failures exceed threshold",
    event_categories=[SecurityEventCategory.AUTHENTICATION_FAILURE],
    severity_threshold=AlertSeverity.HIGH,
    time_window_minutes=10,
    event_count_threshold=10,
    alert_severity=AlertSeverity.CRITICAL,
    channels=[AlertChannel.EMAIL, AlertChannel.SMS],
    escalation_enabled=True,
    escalation_delay_minutes=5
)

alerting_system.alert_rules[rule.rule_id] = rule
```

## Monitoring and Dashboards

### Prometheus Metrics

The system exposes metrics on port 8080 (configurable):

- **Authentication Metrics**:
  - `cac_piv_authentication_attempts_total`
  - `cac_piv_authentication_failures_total`
  - `cac_piv_authentication_duration_seconds`

- **Security Metrics**:
  - `cac_piv_security_events_total`
  - `cac_piv_threat_score_current`
  - `cac_piv_security_violations_total`

- **System Health Metrics**:
  - `cac_piv_component_availability`
  - `cac_piv_card_reader_health`
  - `cac_piv_system_cpu_usage_percent`

### Grafana Dashboards

Sample Grafana dashboard configuration is provided in `grafana/dashboards/`:

1. **Security Overview Dashboard**: High-level security metrics and alerts
2. **Authentication Dashboard**: Detailed authentication monitoring
3. **Compliance Dashboard**: Real-time compliance status
4. **System Health Dashboard**: Infrastructure health and performance

### Health Checks

Health check endpoints are available:

- **Metrics Endpoint**: `http://localhost:8080/metrics`
- **Health Check**: `http://localhost:8080/health`

## Configuration Reference

### Security Monitor Configuration

```python
class SecurityMonitoringConfig:
    # Monitoring intervals
    event_processing_interval = 1.0
    metrics_collection_interval = 30.0
    health_check_interval = 60.0
    compliance_check_interval = 300.0
    
    # Data retention
    event_retention_days = 2555  # 7 years
    metrics_retention_days = 365
    alert_retention_days = 90
    
    # Performance settings
    max_events_per_batch = 1000
    max_metrics_buffer_size = 10000
    worker_thread_count = 4
    async_processing_enabled = True
    
    # Integration settings
    prometheus_enabled = True
    prometheus_port = 8080
    siem_integration_enabled = False
```

### Alerting Configuration

```python
class AlertingConfiguration:
    # Processing settings
    alert_processing_interval = 1.0
    escalation_check_interval = 60.0
    cleanup_interval = 3600.0
    
    # Delivery settings
    max_delivery_attempts = 3
    delivery_retry_delay = 60.0
    delivery_timeout = 30.0
    
    # Rate limiting
    rate_limit_enabled = True
    max_alerts_per_minute = 100
    burst_detection_window = 300
    burst_threshold = 50
    
    # Email configuration
    smtp_server = "localhost"
    smtp_port = 587
    smtp_use_tls = True
    email_from = "security-alerts@company.com"
```

### Compliance Configuration

```python
class ComplianceReportingConfiguration:
    # Report generation
    auto_generation_enabled = True
    daily_report_time = "06:00"
    weekly_report_day = "monday"
    monthly_report_day = 1
    
    # Storage settings
    reports_directory = "/var/reports/compliance"
    archive_reports = True
    retention_years = 7
    
    # Supported frameworks
    enabled_frameworks = [
        ComplianceFramework.DOD_8500_01E,
        ComplianceFramework.NIST_SP_800_53,
        ComplianceFramework.FISMA
    ]
    
    # Notification settings
    notify_on_non_compliance = True
    compliance_threshold = 90.0
```

## Security Considerations

### Data Protection
- All sensitive data is encrypted at rest using AES-256
- TLS 1.3 is used for all network communications
- Database access is restricted to monitoring service account
- Audit logs are tamper-proof with cryptographic integrity

### Access Control
- Role-based access control (RBAC) for all components
- Multi-factor authentication required for administrative access
- Principle of least privilege enforced
- Regular access reviews and audits

### Network Security
- Network segmentation between monitoring and production systems
- Firewall rules restrict access to monitoring ports
- VPN or secure tunnels required for remote access
- Network monitoring and intrusion detection

### Compliance
- Full compliance with DoD 8500.01E requirements
- NIST SP 800-53 control implementation
- FISMA compliance monitoring
- Automated evidence collection for audits

## Troubleshooting

### Common Issues

1. **Service Won't Start**:
```bash
# Check service status
sudo systemctl status security-monitoring

# Check logs
sudo journalctl -u security-monitoring -f

# Verify permissions
sudo ls -la /var/log/security-monitoring
sudo ls -la /var/lib/security-monitoring
```

2. **Database Connection Issues**:
```bash
# Check database files
sudo ls -la /var/lib/security-monitoring/

# Verify SQLite installation
sqlite3 --version

# Test database access
sudo -u monitoring sqlite3 /var/lib/security-monitoring/security_monitoring.db ".tables"
```

3. **Prometheus Metrics Not Available**:
```bash
# Check if metrics endpoint is accessible
curl http://localhost:8080/metrics

# Verify port binding
sudo netstat -tlnp | grep 8080

# Check firewall rules
sudo ufw status
```

4. **Alert Delivery Failures**:
```bash
# Check SMTP configuration
telnet smtp.company.com 587

# Verify email credentials
# Check alerting logs for specific error messages
```

### Performance Tuning

1. **High CPU Usage**:
   - Reduce `worker_thread_count`
   - Increase `event_processing_interval`
   - Enable `async_processing`

2. **High Memory Usage**:
   - Reduce `max_metrics_buffer_size`
   - Decrease `event_retention_days`
   - Enable data compression

3. **Slow Response Times**:
   - Increase database connection pool
   - Add database indexes
   - Optimize queries

### Log Analysis

```bash
# Monitor security events
tail -f /var/log/security-monitoring/security_events.log

# Check alert processing
grep "alert" /var/log/security-monitoring/alerting.log

# Monitor compliance status
grep "compliance" /var/log/security-monitoring/compliance.log

# Performance monitoring
grep "performance" /var/log/security-monitoring/monitoring.log
```

## API Reference

### REST API Endpoints

The monitoring system provides REST API endpoints for integration:

- `GET /api/v1/status` - Get system status
- `GET /api/v1/events` - Query security events
- `GET /api/v1/alerts` - Get active alerts
- `POST /api/v1/alerts/{alert_id}/acknowledge` - Acknowledge alert
- `GET /api/v1/compliance/status` - Get compliance status
- `GET /api/v1/reports` - List compliance reports
- `POST /api/v1/reports/generate` - Generate compliance report

### Python API

```python
# Security Monitor API
status = security_monitor.get_monitoring_status()
events = security_monitor.query_security_events(start_time, end_time)

# Alerting API
alerts = alerting_system.get_active_alerts()
alerting_system.acknowledge_alert(alert_id, acknowledged_by)

# Compliance API
status = compliance_reporting.get_compliance_status()
report_id = compliance_reporting.generate_compliance_report(report_type, framework)
```

## Contributing

When contributing to the monitoring system:

1. Follow DoD security standards and practices
2. Ensure all changes maintain compliance requirements
3. Add comprehensive tests for new features
4. Update documentation for configuration changes
5. Follow secure coding practices

## Support

For support and maintenance:

- Security Team: security-team@company.com
- Monitoring Team: monitoring-team@company.com
- Emergency Contact: soc@company.com (24/7)

## License

This software is developed for use in DoD environments and is subject to applicable security regulations and export controls.

---

**Classification**: UNCLASSIFIED  
**Version**: 1.0.0  
**Last Updated**: 2025-01-27  
**Developed by**: Security Monitoring Team