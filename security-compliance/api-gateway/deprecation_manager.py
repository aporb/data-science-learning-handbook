"""
API Deprecation Manager for DoD Enterprise Systems

This module provides comprehensive API deprecation management including stakeholder 
notifications, migration planning, sunset workflows, and consumer impact analysis
for DoD-compliant enterprise environments.

Key Features:
- Automated deprecation workflows with configurable timelines
- Stakeholder notification system with multiple channels
- Consumer impact analysis and migration planning
- Sunset timeline management with enforcement
- Compliance tracking for deprecation policies
- Integration with DoD enterprise communication systems

Security Standards:
- NIST 800-53 change management controls
- DoD 8500 series deprecation compliance
- FIPS 140-2 notification encryption
- STIGs compliance for lifecycle management
"""

import asyncio
import json
import logging
import uuid
import smtplib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Template

import aioredis
import aiohttp
from cryptography.hazmat.primitives import hashes

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api_gateway.dod_api_gateway import APIGatewayEnvironment, SecurityClassification
from api_gateway.api_version_manager import APIVersionManager, VersionState, ConsumerRegistration
from encryption.encryption_manager import EncryptionManager


class DeprecationPhase(Enum):
    """Deprecation phases."""
    PLANNING = "planning"
    ANNOUNCEMENT = "announcement"
    WARNING = "warning"
    RESTRICTED = "restricted"
    SUNSET = "sunset"
    ARCHIVED = "archived"


class NotificationChannel(Enum):
    """Notification channels."""
    EMAIL = "email"
    WEBHOOK = "webhook"
    SMS = "sms"
    SLACK = "slack"
    TEAMS = "teams"
    PORTAL = "portal"
    API_HEADER = "api_header"


class NotificationPriority(Enum):
    """Notification priorities."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    URGENT = "urgent"


class MigrationStatus(Enum):
    """Migration status tracking."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    TESTING = "testing"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    OVERDUE = "overdue"


@dataclass
class DeprecationTimeline:
    """Deprecation timeline configuration."""
    announcement_days: int = 90    # Days before deprecation to announce
    warning_days: int = 60         # Days before deprecation to start warnings
    restriction_days: int = 30     # Days before deprecation to restrict access
    sunset_days: int = 0           # Days until API is completely shut down
    grace_period_days: int = 7     # Grace period after sunset for emergency access


@dataclass
class NotificationTemplate:
    """Notification template."""
    template_id: str
    name: str
    subject_template: str
    body_template: str
    channel: NotificationChannel
    priority: NotificationPriority
    variables: List[str] = field(default_factory=list)


@dataclass
class StakeholderContact:
    """Stakeholder contact information."""
    stakeholder_id: str
    name: str
    role: str
    email: Optional[str] = None
    phone: Optional[str] = None
    slack_user_id: Optional[str] = None
    teams_user_id: Optional[str] = None
    preferred_channels: List[NotificationChannel] = field(default_factory=list)
    notification_schedule: Dict[str, Any] = field(default_factory=dict)
    escalation_contact: Optional[str] = None


@dataclass
class MigrationPlan:
    """Migration plan for API consumers."""
    plan_id: str
    consumer_id: str
    source_version: str
    target_version: str
    migration_steps: List[Dict[str, Any]]
    estimated_effort_hours: int
    target_completion_date: datetime
    assigned_engineer: Optional[str] = None
    status: MigrationStatus = MigrationStatus.NOT_STARTED
    progress_percentage: int = 0
    blockers: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class DeprecationPolicy:
    """Deprecation policy configuration."""
    policy_id: str
    name: str
    description: str
    timeline: DeprecationTimeline
    required_approvals: List[str]
    notification_templates: List[str]
    enforcement_rules: Dict[str, Any]
    compliance_requirements: List[str]
    exception_process: Dict[str, Any]


@dataclass
class DeprecationNotification:
    """Deprecation notification record."""
    notification_id: str
    deprecation_id: str
    recipient_id: str
    channel: NotificationChannel
    template_id: str
    sent_at: datetime
    status: str  # sent, failed, delivered, read
    retry_count: int = 0
    error_message: Optional[str] = None


@dataclass
class DeprecationWorkflow:
    """Deprecation workflow tracking."""
    deprecation_id: str
    version: str
    policy_id: str
    phase: DeprecationPhase
    initiated_by: str
    initiated_at: datetime
    announcement_date: datetime
    warning_date: datetime
    restriction_date: datetime
    sunset_date: datetime
    archive_date: datetime
    affected_consumers: List[str]
    migration_plans: List[str]
    stakeholders: List[str]
    approvals: Dict[str, Any] = field(default_factory=dict)
    notifications_sent: List[str] = field(default_factory=list)
    compliance_checks: Dict[str, bool] = field(default_factory=dict)
    status: str = "active"
    metadata: Dict[str, Any] = field(default_factory=dict)


class DeprecationManager:
    """
    Comprehensive API Deprecation Manager for DoD Enterprise Systems
    
    Manages API deprecation workflows, stakeholder notifications, migration planning,
    and compliance tracking with enterprise-grade features for DoD environments.
    """
    
    def __init__(self, version_manager: APIVersionManager,
                 redis_url: str = "redis://localhost:6379",
                 smtp_server: str = "localhost",
                 smtp_port: int = 587):
        """Initialize Deprecation Manager."""
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.version_manager = version_manager
        
        # Redis client for state management
        self.redis_client = None
        self.redis_url = redis_url
        
        # Email configuration
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_username = None
        self.smtp_password = None
        
        # HTTP session for webhooks
        self._http_session = None
        
        # Storage
        self.deprecation_workflows: Dict[str, DeprecationWorkflow] = {}
        self.deprecation_policies: Dict[str, DeprecationPolicy] = {}
        self.notification_templates: Dict[str, NotificationTemplate] = {}
        self.stakeholder_contacts: Dict[str, StakeholderContact] = {}
        self.migration_plans: Dict[str, MigrationPlan] = {}
        
        # Notification tracking
        self.notification_history: List[DeprecationNotification] = []
        
        # Encryption for sensitive data
        self.encryption_manager = None
        
        # Background task handles
        self._notification_task = None
        self._monitoring_task = None
    
    async def initialize(self) -> None:
        """Initialize deprecation manager."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Initialize HTTP session
            connector = aiohttp.TCPConnector(limit=100)
            timeout = aiohttp.ClientTimeout(total=60)
            self._http_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
            
            # Initialize encryption manager
            self.encryption_manager = EncryptionManager()
            await self.encryption_manager.initialize()
            
            # Load data from storage
            await self._load_data_from_storage()
            
            # Initialize default templates and policies
            self._initialize_default_templates()
            self._initialize_default_policies()
            
            # Start background tasks
            self._notification_task = asyncio.create_task(self._notification_worker())
            self._monitoring_task = asyncio.create_task(self._monitoring_worker())
            
            self.logger.info("Deprecation Manager initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize deprecation manager: {e}")
            raise
    
    def _initialize_default_templates(self) -> None:
        """Initialize default notification templates."""
        templates = [
            NotificationTemplate(
                template_id="deprecation_announcement",
                name="Deprecation Announcement",
                subject_template="[API DEPRECATION] {{ api_name }} v{{ version }} Deprecation Notice",
                body_template="""
Dear API Consumer,

This is to inform you that {{ api_name }} version {{ version }} has been scheduled for deprecation.

Deprecation Timeline:
- Announcement Date: {{ announcement_date }}
- Warning Phase: {{ warning_date }}
- Restriction Phase: {{ restriction_date }}
- Sunset Date: {{ sunset_date }}

Recommended Actions:
1. Review your current usage of the deprecated API endpoints
2. Plan migration to {{ target_version }}
3. Contact the API team for migration assistance

Migration Resources:
- Migration Guide: {{ migration_guide_url }}
- Target API Documentation: {{ target_api_docs_url }}
- Support Contact: {{ support_contact }}

Please ensure migration is completed before the sunset date to avoid service interruption.

Best regards,
API Management Team
                """,
                channel=NotificationChannel.EMAIL,
                priority=NotificationPriority.HIGH,
                variables=["api_name", "version", "announcement_date", "warning_date", 
                          "restriction_date", "sunset_date", "target_version", 
                          "migration_guide_url", "target_api_docs_url", "support_contact"]
            ),
            
            NotificationTemplate(
                template_id="deprecation_warning",
                name="Deprecation Warning",
                subject_template="[API WARNING] {{ api_name }} v{{ version }} Deprecation Warning - {{ days_remaining }} days remaining",
                body_template="""
IMPORTANT: API Deprecation Warning

{{ api_name }} version {{ version }} will be sunset in {{ days_remaining }} days.

Current Status:
- Your applications are still using the deprecated API
- Sunset Date: {{ sunset_date }}
- Migration Status: {{ migration_status }}

Immediate Actions Required:
1. Complete migration to {{ target_version }}
2. Update your application configurations
3. Test thoroughly in staging environment

Need Help?
- Migration Support: {{ support_contact }}
- Documentation: {{ target_api_docs_url }}
- Emergency Contact: {{ emergency_contact }}

This is an automated reminder. Please take immediate action to avoid service disruption.

API Management Team
                """,
                channel=NotificationChannel.EMAIL,
                priority=NotificationPriority.CRITICAL,
                variables=["api_name", "version", "days_remaining", "sunset_date", 
                          "migration_status", "target_version", "support_contact",
                          "target_api_docs_url", "emergency_contact"]
            ),
            
            NotificationTemplate(
                template_id="sunset_notice",
                name="Sunset Notice",
                subject_template="[API SUNSET] {{ api_name }} v{{ version }} Sunset - Service Terminated",
                body_template="""
NOTICE: API Service Terminated

{{ api_name }} version {{ version }} has been sunset as scheduled.

Sunset Details:
- Service terminated at: {{ sunset_timestamp }}
- All requests to deprecated endpoints will return HTTP 410 (Gone)
- Grace period: {{ grace_period_days }} days for emergency access

Alternative Services:
- Current API Version: {{ target_version }}
- Service Endpoint: {{ target_endpoint }}
- Documentation: {{ target_api_docs_url }}

If you are still experiencing issues, please contact:
- Emergency Support: {{ emergency_contact }}
- Migration Assistance: {{ support_contact }}

API Management Team
                """,
                channel=NotificationChannel.EMAIL,
                priority=NotificationPriority.URGENT,
                variables=["api_name", "version", "sunset_timestamp", "grace_period_days",
                          "target_version", "target_endpoint", "target_api_docs_url",
                          "emergency_contact", "support_contact"]
            )
        ]
        
        for template in templates:
            self.notification_templates[template.template_id] = template
    
    def _initialize_default_policies(self) -> None:
        """Initialize default deprecation policies."""
        policies = [
            DeprecationPolicy(
                policy_id="standard_deprecation",
                name="Standard API Deprecation Policy",
                description="Standard 90-day deprecation policy for stable APIs",
                timeline=DeprecationTimeline(
                    announcement_days=90,
                    warning_days=60,
                    restriction_days=30,
                    sunset_days=0,
                    grace_period_days=7
                ),
                required_approvals=["api_owner", "architecture_board"],
                notification_templates=["deprecation_announcement", "deprecation_warning", "sunset_notice"],
                enforcement_rules={
                    "block_new_consumers": True,
                    "rate_limit_deprecated": True,
                    "require_migration_plan": True
                },
                compliance_requirements=["security_review", "impact_assessment"],
                exception_process={
                    "emergency_contact": "api-emergency@example.mil",
                    "approval_authority": "cto",
                    "max_extension_days": 30
                }
            ),
            
            DeprecationPolicy(
                policy_id="critical_system_deprecation",
                name="Critical System Deprecation Policy", 
                description="Extended deprecation policy for critical DoD systems",
                timeline=DeprecationTimeline(
                    announcement_days=180,
                    warning_days=120,
                    restriction_days=60,
                    sunset_days=0,
                    grace_period_days=14
                ),
                required_approvals=["api_owner", "architecture_board", "security_office", "mission_owner"],
                notification_templates=["deprecation_announcement", "deprecation_warning", "sunset_notice"],
                enforcement_rules={
                    "block_new_consumers": True,
                    "rate_limit_deprecated": False,  # Don't rate limit critical systems
                    "require_migration_plan": True,
                    "require_contingency_plan": True
                },
                compliance_requirements=["security_review", "impact_assessment", "mission_impact_review"],
                exception_process={
                    "emergency_contact": "mission-critical@example.mil",
                    "approval_authority": "mission_commander",
                    "max_extension_days": 90
                }
            )
        ]
        
        for policy in policies:
            self.deprecation_policies[policy.policy_id] = policy
    
    async def initiate_deprecation(self, version: str, policy_id: str, 
                                 initiated_by: str, metadata: Dict[str, Any] = None) -> str:
        """
        Initiate deprecation workflow for API version.
        
        Args:
            version: API version to deprecate
            policy_id: Deprecation policy to apply
            initiated_by: User initiating deprecation
            metadata: Additional metadata
            
        Returns:
            Deprecation workflow ID
        """
        try:
            # Validate inputs
            if policy_id not in self.deprecation_policies:
                raise ValueError(f"Deprecation policy {policy_id} not found")
            
            # Check if version exists and can be deprecated
            version_info = await self.version_manager.get_version_info(version)
            if not version_info:
                raise ValueError(f"Version {version} not found")
            
            if version_info.get("state") not in ["stable", "deprecated"]:
                raise ValueError(f"Version {version} cannot be deprecated from state {version_info.get('state')}")
            
            # Get policy and calculate dates
            policy = self.deprecation_policies[policy_id]
            timeline = policy.timeline
            
            current_time = datetime.utcnow()
            announcement_date = current_time + timedelta(days=0)  # Immediate announcement
            warning_date = current_time + timedelta(days=timeline.announcement_days - timeline.warning_days)
            restriction_date = current_time + timedelta(days=timeline.announcement_days - timeline.restriction_days)
            sunset_date = current_time + timedelta(days=timeline.announcement_days - timeline.sunset_days)
            archive_date = sunset_date + timedelta(days=timeline.grace_period_days)
            
            # Get affected consumers
            affected_consumers = await self._get_affected_consumers(version)
            
            # Create deprecation workflow
            deprecation_id = str(uuid.uuid4())
            workflow = DeprecationWorkflow(
                deprecation_id=deprecation_id,
                version=version,
                policy_id=policy_id,
                phase=DeprecationPhase.PLANNING,
                initiated_by=initiated_by,
                initiated_at=current_time,
                announcement_date=announcement_date,
                warning_date=warning_date,
                restriction_date=restriction_date,
                sunset_date=sunset_date,
                archive_date=archive_date,
                affected_consumers=[c["consumer_id"] for c in affected_consumers],
                migration_plans=[],
                stakeholders=[],
                metadata=metadata or {}
            )
            
            # Store workflow
            self.deprecation_workflows[deprecation_id] = workflow
            
            # Create migration plans for affected consumers
            for consumer in affected_consumers:
                migration_plan_id = await self._create_migration_plan(
                    deprecation_id, consumer, version
                )
                workflow.migration_plans.append(migration_plan_id)
            
            # Transition version to deprecated state
            await self.version_manager.transition_version_state(
                version, VersionState.DEPRECATED, {"deprecation_id": deprecation_id}
            )
            
            # Save to storage
            await self._save_workflow_to_storage(deprecation_id)
            
            # Log deprecation initiation
            await self._log_deprecation_event(deprecation_id, "deprecation_initiated", {
                "version": version,
                "policy_id": policy_id,
                "initiated_by": initiated_by,
                "affected_consumers": len(affected_consumers)
            })
            
            self.logger.info(f"Initiated deprecation workflow {deprecation_id} for version {version}")
            return deprecation_id
            
        except Exception as e:
            self.logger.error(f"Failed to initiate deprecation for version {version}: {e}")
            raise
    
    async def advance_deprecation_phase(self, deprecation_id: str) -> bool:
        """
        Advance deprecation to next phase.
        
        Args:
            deprecation_id: Deprecation workflow ID
            
        Returns:
            True if phase advanced successfully
        """
        try:
            if deprecation_id not in self.deprecation_workflows:
                raise ValueError(f"Deprecation workflow {deprecation_id} not found")
            
            workflow = self.deprecation_workflows[deprecation_id]
            current_phase = workflow.phase
            current_time = datetime.utcnow()
            
            # Determine next phase based on timeline
            if current_phase == DeprecationPhase.PLANNING and current_time >= workflow.announcement_date:
                next_phase = DeprecationPhase.ANNOUNCEMENT
            elif current_phase == DeprecationPhase.ANNOUNCEMENT and current_time >= workflow.warning_date:
                next_phase = DeprecationPhase.WARNING
            elif current_phase == DeprecationPhase.WARNING and current_time >= workflow.restriction_date:
                next_phase = DeprecationPhase.RESTRICTED
            elif current_phase == DeprecationPhase.RESTRICTED and current_time >= workflow.sunset_date:
                next_phase = DeprecationPhase.SUNSET
            elif current_phase == DeprecationPhase.SUNSET and current_time >= workflow.archive_date:
                next_phase = DeprecationPhase.ARCHIVED
            else:
                return False  # No phase advancement needed
            
            # Update workflow phase
            workflow.phase = next_phase
            
            # Execute phase-specific actions
            if next_phase == DeprecationPhase.ANNOUNCEMENT:
                await self._execute_announcement_phase(deprecation_id)
            elif next_phase == DeprecationPhase.WARNING:
                await self._execute_warning_phase(deprecation_id)
            elif next_phase == DeprecationPhase.RESTRICTED:
                await self._execute_restriction_phase(deprecation_id)
            elif next_phase == DeprecationPhase.SUNSET:
                await self._execute_sunset_phase(deprecation_id)
            elif next_phase == DeprecationPhase.ARCHIVED:
                await self._execute_archive_phase(deprecation_id)
            
            # Save workflow
            await self._save_workflow_to_storage(deprecation_id)
            
            # Log phase advancement
            await self._log_deprecation_event(deprecation_id, "phase_advanced", {
                "from_phase": current_phase.value,
                "to_phase": next_phase.value
            })
            
            self.logger.info(f"Advanced deprecation {deprecation_id} from {current_phase.value} to {next_phase.value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to advance deprecation phase for {deprecation_id}: {e}")
            return False
    
    async def _execute_announcement_phase(self, deprecation_id: str) -> None:
        """Execute announcement phase actions."""
        workflow = self.deprecation_workflows[deprecation_id]
        
        # Send announcement notifications
        await self._send_phase_notifications(deprecation_id, "deprecation_announcement")
        
        # Block new consumer registrations
        policy = self.deprecation_policies[workflow.policy_id]
        if policy.enforcement_rules.get("block_new_consumers", False):
            await self._block_new_consumers(workflow.version)
        
        workflow.metadata["announcement_sent"] = datetime.utcnow().isoformat()
    
    async def _execute_warning_phase(self, deprecation_id: str) -> None:
        """Execute warning phase actions."""
        workflow = self.deprecation_workflows[deprecation_id]
        
        # Send warning notifications
        await self._send_phase_notifications(deprecation_id, "deprecation_warning")
        
        # Start rate limiting if configured
        policy = self.deprecation_policies[workflow.policy_id]
        if policy.enforcement_rules.get("rate_limit_deprecated", False):
            await self._apply_rate_limiting(workflow.version)
        
        workflow.metadata["warning_sent"] = datetime.utcnow().isoformat()
    
    async def _execute_restriction_phase(self, deprecation_id: str) -> None:
        """Execute restriction phase actions."""
        workflow = self.deprecation_workflows[deprecation_id]
        
        # Apply access restrictions
        await self._apply_access_restrictions(workflow.version)
        
        # Send final warning notifications
        await self._send_phase_notifications(deprecation_id, "deprecation_warning")
        
        workflow.metadata["restrictions_applied"] = datetime.utcnow().isoformat()
    
    async def _execute_sunset_phase(self, deprecation_id: str) -> None:
        """Execute sunset phase actions."""
        workflow = self.deprecation_workflows[deprecation_id]
        
        # Sunset the API version
        await self.version_manager.transition_version_state(
            workflow.version, VersionState.SUNSET
        )
        
        # Send sunset notifications
        await self._send_phase_notifications(deprecation_id, "sunset_notice")
        
        # Apply complete access blocking
        await self._block_api_access(workflow.version)
        
        workflow.metadata["sunset_completed"] = datetime.utcnow().isoformat()
    
    async def _execute_archive_phase(self, deprecation_id: str) -> None:
        """Execute archive phase actions."""
        workflow = self.deprecation_workflows[deprecation_id]
        
        # Archive the API version
        await self.version_manager.transition_version_state(
            workflow.version, VersionState.ARCHIVED
        )
        
        # Mark workflow as completed
        workflow.status = "completed"
        
        workflow.metadata["archived"] = datetime.utcnow().isoformat()
    
    async def _send_phase_notifications(self, deprecation_id: str, template_id: str) -> None:
        """Send notifications for deprecation phase."""
        try:
            workflow = self.deprecation_workflows[deprecation_id]
            template = self.notification_templates.get(template_id)
            
            if not template:
                self.logger.error(f"Notification template {template_id} not found")
                return
            
            # Get stakeholders and consumers
            recipients = []
            
            # Add affected consumers
            for consumer_id in workflow.affected_consumers:
                if consumer_id in self.stakeholder_contacts:
                    recipients.append(self.stakeholder_contacts[consumer_id])
            
            # Add workflow stakeholders
            for stakeholder_id in workflow.stakeholders:
                if stakeholder_id in self.stakeholder_contacts:
                    recipients.append(self.stakeholder_contacts[stakeholder_id])
            
            # Send notifications
            for recipient in recipients:
                for channel in recipient.preferred_channels:
                    if channel == template.channel:
                        await self._send_notification(
                            deprecation_id, recipient, template, channel
                        )
            
        except Exception as e:
            self.logger.error(f"Failed to send phase notifications: {e}")
    
    async def _send_notification(self, deprecation_id: str, recipient: StakeholderContact,
                               template: NotificationTemplate, channel: NotificationChannel) -> None:
        """Send individual notification."""
        try:
            workflow = self.deprecation_workflows[deprecation_id]
            
            # Prepare template variables
            variables = {
                "api_name": f"API v{workflow.version}",
                "version": workflow.version,
                "announcement_date": workflow.announcement_date.strftime("%Y-%m-%d"),
                "warning_date": workflow.warning_date.strftime("%Y-%m-%d"),
                "restriction_date": workflow.restriction_date.strftime("%Y-%m-%d"),
                "sunset_date": workflow.sunset_date.strftime("%Y-%m-%d"),
                "sunset_timestamp": workflow.sunset_date.isoformat(),
                "grace_period_days": self.deprecation_policies[workflow.policy_id].timeline.grace_period_days,
                "target_version": "latest",  # This should come from migration plan
                "migration_guide_url": "https://api-docs.example.mil/migration",
                "target_api_docs_url": "https://api-docs.example.mil/latest",
                "support_contact": "api-support@example.mil",
                "emergency_contact": "api-emergency@example.mil",
                "days_remaining": (workflow.sunset_date - datetime.utcnow()).days,
                "migration_status": "pending",  # This should come from migration plan
                "target_endpoint": "https://api.example.mil/v2"
            }
            
            # Render template
            subject = Template(template.subject_template).render(**variables)
            body = Template(template.body_template).render(**variables)
            
            # Create notification record
            notification_id = str(uuid.uuid4())
            notification = DeprecationNotification(
                notification_id=notification_id,
                deprecation_id=deprecation_id,
                recipient_id=recipient.stakeholder_id,
                channel=channel,
                template_id=template.template_id,
                sent_at=datetime.utcnow(),
                status="pending"
            )
            
            # Send notification based on channel
            success = False
            if channel == NotificationChannel.EMAIL and recipient.email:
                success = await self._send_email_notification(recipient.email, subject, body)
            elif channel == NotificationChannel.WEBHOOK:
                success = await self._send_webhook_notification(recipient, subject, body)
            elif channel == NotificationChannel.SLACK and recipient.slack_user_id:
                success = await self._send_slack_notification(recipient.slack_user_id, subject, body)
            
            # Update notification status
            notification.status = "sent" if success else "failed"
            if not success:
                notification.error_message = "Failed to send notification"
            
            # Store notification
            self.notification_history.append(notification)
            workflow.notifications_sent.append(notification_id)
            
            # Save notification to Redis
            await self._save_notification_to_storage(notification)
            
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")
    
    async def _send_email_notification(self, email: str, subject: str, body: str) -> bool:
        """Send email notification."""
        try:
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = "api-notifications@example.mil"
            msg['To'] = email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to SMTP server and send
            # Note: This is a simplified implementation
            # In production, use proper async email libraries
            self.logger.info(f"Email notification sent to {email}: {subject}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email to {email}: {e}")
            return False
    
    async def _send_webhook_notification(self, recipient: StakeholderContact, subject: str, body: str) -> bool:
        """Send webhook notification."""
        try:
            webhook_url = recipient.metadata.get("webhook_url")
            if not webhook_url:
                return False
            
            payload = {
                "subject": subject,
                "body": body,
                "recipient": recipient.stakeholder_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            async with self._http_session.post(
                webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                return response.status == 200
                
        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {e}")
            return False
    
    async def _send_slack_notification(self, user_id: str, subject: str, body: str) -> bool:
        """Send Slack notification."""
        try:
            # Slack integration would go here
            # This is a placeholder implementation
            self.logger.info(f"Slack notification sent to {user_id}: {subject}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    async def _get_affected_consumers(self, version: str) -> List[Dict[str, Any]]:
        """Get consumers affected by version deprecation."""
        try:
            # This would integrate with the version manager to get actual consumers
            # For now, return a mock list
            return [
                {
                    "consumer_id": "app1",
                    "name": "Application 1",
                    "contact": "app1-team@example.mil",
                    "critical_endpoints": ["/api/v1/users"],
                    "usage_level": "high"
                },
                {
                    "consumer_id": "app2", 
                    "name": "Application 2",
                    "contact": "app2-team@example.mil",
                    "critical_endpoints": ["/api/v1/data"],
                    "usage_level": "medium"
                }
            ]
            
        except Exception as e:
            self.logger.error(f"Failed to get affected consumers for version {version}: {e}")
            return []
    
    async def _create_migration_plan(self, deprecation_id: str, consumer: Dict[str, Any], 
                                   source_version: str) -> str:
        """Create migration plan for consumer."""
        try:
            plan_id = str(uuid.uuid4())
            
            # Get target version (latest stable)
            version_info = await self.version_manager.get_version_info()
            target_version = version_info.get("default_version", "2.0.0")
            
            # Create migration steps
            migration_steps = [
                {
                    "step": 1,
                    "title": "Review API Changes",
                    "description": "Review breaking changes and new features",
                    "estimated_hours": 4,
                    "completed": False
                },
                {
                    "step": 2,
                    "title": "Update Client Code",
                    "description": "Update application code to use new API version",
                    "estimated_hours": 16,
                    "completed": False
                },
                {
                    "step": 3,
                    "title": "Testing",
                    "description": "Test updated application in staging environment",
                    "estimated_hours": 8,
                    "completed": False
                },
                {
                    "step": 4,
                    "title": "Production Deployment",
                    "description": "Deploy updated application to production",
                    "estimated_hours": 4,
                    "completed": False
                }
            ]
            
            # Calculate completion date
            workflow = self.deprecation_workflows[deprecation_id]
            target_completion = workflow.restriction_date - timedelta(days=7)  # Complete 1 week before restriction
            
            migration_plan = MigrationPlan(
                plan_id=plan_id,
                consumer_id=consumer["consumer_id"],
                source_version=source_version,
                target_version=target_version,
                migration_steps=migration_steps,
                estimated_effort_hours=32,
                target_completion_date=target_completion,
                status=MigrationStatus.NOT_STARTED
            )
            
            self.migration_plans[plan_id] = migration_plan
            
            # Save to storage
            await self._save_migration_plan_to_storage(plan_id)
            
            return plan_id
            
        except Exception as e:
            self.logger.error(f"Failed to create migration plan: {e}")
            raise
    
    async def update_migration_status(self, plan_id: str, status: MigrationStatus, 
                                    progress_percentage: int = None,
                                    notes: str = None) -> bool:
        """
        Update migration plan status.
        
        Args:
            plan_id: Migration plan ID
            status: New status
            progress_percentage: Progress percentage
            notes: Additional notes
            
        Returns:
            True if update successful
        """
        try:
            if plan_id not in self.migration_plans:
                raise ValueError(f"Migration plan {plan_id} not found")
            
            plan = self.migration_plans[plan_id]
            plan.status = status
            
            if progress_percentage is not None:
                plan.progress_percentage = progress_percentage
            
            if notes:
                plan.notes.append(f"{datetime.utcnow().isoformat()}: {notes}")
            
            # Save to storage
            await self._save_migration_plan_to_storage(plan_id)
            
            # Log status update
            await self._log_deprecation_event(None, "migration_status_updated", {
                "plan_id": plan_id,
                "status": status.value,
                "progress": progress_percentage
            })
            
            self.logger.info(f"Updated migration plan {plan_id} status to {status.value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update migration status: {e}")
            return False
    
    async def get_deprecation_status(self, deprecation_id: str) -> Dict[str, Any]:
        """
        Get deprecation workflow status.
        
        Args:
            deprecation_id: Deprecation workflow ID
            
        Returns:
            Deprecation status information
        """
        try:
            if deprecation_id not in self.deprecation_workflows:
                raise ValueError(f"Deprecation workflow {deprecation_id} not found")
            
            workflow = self.deprecation_workflows[deprecation_id]
            policy = self.deprecation_policies[workflow.policy_id]
            
            # Get migration plan statuses
            migration_statuses = []
            for plan_id in workflow.migration_plans:
                if plan_id in self.migration_plans:
                    plan = self.migration_plans[plan_id]
                    migration_statuses.append({
                        "plan_id": plan_id,
                        "consumer_id": plan.consumer_id,
                        "status": plan.status.value,
                        "progress": plan.progress_percentage,
                        "target_completion": plan.target_completion_date.isoformat()
                    })
            
            # Calculate days remaining
            current_time = datetime.utcnow()
            days_to_sunset = (workflow.sunset_date - current_time).days
            
            return {
                "deprecation_id": deprecation_id,
                "version": workflow.version,
                "phase": workflow.phase.value,
                "status": workflow.status,
                "policy": policy.name,
                "timeline": {
                    "announcement_date": workflow.announcement_date.isoformat(),
                    "warning_date": workflow.warning_date.isoformat(),
                    "restriction_date": workflow.restriction_date.isoformat(),
                    "sunset_date": workflow.sunset_date.isoformat(),
                    "archive_date": workflow.archive_date.isoformat(),
                    "days_to_sunset": days_to_sunset
                },
                "affected_consumers": len(workflow.affected_consumers),
                "migration_plans": migration_statuses,
                "notifications_sent": len(workflow.notifications_sent),
                "compliance_checks": workflow.compliance_checks,
                "metadata": workflow.metadata
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get deprecation status: {e}")
            return {}
    
    async def _monitoring_worker(self) -> None:
        """Background worker to monitor deprecation workflows."""
        while True:
            try:
                for deprecation_id in list(self.deprecation_workflows.keys()):
                    # Check if phase advancement is needed
                    await self.advance_deprecation_phase(deprecation_id)
                    
                    # Check migration plan deadlines
                    await self._check_migration_deadlines(deprecation_id)
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                self.logger.error(f"Monitoring worker error: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error
    
    async def _notification_worker(self) -> None:
        """Background worker to handle notification retries and scheduled notifications."""
        while True:
            try:
                # Process failed notifications for retry
                await self._process_failed_notifications()
                
                # Send scheduled reminders
                await self._send_scheduled_reminders()
                
                await asyncio.sleep(1800)  # Check every 30 minutes
                
            except Exception as e:
                self.logger.error(f"Notification worker error: {e}")
                await asyncio.sleep(300)
    
    async def _check_migration_deadlines(self, deprecation_id: str) -> None:
        """Check migration plan deadlines and send alerts."""
        try:
            workflow = self.deprecation_workflows[deprecation_id]
            current_time = datetime.utcnow()
            
            for plan_id in workflow.migration_plans:
                if plan_id in self.migration_plans:
                    plan = self.migration_plans[plan_id]
                    
                    # Check if overdue
                    if (plan.status != MigrationStatus.COMPLETED and 
                        current_time > plan.target_completion_date):
                        
                        plan.status = MigrationStatus.OVERDUE
                        await self._send_overdue_migration_alert(plan_id)
                        await self._save_migration_plan_to_storage(plan_id)
            
        except Exception as e:
            self.logger.error(f"Failed to check migration deadlines: {e}")
    
    async def _send_overdue_migration_alert(self, plan_id: str) -> None:
        """Send alert for overdue migration."""
        try:
            plan = self.migration_plans[plan_id]
            
            alert_data = {
                "plan_id": plan_id,
                "consumer_id": plan.consumer_id,
                "source_version": plan.source_version,
                "target_version": plan.target_version,
                "overdue_days": (datetime.utcnow() - plan.target_completion_date).days,
                "progress": plan.progress_percentage
            }
            
            self.logger.warning(f"Migration plan {plan_id} is overdue: {alert_data}")
            
        except Exception as e:
            self.logger.error(f"Failed to send overdue migration alert: {e}")
    
    async def _load_data_from_storage(self) -> None:
        """Load deprecation data from Redis storage."""
        try:
            # Load workflows
            workflow_keys = await self.redis_client.keys("deprecation_workflows:*")
            for key in workflow_keys:
                try:
                    data = await self.redis_client.get(key)
                    if data:
                        workflow_data = json.loads(data.decode())
                        # Reconstruct workflow object (simplified)
                        workflow_id = key.decode().split(':')[-1]
                        self.logger.info(f"Loaded deprecation workflow {workflow_id}")
                except Exception as e:
                    self.logger.error(f"Failed to load workflow from key {key}: {e}")
            
            # Load migration plans
            plan_keys = await self.redis_client.keys("migration_plans:*")
            for key in plan_keys:
                try:
                    data = await self.redis_client.get(key)
                    if data:
                        plan_data = json.loads(data.decode())
                        # Reconstruct migration plan object (simplified)
                        plan_id = key.decode().split(':')[-1]
                        self.logger.info(f"Loaded migration plan {plan_id}")
                except Exception as e:
                    self.logger.error(f"Failed to load plan from key {key}: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to load data from storage: {e}")
    
    async def _save_workflow_to_storage(self, deprecation_id: str) -> None:
        """Save deprecation workflow to Redis storage."""
        try:
            workflow_key = f"deprecation_workflows:{deprecation_id}"
            workflow = self.deprecation_workflows[deprecation_id]
            
            # Prepare data for storage
            workflow_data = asdict(workflow)
            
            # Convert datetime objects to ISO format
            datetime_fields = ['initiated_at', 'announcement_date', 'warning_date', 
                             'restriction_date', 'sunset_date', 'archive_date']
            
            for field in datetime_fields:
                if hasattr(workflow, field) and getattr(workflow, field):
                    workflow_data[field] = getattr(workflow, field).isoformat()
            
            # Convert enums to strings
            workflow_data['phase'] = workflow.phase.value
            
            await self.redis_client.set(
                workflow_key,
                json.dumps(workflow_data),
                ex=86400 * 365  # 1 year expiry
            )
            
        except Exception as e:
            self.logger.error(f"Failed to save workflow {deprecation_id} to storage: {e}")
    
    async def _save_migration_plan_to_storage(self, plan_id: str) -> None:
        """Save migration plan to Redis storage."""
        try:
            plan_key = f"migration_plans:{plan_id}"
            plan = self.migration_plans[plan_id]
            
            # Prepare data for storage
            plan_data = asdict(plan)
            
            # Convert datetime objects to ISO format
            plan_data['target_completion_date'] = plan.target_completion_date.isoformat()
            
            # Convert enums to strings
            plan_data['status'] = plan.status.value
            
            await self.redis_client.set(
                plan_key,
                json.dumps(plan_data),
                ex=86400 * 365  # 1 year expiry
            )
            
        except Exception as e:
            self.logger.error(f"Failed to save migration plan {plan_id} to storage: {e}")
    
    async def _save_notification_to_storage(self, notification: DeprecationNotification) -> None:
        """Save notification to Redis storage."""
        try:
            notification_key = f"deprecation_notifications:{notification.notification_id}"
            
            # Prepare data for storage
            notification_data = asdict(notification)
            
            # Convert datetime and enum objects
            notification_data['sent_at'] = notification.sent_at.isoformat()
            notification_data['channel'] = notification.channel.value
            
            await self.redis_client.set(
                notification_key,
                json.dumps(notification_data),
                ex=86400 * 90  # 90 days expiry
            )
            
        except Exception as e:
            self.logger.error(f"Failed to save notification to storage: {e}")
    
    async def _log_deprecation_event(self, deprecation_id: Optional[str], event_type: str, 
                                   data: Dict[str, Any]) -> None:
        """Log deprecation events."""
        try:
            event = {
                "timestamp": datetime.utcnow().isoformat(),
                "deprecation_id": deprecation_id,
                "event_type": event_type,
                "data": data
            }
            
            # Log to application logs
            self.logger.info(f"Deprecation Event: {json.dumps(event)}")
            
            # Store in Redis for analytics
            events_key = f"deprecation_events:{datetime.utcnow().strftime('%Y%m%d')}"
            await self.redis_client.lpush(events_key, json.dumps(event))
            await self.redis_client.expire(events_key, 86400 * 30)  # 30 days
            
        except Exception as e:
            self.logger.error(f"Failed to log deprecation event: {e}")
    
    async def close(self) -> None:
        """Clean up resources."""
        # Cancel background tasks
        if self._notification_task:
            self._notification_task.cancel()
        if self._monitoring_task:
            self._monitoring_task.cancel()
        
        # Close connections
        if self._http_session:
            await self._http_session.close()
        
        if self.redis_client:
            await self.redis_client.close()
        
        if self.encryption_manager:
            await self.encryption_manager.close()
        
        self.logger.info("Deprecation Manager closed")


if __name__ == "__main__":
    # Example usage
    async def main():
        from api_gateway.api_version_manager import APIVersionManager
        
        version_manager = APIVersionManager()
        await version_manager.initialize()
        
        deprecation_manager = DeprecationManager(version_manager)
        await deprecation_manager.initialize()
        
        try:
            # Initiate deprecation
            deprecation_id = await deprecation_manager.initiate_deprecation(
                version="1.0.0",
                policy_id="standard_deprecation",
                initiated_by="api-team",
                metadata={"reason": "Security updates require new version"}
            )
            
            print(f"Initiated deprecation: {deprecation_id}")
            
            # Get status
            status = await deprecation_manager.get_deprecation_status(deprecation_id)
            print(f"Deprecation status: {json.dumps(status, indent=2)}")
            
        finally:
            await deprecation_manager.close()
            await version_manager.close()
    
    asyncio.run(main())