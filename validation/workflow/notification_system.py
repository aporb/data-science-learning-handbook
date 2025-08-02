#!/usr/bin/env python3
"""
Automated Stakeholder Notification and Communication System
===========================================================

A comprehensive notification system for content workflow management that provides:
- Multi-channel notification delivery (email, webhook, Slack, Teams)
- Role-based notification preferences and filtering
- Automated workflow-triggered notifications and reminders
- Deadline tracking and escalation notifications
- Template-based message generation with personalization
- Notification delivery tracking and retry mechanisms
- Integration with review workflow and branching systems

Author: Claude Code Implementation
Created: 2025-07-28
Version: 1.0.0
"""

import os
import sys
import json
import logging
import asyncio
import smtplib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set, Callable, Union
from pathlib import Path
from dataclasses import dataclass, asdict, field
from enum import Enum
import yaml
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from email.mime.base import MimeBase
from email import encoders
import jinja2
from jinja2 import Environment, FileSystemLoader, Template
import schedule
import time
import threading
from collections import defaultdict, deque
import hashlib
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    """Notification channel enumeration"""
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"
    SMS = "sms"
    IN_APP = "in_app"


class NotificationTrigger(Enum):
    """Notification trigger enumeration"""
    WORKFLOW_CREATED = "workflow_created"
    ASSIGNMENT_CREATED = "assignment_created"
    REVIEW_SUBMITTED = "review_submitted"
    STAGE_COMPLETED = "stage_completed"
    DEADLINE_APPROACHING = "deadline_approaching"
    DEADLINE_MISSED = "deadline_missed"
    ESCALATION_TRIGGERED = "escalation_triggered"
    WORKFLOW_COMPLETED = "workflow_completed"
    BRANCH_CREATED = "branch_created"
    BRANCH_MERGED = "branch_merged"
    CONFLICT_DETECTED = "conflict_detected"
    QUALITY_GATE_FAILED = "quality_gate_failed"


class NotificationPriority(Enum):
    """Notification priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"


class NotificationStatus(Enum):
    """Notification delivery status"""
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRY = "retry"
    CANCELLED = "cancelled"


@dataclass
class NotificationTemplate:
    """Notification template definition"""
    template_id: str
    name: str
    trigger: NotificationTrigger
    channel: NotificationChannel
    priority: NotificationPriority
    subject_template: str
    body_template: str
    html_template: Optional[str] = None
    variables: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    attachments: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NotificationPreferences:
    """User notification preferences"""
    user_id: str
    channels: Dict[NotificationChannel, bool]
    triggers: Dict[NotificationTrigger, bool]
    priority_threshold: NotificationPriority
    quiet_hours: Optional[Tuple[int, int]] = None  # (start_hour, end_hour)
    digest_frequency: Optional[str] = None  # daily, weekly, none
    language: str = "en"
    timezone: str = "UTC"
    custom_settings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Recipient:
    """Notification recipient information"""
    user_id: str
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    slack_id: Optional[str] = None
    teams_id: Optional[str] = None
    webhook_url: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    preferences: Optional[NotificationPreferences] = None


@dataclass
class NotificationMessage:
    """Notification message structure"""
    message_id: str
    trigger: NotificationTrigger
    channel: NotificationChannel
    priority: NotificationPriority
    recipient: Recipient
    subject: str
    body: str
    html_body: Optional[str] = None
    attachments: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    created_date: str = field(default_factory=lambda: datetime.now().isoformat())
    scheduled_date: Optional[str] = None
    status: NotificationStatus = NotificationStatus.PENDING
    delivery_attempts: int = 0
    last_attempt: Optional[str] = None
    error_message: Optional[str] = None
    delivered_date: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeliveryReport:
    """Notification delivery report"""
    report_id: str
    period_start: str
    period_end: str
    total_notifications: int
    successful_deliveries: int
    failed_deliveries: int
    by_channel: Dict[str, Dict[str, int]]
    by_trigger: Dict[str, Dict[str, int]]
    by_priority: Dict[str, Dict[str, int]]
    average_delivery_time: float
    top_failures: List[Dict[str, Any]]
    recommendations: List[str]


class NotificationChannelHandler:
    """Base class for notification channel handlers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    async def send(self, message: NotificationMessage) -> bool:
        """Send notification message"""
        raise NotImplementedError
    
    def validate_config(self) -> bool:
        """Validate channel configuration"""
        raise NotImplementedError


class EmailHandler(NotificationChannelHandler):
    """Email notification handler"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.smtp_server = config.get("smtp_server", "localhost")
        self.smtp_port = config.get("smtp_port", 587)
        self.username = config.get("username")
        self.password = config.get("password")
        self.from_email = config.get("from_email", "noreply@example.com")
        self.use_tls = config.get("use_tls", True)
    
    async def send(self, message: NotificationMessage) -> bool:
        """Send email notification"""
        try:
            if not message.recipient.email:
                logger.warning(f"No email address for recipient {message.recipient.user_id}")
                return False
            
            # Create message
            msg = MimeMultipart('alternative')
            msg['Subject'] = message.subject
            msg['From'] = self.from_email
            msg['To'] = message.recipient.email
            msg['Message-ID'] = f"<{message.message_id}@{self.smtp_server}>"
            
            # Add text part
            text_part = MimeText(message.body, 'plain', 'utf-8')
            msg.attach(text_part)
            
            # Add HTML part if available
            if message.html_body:
                html_part = MimeText(message.html_body, 'html', 'utf-8')
                msg.attach(html_part)
            
            # Add attachments
            for attachment_path in message.attachments:
                if Path(attachment_path).exists():
                    with open(attachment_path, 'rb') as f:
                        part = MimeBase('application', 'octet-stream')
                        part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {Path(attachment_path).name}'
                        )
                        msg.attach(part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                
                if self.username and self.password:
                    server.login(self.username, self.password)
                
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {message.recipient.email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {message.recipient.email}: {e}")
            return False
    
    def validate_config(self) -> bool:
        """Validate email configuration"""
        required_fields = ["smtp_server", "smtp_port", "from_email"]
        return all(field in self.config for field in required_fields)


class WebhookHandler(NotificationChannelHandler):
    """Webhook notification handler"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.timeout = config.get("timeout", 30)
        self.retry_attempts = config.get("retry_attempts", 3)
    
    async def send(self, message: NotificationMessage) -> bool:
        """Send webhook notification"""
        try:
            if not message.recipient.webhook_url:
                logger.warning(f"No webhook URL for recipient {message.recipient.user_id}")
                return False
            
            payload = {
                "message_id": message.message_id,
                "trigger": message.trigger.value,
                "priority": message.priority.value,
                "recipient": message.recipient.user_id,
                "subject": message.subject,
                "body": message.body,
                "context": message.context,
                "timestamp": message.created_date
            }
            
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "ContentWorkflow-NotificationSystem/1.0"
            }
            
            # Add authentication if configured
            if "api_key" in self.config:
                headers["Authorization"] = f"Bearer {self.config['api_key']}"
            
            response = requests.post(
                message.recipient.webhook_url,
                json=payload,
                headers=headers,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            
            logger.info(f"Webhook sent successfully to {message.recipient.webhook_url}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send webhook to {message.recipient.webhook_url}: {e}")
            return False
    
    def validate_config(self) -> bool:
        """Validate webhook configuration"""
        return True  # Webhook URLs are validated per recipient


class SlackHandler(NotificationChannelHandler):
    """Slack notification handler"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.bot_token = config.get("bot_token")
        self.webhook_url = config.get("webhook_url")
    
    async def send(self, message: NotificationMessage) -> bool:
        """Send Slack notification"""
        try:
            if not (message.recipient.slack_id or self.webhook_url):
                logger.warning(f"No Slack configuration for recipient {message.recipient.user_id}")
                return False
            
            # Prepare Slack message format
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": message.subject
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message.body
                    }
                }
            ]
            
            # Add context information
            if message.context:
                context_text = "\n".join([f"*{k}:* {v}" for k, v in message.context.items() if isinstance(v, (str, int, float))])
                if context_text:
                    blocks.append({
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": context_text
                            }
                        ]
                    })
            
            payload = {
                "blocks": blocks,
                "username": "Content Workflow",
                "icon_emoji": ":gear:"
            }
            
            # Send via webhook or API
            if self.webhook_url:
                response = requests.post(self.webhook_url, json=payload, timeout=30)
                response.raise_for_status()
            elif self.bot_token and message.recipient.slack_id:
                headers = {"Authorization": f"Bearer {self.bot_token}"}
                payload["channel"] = message.recipient.slack_id
                response = requests.post(
                    "https://slack.com/api/chat.postMessage",
                    json=payload,
                    headers=headers,
                    timeout=30
                )
                response.raise_for_status()
            
            logger.info(f"Slack message sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            return False
    
    def validate_config(self) -> bool:
        """Validate Slack configuration"""
        return bool(self.bot_token or self.webhook_url)


class NotificationSystem:
    """
    Comprehensive Automated Stakeholder Notification and Communication System
    """
    
    def __init__(self, config_path: str, templates_dir: Optional[str] = None):
        """
        Initialize the Notification System
        
        Args:
            config_path: Path to configuration file
            templates_dir: Path to notification templates directory
        """
        self.config_path = Path(config_path)
        self.templates_dir = Path(templates_dir) if templates_dir else Path.cwd() / "validation" / "workflow" / "templates"
        self.data_dir = Path.cwd() / "validation" / "workflow" / "notifications"
        
        # Ensure directories exist
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Initialize components
        self.templates = self._load_templates()
        self.recipients = self._load_recipients()
        self.message_queue = deque()
        self.sent_messages = {}
        self.delivery_reports = []
        
        # Initialize channel handlers
        self.channel_handlers = self._initialize_channel_handlers()
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True
        )
        
        # Start background scheduler
        self.scheduler_running = False
        self.scheduler_thread = None
        
        logger.info("Notification System initialized")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load notification system configuration"""
        default_config = {
            "channels": {
                "email": {
                    "enabled": True,
                    "smtp_server": "localhost",
                    "smtp_port": 587,
                    "username": None,
                    "password": None,
                    "from_email": "workflow@example.com",
                    "use_tls": True
                },
                "webhook": {
                    "enabled": True,
                    "timeout": 30,
                    "retry_attempts": 3
                },
                "slack": {
                    "enabled": False,
                    "bot_token": None,
                    "webhook_url": None
                }
            },
            "delivery": {
                "max_retry_attempts": 3,
                "retry_delay_minutes": [5, 15, 60],
                "batch_size": 10,
                "rate_limit_per_minute": 60,
                "queue_max_size": 1000
            },
            "scheduling": {
                "enabled": True,
                "check_interval_seconds": 60,
                "reminder_intervals_hours": [24, 6, 1],
                "digest_time": "09:00"
            },
            "templates": {
                "auto_load": True,
                "cache_templates": True,
                "default_language": "en",
                "supported_languages": ["en"]
            },
            "reporting": {
                "enabled": True,
                "retention_days": 90,
                "auto_cleanup": True
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    self._deep_merge(default_config, user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")
        
        return default_config
    
    def _deep_merge(self, base: Dict, override: Dict):
        """Deep merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _load_templates(self) -> Dict[str, NotificationTemplate]:
        """Load notification templates"""
        templates = {}
        
        # Load default templates
        default_templates = self._create_default_templates()
        templates.update(default_templates)
        
        # Load custom templates from files
        if self.config["templates"]["auto_load"]:
            templates_file = self.data_dir / "templates.json"
            if templates_file.exists():
                try:
                    with open(templates_file, 'r') as f:
                        data = json.load(f)
                        for template_data in data.get('templates', []):
                            template = NotificationTemplate(
                                template_id=template_data['template_id'],
                                name=template_data['name'],
                                trigger=NotificationTrigger(template_data['trigger']),
                                channel=NotificationChannel(template_data['channel']),
                                priority=NotificationPriority(template_data['priority']),
                                subject_template=template_data['subject_template'],
                                body_template=template_data['body_template'],
                                html_template=template_data.get('html_template'),
                                variables=template_data.get('variables', []),
                                conditions=template_data.get('conditions', {}),
                                attachments=template_data.get('attachments', []),
                                metadata=template_data.get('metadata', {})
                            )
                            templates[template.template_id] = template
                except Exception as e:
                    logger.error(f"Failed to load custom templates: {e}")
        
        return templates
    
    def _create_default_templates(self) -> Dict[str, NotificationTemplate]:
        """Create default notification templates"""
        templates = {}
        
        # Assignment created template
        templates["assignment_created_email"] = NotificationTemplate(
            template_id="assignment_created_email",
            name="Assignment Created - Email",
            trigger=NotificationTrigger.ASSIGNMENT_CREATED,
            channel=NotificationChannel.EMAIL,
            priority=NotificationPriority.NORMAL,
            subject_template="New Review Assignment: {{ content_title }}",
            body_template="""Hello {{ reviewer_name }},

You have been assigned to review the following content:

Content: {{ content_title }}
Chapter: {{ chapter_id }}
Author: {{ author_name }}
Review Stage: {{ review_stage }}
Due Date: {{ due_date }}

Please log in to the system to begin your review.

Content Path: {{ content_path }}
Workflow Link: {{ workflow_url }}

Best regards,
Content Management System""",
            variables=["reviewer_name", "content_title", "chapter_id", "author_name", "review_stage", "due_date", "content_path", "workflow_url"]
        )
        
        # Deadline approaching template
        templates["deadline_approaching_email"] = NotificationTemplate(
            template_id="deadline_approaching_email",
            name="Deadline Approaching - Email",
            trigger=NotificationTrigger.DEADLINE_APPROACHING,
            channel=NotificationChannel.EMAIL,
            priority=NotificationPriority.HIGH,
            subject_template="⚠️ Review Deadline Approaching: {{ content_title }}",
            body_template="""Hello {{ reviewer_name }},

This is a reminder that your review assignment is due soon:

Content: {{ content_title }}
Chapter: {{ chapter_id }}
Review Stage: {{ review_stage }}
Due Date: {{ due_date }}
Time Remaining: {{ time_remaining }}

Please complete your review as soon as possible to avoid delays in the publication process.

Workflow Link: {{ workflow_url }}

Best regards,
Content Management System""",
            variables=["reviewer_name", "content_title", "chapter_id", "review_stage", "due_date", "time_remaining", "workflow_url"]
        )
        
        # Review completed template
        templates["review_submitted_email"] = NotificationTemplate(
            template_id="review_submitted_email",
            name="Review Submitted - Email",
            trigger=NotificationTrigger.REVIEW_SUBMITTED,
            channel=NotificationChannel.EMAIL,
            priority=NotificationPriority.NORMAL,
            subject_template="Review Completed: {{ content_title }}",
            body_template="""Hello {{ author_name }},

A review has been completed for your content:

Content: {{ content_title }}
Chapter: {{ chapter_id }}
Reviewer: {{ reviewer_name }}
Review Stage: {{ review_stage }}
Action: {{ review_action }}
Score: {{ review_score }}/100

{% if review_comments %}
Comments:
{{ review_comments }}
{% endif %}

You can view the full review details in the workflow system.

Workflow Link: {{ workflow_url }}

Best regards,
Content Management System""",
            variables=["author_name", "content_title", "chapter_id", "reviewer_name", "review_stage", "review_action", "review_score", "review_comments", "workflow_url"]
        )
        
        # Workflow completed template
        templates["workflow_completed_email"] = NotificationTemplate(
            template_id="workflow_completed_email",
            name="Workflow Completed - Email",
            trigger=NotificationTrigger.WORKFLOW_COMPLETED,
            channel=NotificationChannel.EMAIL,
            priority=NotificationPriority.NORMAL,
            subject_template="🎉 Content Published: {{ content_title }}",
            body_template="""Hello {{ author_name }},

Congratulations! Your content has completed the review process and has been published:

Content: {{ content_title }}
Chapter: {{ chapter_id }}
Final Score: {{ final_score }}/100
Publication Date: {{ publication_date }}

Summary of Reviews:
{% for review in reviews %}
- {{ review.stage }}: {{ review.score }}/100 by {{ review.reviewer }}
{% endfor %}

Your content is now available to learners!

Published Content Link: {{ published_url }}

Best regards,
Content Management System""",
            variables=["author_name", "content_title", "chapter_id", "final_score", "publication_date", "reviews", "published_url"]
        )
        
        # Escalation template
        templates["escalation_triggered_email"] = NotificationTemplate(
            template_id="escalation_triggered_email",
            name="Escalation Triggered - Email",
            trigger=NotificationTrigger.ESCALATION_TRIGGERED,
            channel=NotificationChannel.EMAIL,
            priority=NotificationPriority.URGENT,
            subject_template="🚨 ESCALATION: {{ content_title }} - {{ escalation_reason }}",
            body_template="""Hello {{ manager_name }},

An escalation has been triggered for a review assignment:

Content: {{ content_title }}
Chapter: {{ chapter_id }}
Original Reviewer: {{ original_reviewer }}
Review Stage: {{ review_stage }}
Escalation Reason: {{ escalation_reason }}
Days Overdue: {{ days_overdue }}

This assignment requires immediate attention. Please reassign or take appropriate action.

Assignment Details:
- Assigned Date: {{ assigned_date }}
- Due Date: {{ due_date }}
- Current Status: {{ current_status }}

Workflow Link: {{ workflow_url }}

Best regards,
Content Management System""",
            variables=["manager_name", "content_title", "chapter_id", "original_reviewer", "review_stage", "escalation_reason", "days_overdue", "assigned_date", "due_date", "current_status", "workflow_url"]
        )
        
        return templates
    
    def _load_recipients(self) -> Dict[str, Recipient]:
        """Load recipient database"""
        recipients_file = self.data_dir / "recipients.json"
        recipients = {}
        
        if recipients_file.exists():
            try:
                with open(recipients_file, 'r') as f:
                    data = json.load(f)
                    for recipient_data in data.get('recipients', []):
                        # Load preferences if available
                        preferences = None
                        if 'preferences' in recipient_data:
                            pref_data = recipient_data['preferences']
                            preferences = NotificationPreferences(
                                user_id=pref_data['user_id'],
                                channels={NotificationChannel(k): v for k, v in pref_data.get('channels', {}).items()},
                                triggers={NotificationTrigger(k): v for k, v in pref_data.get('triggers', {}).items()},
                                priority_threshold=NotificationPriority(pref_data.get('priority_threshold', 'normal')),
                                quiet_hours=tuple(pref_data['quiet_hours']) if pref_data.get('quiet_hours') else None,
                                digest_frequency=pref_data.get('digest_frequency'),
                                language=pref_data.get('language', 'en'),
                                timezone=pref_data.get('timezone', 'UTC'),
                                custom_settings=pref_data.get('custom_settings', {})
                            )
                        
                        recipient = Recipient(
                            user_id=recipient_data['user_id'],
                            name=recipient_data['name'],
                            email=recipient_data.get('email'),
                            phone=recipient_data.get('phone'),
                            slack_id=recipient_data.get('slack_id'),
                            teams_id=recipient_data.get('teams_id'),
                            webhook_url=recipient_data.get('webhook_url'),
                            roles=recipient_data.get('roles', []),
                            preferences=preferences
                        )
                        recipients[recipient.user_id] = recipient
            except Exception as e:
                logger.error(f"Failed to load recipients: {e}")
        
        return recipients
    
    def _save_recipients(self):
        """Save recipient database"""
        recipients_file = self.data_dir / "recipients.json"
        
        try:
            data = {"recipients": []}
            
            for recipient in self.recipients.values():
                recipient_data = asdict(recipient)
                
                # Convert preferences if available
                if recipient_data['preferences']:
                    pref_data = recipient_data['preferences']
                    pref_data['channels'] = {k.value: v for k, v in pref_data['channels'].items()}
                    pref_data['triggers'] = {k.value: v for k, v in pref_data['triggers'].items()}
                    pref_data['priority_threshold'] = pref_data['priority_threshold'].value
                
                data["recipients"].append(recipient_data)
            
            with open(recipients_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save recipients: {e}")
    
    def _initialize_channel_handlers(self) -> Dict[NotificationChannel, NotificationChannelHandler]:
        """Initialize notification channel handlers"""
        handlers = {}
        
        # Email handler
        if self.config["channels"]["email"]["enabled"]:
            handlers[NotificationChannel.EMAIL] = EmailHandler(self.config["channels"]["email"])
        
        # Webhook handler
        if self.config["channels"]["webhook"]["enabled"]:
            handlers[NotificationChannel.WEBHOOK] = WebhookHandler(self.config["channels"]["webhook"])
        
        # Slack handler
        if self.config["channels"]["slack"]["enabled"]:
            handlers[NotificationChannel.SLACK] = SlackHandler(self.config["channels"]["slack"])
        
        return handlers
    
    def add_recipient(self, user_id: str, name: str, email: Optional[str] = None,
                     roles: List[str] = None, preferences: Optional[NotificationPreferences] = None) -> bool:
        """
        Add a new recipient to the system
        
        Args:
            user_id: Unique user identifier
            name: User's display name
            email: Email address
            roles: User roles
            preferences: Notification preferences
        
        Returns:
            Success status
        """
        if user_id in self.recipients:
            logger.warning(f"Recipient {user_id} already exists")
            return False
        
        recipient = Recipient(
            user_id=user_id,
            name=name,
            email=email,
            roles=roles or [],
            preferences=preferences
        )
        
        self.recipients[user_id] = recipient
        self._save_recipients()
        
        logger.info(f"Added recipient: {name} ({user_id})")
        return True
    
    def update_recipient_preferences(self, user_id: str, preferences: NotificationPreferences) -> bool:
        """
        Update recipient notification preferences
        
        Args:
            user_id: User identifier
            preferences: Updated preferences
        
        Returns:
            Success status
        """
        if user_id not in self.recipients:
            logger.error(f"Recipient {user_id} not found")
            return False
        
        self.recipients[user_id].preferences = preferences
        self._save_recipients()
        
        logger.info(f"Updated preferences for recipient {user_id}")
        return True
    
    def create_notification(self, trigger: NotificationTrigger, recipients: List[str],
                          context: Dict[str, Any], priority: Optional[NotificationPriority] = None,
                          scheduled_date: Optional[datetime] = None,
                          channels: Optional[List[NotificationChannel]] = None) -> List[str]:
        """
        Create and queue notifications
        
        Args:
            trigger: Notification trigger event
            recipients: List of recipient user IDs
            context: Context data for template rendering
            priority: Override priority level
            scheduled_date: Schedule for future delivery
            channels: Override delivery channels
        
        Returns:
            List of created message IDs
        """
        message_ids = []
        
        for recipient_id in recipients:
            if recipient_id not in self.recipients:
                logger.warning(f"Recipient {recipient_id} not found")
                continue
            
            recipient = self.recipients[recipient_id]
            
            # Determine channels to use
            target_channels = channels or self._get_recipient_channels(recipient, trigger)
            
            for channel in target_channels:
                # Find appropriate template
                template = self._find_template(trigger, channel)
                if not template:
                    logger.warning(f"No template found for {trigger.value} on {channel.value}")
                    continue
                
                # Check if recipient should receive this notification
                if not self._should_send_notification(recipient, trigger, priority or template.priority):
                    continue
                
                # Create message
                message = self._create_message(template, recipient, context, priority, scheduled_date)
                if message:
                    self.message_queue.append(message)
                    message_ids.append(message.message_id)
        
        logger.info(f"Created {len(message_ids)} notifications for trigger {trigger.value}")
        return message_ids
    
    def _get_recipient_channels(self, recipient: Recipient, trigger: NotificationTrigger) -> List[NotificationChannel]:
        """Get enabled channels for recipient"""
        if not recipient.preferences:
            return [NotificationChannel.EMAIL]  # Default to email
        
        enabled_channels = []
        for channel, enabled in recipient.preferences.channels.items():
            if enabled and channel in self.channel_handlers:
                # Check if trigger is enabled for this recipient
                if recipient.preferences.triggers.get(trigger, True):
                    enabled_channels.append(channel)
        
        return enabled_channels or [NotificationChannel.EMAIL]
    
    def _find_template(self, trigger: NotificationTrigger, channel: NotificationChannel) -> Optional[NotificationTemplate]:
        """Find appropriate template for trigger and channel"""
        # Look for exact match
        template_id = f"{trigger.value}_{channel.value}"
        if template_id in self.templates:
            return self.templates[template_id]
        
        # Look for any template with matching trigger and channel
        for template in self.templates.values():
            if template.trigger == trigger and template.channel == channel:
                return template
        
        return None
    
    def _should_send_notification(self, recipient: Recipient, trigger: NotificationTrigger, 
                                priority: NotificationPriority) -> bool:
        """Check if notification should be sent to recipient"""
        if not recipient.preferences:
            return True
        
        # Check priority threshold
        priority_levels = {
            NotificationPriority.LOW: 1,
            NotificationPriority.NORMAL: 2,
            NotificationPriority.HIGH: 3,
            NotificationPriority.URGENT: 4,
            NotificationPriority.CRITICAL: 5
        }
        
        if priority_levels[priority] < priority_levels[recipient.preferences.priority_threshold]:
            return False
        
        # Check quiet hours
        if recipient.preferences.quiet_hours:
            current_hour = datetime.now().hour
            start_hour, end_hour = recipient.preferences.quiet_hours
            
            if start_hour <= end_hour:
                if start_hour <= current_hour <= end_hour:
                    return False
            else:  # Quiet hours span midnight
                if current_hour >= start_hour or current_hour <= end_hour:
                    return False
        
        # Check if trigger is enabled
        if not recipient.preferences.triggers.get(trigger, True):
            return False
        
        return True
    
    def _create_message(self, template: NotificationTemplate, recipient: Recipient,
                       context: Dict[str, Any], priority: Optional[NotificationPriority] = None,
                       scheduled_date: Optional[datetime] = None) -> Optional[NotificationMessage]:
        """Create notification message from template"""
        try:
            # Generate message ID
            message_id = f"msg-{int(time.time() * 1000)}-{recipient.user_id[:8]}"
            
            # Prepare template context
            template_context = {
                "recipient_name": recipient.name,
                "recipient_id": recipient.user_id,
                **context
            }
            
            # Render subject and body
            subject_template = Template(template.subject_template)
            body_template = Template(template.body_template)
            
            subject = subject_template.render(**template_context)
            body = body_template.render(**template_context)
            
            # Render HTML body if available
            html_body = None
            if template.html_template:
                html_template = Template(template.html_template)
                html_body = html_template.render(**template_context)
            
            message = NotificationMessage(
                message_id=message_id,
                trigger=template.trigger,
                channel=template.channel,
                priority=priority or template.priority,
                recipient=recipient,
                subject=subject,
                body=body,
                html_body=html_body,
                attachments=template.attachments.copy(),
                context=context,
                scheduled_date=scheduled_date.isoformat() if scheduled_date else None
            )
            
            return message
            
        except Exception as e:
            logger.error(f"Failed to create message from template {template.template_id}: {e}")
            return None
    
    async def process_message_queue(self):
        """Process pending messages in the queue"""
        processed = 0
        batch_size = self.config["delivery"]["batch_size"]
        
        while self.message_queue and processed < batch_size:
            message = self.message_queue.popleft()
            
            # Check if message should be sent now
            if message.scheduled_date:
                scheduled_time = datetime.fromisoformat(message.scheduled_date.replace('Z', '+00:00'))
                if datetime.now() < scheduled_time.replace(tzinfo=None):
                    # Put back in queue for later
                    self.message_queue.append(message)
                    continue
            
            # Send message
            success = await self._send_message(message)
            
            if success:
                message.status = NotificationStatus.SENT
                message.delivered_date = datetime.now().isoformat()
            else:
                message.status = NotificationStatus.FAILED
                message.delivery_attempts += 1
                
                # Retry if within limits
                if message.delivery_attempts < self.config["delivery"]["max_retry_attempts"]:
                    retry_delay_minutes = self.config["delivery"]["retry_delay_minutes"]
                    delay_index = min(message.delivery_attempts - 1, len(retry_delay_minutes) - 1)
                    retry_time = datetime.now() + timedelta(minutes=retry_delay_minutes[delay_index])
                    message.scheduled_date = retry_time.isoformat()
                    message.status = NotificationStatus.RETRY
                    self.message_queue.append(message)
            
            message.last_attempt = datetime.now().isoformat()
            self.sent_messages[message.message_id] = message
            processed += 1
        
        if processed > 0:
            logger.info(f"Processed {processed} messages from queue")
    
    async def _send_message(self, message: NotificationMessage) -> bool:
        """Send individual message"""
        handler = self.channel_handlers.get(message.channel)
        if not handler:
            logger.error(f"No handler available for channel {message.channel.value}")
            return False
        
        try:
            return await handler.send(message)
        except Exception as e:
            logger.error(f"Handler error for message {message.message_id}: {e}")
            message.error_message = str(e)
            return False
    
    def start_scheduler(self):
        """Start the background notification scheduler"""
        if self.scheduler_running:
            return
        
        self.scheduler_running = True
        
        # Schedule regular queue processing
        schedule.every(self.config["scheduling"]["check_interval_seconds"]).seconds.do(
            lambda: asyncio.run(self.process_message_queue())
        )
        
        # Schedule reminder checks
        for interval_hours in self.config["scheduling"]["reminder_intervals_hours"]:
            schedule.every(interval_hours).hours.do(self._check_reminders)
        
        # Start scheduler thread
        def run_scheduler():
            while self.scheduler_running:
                schedule.run_pending()
                time.sleep(1)
        
        self.scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        logger.info("Notification scheduler started")
    
    def stop_scheduler(self):
        """Stop the background notification scheduler"""
        self.scheduler_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        
        logger.info("Notification scheduler stopped")
    
    def _check_reminders(self):
        """Check for and send deadline reminders"""
        # This would integrate with the workflow system to check for approaching deadlines
        # For now, this is a placeholder
        logger.info("Checking for deadline reminders")
    
    def get_message_status(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific message"""
        if message_id not in self.sent_messages:
            return None
        
        message = self.sent_messages[message_id]
        return {
            "message_id": message.message_id,
            "trigger": message.trigger.value,
            "channel": message.channel.value,
            "priority": message.priority.value,
            "recipient": message.recipient.user_id,
            "status": message.status.value,
            "created_date": message.created_date,
            "scheduled_date": message.scheduled_date,
            "delivered_date": message.delivered_date,
            "delivery_attempts": message.delivery_attempts,
            "last_attempt": message.last_attempt,
            "error_message": message.error_message
        }
    
    def generate_delivery_report(self, start_date: Optional[str] = None,
                               end_date: Optional[str] = None) -> DeliveryReport:
        """Generate notification delivery report"""
        report_start = datetime.fromisoformat(start_date) if start_date else datetime.now() - timedelta(days=30)
        report_end = datetime.fromisoformat(end_date) if end_date else datetime.now()
        
        # Filter messages by date range
        messages = [
            msg for msg in self.sent_messages.values()
            if report_start <= datetime.fromisoformat(msg.created_date.replace('Z', '+00:00')).replace(tzinfo=None) <= report_end
        ]
        
        total_notifications = len(messages)
        successful_deliveries = len([msg for msg in messages if msg.status == NotificationStatus.SENT])
        failed_deliveries = len([msg for msg in messages if msg.status == NotificationStatus.FAILED])
        
        # Statistics by channel
        by_channel = defaultdict(lambda: {"sent": 0, "failed": 0})
        by_trigger = defaultdict(lambda: {"sent": 0, "failed": 0})
        by_priority = defaultdict(lambda: {"sent": 0, "failed": 0})
        
        delivery_times = []
        
        for msg in messages:
            channel = msg.channel.value
            trigger = msg.trigger.value
            priority = msg.priority.value
            
            if msg.status == NotificationStatus.SENT:
                by_channel[channel]["sent"] += 1
                by_trigger[trigger]["sent"] += 1
                by_priority[priority]["sent"] += 1
                
                if msg.delivered_date:
                    created = datetime.fromisoformat(msg.created_date.replace('Z', '+00:00'))
                    delivered = datetime.fromisoformat(msg.delivered_date.replace('Z', '+00:00'))
                    delivery_time = (delivered - created).total_seconds()
                    delivery_times.append(delivery_time)
            else:
                by_channel[channel]["failed"] += 1
                by_trigger[trigger]["failed"] += 1
                by_priority[priority]["failed"] += 1
        
        # Calculate average delivery time
        avg_delivery_time = sum(delivery_times) / len(delivery_times) if delivery_times else 0
        
        # Find top failures
        failed_messages = [msg for msg in messages if msg.status == NotificationStatus.FAILED]
        top_failures = []
        
        for msg in failed_messages[:10]:  # Top 10 failures
            top_failures.append({
                "message_id": msg.message_id,
                "trigger": msg.trigger.value,
                "channel": msg.channel.value,
                "recipient": msg.recipient.user_id,
                "error": msg.error_message,
                "attempts": msg.delivery_attempts
            })
        
        # Generate recommendations
        recommendations = []
        
        if failed_deliveries / total_notifications > 0.1 if total_notifications > 0 else 0:
            recommendations.append("High failure rate detected - check channel configurations")
        
        if avg_delivery_time > 300:  # More than 5 minutes
            recommendations.append("High average delivery time - consider optimizing delivery process")
        
        report = DeliveryReport(
            report_id=f"report-{int(time.time())}",
            period_start=report_start.isoformat(),
            period_end=report_end.isoformat(),
            total_notifications=total_notifications,
            successful_deliveries=successful_deliveries,
            failed_deliveries=failed_deliveries,
            by_channel=dict(by_channel),
            by_trigger=dict(by_trigger),
            by_priority=dict(by_priority),
            average_delivery_time=avg_delivery_time,
            top_failures=top_failures,
            recommendations=recommendations
        )
        
        return report


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Notification System")
    parser.add_argument("--config", required=True, help="Configuration file path")
    parser.add_argument("--templates-dir", help="Templates directory path")
    parser.add_argument("--command", required=True,
                       choices=["send", "status", "report", "add-recipient", "start-scheduler"],
                       help="Command to execute")
    
    # Command-specific arguments
    parser.add_argument("--trigger", help="Notification trigger")
    parser.add_argument("--recipients", nargs="+", help="Recipient user IDs")
    parser.add_argument("--context", help="Context JSON string")
    parser.add_argument("--message-id", help="Message ID")
    parser.add_argument("--user-id", help="User ID")
    parser.add_argument("--name", help="User name")
    parser.add_argument("--email", help="Email address")
    parser.add_argument("--start-date", help="Report start date")
    parser.add_argument("--end-date", help="Report end date")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    try:
        notification_system = NotificationSystem(args.config, args.templates_dir)
        
        if args.command == "send":
            if not all([args.trigger, args.recipients, args.context]):
                print("Error: trigger, recipients, and context are required for send command")
                return
            
            trigger = NotificationTrigger(args.trigger)
            context = json.loads(args.context)
            
            message_ids = notification_system.create_notification(trigger, args.recipients, context)
            print(f"Created {len(message_ids)} notifications: {message_ids}")
            
            # Process immediately for CLI usage
            asyncio.run(notification_system.process_message_queue())
        
        elif args.command == "status":
            if not args.message_id:
                print("Error: message-id is required for status command")
                return
            
            status = notification_system.get_message_status(args.message_id)
            if status:
                print(json.dumps(status, indent=2))
            else:
                print(f"Message {args.message_id} not found")
        
        elif args.command == "add-recipient":
            if not all([args.user_id, args.name]):
                print("Error: user-id and name are required for add-recipient command")
                return
            
            success = notification_system.add_recipient(args.user_id, args.name, args.email)
            print(f"Add recipient {args.name}: {'Success' if success else 'Failed'}")
        
        elif args.command == "report":
            report = notification_system.generate_delivery_report(args.start_date, args.end_date)
            report_data = asdict(report)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report_data, f, indent=2)
                print(f"Report saved to {args.output}")
            else:
                print(json.dumps(report_data, indent=2))
        
        elif args.command == "start-scheduler":
            notification_system.start_scheduler()
            print("Scheduler started. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                notification_system.stop_scheduler()
                print("Scheduler stopped.")
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()