#!/usr/bin/env python3
"""
API Models for CAC/PIV Authentication
Pydantic models for request/response validation
"""

from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum

class AuthenticationMethod(str, Enum):
    """Authentication methods supported"""
    CAC_PIV = "cac_piv"
    CERTIFICATE = "certificate"
    TOKEN = "token"

class PlatformType(str, Enum):
    """Supported platform types"""
    ADVANA = "advana"
    QLIK = "qlik"
    DATABRICKS = "databricks"
    NAVY_JUPITER = "navy_jupiter"

class AuthStatus(str, Enum):
    """Authentication status values"""
    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    EXPIRED = "expired"
    LOCKED = "locked"
    INVALID_CERTIFICATE = "invalid_certificate"
    NETWORK_ERROR = "network_error"

# Request Models
class CACAuthenticationRequest(BaseModel):
    """CAC/PIV authentication request"""
    certificate_data: str = Field(..., description="Base64-encoded X.509 certificate")
    signature: str = Field(..., description="Base64-encoded digital signature")
    challenge: str = Field(..., description="Base64-encoded challenge data")
    platform: PlatformType = Field(..., description="Target platform")
    environment: str = Field(default="production", description="Environment name")
    additional_params: Optional[Dict[str, Any]] = Field(default=None, description="Platform-specific parameters")
    
    @validator('certificate_data', 'signature', 'challenge')
    def validate_base64(cls, v):
        """Validate base64 encoding"""
        try:
            import base64
            base64.b64decode(v)
            return v
        except Exception:
            raise ValueError("Invalid base64 encoding")

class TokenRefreshRequest(BaseModel):
    """Token refresh request"""
    session_token: str = Field(..., description="Current session token")
    platform: PlatformType = Field(..., description="Target platform")
    environment: str = Field(default="production", description="Environment name")

class SessionValidationRequest(BaseModel):
    """Session validation request"""
    session_token: str = Field(..., description="Session token to validate")
    platform: PlatformType = Field(..., description="Target platform")
    environment: str = Field(default="production", description="Environment name")

class LogoutRequest(BaseModel):
    """Logout request"""
    session_token: str = Field(..., description="Session token to invalidate")
    platform: PlatformType = Field(..., description="Target platform")
    environment: str = Field(default="production", description="Environment name")

class UserInfoRequest(BaseModel):
    """User information request"""
    session_token: str = Field(..., description="Valid session token")
    platform: PlatformType = Field(..., description="Target platform")
    environment: str = Field(default="production", description="Environment name")

class PermissionsRequest(BaseModel):
    """User permissions request"""
    session_token: str = Field(..., description="Valid session token")
    platform: PlatformType = Field(..., description="Target platform")
    user_id: Optional[str] = Field(default=None, description="User identifier")
    environment: str = Field(default="production", description="Environment name")

class ChallengeRequest(BaseModel):
    """Challenge generation request"""
    platform: PlatformType = Field(..., description="Target platform")
    client_info: Optional[Dict[str, Any]] = Field(default=None, description="Client information")

# Response Models
class ChallengeResponse(BaseModel):
    """Challenge generation response"""
    challenge: str = Field(..., description="Base64-encoded challenge data")
    expires_in: int = Field(..., description="Challenge expiration in seconds")
    challenge_id: str = Field(..., description="Unique challenge identifier")

class AuthenticationResponse(BaseModel):
    """Authentication response"""
    status: AuthStatus = Field(..., description="Authentication status")
    user_id: Optional[str] = Field(default=None, description="Authenticated user ID")
    session_token: Optional[str] = Field(default=None, description="Session token")
    platform_token: Optional[str] = Field(default=None, description="Platform-specific token")
    roles: List[str] = Field(default_factory=list, description="User roles")
    permissions: List[str] = Field(default_factory=list, description="User permissions")
    expires_at: Optional[datetime] = Field(default=None, description="Session expiration time")
    error_message: Optional[str] = Field(default=None, description="Error message if failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

class TokenRefreshResponse(BaseModel):
    """Token refresh response"""
    status: AuthStatus = Field(..., description="Refresh status")
    session_token: Optional[str] = Field(default=None, description="New session token")
    platform_token: Optional[str] = Field(default=None, description="New platform token")
    expires_at: Optional[datetime] = Field(default=None, description="New expiration time")
    error_message: Optional[str] = Field(default=None, description="Error message if failed")

class SessionValidationResponse(BaseModel):
    """Session validation response"""
    valid: bool = Field(..., description="Whether session is valid")
    expires_at: Optional[datetime] = Field(default=None, description="Session expiration time")
    user_id: Optional[str] = Field(default=None, description="User ID if valid")
    error_message: Optional[str] = Field(default=None, description="Error message if invalid")

class LogoutResponse(BaseModel):
    """Logout response"""
    success: bool = Field(..., description="Whether logout was successful")
    message: str = Field(..., description="Response message")

class UserInfoResponse(BaseModel):
    """User information response"""
    user_id: str = Field(..., description="User identifier")
    user_info: Dict[str, Any] = Field(..., description="User information")
    platform: PlatformType = Field(..., description="Source platform")

class PermissionsResponse(BaseModel):
    """User permissions response"""
    user_id: Optional[str] = Field(default=None, description="User identifier")
    permissions: List[str] = Field(..., description="User permissions")
    platform: PlatformType = Field(..., description="Source platform")

class HealthResponse(BaseModel):
    """API health response"""
    status: str = Field(..., description="Health status")
    timestamp: datetime = Field(..., description="Check timestamp")
    version: str = Field(..., description="API version")
    services: Dict[str, str] = Field(..., description="Service status")

class ErrorResponse(BaseModel):
    """Error response"""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")

# Configuration Models
class PlatformStatus(BaseModel):
    """Platform status information"""
    platform: PlatformType = Field(..., description="Platform name")
    available: bool = Field(..., description="Whether platform is available")
    base_url: str = Field(..., description="Platform base URL")
    api_version: str = Field(..., description="API version")
    last_checked: datetime = Field(..., description="Last health check")
    error_message: Optional[str] = Field(default=None, description="Error if unavailable")

class ConfigurationResponse(BaseModel):
    """Configuration information response"""
    platforms: List[PlatformStatus] = Field(..., description="Platform configurations")
    global_config: Dict[str, Any] = Field(..., description="Global configuration")
    security_config: Dict[str, Any] = Field(..., description="Security configuration")

# Audit Models
class AuditLogEntry(BaseModel):
    """Audit log entry"""
    timestamp: datetime = Field(..., description="Event timestamp")
    event_type: str = Field(..., description="Event type")
    user_id: Optional[str] = Field(default=None, description="User identifier")
    platform: Optional[PlatformType] = Field(default=None, description="Platform")
    success: bool = Field(..., description="Whether event was successful")
    details: Dict[str, Any] = Field(default_factory=dict, description="Event details")
    client_ip: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="User agent string")

class AuditLogResponse(BaseModel):
    """Audit log response"""
    entries: List[AuditLogEntry] = Field(..., description="Audit log entries")
    total_count: int = Field(..., description="Total number of entries")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Page size")

class AuditLogRequest(BaseModel):
    """Audit log request"""
    start_date: Optional[datetime] = Field(default=None, description="Start date filter")
    end_date: Optional[datetime] = Field(default=None, description="End date filter")
    event_type: Optional[str] = Field(default=None, description="Event type filter")
    user_id: Optional[str] = Field(default=None, description="User ID filter")
    platform: Optional[PlatformType] = Field(default=None, description="Platform filter")
    success_only: Optional[bool] = Field(default=None, description="Show only successful events")
    page: int = Field(default=1, description="Page number")
    page_size: int = Field(default=50, description="Page size")
    
    @validator('page', 'page_size')
    def validate_pagination(cls, v):
        """Validate pagination parameters"""
        if v < 1:
            raise ValueError("Must be greater than 0")
        return v
    
    @validator('page_size')
    def validate_page_size(cls, v):
        """Validate page size"""
        if v > 1000:
            raise ValueError("Page size cannot exceed 1000")
        return v