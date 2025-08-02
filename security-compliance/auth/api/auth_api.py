#!/usr/bin/env python3
"""
CAC/PIV Authentication REST API
FastAPI application for platform authentication services
"""

import logging
import secrets
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel

# Import our models and middleware
from .models import *
from .middleware import SecurityMiddleware, CACAuthMiddleware, AuditMiddleware, RequestValidationMiddleware

# Import platform adapters and managers
from ..platform_adapters import (
    AdvanaAuthAdapter, QlikAuthAdapter, DatabricksAuthAdapter, 
    NavyJupiterAuthAdapter, PlatformConfig
)
from ..platform_config_manager import PlatformConfigManager
from ..security_managers import AuditLogger

logger = logging.getLogger(__name__)

class AuthAPIConfig:
    """Configuration for authentication API"""
    def __init__(self):
        self.title = "CAC/PIV Authentication API"
        self.version = "1.0.0"
        self.description = "Multi-platform CAC/PIV authentication service"
        self.host = "0.0.0.0"
        self.port = 8000
        self.debug = False
        self.allowed_ips = []
        self.cors_origins = ["*"]
        self.require_https = True
        self.rate_limit_requests = 100
        self.rate_limit_window = 60
        self.session_timeout = 3600
        self.config_dir = "./config"

class AuthenticationService:
    """Core authentication service"""
    
    def __init__(self, config_manager: PlatformConfigManager):
        """
        Initialize authentication service
        
        Args:
            config_manager: Platform configuration manager
        """
        self.config_manager = config_manager
        self.platform_adapters = {}
        self.challenge_storage = {}  # In production, use Redis
        
        # Initialize platform adapters
        self._initialize_adapters()
        
        logger.info("Authentication service initialized")
    
    def _initialize_adapters(self):
        """Initialize platform adapters"""
        for platform_name in self.config_manager.list_platforms():
            try:
                config = self.config_manager.get_platform_config(platform_name)
                if config:
                    adapter_class = self._get_adapter_class(platform_name)
                    if adapter_class:
                        self.platform_adapters[platform_name] = adapter_class(config)
                        logger.info(f"Initialized adapter for platform: {platform_name}")
            except Exception as e:
                logger.error(f"Failed to initialize adapter for {platform_name}: {e}")
    
    def _get_adapter_class(self, platform_name: str):
        """Get adapter class for platform"""
        adapter_map = {
            "advana": AdvanaAuthAdapter,
            "qlik": QlikAuthAdapter,
            "databricks": DatabricksAuthAdapter,
            "navy_jupiter": NavyJupiterAuthAdapter
        }
        return adapter_map.get(platform_name)
    
    def generate_challenge(self, platform: str) -> Dict[str, Any]:
        """Generate authentication challenge"""
        challenge_data = secrets.token_bytes(32)
        challenge_b64 = base64.b64encode(challenge_data).decode('utf-8')
        challenge_id = secrets.token_urlsafe(16)
        
        # Store challenge (expires in 5 minutes)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        self.challenge_storage[challenge_id] = {
            'challenge': challenge_b64,
            'platform': platform,
            'expires_at': expires_at
        }
        
        return {
            'challenge': challenge_b64,
            'challenge_id': challenge_id,
            'expires_in': 300  # 5 minutes
        }
    
    def validate_challenge(self, challenge_id: str, provided_challenge: str) -> bool:
        """Validate challenge"""
        stored_challenge = self.challenge_storage.get(challenge_id)
        if not stored_challenge:
            return False
        
        # Check expiration
        if datetime.now(timezone.utc) > stored_challenge['expires_at']:
            del self.challenge_storage[challenge_id]
            return False
        
        # Validate challenge
        is_valid = stored_challenge['challenge'] == provided_challenge
        
        # Remove used challenge
        if is_valid:
            del self.challenge_storage[challenge_id]
        
        return is_valid
    
    def authenticate(self, request: CACAuthenticationRequest) -> AuthenticationResponse:
        """Authenticate user with CAC/PIV"""
        platform_name = request.platform.value
        
        # Get platform adapter
        adapter = self.platform_adapters.get(platform_name)
        if not adapter:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Platform '{platform_name}' not supported"
            )
        
        try:
            # Decode base64 data
            certificate_data = base64.b64decode(request.certificate_data)
            signature = base64.b64decode(request.signature)
            challenge = base64.b64decode(request.challenge)
            
            # Authenticate with platform adapter
            result = adapter.authenticate_with_cac(
                certificate_data=certificate_data,
                signature=signature,
                challenge=challenge,
                additional_params=request.additional_params
            )
            
            # Convert to API response
            return AuthenticationResponse(
                status=AuthStatus(result.status.value),
                user_id=result.user_id,
                session_token=result.session_token,
                platform_token=result.platform_token,
                roles=result.roles or [],
                permissions=result.permissions or [],
                expires_at=result.session_expires,
                error_message=result.error_message,
                metadata=result.metadata or {}
            )
            
        except Exception as e:
            logger.error(f"Authentication error for platform {platform_name}: {e}")
            return AuthenticationResponse(
                status=AuthStatus.FAILED,
                error_message=f"Authentication failed: {str(e)}"
            )
    
    def refresh_token(self, request: TokenRefreshRequest) -> TokenRefreshResponse:
        """Refresh authentication token"""
        platform_name = request.platform.value
        
        adapter = self.platform_adapters.get(platform_name)
        if not adapter:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Platform '{platform_name}' not supported"
            )
        
        try:
            result = adapter.refresh_token(request.session_token)
            
            return TokenRefreshResponse(
                status=AuthStatus(result.status.value),
                session_token=result.session_token,
                platform_token=result.platform_token,
                expires_at=result.session_expires,
                error_message=result.error_message
            )
            
        except Exception as e:
            logger.error(f"Token refresh error for platform {platform_name}: {e}")
            return TokenRefreshResponse(
                status=AuthStatus.FAILED,
                error_message=f"Token refresh failed: {str(e)}"
            )
    
    def validate_session(self, request: SessionValidationRequest) -> SessionValidationResponse:
        """Validate session token"""
        platform_name = request.platform.value
        
        adapter = self.platform_adapters.get(platform_name)
        if not adapter:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Platform '{platform_name}' not supported"
            )
        
        try:
            is_valid = adapter.validate_session(request.session_token)
            
            return SessionValidationResponse(
                valid=is_valid,
                error_message=None if is_valid else "Session is invalid or expired"
            )
            
        except Exception as e:
            logger.error(f"Session validation error for platform {platform_name}: {e}")
            return SessionValidationResponse(
                valid=False,
                error_message=f"Session validation failed: {str(e)}"
            )
    
    def logout(self, request: LogoutRequest) -> LogoutResponse:
        """Logout and invalidate session"""
        platform_name = request.platform.value
        
        adapter = self.platform_adapters.get(platform_name)
        if not adapter:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Platform '{platform_name}' not supported"
            )
        
        try:
            success = adapter.logout(request.session_token)
            
            return LogoutResponse(
                success=success,
                message="Logout successful" if success else "Logout failed"
            )
            
        except Exception as e:
            logger.error(f"Logout error for platform {platform_name}: {e}")
            return LogoutResponse(
                success=False,
                message=f"Logout failed: {str(e)}"
            )
    
    def get_user_info(self, request: UserInfoRequest) -> UserInfoResponse:
        """Get user information"""
        platform_name = request.platform.value
        
        adapter = self.platform_adapters.get(platform_name)
        if not adapter:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Platform '{platform_name}' not supported"
            )
        
        try:
            user_info = adapter.get_user_info(request.session_token)
            
            return UserInfoResponse(
                user_id=user_info.get('id', 'unknown'),
                user_info=user_info,
                platform=request.platform
            )
            
        except Exception as e:
            logger.error(f"User info error for platform {platform_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get user info: {str(e)}"
            )
    
    def get_permissions(self, request: PermissionsRequest) -> PermissionsResponse:
        """Get user permissions"""
        platform_name = request.platform.value
        
        adapter = self.platform_adapters.get(platform_name)
        if not adapter:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Platform '{platform_name}' not supported"
            )
        
        try:
            permissions = adapter.get_user_permissions(request.session_token, request.user_id)
            
            return PermissionsResponse(
                user_id=request.user_id,
                permissions=permissions,
                platform=request.platform
            )
            
        except Exception as e:
            logger.error(f"Permissions error for platform {platform_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get permissions: {str(e)}"
            )

def create_auth_app(config: AuthAPIConfig = None) -> FastAPI:
    """
    Create and configure FastAPI application
    
    Args:
        config: API configuration
        
    Returns:
        Configured FastAPI application
    """
    if config is None:
        config = AuthAPIConfig()
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Application lifespan manager"""
        logger.info("Starting CAC/PIV Authentication API")
        yield
        logger.info("Shutting down CAC/PIV Authentication API")
    
    # Create FastAPI app
    app = FastAPI(
        title=config.title,
        version=config.version,
        description=config.description,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # Initialize configuration manager and service
    config_manager = PlatformConfigManager(config_dir=config.config_dir)
    auth_service = AuthenticationService(config_manager)
    
    # Add middleware
    if config.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    app.add_middleware(
        SecurityMiddleware,
        allowed_ips=config.allowed_ips,
        rate_limit_requests=config.rate_limit_requests,
        rate_limit_window=config.rate_limit_window,
        require_https=config.require_https,
        cors_origins=config.cors_origins
    )
    
    app.add_middleware(
        CACAuthMiddleware,
        exempt_paths=["/health", "/docs", "/openapi.json", "/api/v1/auth/challenge"],
        require_valid_session=True
    )
    
    app.add_middleware(
        AuditMiddleware,
        audit_logger_instance=AuditLogger.instance()
    )
    
    app.add_middleware(
        RequestValidationMiddleware,
        max_request_size=10 * 1024 * 1024,  # 10MB
        allowed_content_types=["application/json"]
    )
    
    # Health endpoint
    @app.get("/health", response_model=HealthResponse, tags=["Health"])
    async def health_check():
        """Health check endpoint"""
        services = {}
        
        # Check platform adapters
        for platform_name, adapter in auth_service.platform_adapters.items():
            try:
                # Simple connectivity check
                platform_info = adapter.get_platform_info()
                services[platform_name] = "healthy" if platform_info else "unhealthy"
            except Exception:
                services[platform_name] = "unhealthy"
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.now(timezone.utc),
            version=config.version,
            services=services
        )
    
    # Authentication endpoints
    @app.post("/api/v1/auth/challenge", response_model=ChallengeResponse, tags=["Authentication"])
    async def generate_challenge(request: ChallengeRequest):
        """Generate authentication challenge"""
        try:
            result = auth_service.generate_challenge(request.platform.value)
            return ChallengeResponse(**result)
        except Exception as e:
            logger.error(f"Challenge generation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate challenge: {str(e)}"
            )
    
    @app.post("/api/v1/auth/authenticate", response_model=AuthenticationResponse, tags=["Authentication"])
    async def authenticate(request: CACAuthenticationRequest):
        """Authenticate with CAC/PIV certificate"""
        return auth_service.authenticate(request)
    
    @app.post("/api/v1/auth/refresh", response_model=TokenRefreshResponse, tags=["Authentication"])
    async def refresh_token(request: TokenRefreshRequest):
        """Refresh authentication token"""
        return auth_service.refresh_token(request)
    
    @app.post("/api/v1/auth/validate", response_model=SessionValidationResponse, tags=["Authentication"])
    async def validate_session(request: SessionValidationRequest):
        """Validate session token"""
        return auth_service.validate_session(request)
    
    @app.post("/api/v1/auth/logout", response_model=LogoutResponse, tags=["Authentication"])
    async def logout(request: LogoutRequest):
        """Logout and invalidate session"""
        return auth_service.logout(request)
    
    # User endpoints
    @app.post("/api/v1/user/info", response_model=UserInfoResponse, tags=["User"])
    async def get_user_info(request: UserInfoRequest):
        """Get user information"""
        return auth_service.get_user_info(request)
    
    @app.post("/api/v1/user/permissions", response_model=PermissionsResponse, tags=["User"])
    async def get_permissions(request: PermissionsRequest):
        """Get user permissions"""
        return auth_service.get_permissions(request)
    
    # Configuration endpoints
    @app.get("/api/v1/config", response_model=ConfigurationResponse, tags=["Configuration"])
    async def get_configuration():
        """Get platform configuration information"""
        platforms = []
        
        for platform_name in config_manager.list_platforms():
            platform_config = config_manager.get_platform_config(platform_name)
            if platform_config:
                adapter = auth_service.platform_adapters.get(platform_name)
                available = adapter is not None
                
                platforms.append(PlatformStatus(
                    platform=PlatformType(platform_name),
                    available=available,
                    base_url=platform_config.base_url,
                    api_version=platform_config.api_version,
                    last_checked=datetime.now(timezone.utc),
                    error_message=None if available else "Adapter not initialized"
                ))
        
        config_summary = config_manager.get_config_summary()
        
        return ConfigurationResponse(
            platforms=platforms,
            global_config=config_summary.get("global_config", {}),
            security_config=config_summary.get("security_config", {})
        )
    
    # Audit endpoints
    @app.post("/api/v1/audit/logs", response_model=AuditLogResponse, tags=["Audit"])
    async def get_audit_logs(request: AuditLogRequest):
        """Get audit logs"""
        try:
            audit_logger = AuditLogger.instance()
            
            # This would typically query a database
            # For now, return empty result
            return AuditLogResponse(
                entries=[],
                total_count=0,
                page=request.page,
                page_size=request.page_size
            )
            
        except Exception as e:
            logger.error(f"Audit logs error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get audit logs: {str(e)}"
            )
    
    # Error handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions"""
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error="HTTP_ERROR",
                message=exc.detail,
                details={"status_code": exc.status_code}
            ).dict()
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle general exceptions"""
        logger.error(f"Unhandled exception: {exc}")
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="INTERNAL_ERROR",
                message="An internal error occurred",
                details={"exception": str(exc)} if config.debug else None
            ).dict()
        )
    
    return app

if __name__ == "__main__":
    import uvicorn
    
    # Create and run app
    config = AuthAPIConfig()
    app = create_auth_app(config)
    
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        debug=config.debug
    )