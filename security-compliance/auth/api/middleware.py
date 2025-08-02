#!/usr/bin/env python3
"""
API Middleware for CAC/PIV Authentication
Security and authentication middleware for FastAPI
"""

import logging
import time
from typing import Dict, List, Optional, Callable
from datetime import datetime, timezone
from fastapi import Request, Response, HTTPException, status
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.security.base import SecurityBase
import ipaddress

logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware for API protection
    """
    
    def __init__(self, app, 
                 allowed_ips: List[str] = None,
                 rate_limit_requests: int = 100,
                 rate_limit_window: int = 60,
                 require_https: bool = True,
                 cors_origins: List[str] = None):
        """
        Initialize security middleware
        
        Args:
            app: FastAPI application
            allowed_ips: List of allowed IP addresses/CIDR blocks
            rate_limit_requests: Number of requests per window
            rate_limit_window: Rate limit window in seconds
            require_https: Whether to require HTTPS
            cors_origins: Allowed CORS origins
        """
        super().__init__(app)
        self.allowed_ips = allowed_ips or []
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window
        self.require_https = require_https
        self.cors_origins = cors_origins or []
        
        # Rate limiting storage (in production, use Redis or similar)
        self.rate_limit_storage = {}
        
        logger.info("Security middleware initialized")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through security middleware"""
        
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # IP whitelist check
        if self.allowed_ips and not self._is_ip_allowed(client_ip):
            logger.warning(f"Access denied for IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied from this IP address"
            )
        
        # HTTPS requirement check
        if self.require_https and request.url.scheme != "https":
            logger.warning(f"HTTPS required for request from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="HTTPS is required"
            )
        
        # Rate limiting check
        if not self._check_rate_limit(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        # Process request
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Process-Time"] = str(process_time)
        
        # Add CORS headers if configured
        if self.cors_origins:
            origin = request.headers.get("origin")
            if origin in self.cors_origins or "*" in self.cors_origins:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request"""
        # Check X-Forwarded-For header first (for load balancers/proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to direct client IP
        return request.client.host if request.client else "unknown"
    
    def _is_ip_allowed(self, client_ip: str) -> bool:
        """Check if client IP is in allowed list"""
        try:
            client_addr = ipaddress.ip_address(client_ip)
            
            for allowed_ip in self.allowed_ips:
                try:
                    # Handle CIDR notation
                    if "/" in allowed_ip:
                        allowed_network = ipaddress.ip_network(allowed_ip, strict=False)
                        if client_addr in allowed_network:
                            return True
                    else:
                        # Handle single IP
                        allowed_addr = ipaddress.ip_address(allowed_ip)
                        if client_addr == allowed_addr:
                            return True
                except ValueError:
                    logger.warning(f"Invalid IP address in allowed list: {allowed_ip}")
                    continue
            
            return False
            
        except ValueError:
            logger.warning(f"Invalid client IP address: {client_ip}")
            return False
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check rate limit for client IP"""
        current_time = time.time()
        
        # Clean old entries
        self._cleanup_rate_limit_storage(current_time)
        
        # Get or create client entry
        if client_ip not in self.rate_limit_storage:
            self.rate_limit_storage[client_ip] = []
        
        client_requests = self.rate_limit_storage[client_ip]
        
        # Remove old requests outside the window
        window_start = current_time - self.rate_limit_window
        client_requests[:] = [req_time for req_time in client_requests if req_time > window_start]
        
        # Check if limit exceeded
        if len(client_requests) >= self.rate_limit_requests:
            return False
        
        # Add current request
        client_requests.append(current_time)
        return True
    
    def _cleanup_rate_limit_storage(self, current_time: float):
        """Clean up old rate limit entries"""
        # Only clean every 60 seconds to avoid overhead
        if not hasattr(self, '_last_cleanup') or current_time - self._last_cleanup > 60:
            window_start = current_time - self.rate_limit_window
            
            for client_ip in list(self.rate_limit_storage.keys()):
                client_requests = self.rate_limit_storage[client_ip]
                client_requests[:] = [req_time for req_time in client_requests if req_time > window_start]
                
                # Remove empty entries
                if not client_requests:
                    del self.rate_limit_storage[client_ip]
            
            self._last_cleanup = current_time

class CACAuthMiddleware(BaseHTTPMiddleware):
    """
    CAC/PIV authentication middleware
    """
    
    def __init__(self, app, 
                 exempt_paths: List[str] = None,
                 require_valid_session: bool = True):
        """
        Initialize CAC authentication middleware
        
        Args:
            app: FastAPI application
            exempt_paths: Paths that don't require authentication
            require_valid_session: Whether to validate session tokens
        """
        super().__init__(app)
        self.exempt_paths = exempt_paths or ["/health", "/docs", "/openapi.json", "/api/v1/auth/challenge"]
        self.require_valid_session = require_valid_session
        
        logger.info("CAC authentication middleware initialized")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through authentication middleware"""
        
        # Check if path is exempt from authentication
        if self._is_path_exempt(request.url.path):
            return await call_next(request)
        
        # For authentication endpoints, don't require existing session
        if request.url.path.startswith("/api/v1/auth/") and request.method == "POST":
            return await call_next(request)
        
        # Validate session token for other endpoints
        if self.require_valid_session:
            session_token = self._extract_session_token(request)
            if not session_token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session token required"
                )
            
            # Add session token to request state for use in endpoints
            request.state.session_token = session_token
        
        return await call_next(request)
    
    def _is_path_exempt(self, path: str) -> bool:
        """Check if path is exempt from authentication"""
        for exempt_path in self.exempt_paths:
            if path.startswith(exempt_path):
                return True
        return False
    
    def _extract_session_token(self, request: Request) -> Optional[str]:
        """Extract session token from request"""
        # Check Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header[7:]  # Remove "Bearer " prefix
        
        # Check custom headers
        session_token = request.headers.get("X-Session-Token")
        if session_token:
            return session_token
        
        # Check query parameters (less secure, but sometimes needed)
        session_token = request.query_params.get("session_token")
        if session_token:
            return session_token
        
        return None

class AuditMiddleware(BaseHTTPMiddleware):
    """
    Audit logging middleware
    """
    
    def __init__(self, app, audit_logger_instance=None):
        """
        Initialize audit middleware
        
        Args:
            app: FastAPI application
            audit_logger_instance: Audit logger instance
        """
        super().__init__(app)
        self.audit_logger = audit_logger_instance
        logger.info("Audit middleware initialized")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through audit middleware"""
        
        start_time = time.time()
        
        # Extract request information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "")
        method = request.method
        path = request.url.path
        
        # Get user ID from session if available
        user_id = getattr(request.state, 'user_id', None)
        session_token = getattr(request.state, 'session_token', None)
        
        response = None
        error = None
        
        try:
            response = await call_next(request)
            
            # Log successful request if audit logger is available
            if self.audit_logger and self._should_audit(path, method):
                self.audit_logger.log_api_request(
                    method=method,
                    path=path,
                    user_id=user_id,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    status_code=response.status_code,
                    response_time=time.time() - start_time,
                    success=response.status_code < 400
                )
            
            return response
            
        except Exception as e:
            error = str(e)
            
            # Log failed request
            if self.audit_logger and self._should_audit(path, method):
                self.audit_logger.log_api_request(
                    method=method,
                    path=path,
                    user_id=user_id,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    status_code=500,
                    response_time=time.time() - start_time,
                    success=False,
                    error_message=error
                )
            
            raise
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _should_audit(self, path: str, method: str) -> bool:
        """Determine if request should be audited"""
        # Skip health checks and static content
        skip_paths = ["/health", "/metrics", "/favicon.ico"]
        
        for skip_path in skip_paths:
            if path.startswith(skip_path):
                return False
        
        # Audit all authentication-related requests
        if path.startswith("/api/v1/auth/"):
            return True
        
        # Audit all POST, PUT, DELETE requests
        if method in ["POST", "PUT", "DELETE"]:
            return True
        
        # Audit sensitive GET requests
        sensitive_paths = ["/api/v1/user/", "/api/v1/admin/", "/api/v1/audit/"]
        for sensitive_path in sensitive_paths:
            if path.startswith(sensitive_path):
                return True
        
        return False

class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Request validation middleware
    """
    
    def __init__(self, app, 
                 max_request_size: int = 10 * 1024 * 1024,  # 10MB
                 allowed_content_types: List[str] = None):
        """
        Initialize request validation middleware
        
        Args:
            app: FastAPI application
            max_request_size: Maximum request size in bytes
            allowed_content_types: Allowed content types
        """
        super().__init__(app)
        self.max_request_size = max_request_size
        self.allowed_content_types = allowed_content_types or [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data"
        ]
        
        logger.info("Request validation middleware initialized")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through validation middleware"""
        
        # Check request size
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > self.max_request_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Request size exceeds maximum allowed size of {self.max_request_size} bytes"
            )
        
        # Check content type for requests with body
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("Content-Type", "").split(";")[0]
            if content_type and content_type not in self.allowed_content_types:
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail=f"Unsupported content type: {content_type}"
                )
        
        return await call_next(request)