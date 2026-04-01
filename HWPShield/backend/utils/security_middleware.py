"""
Security Middleware for HWPShield
Implements rate limiting, input validation, and security headers
"""
import time
import hashlib
import json
from typing import Dict, Optional
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler

class RateLimiter:
    """IP-based rate limiter"""
    
    def __init__(self, max_requests_per_minute: int = 10, max_file_size_mb: int = 100):
        self.max_requests = max_requests_per_minute
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.requests = defaultdict(lambda: deque())
        
    def is_allowed(self, client_ip: str) -> tuple[bool, Optional[str]]:
        """Check if IP is allowed to make request"""
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Clean old requests
        request_times = self.requests[client_ip]
        while request_times and request_times[0] < minute_ago:
            request_times.popleft()
        
        # Check rate limit
        if len(request_times) >= self.max_requests:
            return False, f"Rate limit exceeded: {self.max_requests} requests per minute"
        
        # Add current request
        request_times.append(current_time)
        return True, None
    
    def check_file_size(self, file_size: int) -> tuple[bool, Optional[str]]:
        """Check if file size is allowed"""
        if file_size > self.max_file_size:
            return False, f"File too large: {file_size} bytes (max: {self.max_file_size})"
        return True, None

class SecurityValidator:
    """Input validation and security checks"""
    
    ALLOWED_MIME_TYPES = [
        'application/x-hwp',
        'application/haansofthwp', 
        'application/octet-stream',
        'application/zip'  # For HWPX
    ]
    
    ALLOWED_EXTENSIONS = ['.hwp', '.hwpx']
    # File content patterns that indicate actual malicious content (not binary artifacts)
    DANGEROUS_PATTERNS = [
        b'<script',  # Script injection in text
        b'javascript:',  # JS injection in text
        b'eval(',  # JavaScript eval
        b'ActiveXObject',  # ActiveX creation
        b'WScript.Shell',  # WScript shell
    ]
    
    # Path traversal patterns - only check in filenames, not binary content
    PATH_TRAVERSAL_PATTERNS = [b'../', b'..\\']
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        import re
        import os
        
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove dangerous characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext
        
        return filename
    
    @staticmethod
    def validate_mime_type(content_type: str) -> bool:
        """Validate MIME type"""
        return any(content_type.startswith(allowed) for allowed in [
            'application/x-hwp',
            'application/haansofthwp',
            'application/octet-stream',
            'application/zip',
            'multipart/form-data'
        ])
    
    @staticmethod
    def validate_file_extension(filename: str) -> bool:
        """Validate file extension"""
        filename = filename.lower()
        return any(filename.endswith(ext) for ext in ['.hwp', '.hwpx'])
    
    @staticmethod
    def scan_for_dangerous_content(data: bytes) -> tuple[bool, Optional[str]]:
        """Scan for dangerous content patterns"""
        for pattern in SecurityValidator.DANGEROUS_PATTERNS:
            if pattern in data.lower():
                return False, f"Dangerous content detected: {pattern.decode('utf-8', errors='ignore')}"
        return True, None

class SecureRequestHandler:
    """Security-enhanced request handler mixin"""
    
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.validator = SecurityValidator()
    
    def get_client_ip(self) -> str:
        """Extract client IP from request"""
        # Check for forwarded headers
        forwarded_for = self.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = self.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        
        # Fallback to client address
        return self.client_address[0]
    
    def validate_request(self, file_data: bytes, filename: str) -> tuple[bool, str, Optional[str]]:
        """Comprehensive request validation"""
        client_ip = self.get_client_ip()
        
        # Debug logging
        
        # Rate limiting
        allowed, rate_error = self.rate_limiter.is_allowed(client_ip)
        if not allowed:
            return False, "RATE_LIMIT", rate_error
        
        # File size check
        allowed, size_error = self.rate_limiter.check_file_size(len(file_data))
        if not allowed:
            return False, "FILE_TOO_LARGE", size_error
        
        # Filename sanitization
        safe_filename = self.validator.sanitize_filename(filename)
        
        # MIME type validation
        content_type = self.headers.get('Content-Type', '')
        if not self.validator.validate_mime_type(content_type):
            return False, "INVALID_MIME", f"Invalid MIME type: {content_type}"
        
        # Extension validation
        ext_valid = self.validator.validate_file_extension(safe_filename)
        if not ext_valid:
            return False, "INVALID_EXTENSION", f"Invalid file extension: {safe_filename}"
        
        # Content scanning
        allowed, content_error = self.validator.scan_for_dangerous_content(file_data)
        if not allowed:
            return False, "DANGEROUS_CONTENT", content_error
        
        return True, safe_filename, None
    
    def send_security_error(self, error_code: int, error_type: str, message: str):
        """Send security error response"""
        self.send_response(error_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()
        
        error_response = {
            "error": True,
            "error_type": error_type,
            "message": message,
            "timestamp": time.time()
        }
        
        self.wfile.write(json.dumps(error_response).encode())
    
    def add_security_headers(self):
        """Add security headers to response"""
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        self.send_header('Content-Security-Policy', "default-src 'self'")

# Security configuration
SECURITY_CONFIG = {
    'max_requests_per_minute': 10,
    'max_file_size_mb': 50,
    'enable_rate_limiting': True,
    'enable_content_scanning': True,
    'log_security_events': True
}
