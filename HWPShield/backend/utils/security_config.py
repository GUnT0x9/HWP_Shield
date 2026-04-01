"""
Security Configuration Module
Handles authentication, WAF rules, and security patch management.
"""
import os
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from functools import wraps
from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")  # bcrypt hash

# WAF Rules
WAF_RULES = {
    "sql_injection": [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"UNION\s+SELECT",
        r"INSERT\s+INTO",
        r"DELETE\s+FROM",
    ],
    "xss": [
        r"((\%3C)|<)[^\n]+((\%3E)|>)",
        r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)",
        r"((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)",
        r"<script[^>]*>[\\s\\S]*?</script>",
        r"javascript:",
        r"on\w+\s*=",
    ],
    "path_traversal": [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%252e%252e%252f",
        r"%c0%ae%c0%ae%c0%af",
    ],
    "command_injection": [
        r"[;&|`]\s*[a-zA-Z]+",
        r"\$\(.*\)",
        r"`.*`",
        r"\|\s*[a-zA-Z]+",
    ],
}


class WAFMiddleware:
    """Web Application Firewall middleware."""
    
    def __init__(self):
        self.blocked_ips: set = set()
        self.suspicious_count: Dict[str, int] = {}
        self.block_threshold = 10  # Block after 10 suspicious requests
    
    def check_request(self, request: Request) -> tuple[bool, Optional[str]]:
        """
        Check request against WAF rules.
        
        Returns:
            (is_safe, reason) - is_safe is False if blocked
        """
        client_ip = request.client.host
        
        # Check if IP is already blocked
        if client_ip in self.blocked_ips:
            return False, "IP blocked due to suspicious activity"
        
        # Check query parameters
        query_string = str(request.query_params)
        for category, patterns in WAF_RULES.items():
            for pattern in patterns:
                import re
                if re.search(pattern, query_string, re.IGNORECASE):
                    self._record_suspicious(client_ip, category)
                    return False, f"WAF blocked: {category} pattern detected"
        
        # Check headers for suspicious content
        for header_name, header_value in request.headers.items():
            header_str = f"{header_name}: {header_value}"
            for category, patterns in WAF_RULES.items():
                for pattern in patterns:
                    import re
                    if re.search(pattern, header_str, re.IGNORECASE):
                        self._record_suspicious(client_ip, category)
                        return False, f"WAF blocked: {category} in headers"
        
        return True, None
    
    def _record_suspicious(self, ip: str, reason: str):
        """Record suspicious activity from IP."""
        if ip not in self.suspicious_count:
            self.suspicious_count[ip] = 0
        self.suspicious_count[ip] += 1
        
        if self.suspicious_count[ip] >= self.block_threshold:
            self.blocked_ips.add(ip)


# JWT Token handling
security = HTTPBearer()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify JWT token."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_admin(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Require admin authentication."""
    payload = verify_token(credentials)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload


def admin_login(username: str, password: str) -> Optional[str]:
    """
    Admin login with username/password.
    Returns JWT token if successful.
    """
    # In production, use bcrypt to verify password
    # This is a simplified version for demonstration
    if username == ADMIN_USERNAME:
        # Check password hash
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if ADMIN_PASSWORD_HASH and hmac.compare_digest(password_hash, ADMIN_PASSWORD_HASH):
            token = create_access_token(
                {"sub": username, "role": "admin"},
                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            return token
    return None


class SecurityPatchManager:
    """Manage security patches and updates."""
    
    def __init__(self):
        self.patches: List[Dict] = []
        self.last_check: Optional[datetime] = None
    
    def check_patches(self) -> Dict:
        """Check for available security patches."""
        import subprocess
        
        patches = {
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "os_patches": [],
            "python_packages": [],
            "docker_updates": [],
            "recommendations": []
        }
        
        # Check Python package updates
        try:
            result = subprocess.run(
                ["pip", "list", "--outdated", "--format=json"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                import json
                outdated = json.loads(result.stdout)
                security_packages = [
                    "fastapi", "uvicorn", "pydantic", "cryptography",
                    "requests", "urllib3", "certifi"
                ]
                for pkg in outdated:
                    if pkg["name"].lower() in security_packages:
                        patches["python_packages"].append({
                            "package": pkg["name"],
                            "current": pkg["version"],
                            "latest": pkg["latest_version"]
                        })
        except Exception as e:
            patches["recommendations"].append(f"Failed to check Python packages: {e}")
        
        # Check for critical vulnerabilities
        if patches["python_packages"]:
            patches["recommendations"].append(
                "Critical security packages have updates available. Run 'pip install -U' to update."
            )
        
        self.last_check = datetime.utcnow()
        return patches
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get recommended security headers."""
        return {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        }


# Initialize WAF
waf = WAFMiddleware()


def apply_security_headers(response):
    """Apply security headers to response."""
    patch_manager = SecurityPatchManager()
    headers = patch_manager.get_security_headers()
    for header, value in headers.items():
        response.headers[header] = value
    return response
