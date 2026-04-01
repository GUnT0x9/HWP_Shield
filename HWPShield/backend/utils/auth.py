"""
Enhanced security and authentication module for HWPShield.
Provides API key management, JWT authentication, and request signing.
"""
import os
import hmac
import hashlib
import secrets
import time
from typing import Optional, Dict, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from functools import wraps

import jwt
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


security_bearer = HTTPBearer()


@dataclass
class APIKey:
    """API key information."""
    key_id: str
    key_hash: str
    name: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    rate_limit: int = 100  # requests per hour
    allowed_ips: Set[str] = field(default_factory=set)
    permissions: Set[str] = field(default_factory=lambda: {"analyze", "health"})
    last_used: Optional[datetime] = None
    request_count: int = 0
    is_active: bool = True


class APIKeyManager:
    """Manages API keys for service authentication."""
    
    def __init__(self):
        self._keys: Dict[str, APIKey] = {}
        self._key_prefix = "hwps_"
        self._load_from_env()
    
    def _load_from_env(self):
        """Load API keys from environment variables."""
        # Format: HWPSHIELD_API_KEY_<NAME>=<KEY>
        for key, value in os.environ.items():
            if key.startswith("HWPSHIELD_API_KEY_"):
                name = key.replace("HWPSHIELD_API_KEY_", "").lower()
                self.create_key(name, value)
    
    def create_key(self, name: str, key: Optional[str] = None, 
                   expires_days: Optional[int] = None,
                   rate_limit: int = 100) -> tuple[str, str]:
        """
        Create a new API key.
        
        Returns:
            Tuple of (key_id, full_key)
        """
        key_id = secrets.token_urlsafe(12)
        if key is None:
            key = secrets.token_urlsafe(32)
        
        full_key = f"{self._key_prefix}{key_id}.{key}"
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            rate_limit=rate_limit
        )
        
        self._keys[key_id] = api_key
        return key_id, full_key
    
    def validate_key(self, key: str, client_ip: str) -> Optional[APIKey]:
        """Validate an API key and return its info if valid."""
        # Check format
        if not key.startswith(self._key_prefix):
            return None
        
        parts = key.replace(self._key_prefix, "").split(".")
        if len(parts) != 2:
            return None
        
        key_id = parts[0]
        api_key = self._keys.get(key_id)
        
        if not api_key:
            return None
        
        # Check if active
        if not api_key.is_active:
            return None
        
        # Check expiration
        if api_key.expires_at and datetime.utcnow() > api_key.expires_at:
            return None
        
        # Verify hash
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        if not hmac.compare_digest(key_hash, api_key.key_hash):
            return None
        
        # Check IP whitelist (if configured)
        if api_key.allowed_ips and client_ip not in api_key.allowed_ips:
            return None
        
        # Update usage
        api_key.last_used = datetime.utcnow()
        api_key.request_count += 1
        
        return api_key
    
    def revoke_key(self, key_id: str) -> bool:
        """Revoke an API key."""
        if key_id in self._keys:
            self._keys[key_id].is_active = False
            return True
        return False
    
    def get_key_info(self, key_id: str) -> Optional[Dict]:
        """Get non-sensitive key information."""
        key = self._keys.get(key_id)
        if not key:
            return None
        
        return {
            "key_id": key.key_id,
            "name": key.name,
            "created_at": key.created_at.isoformat(),
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
            "last_used": key.last_used.isoformat() if key.last_used else None,
            "request_count": key.request_count,
            "is_active": key.is_active,
            "rate_limit": key.rate_limit
        }


class JWTAuthManager:
    """JWT token manager for user authentication."""
    
    def __init__(self):
        self.secret_key = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
        self.algorithm = "HS256"
        self.access_token_expire = timedelta(minutes=30)
        self.refresh_token_expire = timedelta(days=7)
    
    def create_access_token(self, user_id: str, permissions: list = None) -> str:
        """Create a new access token."""
        expire = datetime.utcnow() + self.access_token_expire
        
        payload = {
            "sub": user_id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access",
            "permissions": permissions or ["analyze"]
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create a new refresh token."""
        expire = datetime.utcnow() + self.refresh_token_expire
        
        payload = {
            "sub": user_id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict]:
        """Verify and decode a token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check token type
            if payload.get("type") != token_type:
                return None
            
            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.utcnow().timestamp() > exp:
                return None
            
            return payload
            
        except jwt.InvalidTokenError:
            return None


class RequestSigner:
    """Request signing for integrity verification."""
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or os.getenv("REQUEST_SIGNING_KEY", secrets.token_urlsafe(32))
    
    def sign_request(self, method: str, path: str, timestamp: int, 
                     body_hash: Optional[str] = None) -> str:
        """Sign a request with HMAC-SHA256."""
        message = f"{method}:{path}:{timestamp}"
        if body_hash:
            message += f":{body_hash}"
        
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_signature(self, signature: str, method: str, path: str, 
                         timestamp: int, body_hash: Optional[str] = None,
                         max_age: int = 300) -> bool:
        """Verify request signature and timestamp."""
        # Check timestamp (prevent replay attacks)
        current_time = int(time.time())
        if abs(current_time - timestamp) > max_age:
            return False
        
        expected = self.sign_request(method, path, timestamp, body_hash)
        return hmac.compare_digest(signature, expected)


# Global instances
api_key_manager = APIKeyManager()
jwt_auth_manager = JWTAuthManager()
request_signer = RequestSigner()


async def verify_api_key(request: Request) -> APIKey:
    """Dependency to verify API key from request."""
    # Get API key from header
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail={"code": "MISSING_API_KEY", "message": "API key is required"}
        )
    
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    
    # Validate key
    key_info = api_key_manager.validate_key(api_key, client_ip)
    if not key_info:
        raise HTTPException(
            status_code=401,
            detail={"code": "INVALID_API_KEY", "message": "Invalid or expired API key"}
        )
    
    return key_info


async def verify_jwt_token(
    credentials: HTTPAuthorizationCredentials = Depends(security_bearer)
) -> Dict:
    """Dependency to verify JWT token."""
    token = credentials.credentials
    payload = jwt_auth_manager.verify_token(token, token_type="access")
    
    if not payload:
        raise HTTPException(
            status_code=401,
            detail={"code": "INVALID_TOKEN", "message": "Invalid or expired token"}
        )
    
    return payload
