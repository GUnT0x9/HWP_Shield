"""
Enhanced Input Validation and Security Module
Implements comprehensive input validation and security checks
"""
import os
import re
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path

# Make python-magic optional
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    magic = None

class SecureInputValidator:
    """Enhanced input validator for HWPShield"""
    
    # Security configuration
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    MAX_STREAM_SIZE = 10 * 1024 * 1024  # 10MB per stream
    MAX_FILENAME_LENGTH = 255
    ALLOWED_EXTENSIONS = {'.hwp', '.hwpx'}
    ALLOWED_MIME_TYPES = {
        'application/x-hwp',
        'application/haansofthwp',
        'application/octet-stream',
        'application/zip'  # For HWPX
    }
    
    # Dangerous patterns
    DANGEROUS_PATTERNS = [
        rb'<script',        # Script injection
        rb'javascript:',    # JS injection
        rb'eval\s*\(',      # Code execution
        rb'exec\s*\(',      # Code execution
        rb'system\s*\(',    # System command
    ]
    
    # Suspicious content patterns
    SUSPICIOUS_PATTERNS = [
        rb'%TEMP%',         # Temp path execution
        rb'temp\\',         # Windows temp path
        rb'cmd\.exe',       # Command execution
        rb'powershell',     # PowerShell
        rb'wscript',        # Windows Script Host
        rb'cscript',        # Windows Script Host
        rb'ShellExecute',   # Shell API
        rb'URLDownloadToFile', # URL download
    ]
    
    def __init__(self):
        self.magic = None
        if HAS_MAGIC and magic:
            try:
                self.magic = magic.Magic(mime=True)
            except Exception:
                pass
    
    def validate_file(self, file_data: bytes, filename: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Comprehensive file validation
        
        Returns:
            (is_valid, error_message, metadata)
        """
        
        metadata = {
            'size': len(file_data),
            'hash': self._calculate_hashes(file_data),
            'filename': filename,
            'extension': os.path.splitext(filename)[1].lower(),
            'entropy': self._calculate_entropy(file_data)
        }
        
        # 1. Size validation
        if not self._validate_size(file_data):
            return False, f"File too large: {metadata['size']} bytes (max: {self.MAX_FILE_SIZE})", metadata
        
        # 2. Filename validation
        if not self._validate_filename(filename):
            return False, f"Invalid filename: {filename}", metadata
        
        # 3. Extension validation
        if not self._validate_extension(filename):
            return False, f"Invalid file extension: {metadata['extension']}", metadata
        
        # 4. Content validation
        content_result = self._validate_content(file_data)
        if not content_result['is_safe']:
            return False, content_result.get('reason', 'Dangerous content detected'), metadata
        
        # 5. Magic bytes validation
        magic_result = self._validate_magic_bytes(file_data, metadata['extension'])
        if not magic_result['is_valid']:
            return False, magic_result.get('error', 'Invalid magic bytes'), metadata
        
        # 6. Entropy analysis
        entropy_result = self._analyze_entropy(file_data, metadata['entropy'])
        metadata['entropy_analysis'] = entropy_result
        
        return True, None, metadata
    
    def _calculate_hashes(self, data: bytes) -> Dict[str, str]:
        """Calculate multiple file hashes"""
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        import math
        
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate Shannon entropy: -sum(p * log2(p))
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _validate_size(self, data: bytes) -> bool:
        """Validate file size"""
        return len(data) <= self.MAX_FILE_SIZE
    
    def _validate_filename(self, filename: str) -> bool:
        """Validate filename"""
        # Check length
        if len(filename) > self.MAX_FILENAME_LENGTH:
            return False
        
        # Check for dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
        if any(char in filename for char in dangerous_chars):
            return False
        
        # Check for path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False
        
        return True
    
    def _validate_extension(self, filename: str) -> bool:
        """Validate file extension"""
        extension = os.path.splitext(filename)[1].lower()
        return extension in self.ALLOWED_EXTENSIONS
    
    def _validate_content(self, data: bytes) -> Dict[str, Any]:
        """Validate content for dangerous patterns"""
        result = {'is_safe': True, 'error': None, 'patterns_found': []}
        
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            matches = list(re.finditer(pattern, data, re.IGNORECASE))
            if matches:
                result['is_safe'] = False
                result['error'] = f"Dangerous content detected: {pattern.decode('utf-8', errors='ignore')}"
                result['patterns_found'].extend([m.start() for m in matches])
                break
        
        # Check for suspicious patterns (warning only)
        if result['is_safe']:
            for pattern in self.SUSPICIOUS_PATTERNS:
                matches = list(re.finditer(pattern, data, re.IGNORECASE))
                if matches:
                    result['patterns_found'].extend([m.start() for m in matches])
        
        return result
    
    def _validate_magic_bytes(self, data: bytes, extension: str) -> Dict[str, Any]:
        """Validate magic bytes match file type"""
        result = {'is_valid': True, 'error': None, 'detected_type': 'unknown'}
        
        if len(data) < 8:
            return result
        
        # Check magic bytes
        magic_bytes = data[:8]
        
        if extension == '.hwp':
            # HWP should have OLE magic bytes
            if magic_bytes[:8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                result['is_valid'] = False
                result['error'] = f"Invalid HWP magic bytes: {magic_bytes.hex()}"
            else:
                result['detected_type'] = 'HWP (OLE)'
        
        elif extension == '.hwpx':
            # HWPX should have ZIP magic bytes
            if magic_bytes[:4] != b'PK\x03\x04':
                result['is_valid'] = False
                result['error'] = f"Invalid HWPX magic bytes: {magic_bytes.hex()}"
            else:
                result['detected_type'] = 'HWPX (ZIP)'
        
        return result
    
    def _analyze_entropy(self, data: bytes, entropy: float) -> Dict[str, Any]:
        """Analyze file entropy for obfuscation detection"""
        analysis = {
            'entropy': entropy,
            'is_encrypted': False,
            'is_compressed': False,
            'is_suspicious': False
        }
        
        # High entropy indicates encryption or compression
        if entropy > 7.5:
            analysis['is_encrypted'] = True
            analysis['is_suspicious'] = True
        elif entropy > 6.5:
            analysis['is_compressed'] = True
        
        # Low entropy with suspicious patterns is also concerning
        if entropy < 4.0 and len(data) > 1024:
            # Check for repeated patterns
            chunk_size = 1024
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            unique_chunks = len(set(chunks))
            
            if unique_chunks < len(chunks) * 0.5:  # Less than 50% unique
                analysis['is_suspicious'] = True
        
        return analysis
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage"""
        # Get base name without path
        safe_name = os.path.basename(filename)
        
        # Replace dangerous characters
        replacements = {
            '<': '_', '>': '_', ':': '_', '"': '_',
            '|': '_', '?': '_', '*': '_', '/': '_',
            '\\': '_', ' ': '_'
        }
        
        for old, new in replacements.items():
            safe_name = safe_name.replace(old, new)
        
        # Limit length
        if len(safe_name) > self.MAX_FILENAME_LENGTH:
            name, ext = os.path.splitext(safe_name)
            safe_name = name[:self.MAX_FILENAME_LENGTH - len(ext)] + ext
        
        return safe_name
    
    def validate_stream_data(self, stream_name: str, stream_data: bytes) -> Dict[str, Any]:
        """Validate individual stream data"""
        result = {
            'is_valid': True,
            'is_suspicious': False,
            'warnings': [],
            'size': len(stream_data)
        }
        
        # Size validation
        if len(stream_data) > self.MAX_STREAM_SIZE:
            result['is_valid'] = False
            result['warnings'].append(f"Stream too large: {len(stream_data)} bytes")
        
        # Content validation
        content_result = self._validate_content(stream_data)
        if not content_result['is_safe']:
            result['is_valid'] = False
            result['warnings'].append("Dangerous content detected")
        elif content_result['patterns_found']:
            result['is_suspicious'] = True
            result['warnings'].append(f"Suspicious patterns: {len(content_result['patterns_found'])}")
        
        # Entropy analysis
        if len(stream_data) > 512:  # Only analyze meaningful streams
            entropy = self._calculate_entropy(stream_data)
            if entropy > 7.0:
                result['is_suspicious'] = True
                result['warnings'].append(f"High entropy: {entropy:.2f}")
        
        return result

class SecurityLogger:
    """Security event logger"""
    
    def __init__(self, log_file: str = 'security_events.log'):
        self.log_file = log_file
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security event"""
        import json
        from datetime import datetime
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details
        }
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception:
            pass  # Silent fail for logging
    
    def log_validation_failure(self, filename: str, error: str, metadata: Dict[str, Any]):
        """Log validation failure"""
        self.log_security_event('VALIDATION_FAILURE', {
            'filename': filename,
            'error': error,
            'file_size': metadata.get('size', 0),
            'file_hash': metadata.get('hash', {}),
            'extension': metadata.get('extension', '')
        })
    
    def log_suspicious_content(self, filename: str, patterns: List[int], metadata: Dict[str, Any]):
        """Log suspicious content detection"""
        self.log_security_event('SUSPICIOUS_CONTENT', {
            'filename': filename,
            'pattern_positions': patterns,
            'file_size': metadata.get('size', 0),
            'entropy': metadata.get('entropy', 0)
        })

# Global instances
validator = SecureInputValidator()
security_logger = SecurityLogger()
