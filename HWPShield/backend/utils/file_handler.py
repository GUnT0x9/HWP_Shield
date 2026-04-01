"""
Secure file handling utilities.
Handles temporary file storage and cleanup for security.
"""
import os
import re
import tempfile
import uuid
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SecureFileHandler:
    """Secure file handler for temporary file operations."""
    
    ALLOWED_EXTENSIONS = {'.hwp', '.hwpx'}
    OLE_MAGIC = b'\xd0\xcf\x11\xe0'
    MAX_SIZE = 50 * 1024 * 1024  # 50MB
    
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="hwpshield_")
    
    def validate_file(self, filename: str, content: bytes) -> tuple[bool, Optional[str]]:
        """
        Validate uploaded file.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check extension
        ext = Path(filename).suffix.lower()
        if ext not in self.ALLOWED_EXTENSIONS:
            return False, f"Unsupported file extension: {ext}"
        
        # Check size
        if len(content) > self.MAX_SIZE:
            return False, f"File size exceeds limit: {len(content)} bytes"
        
        # Check magic bytes
        if not content.startswith(self.OLE_MAGIC):
            return False, "Invalid HWP file: OLE magic bytes mismatch"
        
        return True, None
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for security."""
        # Get basename only
        safe = os.path.basename(filename)
        
        # Remove dangerous characters
        safe = re.sub(r'[^a-zA-Z0-9._-]', '_', safe)
        
        # Limit length
        if len(safe) > 255:
            name, ext = os.path.splitext(safe)
            safe = name[:250] + ext
        
        return safe
    
    def save_temporarily(self, content: bytes, original_name: str) -> str:
        """Save file to temporary location."""
        safe_name = self.sanitize_filename(original_name)
        unique_name = f"{uuid.uuid4()}_{safe_name}"
        temp_path = os.path.join(self.temp_dir, unique_name)
        
        with open(temp_path, 'wb') as f:
            f.write(content)
        
        # Restrict permissions (owner only)
        os.chmod(temp_path, 0o600)
        
        return temp_path
    
    def cleanup(self, file_path: str) -> None:
        """Safely delete temporary file."""
        if not file_path or not os.path.exists(file_path):
            return
        
        # Verify file is in temp directory
        if not file_path.startswith(self.temp_dir):
            logger.error(f"Attempted to delete file outside temp directory: {file_path}")
            return
        
        try:
            os.unlink(file_path)
        except Exception as e:
            logger.error(f"Failed to delete file {file_path}: {e}")
    
    def cleanup_all(self) -> None:
        """Clean up entire temp directory."""
        if os.path.exists(self.temp_dir):
            for filename in os.listdir(self.temp_dir):
                file_path = os.path.join(self.temp_dir, filename)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                except Exception as e:
                    logger.error(f"Failed to delete {file_path}: {e}")
            
            try:
                os.rmdir(self.temp_dir)
            except Exception as e:
                logger.error(f"Failed to remove temp directory: {e}")
