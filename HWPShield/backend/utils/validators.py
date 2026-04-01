"""
Input validation utilities.
"""
import re
from typing import Optional


def validate_filename(filename: str) -> tuple[bool, Optional[str]]:
    """
    Validate filename for security issues.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check for null bytes
    if '\x00' in filename:
        return False, "Filename contains null bytes"
    
    # Check for path traversal
    if '..' in filename or '~' in filename:
        return False, "Filename contains path traversal characters"
    
    # Check for shell special characters
    dangerous_chars = ['$', '`', '|', ';', '&', '<', '>']
    for char in dangerous_chars:
        if char in filename:
            return False, f"Filename contains dangerous character: {char}"
    
    # Check filename pattern
    if not re.match(r'^[a-zA-Z0-9._-]+$', os.path.basename(filename)):
        return False, "Filename contains invalid characters"
    
    return True, None


def validate_file_size(size: int, max_size: int = 50 * 1024 * 1024) -> tuple[bool, Optional[str]]:
    """Validate file size."""
    if size > max_size:
        return False, f"File size {size} exceeds maximum {max_size}"
    return True, None


# Import os here to avoid circular import issues
import os
