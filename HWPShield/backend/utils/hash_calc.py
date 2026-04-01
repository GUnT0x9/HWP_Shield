"""
Hash calculation utilities for file integrity verification.
"""
import hashlib
from typing import Dict


def calculate_hashes(data: bytes) -> Dict[str, str]:
    """
    Calculate MD5 and SHA256 hashes of file content.
    
    Args:
        data: File content as bytes
        
    Returns:
        Dictionary with 'md5' and 'sha256' keys
    """
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def calculate_file_hashes(file_path: str) -> Dict[str, str]:
    """
    Calculate hashes of a file on disk.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with 'md5' and 'sha256' keys
    """
    with open(file_path, "rb") as f:
        data = f.read()
    return calculate_hashes(data)
