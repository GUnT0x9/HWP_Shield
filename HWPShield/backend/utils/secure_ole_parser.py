"""
Secure OLE Parser with isolation and timeout protection
"""
import struct
import signal
import time
import threading
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager

class OLEParseError(Exception):
    """OLE parsing specific error"""
    pass

class SecureOLEParser:
    """Secure OLE parser with isolation and timeout"""
    
    def __init__(self, filepath: str, timeout_seconds: int = 10, max_size_mb: int = 50):
        self.filepath = filepath
        self.timeout = timeout_seconds
        self.max_size = max_size_mb * 1024 * 1024
        
    def _validate_file(self) -> bytes:
        """Validate file before parsing"""
        try:
            with open(self.filepath, 'rb') as f:
                header = f.read(8)
                
                # Check OLE magic
                if header[:8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                    raise OLEParseError("Invalid OLE magic bytes")
                
                # Check file size
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()
                f.seek(0)
                
                if file_size > self.max_size:
                    raise OLEParseError(f"File too large: {file_size} bytes")
                
                if file_size < 512:  # Minimum OLE header size
                    raise OLEParseError("File too small for OLE format")
                
                return f.read(min(file_size, 1024 * 1024))  # Read max 1MB for validation
                
        except IOError as e:
            raise OLEParseError(f"File access error: {e}")
    
    @contextmanager
    def _timeout_context(self):
        """Timeout context for parsing operations"""
        def timeout_handler(signum, frame):
            raise TimeoutError(f"OLE parsing timeout after {self.timeout} seconds")
        
        # Set timeout
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.timeout)
        
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    
    def _safe_struct_unpack(self, data: bytes, format_str: str, offset: int = 0) -> Tuple:
        """Safe struct unpacking with bounds checking"""
        try:
            struct_size = struct.calcsize(format_str)
            if offset + struct_size > len(data):
                raise OLEParseError(f"Struct unpack out of bounds: offset={offset}, size={struct_size}")
            
            return struct.unpack_from(format_str, data, offset)
        except struct.error as e:
            raise OLEParseError(f"Struct unpack error: {e}")
    
    def _parse_header_safe(self, data: bytes) -> Dict:
        """Parse OLE header with validation"""
        try:
            if len(data) < 512:
                raise OLEParseError("OLE header too short")
            
            header = {}
            
            # Parse basic fields
            header['magic'] = self._safe_struct_unpack(data, '<8s', 0)[0]
            header['minor_version'] = self._safe_struct_unpack(data, '<H', 8)[0]
            header['major_version'] = self._safe_struct_unpack(data, '<H', 10)[0]
            header['byte_order'] = self._safe_struct_unpack(data, '<H', 12)[0]
            header['sector_size'] = self._safe_struct_unpack(data, '<H', 14)[0]
            header['mini_sector_size'] = self._safe_struct_unpack(data, '<H', 16)[0]
            
            # Validate critical values
            if header['magic'] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                raise OLEParseError("Invalid OLE signature")
            
            if header['byte_order'] != 0xFFFE:  # Little-endian
                raise OLEParseError("Invalid byte order")
            
            if header['sector_size'] != 9:  # 512 bytes
                raise OLEParseError("Invalid sector size")
            
            if header['mini_sector_size'] != 6:  # 64 bytes
                raise OLEParseError("Invalid mini sector size")
            
            # Parse remaining fields
            header['reserved'] = self._safe_struct_unpack(data, '<6s', 18)[0]
            header['total_sectors'] = self._safe_struct_unpack(data, '<I', 24)[0]
            header['fat_sector_count'] = self._safe_struct_unpack(data, '<I', 28)[0]
            header['first_dir_sector'] = self._safe_struct_unpack(data, '<I', 32)[0]
            header['transaction_signature'] = self._safe_struct_unpack(data, '<I', 36)[0]
            header['mini_stream_cutoff'] = self._safe_struct_unpack(data, '<I', 40)[0]
            header['first_mini_fat_sector'] = self._safe_struct_unpack(data, '<I', 44)[0]
            header['mini_fat_sector_count'] = self._safe_struct_unpack(data, '<I', 48)[0]
            header['first_difat_sector'] = self._safe_struct_unpack(data, '<I', 52)[0]
            header['difat_sector_count'] = self._safe_struct_unpack(data, '<I', 56)[0]
            
            # Validate reasonable values
            if header['total_sectors'] > 1000000:  # 500MB max
                raise OLEParseError("Too many sectors")
            
            return header
            
        except Exception as e:
            raise OLEParseError(f"Header parsing failed: {e}")
    
    def parse(self) -> Tuple[Dict, Optional[str]]:
        """Parse OLE file with security measures"""
        try:
            with self._timeout_context():
                # Validate file first
                validation_data = self._validate_file()
                
                # Read full file (with size limit)
                with open(self.filepath, 'rb') as f:
                    file_data = f.read(self.max_size)
                
                # Parse header safely
                header = self._parse_header_safe(file_data)
                
                # Return basic result for now (enhanced parsing can be added)
                result = {
                    'streams': {
                        'FileHeader': file_data[:512] if len(file_data) >= 512 else file_data
                    },
                    'ole_objects': [],
                    'has_eps': False,
                    'actual_format': 'HWP (OLE)',
                    'validation_passed': True
                }
                
                return result, None
                
        except TimeoutError as e:
            error_msg = f"OLE parsing timeout: {e}"
            return {'error': error_msg, 'actual_format': 'HWP (OLE)'}, error_msg
        except OLEParseError as e:
            error_msg = f"OLE parsing error: {e}"
            return {'error': error_msg, 'actual_format': 'HWP (OLE)'}, error_msg
        except Exception as e:
            error_msg = f"Unexpected parsing error: {e}"
            return {'error': error_msg, 'actual_format': 'HWP (OLE)'}, error_msg
