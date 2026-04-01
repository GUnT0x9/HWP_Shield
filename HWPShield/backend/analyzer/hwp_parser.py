"""
HWP file parser - OLE2 format handling and stream extraction.
"""
import io
import re
import struct
import zlib
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

try:
    import olefile
except ImportError:
    olefile = None
    logging.warning("olefile module not installed. HWP parsing will fail.")


@dataclass
class HWPHeader:
    """HWP FileHeader structure."""
    signature: str
    version: str
    flags: int
    is_encrypted: bool
    has_script: bool
    is_distribution: bool
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "HWPHeader":
        """Parse FileHeader stream."""
        if len(data) < 36:
            raise ValueError("FileHeader too short")
        
        # Signature: "HWP Document File" + null padding
        signature = data[:20].decode('utf-8', errors='ignore').rstrip('\x00')
        
        # Version (4 bytes, little-endian)
        version_int = struct.unpack('<I', data[20:24])[0]
        major = (version_int >> 24) & 0xFF
        minor = (version_int >> 16) & 0xFF
        build = version_int & 0xFFFF
        version = f"{major}.{minor}.{build}"
        
        # Flags (4 bytes)
        flags = struct.unpack('<I', data[24:28])[0]
        is_encrypted = bool(flags & 0x01)
        is_distribution = bool(flags & 0x02)
        has_script = bool(flags & 0x04)
        
        return cls(
            signature=signature,
            version=version,
            flags=flags,
            is_encrypted=is_encrypted,
            has_script=has_script,
            is_distribution=is_distribution
        )


class HWPParser:
    """Parser for HWP (Hangul Word Processor) files."""
    
    OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    
    def __init__(self):
        self.streams: Dict[str, bytes] = {}
        self.header: Optional[HWPHeader] = None
        self.extracted_strings: List[str] = []
    
    def parse(self, file_path: str) -> Dict[str, Any]:
        """
        Parse HWP file and extract all streams.
        
        Returns:
            Dictionary containing parsed data
        """
        if olefile is None:
            raise ImportError("olefile module is not installed. Run: pip install olefile")
        
        self.streams = {}
        self.extracted_strings = []
        
        # Open OLE file
        ole = olefile.OleFileIO(file_path)
        
        try:
            # Enumerate all streams
            for stream_name in ole.listdir():
                full_name = '/'.join(stream_name)
                
                # Read stream data
                try:
                    stream_data = ole.openstream(stream_name).read()
                    
                    # Decompress if needed (except FileHeader)
                    if full_name == 'FileHeader':
                        decompressed = stream_data
                    else:
                        decompressed = self._decompress(stream_data)
                    
                    self.streams[full_name] = decompressed
                    
                except Exception as e:
                    # Store raw data if decompression fails
                    self.streams[full_name] = stream_data
            
            # Parse FileHeader
            if 'FileHeader' in self.streams:
                self.header = HWPHeader.from_bytes(self.streams['FileHeader'])
            
            # Extract all strings for IOC analysis
            self._extract_strings()
            
            # Extract BinData items
            bindata = self._extract_bindata()
            
            # Extract Scripts
            scripts = self._extract_scripts()
            
        finally:
            ole.close()
        
        return {
            'header': {
                'signature': self.header.signature if self.header else None,
                'version': self.header.version if self.header else None,
                'is_encrypted': self.header.is_encrypted if self.header else None,
                'has_script': self.header.has_script if self.header else None,
            },
            'streams': list(self.streams.keys()),
            'bindata': bindata,
            'scripts': scripts,
            'strings': self.extracted_strings[:100],  # Limit to 100 strings
            'all_streams': self.streams,
        }
    
    def _decompress(self, data: bytes) -> bytes:
        """
        Decompress zlib-compressed stream.
        HWP uses raw deflate (wbits=-15).
        """
        try:
            decompressor = zlib.decompressobj(wbits=-15)
            return decompressor.decompress(data)
        except zlib.error:
            # Try with default wbits
            try:
                return zlib.decompress(data)
            except zlib.error:
                # Return raw data if both fail
                return data
    
    def _extract_strings(self) -> None:
        """Extract printable strings from all streams."""
        all_data = b''.join(self.streams.values())
        
        # Find printable strings (4+ chars)
        pattern = rb'[\x20-\x7E]{4,}'
        matches = re.findall(pattern, all_data)
        
        # Decode and filter
        for match in matches:
            try:
                decoded = match.decode('ascii', errors='ignore')
                if len(decoded) >= 4:
                    self.extracted_strings.append(decoded)
            except:
                pass
        
        # Also try UTF-16LE (Korean text)
        try:
            utf16_pattern = rb'(?:[\x00-\x7F][\x00]){4,}'
            utf16_matches = re.findall(utf16_pattern, all_data)
            for match in utf16_matches:
                try:
                    decoded = match.decode('utf-16le', errors='ignore')
                    if len(decoded) >= 4 and decoded not in self.extracted_strings:
                        self.extracted_strings.append(decoded)
                except:
                    pass
        except:
            pass
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for s in self.extracted_strings:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        self.extracted_strings = unique
    
    def _extract_bindata(self) -> List[Tuple[str, bytes]]:
        """Extract BinData streams."""
        bindata = []
        
        for stream_name, data in self.streams.items():
            if stream_name.startswith('BinData/'):
                bindata.append((stream_name, data))
        
        return bindata
    
    def _extract_scripts(self) -> Dict[str, bytes]:
        """Extract Scripts streams."""
        scripts = {}
        
        for stream_name, data in self.streams.items():
            if stream_name.startswith('Scripts/'):
                scripts[stream_name] = data
        
        return scripts
    
    def get_body_text(self) -> bytes:
        """Get BodyText stream if available."""
        return self.streams.get('BodyText/Section0', b'')
    
    def get_doc_info(self) -> bytes:
        """Get DocInfo stream if available."""
        return self.streams.get('DocInfo', b'')
    
    def identify_bindata_type(self, data: bytes) -> Optional[str]:
        """
        Identify the type of BinData by magic bytes.
        
        Returns:
            Type string or None
        """
        if data.startswith(b'%!PS-Adobe') or data.startswith(b'%!PS'):
            return 'EPS'
        elif data.startswith(b'\xc5\xd0\xc3\xc6'):  # Binary EPS
            return 'EPS_BINARY'
        elif data.startswith(b'\xd0\xcf\x11\xe0'):  # OLE
            return 'OLE'
        elif data.startswith(b'\xff\xd8\xff'):  # JPEG
            return 'JPEG'
        elif data.startswith(b'\x89PNG'):  # PNG
            return 'PNG'
        elif data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
            return 'GIF'
        elif data.startswith(b'BM'):  # BMP
            return 'BMP'
        elif data.startswith(b'MZ'):  # Windows executable
            return 'PE'
        elif data.startswith(b'\x50\x4b\x03\x04'):  # ZIP (contains multiple files)
            return 'ZIP'
        else:
            return 'UNKNOWN'
