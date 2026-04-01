"""
Enhanced HWP/HWPX Scanner
Properly analyzes HWP (CFB/OLE) and HWPX (ZIP/XML) formats
detects EPS exploits, OLE objects, scripts, and classifies threats
"""
import os
import sys
import json
import struct
import zlib
import re
import hashlib
import zipfile
import io
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

# Import PE analyzer for accurate EXE detection
try:
    from utils.pe_analyzer import PEAnalyzer
except ImportError:
    # Fallback if utils not in path
    PEAnalyzer = None
from improved_analyzer import ImprovedThreatAnalyzer

# HWP File Header Structure
class HWPHeader:
    """HWP File Header Parser"""
    def __init__(self, data: bytes):
        self.signature = data[:32]
        self.version = struct.unpack('<I', data[32:36])[0] if len(data) >= 36 else 0
        self.flags = struct.unpack('<I', data[36:40])[0] if len(data) >= 40 else 0
        
    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & 0x01)
    
    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & 0x02)
    
    @property
    def is_distribution(self) -> bool:
        return bool(self.flags & 0x04)
    
    @property
    def version_string(self) -> str:
        major = (self.version >> 24) & 0xFF
        minor = (self.version >> 16) & 0xFF
        patch = (self.version >> 8) & 0xFF
        build = self.version & 0xFF
        return f"{major}.{minor}.{patch}.{build}"


class OLEParser:
    """Proper CFB/OLE format parser for HWP files"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.streams = {}
        self.header = None
        self.errors = []
        
    def parse(self) -> Tuple[Dict, Optional[str]]:
        """Parse OLE file and extract streams"""
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
            
            # Check OLE magic
            if not data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                return {}, "Not a valid OLE/CFB file"
            
            # Parse OLE header
            sector_size = 512
            mini_sector_size = 64
            
            # Read FAT sector count
            num_fat_sectors = struct.unpack('<I', data[44:48])[0]
            
            # Read first directory sector SID
            first_dir_sector = struct.unpack('<I', data[48:52])[0]
            
            # Read mini stream cutoff size
            mini_stream_cutoff = struct.unpack('<I', data[56:60])[0]
            
            # Read FAT array
            fat_sectors = []
            for i in range(109):  # Header-resident FAT
                sid = struct.unpack('<I', data[76 + i*4:80 + i*4])[0]
                if sid != 0xFFFFFFFF:
                    fat_sectors.append(sid)
            
            # Build FAT chain
            fat = []
            for sector in fat_sectors:
                offset = (sector + 1) * sector_size
                for j in range(sector_size // 4):
                    fat.append(struct.unpack('<I', data[offset + j*4:offset + j*4 + 4])[0])
            
            # Parse directory entries
            self._parse_directory(data, first_dir_sector, sector_size, fat)
            
            # Extract stream data
            result = {
                'header': self._parse_hwp_header(),
                'streams': {},
                'ole_objects': [],
                'scripts': [],
                'has_eps': False,
                'has_macro': False,
                'external_links': [],
                'raw_strings': []
            }
            
            for stream_name, stream_data in self.streams.items():
                # Try to decompress if needed
                if result['header'] and result['header'].is_compressed and stream_name not in ['FileHeader']:
                    try:
                        decompressed = zlib.decompress(stream_data, -15)
                        stream_data = decompressed
                    except:
                        pass  # Keep original if decompression fails
                
                result['streams'][stream_name] = stream_data
                
                # Check for specific stream types - MORE PERMISSIVE
                stream_lower = stream_name.lower()
                
                # Check for EPS in stream name or content
                if '.eps' in stream_lower or b'%!PS-Adobe' in stream_data or b'%%BoundingBox' in stream_data:
                    result['has_eps'] = True
                    
                if stream_name == 'Script' or 'script' in stream_lower:
                    result['has_macro'] = True
                    result['scripts'].append(stream_data.decode('utf-8', errors='ignore'))
                
                # Check for OLE objects - BROADER MATCH
                if b'Ole10Native' in stream_data or b'\x01Ole10Native' in stream_data:
                    ole_info = self._extract_ole_object(stream_data, stream_name)
                    if ole_info:
                        result['ole_objects'].append(ole_info)
                
                # Check raw data for MZ (EXE) embedded anywhere
                if b'MZ' in stream_data[:1000] or b'\x4d\x5a' in stream_data[:1000]:
                    # Check if it's actually an embedded EXE in any stream
                    if stream_name not in result.get('streams', {}):
                        ole_info = {
                            'stream_name': stream_name,
                            'size': len(stream_data),
                            'type': 'EXE',
                            'magic': stream_data[:8].hex(),
                            'suspicious': True,
                            'has_temp_path': b'%TEMP%' in stream_data,
                            'has_url': b'http://' in stream_data or b'https://' in stream_data
                        }
                        result['ole_objects'].append(ole_info)
                
                # Extract strings for analysis
                strings = self._extract_strings(stream_data)
                result['raw_strings'].extend(strings)
                
                # Check for external URLs
                urls = self._find_urls(stream_data)
                result['external_links'].extend(urls)
            
            return result, None
            
        except Exception as e:
            return {}, f"Parse error: {str(e)}"
    
    def _parse_directory(self, data: bytes, first_dir_sector: int, sector_size: int, fat: List[int]):
        """Parse directory entries to find streams"""
        current_sector = first_dir_sector
        entry_size = 128
        
        while current_sector != 0xFFFFFFFE and current_sector < len(fat):
            offset = (current_sector + 1) * sector_size
            
            for i in range(sector_size // entry_size):
                entry_offset = offset + i * entry_size
                if entry_offset + entry_size > len(data):
                    break
                    
                entry = data[entry_offset:entry_offset + entry_size]
                
                # Parse entry name (UTF-16-LE, max 64 chars including null)
                name_len_bytes = struct.unpack('<H', entry[64:66])[0]
                if name_len_bytes == 0 or name_len_bytes > 64:
                    continue
                
                # Decode name - handle padding properly
                name_bytes = entry[:name_len_bytes]
                try:
                    name = name_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
                except:
                    continue
                
                if not name or name.startswith('\x00'):
                    continue
                    
                # Entry type
                entry_type = entry[66]
                if entry_type == 2:  # Stream
                    start_sid = struct.unpack('<I', entry[116:120])[0]
                    stream_size = struct.unpack('<I', entry[120:124])[0]
                    
                    if stream_size > 0 and start_sid != 0xFFFFFFFF and start_sid < len(fat):
                        stream_data = self._read_stream(data, start_sid, stream_size, sector_size, fat)
                        if stream_data:
                            self.streams[name] = stream_data
                
            # Next directory sector
            if current_sector < len(fat):
                current_sector = fat[current_sector]
            else:
                break
    
    def _read_stream(self, data: bytes, start_sid: int, size: int, sector_size: int, fat: List[int]) -> bytes:
        """Read stream data following FAT chain"""
        result = bytearray()
        current_sid = start_sid
        bytes_read = 0
        
        while current_sid != 0xFFFFFFFE and bytes_read < size:
            offset = (current_sid + 1) * sector_size
            chunk = data[offset:offset + sector_size]
            remaining = size - bytes_read
            result.extend(chunk[:min(sector_size, remaining)])
            bytes_read += min(sector_size, len(chunk))
            
            if current_sid < len(fat):
                current_sid = fat[current_sid]
            else:
                break
        
        return bytes(result)
    
    def _extract_ole_object(self, data: bytes, stream_name: str) -> Dict[str, Any]:
        """Extract and analyze OLE object information with PE validation"""
        obj_info = {
            'stream_name': stream_name,
            'size': len(data),
            'type': 'unknown',
            'is_executable': False,
            'is_valid_pe': False,
            'details': []
        }
        
        # Enhanced PE validation
        if PEAnalyzer:
            pe_analysis = PEAnalyzer.analyze_exe_embeddings(data)
            if pe_analysis["has_real_executable"]:
                obj_info['type'] = 'EXE'
                obj_info['is_executable'] = True
                obj_info['is_valid_pe'] = True
                obj_info['details'].append(f"Valid PE: {pe_analysis['valid_pe_count']} executable(s)")
            elif pe_analysis["false_positive_count"] > 0:
                obj_info['details'].append(f"MZ patterns without PE structure: {pe_analysis['false_positive_count']}")
        else:
            # Fallback to simple detection
            if data.startswith(b'MZ') or data[:2] == b'MZ':
                # Quick PE check
                if len(data) > 64:
                    try:
                        e_lfanew = struct.unpack('<I', data[60:64])[0]
                        pe_offset = 60 + e_lfanew
                        if pe_offset + 4 < len(data) and data[pe_offset:pe_offset + 4] == b'PE\0\0':
                            obj_info['type'] = 'EXE'
                            obj_info['is_executable'] = True
                            obj_info['is_valid_pe'] = True
                    except:
                        pass
                else:
                    obj_info['type'] = 'EXE (suspected)'
                    obj_info['details'].append('MZ signature found but too small for PE validation')
        
        # Check for other file types
        if data.startswith(b'\x89PNG'):
            obj_info['type'] = 'PNG'
        elif data.startswith(b'\xff\xd8\xff'):
            obj_info['type'] = 'JPEG'
        elif data.startswith(b'GIF8'):
            obj_info['type'] = 'GIF'
        elif data.startswith(b'BM'):
            obj_info['type'] = 'BMP'
        elif data.startswith(b'%!PS-Adobe'):
            obj_info['type'] = 'EPS'
        
        # Check for suspicious keywords
        suspicious_keywords = [b'%TEMP%', b'temp\\', b'cmd.exe', b'powershell', b'shell.exe']
        for keyword in suspicious_keywords:
            if keyword.lower() in data.lower():
                obj_info['details'].append(f'Suspicious keyword: {keyword.decode()}')
        
        return obj_info
    
    def _parse_hwp_header(self) -> Optional[HWPHeader]:
        """Parse HWP file header from the file data"""
        try:
            with open(self.filepath, 'rb') as f:
                header_data = f.read(1024)  # Read first 1KB for header
            
            if len(header_data) < 32:
                return None
            
            return HWPHeader(header_data)
        except Exception:
            return None
    
    def _extract_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_len:
                    strings.append(current_string)
                current_string = ""
        
        # Add final string if valid
        if len(current_string) >= min_len:
            strings.append(current_string)
        
        return strings
    
    def _find_urls(self, data: bytes) -> List[str]:
        """Extract URLs from binary data"""
        import re
        
        # URL patterns
        url_patterns = [
            rb'https?://[^\s<>"]+',
            rb'www\.[^\s<>"]+\.[a-zA-Z]{2,}'
        ]
        
        urls = []
        for pattern in url_patterns:
            matches = re.findall(pattern, data)
            urls.extend([match.decode('utf-8', errors='ignore') for match in matches])
        
        return urls


class HWPXParser:
    """HWPX (ZIP/XML) format parser"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        
    def parse(self) -> Tuple[Dict, Optional[str]]:
        """Parse HWPX file"""
        try:
            with zipfile.ZipFile(self.filepath, 'r') as zf:
                # Get file list
                file_list = zf.namelist()
                
                result = {
                    'format': 'HWPX',
                    'files': file_list,
                    'bin_data': [],
                    'external_refs': [],
                    'has_macro': False,
                    'has_script': False,
                    'xml_content': {},
                    'ole_objects': []
                }
                
                # Check mimetype
                if 'mimetype' in file_list:
                    mimetype = zf.read('mimetype').decode('utf-8', errors='ignore')
                    result['mimetype'] = mimetype
                
                # Read version.xml
                if 'version.xml' in file_list:
                    try:
                        version_xml = zf.read('version.xml').decode('utf-8')
                        result['version'] = self._extract_version(version_xml)
                    except:
                        pass
                
                # Analyze BinData/
                for name in file_list:
                    if name.startswith('BinData/'):
                        try:
                            data = zf.read(name)
                            bin_info = self._analyze_bin_data(name, data)
                            result['bin_data'].append(bin_info)
                            
                            # Check for OLE objects in BinData
                            if b'\x01Ole10Native' in data or b'dOlE' in data:
                                ole_info = self._extract_ole_from_bindata(name, data)
                                if ole_info:
                                    result['ole_objects'].append(ole_info)
                        except:
                            pass
                
                # Parse Contents XML for hyperlinks and references
                for name in file_list:
                    if name.startswith('Contents/') and name.endswith('.xml'):
                        try:
                            content = zf.read(name).decode('utf-8')
                            result['xml_content'][name] = content[:1000]  # Limit size
                            
                            # Extract URLs
                            urls = self._extract_xml_urls(content)
                            result['external_refs'].extend(urls)
                            
                            # Check for scripts/macros
                            if '<script' in content.lower() or 'macro' in content.lower():
                                result['has_script'] = True
                                result['has_macro'] = True
                        except:
                            pass
                
                # Parse settings.xml for external references
                if 'settings.xml' in file_list:
                    try:
                        settings = zf.read('settings.xml').decode('utf-8')
                        urls = self._extract_xml_urls(settings)
                        result['external_refs'].extend(urls)
                    except:
                        pass
                
                return result, None
                
        except zipfile.BadZipFile:
            return {}, "Not a valid ZIP file (HWPX)"
        except Exception as e:
            return {}, f"HWPX parse error: {str(e)}"
    
    def _analyze_bin_data(self, name: str, data: bytes) -> Dict:
        """Analyze BinData entry"""
        magic = data[:8] if data else b''
        
        file_type = 'unknown'
        if magic[:2] == b'MZ':
            file_type = 'EXE'
        elif magic[:4] == b'\x89PNG':
            file_type = 'PNG'
        elif magic[:3] == b'\xff\xd8\xff':
            file_type = 'JPEG'
        elif magic[:4] == b'GIF8':
            file_type = 'GIF'
        elif b'%!PS-Adobe' in data[:100]:
            file_type = 'EPS'
        elif magic[:4] == b'\xd0\xcf\x11\xe0':
            file_type = 'OLE'
        
        return {
            'name': name,
            'size': len(data),
            'type': file_type,
            'magic': magic.hex() if magic else '',
            'suspicious': file_type in ['EXE', 'OLE', 'EPS']
        }
    
    def _extract_ole_from_bindata(self, name: str, data: bytes) -> Optional[Dict]:
        """Extract OLE object from BinData"""
        try:
            # Look for OLE container
            if b'\xd0\xcf\x11\xe0' not in data:
                return None
            
            # Check for embedded executable
            has_exe = b'MZ' in data
            has_temp = b'%TEMP%' in data or b'%temp%' in data
            
            return {
                'source': name,
                'type': 'OLE_CONTAINER',
                'has_executable': has_exe,
                'has_temp_reference': has_temp,
                'size': len(data)
            }
        except:
            return None
    
    def _extract_version(self, xml: str) -> str:
        """Extract version from XML"""
        try:
            root = ET.fromstring(xml)
            # Try to find version element
            for elem in root.iter():
                if 'version' in elem.tag.lower():
                    return elem.text or 'unknown'
            return 'unknown'
        except:
            return 'unknown'
    
    def _extract_xml_urls(self, xml: str) -> List[str]:
        """Extract URLs from XML content"""
        urls = []
        # Match href attributes
        href_pattern = r'href=["\'](https?://[^"\']+)["\']'
        urls.extend(re.findall(href_pattern, xml))
        
        # Match explicit URLs
        url_pattern = r'https?://[^\s<>"\']+'
        urls.extend(re.findall(url_pattern, xml))
        
        return list(set(urls))  # Remove duplicates


def compute_hashes(filepath: str) -> Dict[str, str]:
    """Compute file hashes"""
    hashes = {'md5': '', 'sha1': '', 'sha256': ''}
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
    except:
        pass
    
    return hashes


def analyze_file(filepath: str) -> Dict:
    """Main file analysis function with raw fallback"""
    
    result = {
        'filename': os.path.basename(filepath),
        'file_hash': {'md5': '', 'sha1': '', 'sha256': ''},
        'file_size': os.path.getsize(filepath),
        'actual_format': 'unknown',
        'hwp_version': None,
        'header_flags': {},
        'streams': [],
        'threats': [],
        'indicators': [],
        'iocs': [],
        'risk_score': 0,
        'overall_risk': 'CLEAN',
        'analysis_details': {}
    }
    
    
    # Compute hashes
    result['file_hash'] = compute_hashes(filepath)
    
    # Read entire file for raw analysis fallback
    with open(filepath, 'rb') as f:
        raw_data = f.read()
    
    # Detect format and parse
    header = raw_data[:8] if len(raw_data) >= 8 else b''
    
    # Check OLE magic (HWP)
    if header[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        result['actual_format'] = 'HWP (OLE)'
        parser = OLEParser(filepath)
        parse_result, error = parser.parse()
        
        
        # If parsing failed or returned empty streams, use raw data
        if error or not parse_result.get('streams'):
            # Create minimal parse_result from raw data
            parse_result = {
                'header': None,
                'streams': {'RAW': raw_data},  # Use entire file as one stream
                'ole_objects': [],
                'scripts': [],
                'has_eps': False,
                'has_macro': False,
                'external_links': [],
                'raw_strings': []
            }
            result['analysis_details']['parse_warning'] = error or 'No streams found, using raw analysis'
        else:
            # Add raw data to streams for pattern matching
            parse_result['streams']['__RAW__'] = raw_data
            
            # Extract HWP header info
            hwp_header = parse_result.get('header')
            if hwp_header:
                result['hwp_version'] = hwp_header.version_string
                result['header_flags'] = {
                    'compressed': hwp_header.is_compressed,
                    'encrypted': hwp_header.is_encrypted,
                    'distribution': hwp_header.is_distribution
                }
            
            # List streams
            result['streams'] = list(parse_result.get('streams', {}).keys())
            # Also include the full streams dict with content for analysis
            result['streams_dict'] = parse_result.get('streams', {})
        
        # Run threat analysis with improved analyzer
        analyzer = ImprovedThreatAnalyzer()
        threat_result = analyzer.analyze(parse_result, 'HWP')
        
        
        result['threats'] = threat_result['threats']
        result['indicators'] = threat_result['indicators']
        result['iocs'] = threat_result['iocs']
        result['risk_score'] = threat_result['score']
        result['overall_risk'] = threat_result['risk_level']
        result['analysis_details'].update({
            'has_eps': parse_result.get('has_eps', False),
            'has_macro': parse_result.get('has_macro', False),
            'ole_object_count': len(parse_result.get('ole_objects', [])),
            'external_link_count': len(parse_result.get('external_links', [])),
            'found_patterns': threat_result.get('found_patterns', 0)
        })
    
    # Check ZIP magic (HWPX)
    elif header[:4] == b'PK\x03\x04':
        result['actual_format'] = 'HWPX (ZIP/XML)'
        parser = HWPXParser(filepath)
        parse_result, error = parser.parse()
        
        if error:
            result['analysis_details']['error'] = error
            # Use raw data as fallback
            parse_result = {
                'format': 'HWPX',
                'files': [],
                'bin_data': [],
                'external_refs': [],
                'has_macro': False,
                'has_script': False,
                'xml_content': {},
                'ole_objects': [],
                'raw_data': raw_data
            }
        else:
            result['streams'] = parse_result.get('files', [])
            result['hwp_version'] = parse_result.get('version', 'unknown')
        
        # Run threat analysis with improved analyzer
        analyzer = ImprovedThreatAnalyzer()
        threat_result = analyzer.analyze(parse_result, 'HWPX')
        
        result['threats'] = threat_result['threats']
    else:
        result['analysis_details']['error'] = "Unknown file format - not HWP or HWPX"
        result['overall_risk'] = "ERROR"
    
    return result
