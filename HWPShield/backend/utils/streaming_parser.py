"""
Streaming HWP Parser
Memory-efficient streaming parser for large HWP files
"""
import os
import struct
import zlib
from typing import Dict, List, Tuple, Optional, Any, Iterator, BinaryIO
from dataclasses import dataclass
from contextlib import contextmanager
import threading
import queue
import time

@dataclass
class StreamInfo:
    """Information about a parsed stream"""
    name: str
    size: int
    offset: int
    compressed: bool
    estimated_entropy: float
    threat_indicators: List[str]

@dataclass
class ParseProgress:
    """Parsing progress information"""
    total_bytes: int
    processed_bytes: int
    current_stream: str
    streams_found: int
    threats_detected: int
    start_time: float

class StreamingHWPParser:
    """Memory-efficient streaming HWP parser"""
    
    def __init__(self, chunk_size: int = 65536, max_memory_mb: int = 100):
        self.chunk_size = chunk_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.memory_usage = 0
        self.parse_cache = {}
        
    def parse_streaming(self, filepath: str, progress_callback=None) -> Iterator[Tuple[str, Any]]:
        """
        Stream parse HWP file with memory efficiency
        
        Yields:
            (event_type, data) tuples where event_type can be:
            - 'stream_start': StreamInfo
            - 'stream_chunk': (stream_name, chunk_data)
            - 'stream_end': stream_name
            - 'threat_found': threat_info
            - 'progress': ParseProgress
            - 'complete': final_result
        """
        # Initialize parsing
        file_size = os.path.getsize(filepath)
        start_time = time.time()
        
        progress = ParseProgress(
            total_bytes=file_size,
            processed_bytes=0,
            current_stream="",
            streams_found=0,
            threats_detected=0,
            start_time=start_time
        )
        
        try:
            with open(filepath, 'rb') as f:
                # Parse OLE header
                header_info = self._parse_ole_header_streaming(f)
                yield 'header', header_info
                
                # Stream parse directory entries
                for event, data in self._stream_parse_directory(f, header_info, progress):
                    if event == 'stream_found':
                        stream_info = data
                        progress.streams_found += 1
                        yield 'stream_start', stream_info
                        
                        # Process stream in chunks
                        for chunk_event, chunk_data in self._stream_process_chunks(f, stream_info, progress):
                            if chunk_event == 'threat':
                                progress.threats_detected += 1
                                yield 'threat_found', chunk_data
                            yield chunk_event, chunk_data
                        
                        yield 'stream_end', stream_info.name
                    
                    elif event == 'progress':
                        progress = data
                        if progress_callback:
                            progress_callback(progress)
                        yield 'progress', progress
            
            # Final result
            result = {
                'total_streams': progress.streams_found,
                'total_threats': progress.threats_detected,
                'parse_time': time.time() - start_time,
                'memory_peak': self.memory_usage
            }
            yield 'complete', result
            
        except Exception as e:
            yield 'error', {'error': str(e), 'progress': progress}
    
    def _parse_ole_header_streaming(self, file_handle: BinaryIO) -> Dict[str, Any]:
        """Parse OLE header with streaming"""
        header_data = file_handle.read(512)
        
        if len(header_data) < 512 or header_data[:8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            raise ValueError("Invalid OLE header")
        
        # Parse header fields
        header = {
            'magic': header_data[:8],
            'minor_version': struct.unpack('<H', header_data[8:10])[0],
            'major_version': struct.unpack('<H', header_data[10:12])[0],
            'byte_order': struct.unpack('<H', header_data[12:14])[0],
            'sector_size': struct.unpack('<H', header_data[14:16])[0],
            'mini_sector_size': struct.unpack('<H', header_data[16:18])[0],
            'total_sectors': struct.unpack('<I', header_data[24:28])[0],
            'fat_sector_count': struct.unpack('<I', header_data[28:32])[0],
            'first_dir_sector': struct.unpack('<I', header_data[32:36])[0],
            'mini_stream_cutoff': struct.unpack('<I', header_data[40:44])[0]
        }
        
        return header
    
    def _stream_parse_directory(self, file_handle: BinaryIO, header: Dict, progress: ParseProgress) -> Iterator[Tuple[str, Any]]:
        """Stream parse directory entries"""
        sector_size = 2 ** header['sector_size']
        first_dir_sector = header['first_dir_sector']
        
        # Build FAT
        fat = self._build_fat_streaming(file_handle, header, progress)
        
        # Parse directory sectors
        current_sector = first_dir_sector
        entry_size = 128
        
        while current_sector != 0xFFFFFFFE and current_sector < len(fat):
            offset = (current_sector + 1) * sector_size
            
            # Seek to sector
            file_handle.seek(offset)
            sector_data = file_handle.read(sector_size)
            progress.processed_bytes += len(sector_data)
            
            # Parse entries in sector
            for i in range(sector_size // entry_size):
                entry_offset = i * entry_size
                if entry_offset + entry_size > len(sector_data):
                    break
                
                entry = sector_data[entry_offset:entry_offset + entry_size]
                
                # Parse entry name
                name_len_bytes = struct.unpack('<H', entry[64:66])[0]
                if name_len_bytes == 0 or name_len_bytes > 64:
                    continue
                
                name_bytes = entry[:name_len_bytes]
                try:
                    name = name_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
                except:
                    continue
                
                if not name or name.startswith('\x00'):
                    continue
                
                # Check entry type
                entry_type = entry[66]
                if entry_type == 2:  # Stream
                    start_sid = struct.unpack('<I', entry[116:120])[0]
                    stream_size = struct.unpack('<I', entry[120:124])[0]
                    
                    if stream_size > 0 and start_sid != 0xFFFFFFFF and start_sid < len(fat):
                        stream_info = StreamInfo(
                            name=name,
                            size=stream_size,
                            offset=start_sid,
                            compressed=self._is_compressed_stream(name),
                            estimated_entropy=0.0,
                            threat_indicators=[]
                        )
                        
                        yield 'stream_found', stream_info
            
            # Move to next directory sector
            if current_sector < len(fat):
                current_sector = fat[current_sector]
            else:
                break
    
    def _build_fat_streaming(self, file_handle: BinaryIO, header: Dict, progress: ParseProgress) -> List[int]:
        """Build FAT table with streaming"""
        sector_size = 2 ** header['sector_size']
        fat_sector_count = header['fat_sector_count']
        
        # Read initial FAT sectors from header
        fat_sectors = []
        for i in range(109):
            sid = struct.unpack('<I', header[76 + i*4:80 + i*4])[0]
            if sid != 0xFFFFFFFF:
                fat_sectors.append(sid)
        
        # Read additional FAT sectors
        if fat_sector_count > 109:
            # Read DIFAT
            first_difat = struct.unpack('<I', header[56:60])[0]
            difat_count = struct.unpack('<I', header[60:64])[0]
            
            # This is simplified - full implementation would handle DIFAT chains
            pass
        
        # Build FAT
        fat = []
        for sector in fat_sectors:
            offset = (sector + 1) * sector_size
            file_handle.seek(offset)
            sector_data = file_handle.read(sector_size)
            progress.processed_bytes += len(sector_data)
            
            for j in range(sector_size // 4):
                fat_value = struct.unpack('<I', sector_data[j*4:j*4 + 4])[0]
                fat.append(fat_value)
        
        return fat
    
    def _stream_process_chunks(self, file_handle: BinaryIO, stream_info: StreamInfo, 
                             progress: ParseProgress) -> Iterator[Tuple[str, Any]]:
        """Process stream data in chunks"""
        # This is a simplified implementation
        # In practice, you'd need to follow the FAT chain to read the stream
        
        # For demonstration, we'll simulate reading chunks
        chunk_size = min(self.chunk_size, stream_info.size)
        bytes_read = 0
        
        progress.current_stream = stream_info.name
        
        while bytes_read < stream_info.size:
            # Simulate reading chunk
            chunk_data = file_handle.read(min(chunk_size, stream_info.size - bytes_read))
            if not chunk_data:
                break
            
            bytes_read += len(chunk_data)
            progress.processed_bytes += len(chunk_data)
            
            # Update memory usage
            self.memory_usage = max(self.memory_usage, len(chunk_data))
            
            # Analyze chunk for threats
            threats = self._analyze_chunk_threats(chunk_data, stream_info.name)
            for threat in threats:
                yield 'threat', threat
            
            # Yield chunk data
            yield 'stream_chunk', (stream_info.name, chunk_data)
            
            # Check memory limit
            if self.memory_usage > self.max_memory_bytes:
                yield 'warning', {'type': 'memory_limit', 'usage': self.memory_usage}
    
    def _is_compressed_stream(self, stream_name: str) -> bool:
        """Check if stream is typically compressed"""
        compressed_streams = [
            'BodyText', 'BinData', 'PrvText', 'PrvImage'
        ]
        return any(comp in stream_name for comp in compressed_streams)
    
    def _analyze_chunk_threats(self, chunk_data: bytes, stream_name: str) -> List[Dict[str, Any]]:
        """Analyze chunk for immediate threats"""
        threats = []
        
        # Quick threat patterns
        threat_patterns = {
            b'MZ': {'type': 'executable_signature', 'severity': 'high'},
            b'PE\0\0': {'type': 'pe_header', 'severity': 'critical'},
            b'eqproc': {'type': 'eps_exploit', 'severity': 'high'},
            b'ShellExecute': {'type': 'shell_execution', 'severity': 'high'},
            b'%TEMP%': {'type': 'temp_path', 'severity': 'medium'},
            b'powershell': {'type': 'powershell', 'severity': 'medium'}
        }
        
        for pattern, threat_info in threat_patterns.items():
            if pattern in chunk_data:
                position = chunk_data.find(pattern)
                threats.append({
                    'type': threat_info['type'],
                    'severity': threat_info['severity'],
                    'stream': stream_name,
                    'position': position,
                    'pattern': pattern.hex() if isinstance(pattern, bytes) else pattern
                })
        
        return threats

class ParallelStreamingParser:
    """Parallel streaming parser for multiple files"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.workers = []
        self.running = False
    
    def start_workers(self):
        """Start worker threads"""
        self.running = True
        for i in range(self.max_workers):
            worker = threading.Thread(target=self._worker_loop, args=(i,))
            worker.daemon = True
            worker.start()
            self.workers.append(worker)
    
    def stop_workers(self):
        """Stop worker threads"""
        self.running = False
        for worker in self.workers:
            worker.join(timeout=1)
    
    def _worker_loop(self, worker_id: int):
        """Worker thread loop"""
        parser = StreamingHWPParser()
        
        while self.running:
            try:
                # Get task from queue
                task = self.task_queue.get(timeout=1)
                
                # Process task
                filepath, task_id = task
                result = self._process_file(parser, filepath, task_id, worker_id)
                
                # Put result in result queue
                self.result_queue.put(result)
                
                self.task_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.result_queue.put({
                    'task_id': task_id,
                    'worker_id': worker_id,
                    'error': str(e)
                })
    
    def _process_file(self, parser: StreamingHWPParser, filepath: str, 
                     task_id: str, worker_id: int) -> Dict[str, Any]:
        """Process single file"""
        start_time = time.time()
        
        try:
            results = {
                'task_id': task_id,
                'worker_id': worker_id,
                'filepath': filepath,
                'start_time': start_time,
                'streams': [],
                'threats': [],
                'errors': []
            }
            
            for event, data in parser.parse_streaming(filepath):
                if event == 'stream_start':
                    results['streams'].append({
                        'name': data.name,
                        'size': data.size,
                        'compressed': data.compressed
                    })
                
                elif event == 'threat_found':
                    results['threats'].append(data)
                
                elif event == 'error':
                    results['errors'].append(data)
                
                elif event == 'complete':
                    results.update(data)
                    break
            
            results['end_time'] = time.time()
            results['total_time'] = results['end_time'] - results['start_time']
            
            return results
            
        except Exception as e:
            return {
                'task_id': task_id,
                'worker_id': worker_id,
                'filepath': filepath,
                'error': str(e),
                'start_time': start_time,
                'end_time': time.time()
            }
    
    def parse_files_parallel(self, filepaths: List[str]) -> Iterator[Dict[str, Any]]:
        """Parse multiple files in parallel"""
        # Start workers
        self.start_workers()
        
        # Add tasks to queue
        task_id = 0
        for filepath in filepaths:
            self.task_queue.put((filepath, str(task_id)))
            task_id += 1
        
        # Process results
        completed = 0
        total_tasks = len(filepaths)
        
        while completed < total_tasks:
            try:
                result = self.result_queue.get(timeout=5)
                yield result
                completed += 1
            except queue.Empty:
                continue
        
        # Stop workers
        self.stop_workers()

@contextmanager
def memory_monitor():
    """Context manager for monitoring memory usage"""
    import psutil
    process = psutil.Process()
    
    initial_memory = process.memory_info().rss
    peak_memory = initial_memory
    
    def update_peak():
        nonlocal peak_memory
        current = process.memory_info().rss
        peak_memory = max(peak_memory, current)
    
    try:
        yield update_peak
    finally:
        final_memory = process.memory_info().rss
        print(f"Memory usage: Initial={initial_memory//1024//1024}MB, "
              f"Peak={peak_memory//1024//1024}MB, "
              f"Final={final_memory//1024//1024}MB")
