"""
Secure File Handler for HWPShield
Implements secure temp file handling with guaranteed deletion
"""
import os
import tempfile
import uuid
import signal
import threading
import time
from contextlib import contextmanager
from typing import Optional

class SecureFileHandler:
    """Secure file handler with guaranteed cleanup"""
    
    def __init__(self):
        self._active_files = {}  # {file_path: cleanup_time}
        self._cleanup_thread = None
        self._running = False
        
    def start(self):
        """Start background cleanup thread"""
        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self._cleanup_thread.start()
        
    def stop(self):
        """Stop cleanup thread"""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=1)
    
    def _cleanup_worker(self):
        """Background thread for cleanup"""
        while self._running:
            try:
                current_time = time.time()
                expired_files = [
                    path for path, cleanup_time in self._active_files.items()
                    if current_time > cleanup_time
                ]
                
                for file_path in expired_files:
                    self._force_delete(file_path)
                    del self._active_files[file_path]
                    
            except Exception:
                pass  # Silent cleanup
            
            time.sleep(5)  # Check every 5 seconds
    
    def _force_delete(self, file_path: str):
        """Force delete file with multiple attempts"""
        try:
            if os.path.isfile(file_path):
                os.chmod(file_path, 0o777)  # Ensure write permissions
                os.unlink(file_path)
        except Exception:
            try:
                # Try with shutil
                import shutil
                if os.path.exists(file_path):
                    shutil.rmtree(file_path, ignore_errors=True)
            except Exception:
                pass  # Final attempt failed
    
    @contextmanager
    def secure_temp_file(self, filename: str, timeout_seconds: int = 60):
        """
        Create secure temp file with guaranteed cleanup
        
        Args:
            filename: Original filename
            timeout_seconds: Auto-cleanup timeout
            
        Returns:
            tuple: (temp_path, cleanup_func)
        """
        # Generate UUID-based filename
        file_ext = os.path.splitext(filename)[1]
        uuid_name = f"hwpshield_{uuid.uuid4().hex}{file_ext}"
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix="hwpshield_")
        temp_path = os.path.join(temp_dir, uuid_name)
        
        # Register for cleanup
        cleanup_time = time.time() + timeout_seconds
        self._active_files[temp_path] = cleanup_time
        
        def cleanup():
            self._force_delete(temp_path)
            if temp_path in self._active_files:
                del self._active_files[temp_path]
            # Clean up temp directory
            try:
                parent_dir = os.path.dirname(temp_path)
                if os.path.exists(parent_dir):
                    os.rmdir(parent_dir)
            except:
                pass
        
        try:
            yield temp_path, cleanup
        finally:
            cleanup()
    
    @contextmanager
    def secure_temp_directory(self, timeout_seconds: int = 60):
        """
        Create secure temp directory with guaranteed cleanup
        
        Args:
            timeout_seconds: Auto-cleanup timeout
            
        Returns:
            tuple: (temp_dir, cleanup_func)
        """
        # Generate UUID-based directory name
        uuid_name = f"hwpshield_dir_{uuid.uuid4().hex}"
        temp_dir = os.path.join(tempfile.gettempdir(), uuid_name)
        os.makedirs(temp_dir, mode=0o700, exist_ok=True)
        
        # Register for cleanup
        cleanup_time = time.time() + timeout_seconds
        self._active_files[temp_dir] = cleanup_time
        
        def cleanup():
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            if temp_dir in self._active_files:
                del self._active_files[temp_dir]
        
        try:
            yield temp_dir, cleanup
        finally:
            cleanup()

# Global instance
secure_handler = SecureFileHandler()

# Signal handlers for emergency cleanup
def emergency_cleanup(signum, frame):
    """Emergency cleanup on signal"""
    secure_handler.stop()
    os._exit(1)

# Register signal handlers
signal.signal(signal.SIGTERM, emergency_cleanup)
signal.signal(signal.SIGINT, emergency_cleanup)

# Auto-start handler
secure_handler.start()

# Auto-cleanup on exit
import atexit
atexit.register(secure_handler.stop)
