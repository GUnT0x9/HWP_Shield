"""
Debug and error tracking module for HWPShield.
Captures and stores errors for debugging without relying on file system.
"""
import sys
import traceback
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import deque
import json


@dataclass
class ErrorRecord:
    """Error record for debugging."""
    timestamp: str
    error_type: str
    message: str
    traceback_str: str
    request_info: Dict[str, Any]
    context: Dict[str, Any]


class DebugLogger:
    """
    In-memory error logger for debugging.
    Stores last N errors in memory for easy retrieval.
    """
    
    def __init__(self, max_errors: int = 50):
        self.max_errors = max_errors
        self.errors: deque = deque(maxlen=max_errors)
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
    
    def log_error(self, exc: Exception, request_info: Optional[Dict] = None, 
                  context: Optional[Dict] = None) -> str:
        """
        Log an error with full context.
        
        Returns:
            Error ID for reference
        """
        self.error_count += 1
        
        error_id = f"ERR-{int(time.time()*1000)}-{self.error_count}"
        
        record = ErrorRecord(
            timestamp=datetime.utcnow().isoformat(),
            error_type=type(exc).__name__,
            message=str(exc),
            traceback_str=traceback.format_exc(),
            request_info=request_info or {},
            context=context or {}
        )
        
        # Store with error ID
        self.errors.append({
            "id": error_id,
            **asdict(record)
        })
        
        # Also print to stderr immediately
        self._print_error(error_id, record)
        
        return error_id
    
    def _print_error(self, error_id: str, record: ErrorRecord):
        """Print error to stderr for immediate visibility."""
        print(f"\n{'='*80}", file=sys.stderr)
        print(f"ERROR [{error_id}] {record.timestamp}", file=sys.stderr)
        print(f"Type: {record.error_type}", file=sys.stderr)
        print(f"Message: {record.message}", file=sys.stderr)
        if record.request_info:
            print(f"Request: {json.dumps(record.request_info, ensure_ascii=False)}", file=sys.stderr)
        print(f"Traceback:\n{record.traceback_str}", file=sys.stderr)
        print(f"{'='*80}\n", file=sys.stderr)
    
    def get_recent_errors(self, limit: int = 10) -> List[Dict]:
        """Get recent errors (newest first)."""
        return list(self.errors)[-limit:][::-1]
    
    def get_error_by_id(self, error_id: str) -> Optional[Dict]:
        """Get specific error by ID."""
        for err in self.errors:
            if err.get("id") == error_id:
                return err
        return None
    
    def get_stats(self) -> Dict:
        """Get debug statistics."""
        return {
            "uptime_seconds": int(time.time() - self.start_time),
            "total_errors_logged": self.error_count,
            "errors_in_memory": len(self.errors),
            "max_errors_stored": self.max_errors
        }
    
    def clear(self):
        """Clear all stored errors."""
        self.errors.clear()
        self.error_count = 0


# Global debug logger instance
debug_logger = DebugLogger()
