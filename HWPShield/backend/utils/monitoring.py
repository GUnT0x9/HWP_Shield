"""
Monitoring and metrics module for HWPShield.
Provides Prometheus metrics, request tracking, and audit logging.
"""
import time
import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict
from contextlib import contextmanager

from fastapi import Request, Response


@dataclass
class AnalysisAudit:
    """Audit record for file analysis."""
    timestamp: str
    request_id: str
    client_ip: str
    user_agent: str
    api_key_id: Optional[str]
    filename: str
    file_size: int
    file_hash: str
    duration_ms: float
    risk_level: str
    risk_score: int
    modules_triggered: List[str]
    iocs_found: int
    antivirus_result: str
    success: bool
    error_message: Optional[str] = None


class MetricsCollector:
    """Collect and expose application metrics."""
    
    def __init__(self):
        self._request_count = defaultdict(int)
        self._request_duration = defaultdict(list)
        self._analysis_count = defaultdict(int)
        self._risk_distribution = defaultdict(int)
        self._error_count = defaultdict(int)
        self._active_requests = 0
        self._start_time = time.time()
    
    def record_request(self, method: str, path: str, status_code: int, duration: float):
        """Record API request metrics."""
        key = f"{method}:{path}:{status_code}"
        self._request_count[key] += 1
        self._request_duration[key].append(duration)
        
        # Keep only last 100 durations for memory efficiency
        if len(self._request_duration[key]) > 100:
            self._request_duration[key] = self._request_duration[key][-100:]
    
    def record_analysis(self, risk_level: str, score: int):
        """Record analysis result metrics."""
        self._analysis_count[risk_level] += 1
        self._risk_distribution[score // 10] += 1  # Bucket by score ranges
    
    def record_error(self, error_type: str):
        """Record error metrics."""
        self._error_count[error_type] += 1
    
    def increment_active_requests(self):
        """Increment active request counter."""
        self._active_requests += 1
    
    def decrement_active_requests(self):
        """Decrement active request counter."""
        self._active_requests -= 1
    
    def get_metrics(self) -> Dict:
        """Get current metrics snapshot."""
        total_requests = sum(self._request_count.values())
        total_analyses = sum(self._analysis_count.values())
        
        # Calculate average response times
        avg_durations = {}
        for key, durations in self._request_duration.items():
            if durations:
                avg_durations[key] = sum(durations) / len(durations)
        
        return {
            "uptime_seconds": int(time.time() - self._start_time),
            "total_requests": total_requests,
            "total_analyses": total_analyses,
            "active_requests": self._active_requests,
            "request_breakdown": dict(self._request_count),
            "analysis_by_risk": dict(self._analysis_count),
            "risk_distribution": dict(self._risk_distribution),
            "error_counts": dict(self._error_count),
            "average_response_times": avg_durations
        }
    
    def get_prometheus_format(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        
        # Uptime
        uptime = time.time() - self._start_time
        lines.append(f"# HELP hwpshield_uptime_seconds Server uptime")
        lines.append(f"# TYPE hwpshield_uptime_seconds gauge")
        lines.append(f"hwpshield_uptime_seconds {uptime}")
        
        # Active requests
        lines.append(f"# HELP hwpshield_active_requests Active HTTP requests")
        lines.append(f"# TYPE hwpshield_active_requests gauge")
        lines.append(f"hwpshield_active_requests {self._active_requests}")
        
        # Request counts
        lines.append(f"# HELP hwpshield_requests_total Total HTTP requests")
        lines.append(f"# TYPE hwpshield_requests_total counter")
        for key, count in self._request_count.items():
            method, path, status = key.split(":")
            lines.append(f'hwpshield_requests_total{{method="{method}",path="{path}",status="{status}"}} {count}')
        
        # Analysis counts
        lines.append(f"# HELP hwpshield_analyses_total Total file analyses")
        lines.append(f"# TYPE hwpshield_analyses_total counter")
        for risk, count in self._analysis_count.items():
            lines.append(f'hwpshield_analyses_total{{risk_level="{risk}"}} {count}')
        
        # Error counts
        lines.append(f"# HELP hwpshield_errors_total Total errors")
        lines.append(f"# TYPE hwpshield_errors_total counter")
        for error_type, count in self._error_count.items():
            lines.append(f'hwpshield_errors_total{{type="{error_type}"}} {count}')
        
        return "\n".join(lines)


class AuditLogger:
    """Audit logging for security and compliance."""
    
    def __init__(self, log_file: Optional[str] = None):
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)
        
        # File handler for audit logs
        if log_file:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
            self.logger.addHandler(handler)
        
        # Also log to stdout
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter('AUDIT | %(asctime)s | %(message)s'))
        self.logger.addHandler(console)
    
    def log_analysis(self, audit: AnalysisAudit):
        """Log file analysis audit record."""
        record = asdict(audit)
        self.logger.info(json.dumps(record, ensure_ascii=False))
    
    def log_access(self, request_id: str, client_ip: str, method: str, 
                   path: str, status_code: int, user_id: Optional[str] = None):
        """Log API access."""
        record = {
            "type": "access",
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status_code": status_code,
            "user_id": user_id
        }
        self.logger.info(json.dumps(record))
    
    def log_security_event(self, event_type: str, details: Dict, 
                          severity: str = "info"):
        """Log security-related events."""
        record = {
            "type": "security",
            "event": event_type,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
        if severity in ["warning", "error", "critical"]:
            self.logger.warning(json.dumps(record))
        else:
            self.logger.info(json.dumps(record))


class RequestTracker:
    """Track and monitor HTTP requests."""
    
    def __init__(self, metrics: MetricsCollector, audit_logger: AuditLogger):
        self.metrics = metrics
        self.audit = audit_logger
        self._request_times: Dict[str, float] = {}
    
    def start_request(self, request_id: str):
        """Mark request start time."""
        self.metrics.increment_active_requests()
        self._request_times[request_id] = time.time()
    
    def end_request(self, request_id: str, request: Request, response: Response,
                    api_key_id: Optional[str] = None, user_id: Optional[str] = None):
        """Record request completion."""
        self.metrics.decrement_active_requests()
        
        start_time = self._request_times.pop(request_id, None)
        duration = time.time() - start_time if start_time else 0
        
        # Record metrics
        self.metrics.record_request(
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration=duration * 1000  # Convert to ms
        )
        
        # Log access
        client_ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        
        self.audit.log_access(
            request_id=request_id,
            client_ip=client_ip,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            user_id=user_id or api_key_id
        )
    
    def log_analysis(self, audit: AnalysisAudit):
        """Log analysis audit and update metrics."""
        self.audit.log_analysis(audit)
        
        if audit.success:
            self.metrics.record_analysis(audit.risk_level, audit.risk_score)
        else:
            self.metrics.record_error("analysis_failed")


@contextmanager
def analysis_timer():
    """Context manager to time analysis operations."""
    start = time.time()
    try:
        yield
    finally:
        elapsed = (time.time() - start) * 1000


# Global instances
metrics = MetricsCollector()
audit_logger = AuditLogger("/tmp/hwpshield_audit.log")
request_tracker = RequestTracker(metrics, audit_logger)
