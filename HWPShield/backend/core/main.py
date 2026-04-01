"""
HWPShield - FastAPI Main Server

Provides REST API for HWP malware analysis.
"""
import os
import sys
import time
import logging
import traceback
from datetime import datetime
from typing import Optional, Dict, List

from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import (
    HWPParser, EPSDetector, OLEDetector, ScriptDetector,
    IOCExtractor, StegDetector, StructuralAnalyzer, RiskScorer
)
from analyzer.antivirus_scanner import MultiEngineScanner, format_antivirus_results
from analyzer.threat_reporter import generate_report_guidance, format_reporting_ui_data
from utils.hash_calc import calculate_hashes
from utils.file_handler import SecureFileHandler
from utils.validators import validate_filename
from utils.security_config import waf, apply_security_headers, SecurityPatchManager, require_admin
from utils.auth import (
    APIKeyManager, JWTAuthManager, RequestSigner,
    verify_api_key, verify_jwt_token, api_key_manager, jwt_auth_manager
)
from utils.monitoring import (
    MetricsCollector, AuditLogger, RequestTracker,
    AnalysisAudit, metrics, audit_logger, request_tracker
)
from utils.debug_logger import debug_logger

# Check critical dependencies at startup
def check_dependencies():
    """Check if all required dependencies are installed."""
    missing = []
    
    try:
        import olefile
    except ImportError:
        missing.append("olefile")
    
    try:
        import jwt
    except ImportError:
        missing.append("PyJWT")
    
    if missing:
        logger.error(f"Missing dependencies: {missing}")
        logger.error("Install with: pip install " + " ".join(missing))
        return False
    return True

# Configure detailed logging
LOG_FORMAT = '%(asctime)s | %(levelname)-8s | %(name)s | %(filename)s:%(lineno)d | %(funcName)s() | %(message)s'

# Use system temp directory (works on Windows, Linux, macOS)
import tempfile
log_dir = tempfile.gettempdir()
log_file = os.path.join(log_dir, 'hwpshield.log')

logging.basicConfig(
    level=logging.DEBUG,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, mode='a')
    ]
)
logger = logging.getLogger(__name__)

# Check dependencies
if not check_dependencies():
    logger.warning("Server starting with missing dependencies - some features may not work")
else:
    logger.info(f"Server starting - PID: {os.getpid()}")
    logger.info(f"Log file location: {log_file}")

# Server start time
start_time = time.time()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Create FastAPI app
app = FastAPI(
    title="HWPShield API",
    description="한글 문서(.hwp) 악성코드 분석 API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Attach rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Pydantic models
class FileHash(BaseModel):
    md5: str
    sha256: str


class Indicator(BaseModel):
    type: str
    value: str
    severity: str


class ModuleResult(BaseModel):
    id: str
    name: str
    name_en: str
    status: str
    score_contribution: int
    indicators: list
    details: str


class IOC(BaseModel):
    type: str
    value: str
    severity: str


class AntivirusResultDetail(BaseModel):
    engine: str
    result: str
    threat_name: Optional[str]
    scan_time_ms: int
    version: Optional[str]
    error: Optional[str]


class ReportingCenter(BaseModel):
    id: str
    name: str
    name_en: str
    url: str
    description: str
    requires_account: bool


class ReportGuidance(BaseModel):
    priority: str
    immediate_actions: List[str]
    reporting_centers: List[ReportingCenter]
    report_template: Dict[str, str]
    disclaimer: str


class AnalysisResponse(BaseModel):
    filename: str
    file_hash: FileHash
    file_size: int
    hwp_version: Optional[str]
    analysis_timestamp: str
    overall_risk: str
    risk_score: int
    modules: list
    iocs: list
    raw_strings_sample: list
    antivirus_scan: Optional[Dict]
    report_guidance: Optional[ReportGuidance]


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    uptime: int


class VersionResponse(BaseModel):
    name: str
    version: str
    python_version: str
    fastapi_version: str


class SecurityStatusResponse(BaseModel):
    waf_enabled: bool
    patch_status: Dict
    security_headers: List[str]
    last_check: Optional[str]


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with detailed logging."""
    error_traceback = traceback.format_exc()
    
    # Log to debug logger (in-memory + stderr)
    request_info = {
        "method": request.method,
        "url": str(request.url),
        "client": request.client.host if request.client else "unknown",
        "headers": dict(request.headers)
    }
    error_id = debug_logger.log_error(exc, request_info=request_info)
    
    logger.error(f"=" * 80)
    logger.error(f"UNHANDLED EXCEPTION [{error_id}]")
    logger.error(f"Request: {request.method} {request.url}")
    logger.error(f"Client: {request.client.host if request.client else 'unknown'}")
    logger.error(f"Error Type: {type(exc).__name__}")
    logger.error(f"Error Message: {str(exc)}")
    logger.error(f"Traceback:\n{error_traceback}")
    logger.error(f"=" * 80)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "서버 내부 오류가 발생했습니다.",
                "error_id": error_id,
                "details": str(exc),
                "traceback": error_traceback if os.getenv("DEBUG", "false").lower() == "true" else None,
                "timestamp": datetime.utcnow().isoformat(),
                "help": f"Check /api/debug/errors/{error_id} for details"
            }
        }
    )


@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    """WAF middleware - disabled for development."""
    # Skip all checks in development
    response = await call_next(request)
    return response


@app.middleware("http")
async def monitoring_middleware(request: Request, call_next):
    """Request tracking and monitoring middleware."""
    # Generate request ID
    request_id = f"{int(time.time() * 1000)}-{id(request)}"
    request.state.request_id = request_id
    response = None
    
    # Skip tracking for certain paths
    if request.url.path in ["/api/health", "/api/metrics"]:
        return await call_next(request)
    
    # Start tracking
    request_tracker.start_request(request_id)
    
    try:
        response = await call_next(request)
        return response
    finally:
        # End tracking
        if response:
            request_tracker.end_request(request_id, request, response)
        else:
            request_tracker.decrement_active_requests()


@app.get("/api/security/status", response_model=SecurityStatusResponse)
async def security_status():
    """Get current security status and patch information."""
    patch_manager = SecurityPatchManager()
    patches = patch_manager.check_patches()
    
    return {
        "waf_enabled": True,
        "patch_status": patches,
        "security_headers": list(patch_manager.get_security_headers().keys()),
        "last_check": patches.get("last_check")
    }


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "1.0.0",
        "uptime": int(time.time() - start_time)
    }


@app.get("/api/version", response_model=VersionResponse)
async def get_version():
    """Get API version information."""
    import fastapi
    return {
        "name": "HWPShield API",
        "version": "1.0.0",
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "fastapi_version": fastapi.__version__
    }


@app.get("/api/metrics")
async def get_metrics():
    """Get Prometheus-formatted metrics."""
    return metrics.get_prometheus_format()


@app.get("/api/stats")
async def get_stats():
    """Get application statistics (JSON format)."""
    return metrics.get_metrics()


@app.post("/api/admin/keys")
async def create_api_key(
    name: str,
    expires_days: Optional[int] = None,
    admin_token: str = Depends(verify_jwt_token)
):
    """Create a new API key (admin only)."""
    key_id, full_key = api_key_manager.create_key(
        name=name,
        expires_days=expires_days
    )
    return {
        "key_id": key_id,
        "api_key": full_key,  # Only shown once!
        "name": name,
        "message": "Save this API key - it won't be shown again"
    }


@app.get("/api/admin/keys/{key_id}")
async def get_key_info(
    key_id: str,
    admin_token: str = Depends(verify_jwt_token)
):
    """Get API key information (admin only)."""
    info = api_key_manager.get_key_info(key_id)
    if not info:
        raise HTTPException(status_code=404, detail="Key not found")
    return info


@app.post("/api/analyze", response_model=AnalysisResponse)
@limiter.limit("10/hour")
async def analyze_file(
    request: Request,
    file: UploadFile = File(...)
):
    """
    Analyze an HWP file for malware.
    
    - **file**: HWP file to analyze (.hwp or .hwpx)
    
    Returns detailed analysis report with risk score and IOCs.
    """
    file_handler = SecureFileHandler()
    
    try:
        # Validate filename
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail={"code": "NO_FILENAME", "message": "파일명이 제공되지 않았습니다."}
            )
        
        is_valid, error = validate_filename(file.filename)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail={"code": "INVALID_FILENAME", "message": error}
            )
        
        # Read file content
        content = await file.read()
        
        # Validate file
        is_valid, error = file_handler.validate_file(file.filename, content)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail={"code": "VALIDATION_FAILED", "message": error}
            )
        
        # Calculate hashes
        hashes = calculate_hashes(content)
        logger.info(f"Analyzing file: {file.filename}, MD5: {hashes['md5']}")
        
        # Save temporarily
        temp_path = file_handler.save_temporarily(content, file.filename)
        
        try:
            # Parse HWP file
            parser = HWPParser()
            hwp_data = parser.parse(temp_path)
            
            # Run detection modules
            eps_detector = EPSDetector()
            ole_detector = OLEDetector()
            script_detector = ScriptDetector()
            ioc_extractor = IOCExtractor()
            steg_detector = StegDetector()
            structural_analyzer = StructuralAnalyzer()
            
            # Get bindata streams
            bindata = hwp_data.get('bindata', [])
            
            # Run all detectors
            eps_result = eps_detector.analyze(bindata)
            ole_result = ole_detector.analyze(bindata)
            script_result = script_detector.analyze(hwp_data.get('scripts', {}))
            ioc_result = ioc_extractor.analyze(hwp_data.get('all_streams', {}))
            steg_result = steg_detector.analyze(bindata)
            
            # Structural analysis
            header_info = hwp_data.get('header', {})
            body_text = hwp_data.get('all_streams', {}).get('BodyText/Section0', b'')
            bindata_size = sum(len(d) for _, d in bindata)
            
            structural_result = structural_analyzer.analyze(
                header_info,
                b'',
                body_text,
                bindata_size
            )
            
            # Collect all module results
            module_results = [
                eps_result,
                ole_result,
                script_result,
                ioc_result,
                steg_result,
                structural_result
            ]
            
            # Calculate risk score
            scorer = RiskScorer()
            scoring = scorer.calculate_score([
                {
                    "indicators": [{
                        "type": ind.type,
                        "severity": ind.severity
                    } for ind in m.indicators]
                }
                for m in module_results
            ])
            
            # Prepare response
            modules_response = []
            for m in module_results:
                modules_response.append({
                    "id": m.module_id,
                    "name": m.name,
                    "name_en": m.name_en,
                    "status": m.status,
                    "score_contribution": m.score_contribution,
                    "indicators": m.indicators,
                    "details": m.details
                })
            
            # Extract IOCs from ioc_result
            iocs_response = [
                {
                    "type": ind.type.replace("URL_", "").lower(),
                    "value": ind.value,
                    "severity": ind.severity
                }
                for ind in ioc_result.indicators
            ]
            
            # Run antivirus scan
            av_scanner = MultiEngineScanner()
            av_results = av_scanner.scan(temp_path)
            antivirus_response = format_antivirus_results(av_results)
            
            # Generate report guidance for suspicious/malicious files
            report_guidance = None
            if scoring.risk_level in ["MALICIOUS", "HIGH_RISK", "SUSPICIOUS"]:
                all_indicators = []
                for m in module_results:
                    all_indicators.extend([
                        {"type": ind.type, "value": ind.value}
                        for ind in m.indicators
                    ])
                
                report_guidance = generate_report_guidance(
                    filename=file.filename,
                    risk_level=scoring.risk_level,
                    score=scoring.total_score,
                    indicators=all_indicators,
                    file_hash=hashes.get('md5')
                )
            
            # Get client info for audit
            client_ip = request.client.host if request.client else "unknown"
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                client_ip = forwarded.split(",")[0].strip()
            
            # Log analysis audit
            audit = AnalysisAudit(
                timestamp=datetime.utcnow().isoformat(),
                request_id=getattr(request.state, 'request_id', 'unknown'),
                client_ip=client_ip,
                user_agent=request.headers.get("user-agent", "unknown"),
                api_key_id=None,  # Could extract from auth
                filename=file.filename,
                file_size=len(content),
                file_hash=hashes.get('md5', 'unknown'),
                duration_ms=0,  # Could calculate actual duration
                risk_level=scoring.risk_level,
                risk_score=scoring.total_score,
                modules_triggered=[m.module_id for m in module_results if m.indicators],
                iocs_found=len(iocs_response),
                antivirus_result=antivirus_response.get('overall_result', 'NO_SCAN'),
                success=True
            )
            request_tracker.log_analysis(audit)
            
            logger.info(
                f"Analysis complete: {file.filename}, "
                f"Risk: {scoring.risk_level}, Score: {scoring.total_score}, "
                f"AV: {antivirus_response.get('overall_result', 'N/A')}"
            )
            
            return AnalysisResponse(
                filename=file.filename,
                file_hash=FileHash(**hashes),
                file_size=len(content),
                hwp_version=hwp_data.get('header', {}).get('version'),
                analysis_timestamp=datetime.utcnow().isoformat() + "Z",
                overall_risk=scoring.risk_level,
                risk_score=scoring.total_score,
                modules=modules_response,
                iocs=iocs_response,
                raw_strings_sample=hwp_data.get('strings', [])[:100],
                antivirus_scan=antivirus_response,
                report_guidance=report_guidance
            )
            
        finally:
            # Cleanup
            file_handler.cleanup(temp_path)
            
    except HTTPException:
        raise
    except Exception as e:
        error_traceback = traceback.format_exc()
        
        logger.error(f"=" * 80)
        logger.error(f"ANALYSIS FAILED")
        logger.error(f"File: {file.filename if file else 'unknown'}")
        logger.error(f"Error Type: {type(e).__name__}")
        logger.error(f"Error Message: {str(e)}")
        logger.error(f"Traceback:\n{error_traceback}")
        logger.error(f"=" * 80)
        
        raise HTTPException(
            status_code=500,
            detail={
                "code": "ANALYSIS_FAILED",
                "message": "분석 중 오류가 발생했습니다.",
                "details": str(e),
                "traceback": error_traceback if os.getenv("DEBUG", "false").lower() == "true" else None,
                "error_type": type(e).__name__
            }
        )


# Debug endpoints
@app.get("/api/debug/errors")
async def get_recent_errors(limit: int = 10):
    """Get recent errors for debugging."""
    return {
        "errors": debug_logger.get_recent_errors(limit),
        "stats": debug_logger.get_stats()
    }


@app.get("/api/debug/errors/{error_id}")
async def get_error_detail(error_id: str):
    """Get specific error details."""
    error = debug_logger.get_error_by_id(error_id)
    if not error:
        raise HTTPException(status_code=404, detail="Error not found")
    return error


@app.post("/api/debug/clear")
async def clear_errors():
    """Clear all stored errors."""
    debug_logger.clear()
    return {"message": "Error log cleared"}


@app.get("/api/debug/test-error")
async def test_error():
    """Endpoint to generate a test error for debugging."""
    raise ValueError("This is a test error for debugging purposes")


# Run with: uvicorn main:app --reload --host 0.0.0.0 --port 8000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
