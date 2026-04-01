"""
Enhanced HWP/HWPX Scanner Server
Properly analyzes both HWP (CFB/OLE) and HWPX (ZIP/XML) formats
"""
import os
import sys
import json
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi
import tempfile
import shutil
import uuid
import atexit

# Import enhanced scanner
from enhanced_scanner import analyze_file
# Import security utilities
from utils.secure_file_handler import secure_handler
from utils.security_middleware import SecureRequestHandler, SECURITY_CONFIG
# Import advanced analysis engine
from utils.advanced_analysis_engine import advanced_engine

class SimpleHandler(BaseHTTPRequestHandler, SecureRequestHandler):
    """HTTP handler for file scanning with security enhancements."""
    
    def __init__(self, *args, **kwargs):
        SecureRequestHandler.__init__(self)
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        pass
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
    
    def do_GET(self):
        if self.path == '/api/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "scanner": "enhanced_hwp_analyzer",
                "version": "2.0"
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/api/analyze':
            self.handle_analyze()
        else:
            self.send_response(404)
            self.end_headers()
    
    def handle_analyze(self):
        """Handle file upload and analysis with security."""
        print(f"\n{'='*60}")
        try:
            # Parse multipart form
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' not in content_type:
                self.send_security_error(400, "INVALID_CONTENT_TYPE", f"Expected multipart/form-data, got: {content_type}")
                return
            
            # Read form data with proper content length
            content_length = int(self.headers.get('Content-Length', 0))
            
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers.get('Content-Type'),
                    'CONTENT_LENGTH': str(content_length)
                }
            )
            
            if 'file' not in form:
                self.send_security_error(400, "NO_FILE", "No file uploaded")
                return
            
            file_item = form['file']
            
            if not file_item.filename:
                self.send_security_error(400, "EMPTY_FILENAME", "Empty filename")
                return
            
            # Read file data
            file_data = file_item.file.read()
            
            if len(file_data) == 0:
                self.send_security_error(400, "EMPTY_FILE", "File data is empty (0 bytes)")
                return
            
            # Security validation
            validation_result = self.validate_request(file_data, file_item.filename)
            is_valid = validation_result[0]
            
            if not is_valid:
                error_type = validation_result[1]
                error_msg = validation_result[2]
                error_code = {
                    "RATE_LIMIT": 429,
                    "FILE_TOO_LARGE": 413,
                    "INVALID_MIME": 400,
                    "INVALID_EXTENSION": 400,
                    "DANGEROUS_CONTENT": 400
                }.get(error_type, 400)
                self.send_security_error(error_code, error_type, error_msg)
                return
            
            safe_filename = validation_result[1]
            
            # Use secure temp file handler
            with secure_handler.secure_temp_file(safe_filename, timeout_seconds=120) as (temp_path, cleanup):
                try:
                    # Write file securely
                    with open(temp_path, 'wb') as f:
                        f.write(file_data)
                    
                    # Check temp file size
                    temp_size = os.path.getsize(temp_path)
                    
                    # Perform advanced analysis
                    try:
                        analysis_result = advanced_engine.analyze_comprehensive(temp_path)
                    except Exception as e:
                        import traceback
                        analysis_result = analyze_file(temp_path)
                        basic_result = self._build_basic_response(analysis_result)
                        self._send_response(basic_result)
                        return
                    
                    # Build advanced response with original filename and size
                    result = self._build_advanced_response(analysis_result, original_filename=safe_filename, original_size=len(file_data))
                    
                    # Send response with security headers
                    self._send_response(result)
                    print(f"{'='*60}\n")
                    
                except Exception as e:
                    import traceback
                    self.send_security_error(500, "ANALYSIS_ERROR", f"File analysis failed: {str(e)}")
                    
        except Exception as e:
            import traceback
            self.send_security_error(500, "SERVER_ERROR", f"Internal server error: {str(e)}")
    
    def _build_secure_response(self, analysis_result: dict) -> dict:
        """Build secure response without sensitive data"""
        # Filter indicators to remove sensitive information
        safe_indicators = []
        for indicator in analysis_result.get('indicators', []):
            safe_indicator = {
                'type': indicator.get('type', 'unknown'),
                'description': indicator.get('description', ''),
                'severity': indicator.get('severity', 'low'),
                'score': indicator.get('score', 0)
            }
            safe_indicators.append(safe_indicator)
        
        # Filter threats
        safe_threats = []
        for threat in analysis_result.get('threats', []):
            safe_threat = {
                'type': threat.get('type', 'unknown'),
                'description': threat.get('description', ''),
                'score': threat.get('score', 0),
                'category': threat.get('category', 'LOW')
            }
            safe_threats.append(safe_threat)
        
        # Build response
        result = {
            "filename": analysis_result['filename'],
            "file_hash": analysis_result['file_hash'],
            "file_size": analysis_result['file_size'],
            "actual_format": analysis_result['actual_format'],
            "hwp_version": analysis_result['hwp_version'],
            "analysis_timestamp": datetime.now().isoformat(),
            "overall_risk": analysis_result['overall_risk'],
            "risk_score": analysis_result['risk_score'],
            "header_flags": analysis_result.get('header_flags', {}),
            "modules": [
                {
                    "id": "format_detector",
                    "name": "포맷 분석기",
                    "name_en": "Format Detector",
                    "status": "DETECTED" if analysis_result['actual_format'] != 'unknown' else "CLEAN",
                    "score_contribution": 0,
                    "indicators": [{
                        "type": "format",
                        "value": analysis_result['actual_format'],
                        "severity": "info"
                    }],
                    "details": f"파일 형식: {analysis_result['actual_format']}"
                },
                {
                    "id": "threat_detector",
                    "name": "위협 탐지기",
                    "name_en": "Threat Detector",
                    "status": "DETECTED" if len(safe_threats) > 0 else "CLEAN",
                    "score_contribution": analysis_result['risk_score'],
                    "indicators": safe_indicators,
                    "details": f"{len(safe_threats)}개 위협 패턴 탐지" if safe_threats else "위협 없음"
                }
            ],
            "threats": safe_threats,
            "iocs": analysis_result.get('iocs', []),
            "analysis_details": {
                "has_eps": analysis_result.get('analysis_details', {}).get('has_eps', False),
                "has_macro": analysis_result.get('analysis_details', {}).get('has_macro', False),
                "ole_object_count": analysis_result.get('analysis_details', {}).get('ole_object_count', 0),
                "external_link_count": analysis_result.get('analysis_details', {}).get('external_link_count', 0)
            },
            "message": self._get_risk_message(analysis_result['overall_risk'])
        }
        
        return result
    
    def _build_advanced_response(self, analysis_result, original_filename=None, original_size=None) -> dict:
        """Build comprehensive response from advanced analysis"""
        from dataclasses import asdict
        import json
        
        
        # Convert AnalysisResult to dict
        result_dict = asdict(analysis_result)
        
        # Debug full result_dict structure
        
        # Get file_info safely
        file_info = result_dict.get("file_info", {})
        
        # Use original filename and size if provided, otherwise fall back to analysis result
        final_filename = original_filename if original_filename else file_info.get("filename", "unknown")
        final_size = original_size if original_size is not None else file_info.get("size", 0)
        
        
        # Build API response with safe defaults
        api_response = {
            "filename": final_filename,
            "file_hash": file_info.get("hashes", {}),
            "file_size": final_size,
            "hwp_version": file_info.get("hwp_version", "알 수 없음"),
            "analysis_timestamp": result_dict.get("analysis_timestamp", ""),
            "overall_risk": result_dict.get("overall_risk_level", "ERROR"),
            "confidence_score": result_dict.get("confidence_score", 0),
            "recommendations": result_dict.get("recommendations", []),
            
            # Advanced threat assessment
            "advanced_threats": {
                "threat_score": result_dict.get("threat_assessment", {}).get("threat_score", 0),
                "threat_level": result_dict.get("threat_assessment", {}).get("threat_level", "CLEAN"),
                "signatures_detected": result_dict.get("threat_assessment", {}).get("signatures_detected", []),
                "behavioral_indicators": result_dict.get("threat_assessment", {}).get("behavioral_indicators", []),
                "obfuscation_evidence": result_dict.get("threat_assessment", {}).get("obfuscation_evidence", {})
            },
            
            # Behavioral analysis
            "behavioral_analysis": {
                "mitre_techniques": result_dict.get("behavioral_analysis", {}).get("mitre_techniques", []),
                "kill_chain_phase": result_dict.get("behavioral_analysis", {}).get("kill_chain_phase", "unknown"),
                "rule_based_score": result_dict.get("behavioral_analysis", {}).get("rule_based_analysis", {}).get("score", 0)
            },
            
            # ML prediction
            "ml_prediction": {
                "ml_score": result_dict.get("ml_prediction", {}).get("ml_score", 0),
                "ml_level": result_dict.get("ml_prediction", {}).get("ml_level", "CLEAN"),
                "confidence": result_dict.get("ml_prediction", {}).get("confidence", 0),
                "top_features": result_dict.get("ml_prediction", {}).get("top_features", [])
            },
            
            # Performance metrics
            "performance": {
                "analysis_time_seconds": result_dict["performance_metrics"].get("analysis_time_seconds", 0),
                "processing_rate_mbps": result_dict["performance_metrics"].get("processing_rate_mbps", 0),
                "file_size_mb": result_dict["performance_metrics"].get("file_size_mb", 0)
            },
            
            # Modules for UI compatibility
            "modules": [
                {
                    "id": "advanced_detector",
                    "name": "고급 위협 탐지기",
                    "name_en": "Advanced Threat Detector",
                    "status": result_dict["overall_risk_level"],
                    "score_contribution": result_dict["threat_assessment"].get("threat_score", 0),
                    "indicators": self._convert_indicators(result_dict["threat_assessment"]),
                    "details": f"고급 분석 위협 점수: {result_dict['threat_assessment'].get('threat_score', 0)}",
                    "analysis_summary": result_dict["threat_assessment"].get("analysis_summary", "분석 정보 없음"),
                    "signatures_found": result_dict["threat_assessment"].get("signatures_detected", []),
                    "patterns_checked": result_dict["threat_assessment"].get("patterns_checked", 0),
                    "streams_analyzed": result_dict["threat_assessment"].get("streams_analyzed", 0)
                },
                {
                    "id": "ml_classifier",
                    "name": "ML 분류기",
                    "name_en": "ML Classifier",
                    "status": result_dict["ml_prediction"].get("ml_level", "CLEAN"),
                    "score_contribution": result_dict["ml_prediction"].get("ml_score", 0),
                    "indicators": [],
                    "details": f"ML 위협 점수: {result_dict['ml_prediction'].get('ml_score', 0)}",
                    "ml_confidence": result_dict["ml_prediction"].get("confidence", 0),
                    "top_features": result_dict["ml_prediction"].get("top_features", []),
                    "model_version": result_dict["ml_prediction"].get("model_version", "unknown")
                },
                {
                    "id": "behavioral_analyzer",
                    "name": "행동 분석기",
                    "name_en": "Behavioral Analyzer",
                    "status": result_dict["behavioral_analysis"].get("rule_based_analysis", {}).get("risk_level", "CLEAN"),
                    "score_contribution": result_dict["behavioral_analysis"].get("rule_based_analysis", {}).get("score", 0),
                    "indicators": self._convert_behavioral_indicators(result_dict["behavioral_analysis"]),
                    "details": f"MITRE 기법: {len(result_dict['behavioral_analysis'].get('mitre_techniques', []))}개",
                    "rule_based_score": result_dict["behavioral_analysis"].get("rule_based_analysis", {}).get("score", 0),
                    "rules_triggered": result_dict["behavioral_analysis"].get("rule_based_analysis", {}).get("rules_triggered", []),
                    "patterns_detected": result_dict["behavioral_analysis"].get("patterns_detected", [])
                }
            ],
            
            # Legacy compatibility
            "threats": self._convert_legacy_threats(result_dict["threat_assessment"]),
            "indicators": self._convert_indicators(result_dict["threat_assessment"]),
            "risk_score": result_dict["threat_assessment"].get("threat_score", 0),
            "message": self._get_risk_message(result_dict["overall_risk_level"])
        }
        
        return api_response
    
    def _build_basic_response(self, analysis_result: dict) -> dict:
        """Build basic response for fallback analysis"""
        return self._build_secure_response(analysis_result)
    
    def _convert_indicators(self, threat_assessment: dict) -> list:
        """Convert threat assessment to indicator format"""
        indicators = []
        
        # From signatures detected
        for signature in threat_assessment.get("signatures_detected", []):
            indicators.append({
                "type": signature.get("category", "unknown"),
                "description": signature.get("description", ""),
                "severity": "high" if signature.get("weight", 0) > 0.7 else "medium",
                "score": signature.get("risk_contribution", 0) * 100
            })
        
        return indicators
    
    def _convert_behavioral_indicators(self, behavioral_analysis: dict) -> list:
        """Convert behavioral analysis to indicator format"""
        indicators = []
        
        for technique in behavioral_analysis.get("mitre_techniques", []):
            indicators.append({
                "type": "mitre_technique",
                "description": technique,
                "severity": "high",
                "score": 50
            })
        
        return indicators
    
    def _convert_legacy_threats(self, threat_assessment: dict) -> list:
        """Convert to legacy threat format"""
        threats = []
        
        # From signatures
        for signature in threat_assessment.get("signatures_detected", []):
            threats.append({
                "type": signature.get("category", "unknown"),
                "description": signature.get("description", ""),
                "score": signature.get("risk_contribution", 0) * 100,
                "category": "HIGH" if signature.get("weight", 0) > 0.7 else "MEDIUM"
            })
        
        return threats
    
    def _send_response(self, response: dict):
        """Send HTTP response with security headers"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.add_security_headers()
        self.end_headers()
        self.wfile.write(json.dumps(response, ensure_ascii=False).encode())
    
    def _get_risk_message(self, risk: str) -> str:
        messages = {
            "CLEAN": "정상 파일로 판단됩니다",
            "SUSPICIOUS": "의심스러운 요소가 발견되었습니다. 주의가 필요합니다",
            "HIGH_RISK": "높은 위험이 감지되었습니다. 실행을 자제하세요",
            "MALICIOUS": "악성 코드가 탐지되었습니다! 절대 실행하지 마세요",
            "ERROR": "분석 중 오류가 발생했습니다"
        }
        return messages.get(risk, "알 수 없음")


def run_server(port=8080):
    """Run HTTP server."""
    server = HTTPServer(('0.0.0.0', port), SimpleHandler)
    print(f"╔════════════════════════════════════════════════════════════╗")
    print(f"║     Enhanced HWP/HWPX Scanner Server v2.0                ║")
    print(f"╠════════════════════════════════════════════════════════════╣")
    print(f"║  Server running at: http://localhost:{port}/                  ║")
    print(f"║  API endpoint:      http://localhost:{port}/api/analyze       ║")
    print(f"║  Health check:     http://localhost:{port}/api/health         ║")
    print(f"╚════════════════════════════════════════════════════════════╝")
    print(f"\nSupported formats:")
    print(f"  • HWP (OLE/CFB) - Legacy Hancom format")
    print(f"  • HWPX (ZIP/XML) - OWPML standard format")
    print(f"\nDetection capabilities:")
    print(f"  • EPS exploit (CVE-2017-8291)")
    print(f"  • OLE objects with executables")
    print(f"  • Script/Macro storage")
    print(f"  • External URL references")
    print(f"  • TEMP path execution indicators")
    print(f"\nPress Ctrl+C to stop\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        server.shutdown()


if __name__ == '__main__':
    # Get port from command line arguments
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}. Using default port 8000.")
            port = 8000
    
    run_server(port)
