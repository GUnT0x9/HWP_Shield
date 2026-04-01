"""
Simple HWP Scanner Engine
Minimal HWP file scanner without advanced features
"""
import os
import sys
import re
import struct
from typing import Dict, List, Optional, Any

class SimpleHWPSniffer:
    """Simple HWP threat detection engine"""
    
    def __init__(self):
        # Basic threat patterns
        self.threat_patterns = {
            'executable': [
                b'MZ',                    # DOS header
                b'PE\0\0',               # PE header
                b'\x7fELF',              # ELF header
            ],
            'eps_exploit': [
                b'eqproc',               # EPS operator
                b'system',               # System command
                b'execute',              # Execute command
                b'ShellExecute',         # Windows Shell API
            ],
            'suspicious_strings': [
                b'%TEMP%',               # Temp path
                b'temp\\',               # Windows temp
                b'cmd.exe',              # Command prompt
                b'powershell',           # PowerShell
                b'wscript',              # Windows Script Host
                b'cscript',              # Windows Script Host
                b'URLDownloadToFile',    # URL download API
            ],
            'external_links': [
                b'http://',
                b'https://',
                b'ftp://',
            ]
        }
        
        # Risk scores
        self.risk_scores = {
            'executable': 50,
            'eps_exploit': 30,
            'suspicious_strings': 20,
            'external_links': 10
        }
    
    def scan_file(self, filepath: str) -> Dict[str, Any]:
        """Scan HWP file for threats"""
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            result = {
                'filename': os.path.basename(filepath),
                'file_size': len(file_data),
                'threats': [],
                'risk_score': 0,
                'risk_level': 'CLEAN',
                'scan_time': self._get_timestamp()
            }
            
            # Scan for each threat category
            for category, patterns in self.threat_patterns.items():
                found_threats = self._scan_patterns(file_data, patterns, category)
                result['threats'].extend(found_threats)
                
                # Add risk score
                if found_threats:
                    result['risk_score'] += self.risk_scores[category]
            
            # Determine risk level
            result['risk_level'] = self._get_risk_level(result['risk_score'])
            
            # Add summary
            result['threat_count'] = len(result['threats'])
            result['summary'] = self._generate_summary(result)
            
            return result
            
        except Exception as e:
            return {
                'filename': os.path.basename(filepath),
                'error': str(e),
                'risk_level': 'ERROR',
                'scan_time': self._get_timestamp()
            }
    
    def _scan_patterns(self, data: bytes, patterns: List[bytes], category: str) -> List[Dict[str, Any]]:
        """Scan for specific patterns in data"""
        found = []
        
        for pattern in patterns:
            positions = []
            start = 0
            
            while True:
                pos = data.find(pattern, start)
                if pos == -1:
                    break
                
                positions.append(pos)
                start = pos + len(pattern)
            
            if positions:
                found.append({
                    'type': category,
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'positions': positions,
                    'count': len(positions)
                })
        
        return found
    
    def _get_risk_level(self, score: int) -> str:
        """Determine risk level from score"""
        if score >= 80:
            return 'MALICIOUS'
        elif score >= 60:
            return 'HIGH_RISK'
        elif score >= 40:
            return 'SUSPICIOUS'
        elif score >= 20:
            return 'LOW_RISK'
        else:
            return 'CLEAN'
    
    def _generate_summary(self, result: Dict[str, Any]) -> str:
        """Generate scan summary"""
        if result['risk_level'] == 'MALICIOUS':
            return f"악성 코드가 탐지되었습니다! 위협 점수: {result['risk_score']}"
        elif result['risk_level'] == 'HIGH_RISK':
            return f"높은 위험이 감지되었습니다. 위협 점수: {result['risk_score']}"
        elif result['risk_level'] == 'SUSPICIOUS':
            return f"의심스러운 요소가 발견되었습니다. 위협 점수: {result['risk_score']}"
        elif result['risk_level'] == 'LOW_RISK':
            return f"낮은 위험이 감지되었습니다. 위협 점수: {result['risk_score']}"
        else:
            return "정상 파일로 판단됩니다"
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Simple HTTP server
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class SimpleScannerHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for HWP scanning"""
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/':
            self._send_html_response()
        elif self.path == '/health':
            self._send_json_response({'status': 'ok', 'message': 'Scanner ready'})
        else:
            self._send_404()
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/scan':
            self._handle_scan()
        else:
            self._send_404()
    
    def _handle_scan(self):
        """Handle file scan request"""
        try:
            # Get content type
            content_type = self.headers.get('Content-Type', '')
            
            if 'multipart/form-data' in content_type:
                # Parse multipart form data
                import cgi
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={'REQUEST_METHOD': 'POST'}
                )
                
                if 'file' not in form:
                    self._send_error('No file uploaded')
                    return
                
                file_item = form['file']
                filename = file_item.filename
                file_data = file_item.file.read()
                
                # Save to temp file
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix='.hwp') as tmp:
                    tmp.write(file_data)
                    tmp_path = tmp.name
                
                try:
                    # Scan file
                    scanner = SimpleHWPSniffer()
                    result = scanner.scan_file(tmp_path)
                    
                    # Add file info
                    result['original_filename'] = filename
                    
                    self._send_json_response(result)
                    
                finally:
                    # Clean up temp file
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
            
            else:
                self._send_error('Unsupported content type')
                
        except Exception as e:
            self._send_error(f'Scan error: {str(e)}')
    
    def _send_html_response(self):
        """Send HTML response"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>HWP Scanner</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .upload-area { 
            border: 2px dashed #ccc; 
            padding: 40px; 
            text-align: center; 
            margin: 20px 0;
        }
        .btn { 
            background: #007bff; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            cursor: pointer;
        }
        .result { 
            margin: 20px 0; 
            padding: 20px; 
            border-radius: 5px;
        }
        .clean { background: #d4edda; border: 1px solid #c3e6cb; }
        .suspicious { background: #fff3cd; border: 1px solid #ffeaa7; }
        .high-risk { background: #f8d7da; border: 1px solid #f5c6cb; }
        .malicious { background: #f5c6cb; border: 1px solid #f1b0b7; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 HWP 파일 검색엔진</h1>
        <p>HWP/HWPX 파일의 위협을 스캔합니다.</p>
        
        <form action="/scan" method="post" enctype="multipart/form-data">
            <div class="upload-area">
                <input type="file" name="file" accept=".hwp,.hwpx" required>
                <br><br>
                <button type="submit" class="btn">파일 스캔</button>
            </div>
        </form>
        
        <div id="result"></div>
    </div>
    
    <script>
        document.querySelector('form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const resultDiv = document.getElementById('result');
            
            resultDiv.innerHTML = '<p>스캔 중...</p>';
            
            fetch('/scan', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                let riskClass = 'clean';
                if (data.risk_level === 'MALICIOUS') riskClass = 'malicious';
                else if (data.risk_level === 'HIGH_RISK') riskClass = 'high-risk';
                else if (data.risk_level === 'SUSPICIOUS') riskClass = 'suspicious';
                else if (data.risk_level === 'LOW_RISK') riskClass = 'suspicious';
                
                resultDiv.innerHTML = `
                    <div class="result ${riskClass}">
                        <h3>스캔 결과</h3>
                        <p><strong>파일:</strong> ${data.original_filename || data.filename}</p>
                        <p><strong>위험 수준:</strong> ${data.risk_level}</p>
                        <p><strong>위협 점수:</strong> ${data.risk_score}</p>
                        <p><strong>발견된 위협:</strong> ${data.threat_count}개</p>
                        <p><strong>요약:</strong> ${data.summary}</p>
                        <p><strong>스캔 시간:</strong> ${data.scan_time}</p>
                    </div>
                `;
            })
            .catch(error => {
                resultDiv.innerHTML = `<div class="result malicious"><p>오류: ${error.message}</p></div>`;
            });
        });
    </script>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def _send_json_response(self, data):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))
    
    def _send_error(self, message):
        """Send error response"""
        self.send_response(400)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode('utf-8'))
    
    def _send_404(self):
        """Send 404 response"""
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'404 Not Found')
    
    def log_message(self, format, *args):
        """Disable logging"""
        pass

def run_server(port=3000):
    """Run the simple scanner server"""
    server = HTTPServer(('localhost', port), SimpleScannerHandler)
    print(f"🔍 HWP Scanner Engine running on http://localhost:{port}")
    print("📁 Upload HWP files to scan for threats")
    print("🛑 Press Ctrl+C to stop the server")
    print()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
        server.shutdown()

if __name__ == '__main__':
    import sys
    
    # Get port from command line
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except:
            pass
    
    run_server(port)
