"""
External Antivirus Scanner Integration
Supports ClamAV and other antivirus engines for secondary scanning.
"""
import subprocess
import json
import logging
from typing import Dict, Optional, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ScanResult(Enum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    SUSPICIOUS = "SUSPICIOUS"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass
class AntivirusResult:
    """Antivirus scan result."""
    engine: str
    result: ScanResult
    threat_name: Optional[str]
    scan_time: float
    version: Optional[str]
    error_message: Optional[str] = None


class ClamAVScanner:
    """ClamAV (open source antivirus) integration."""
    
    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.engine_name = "ClamAV"
    
    def scan(self, file_path: str) -> AntivirusResult:
        """
        Scan file using clamdscan.
        
        Returns:
            AntivirusResult with scan details
        """
        import time
        start_time = time.time()
        
        try:
            # Try clamdscan first (daemon mode - faster)
            result = subprocess.run(
                ['clamdscan', '--no-summary', '--infected', file_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            scan_time = time.time() - start_time
            
            if result.returncode == 0:
                return AntivirusResult(
                    engine=self.engine_name,
                    result=ScanResult.CLEAN,
                    threat_name=None,
                    scan_time=scan_time,
                    version=self._get_version()
                )
            elif result.returncode == 1:
                # Infected
                threat = self._parse_threat(result.stdout)
                return AntivirusResult(
                    engine=self.engine_name,
                    result=ScanResult.INFECTED,
                    threat_name=threat,
                    scan_time=scan_time,
                    version=self._get_version()
                )
            else:
                return AntivirusResult(
                    engine=self.engine_name,
                    result=ScanResult.ERROR,
                    threat_name=None,
                    scan_time=scan_time,
                    version=self._get_version(),
                    error_message=result.stderr or "Unknown error"
                )
                
        except subprocess.TimeoutExpired:
            return AntivirusResult(
                engine=self.engine_name,
                result=ScanResult.TIMEOUT,
                threat_name=None,
                scan_time=self.timeout,
                version=None,
                error_message="Scan timeout"
            )
        except FileNotFoundError:
            return AntivirusResult(
                engine=self.engine_name,
                result=ScanResult.ERROR,
                threat_name=None,
                scan_time=0,
                version=None,
                error_message="ClamAV not installed (clamdscan not found)"
            )
        except Exception as e:
            return AntivirusResult(
                engine=self.engine_name,
                result=ScanResult.ERROR,
                threat_name=None,
                scan_time=0,
                version=None,
                error_message=str(e)
            )
    
    def _get_version(self) -> Optional[str]:
        """Get ClamAV version."""
        try:
            result = subprocess.run(
                ['clamdscan', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip().split()[0] if result.stdout else None
        except:
            return None
    
    def _parse_threat(self, output: str) -> Optional[str]:
        """Parse threat name from scan output."""
        # Format: "filename: Threat.Name FOUND"
        if 'FOUND' in output:
            parts = output.split(':')
            if len(parts) >= 2:
                threat_part = parts[-1].strip()
                return threat_part.replace('FOUND', '').strip()
        return "Unknown threat"
    
    def is_available(self) -> bool:
        """Check if ClamAV is installed and available."""
        try:
            subprocess.run(
                ['which', 'clamdscan'],
                capture_output=True,
                check=True
            )
            return True
        except:
            return False


class MultiEngineScanner:
    """Multi-engine antivirus scanner."""
    
    def __init__(self):
        self.scanners: List[ClamAVScanner] = []
        
        # Initialize available scanners
        clamav = ClamAVScanner()
        if clamav.is_available():
            self.scanners.append(clamav)
    
    def scan(self, file_path: str) -> List[AntivirusResult]:
        """
        Scan file with all available engines.
        
        Returns:
            List of AntivirusResult from each engine
        """
        results = []
        
        for scanner in self.scanners:
            try:
                result = scanner.scan(file_path)
                results.append(result)
            except Exception as e:
                logger.error(f"Scanner {scanner.engine_name} failed: {e}")
                results.append(AntivirusResult(
                    engine=scanner.engine_name,
                    result=ScanResult.ERROR,
                    threat_name=None,
                    scan_time=0,
                    version=None,
                    error_message=str(e)
                ))
        
        return results
    
    def get_available_engines(self) -> List[str]:
        """Get list of available scanner engines."""
        return [s.engine_name for s in self.scanners]


# Placeholder for commercial AV integration (V3, VirusTotal, etc.)
class VirusTotalScanner:
    """
    VirusTotal API integration.
    Requires API key and internet connectivity.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.engine_name = "VirusTotal"
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def scan(self, file_path: str) -> Optional[AntivirusResult]:
        """
        Upload and scan file via VirusTotal.
        Note: Requires API key and respects rate limits.
        """
        if not self.api_key:
            return AntivirusResult(
                engine=self.engine_name,
                result=ScanResult.ERROR,
                threat_name=None,
                scan_time=0,
                version=None,
                error_message="VirusTotal API key not configured"
            )
        
        # Implementation would use requests to call VirusTotal API
        # This is a placeholder
        return AntivirusResult(
            engine=self.engine_name,
            result=ScanResult.ERROR,
            threat_name=None,
            scan_time=0,
            version=None,
            error_message="VirusTotal integration not yet implemented"
        )
    
    def is_available(self) -> bool:
        return self.api_key is not None


def format_antivirus_results(results: List[AntivirusResult]) -> Dict:
    """Format antivirus results for API response."""
    return {
        "scanned_engines": len(results),
        "engines_available": len([r for r in results if r.result != ScanResult.ERROR]),
        "overall_result": _calculate_overall_result(results),
        "details": [
            {
                "engine": r.engine,
                "result": r.result.value,
                "threat_name": r.threat_name,
                "scan_time_ms": int(r.scan_time * 1000),
                "version": r.version,
                "error": r.error_message
            }
            for r in results
        ]
    }


def _calculate_overall_result(results: List[AntivirusResult]) -> str:
    """Calculate overall result from multiple engines."""
    if not results:
        return "NO_SCAN"
    
    # Priority: INFECTED > SUSPICIOUS > ERROR > TIMEOUT > CLEAN
    if any(r.result == ScanResult.INFECTED for r in results):
        return "MALICIOUS"
    if any(r.result == ScanResult.SUSPICIOUS for r in results):
        return "SUSPICIOUS"
    if all(r.result == ScanResult.ERROR for r in results):
        return "ERROR"
    if any(r.result == ScanResult.TIMEOUT for r in results):
        return "TIMEOUT"
    
    return "CLEAN"
