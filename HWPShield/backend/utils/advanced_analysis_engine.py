"""
Advanced Analysis Engine - Simplified Version
"""
import os
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Simplified imports - only essential components
from .secure_validator import SecureInputValidator, SecurityLogger
from .pe_analyzer import PEAnalyzer
from .rule_based_analyzer import RuleBasedThreatAnalyzer

try:
    from .advanced_threat_detector import AdvancedThreatDetector
    HAS_ADVANCED = True
except ImportError:
    HAS_ADVANCED = False
    AdvancedThreatDetector = None

try:
    from .streaming_parser import StreamingHWPParser
    HAS_STREAMING = True
except ImportError:
    HAS_STREAMING = False
    StreamingHWPParser = None

try:
    from .ml_classifier import LightweightThreatClassifier
    HAS_ML = True
except ImportError:
    HAS_ML = False
    LightweightThreatClassifier = None

@dataclass
class AnalysisResult:
    file_info: Dict[str, Any]
    threat_assessment: Dict[str, Any]
    behavioral_analysis: Dict[str, Any]
    ml_prediction: Dict[str, Any]
    security_validation: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    recommendations: List[str]
    confidence_score: float
    overall_risk_level: str
    analysis_timestamp: str

class AdvancedAnalysisEngine:
    def __init__(self):
        self.secure_validator = SecureInputValidator()
        self.security_logger = SecurityLogger()
        self.pe_analyzer = PEAnalyzer()
        self.rule_analyzer = RuleBasedThreatAnalyzer()
        self.advanced_detector = AdvancedThreatDetector() if HAS_ADVANCED and AdvancedThreatDetector else None
        self.streaming_parser = StreamingHWPParser() if HAS_STREAMING and StreamingHWPParser else None
        self.ml_classifier = LightweightThreatClassifier() if HAS_ML and LightweightThreatClassifier else None
        self.analysis_cache = {}
    
    def analyze_comprehensive(self, filepath: str, progress_callback=None):
        """Comprehensive file analysis"""
        start_time = time.time()
        
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            filename = os.path.basename(filepath)
            
            is_valid, error, metadata = self.secure_validator.validate_file(file_data, filename)
            
            if not is_valid:
                raise ValueError(f"Validation failed: {error}")
            
            file_info = {
                'filepath': filepath,
                'filename': filename,
                'size': len(file_data),
                'hashes': metadata.get('hash', {}),
                'extension': metadata.get('extension', ''),
                'entropy': metadata.get('entropy', 0)
            }
            
            # Basic analysis
            from enhanced_scanner import analyze_file
            parse_result = analyze_file(filepath)
            
            # Update file_info with hwp_version from parse_result
            hwp_version = parse_result.get('hwp_version')
            if hwp_version:
                file_info['hwp_version'] = hwp_version
            else:
            
            # Update hashes from parse_result if available
            file_hash = parse_result.get('file_hash')
            if file_hash and isinstance(file_hash, dict) and file_hash.get('md5'):
                file_info['hashes'] = file_hash
            else:
            
            
            # Rule-based analysis
            behavioral_result = self.rule_analyzer.analyze(parse_result, 'HWP')
            
            # Calculate risk
            risk_score = behavioral_result.get('score', 0)
            risk_level = behavioral_result.get('risk_level', 'CLEAN')
            
            # ML prediction (if available)
            ml_result = {}
            if self.ml_classifier:
                try:
                    streams_data = parse_result.get('streams', {})
                    # streams can be either a dict or a list (stream names)
                    if isinstance(streams_data, list):
                        # Convert list of stream names to empty dict for ML
                        streams_dict = {}
                    else:
                        streams_dict = streams_data
                    feature_vector = self.ml_classifier.extract_features(file_data, streams_dict, parse_result)
                    prediction = self.ml_classifier.predict_threat_score(feature_vector)
                    ml_result = {
                        'ml_score': round(prediction.get('threat_score', 0), 2),
                        'ml_level': prediction.get('threat_level', 'CLEAN'),
                        'confidence': round(prediction.get('confidence', 0), 2)
                    }
                except Exception as e:
                    ml_result = {'ml_score': 0}
            else:
                ml_result = {'ml_score': 0}
            
            # Performance metrics
            analysis_time = time.time() - start_time
            
            # Recommendations
            recommendations = []
            if risk_score >= 80:
                recommendations = ["CRITICAL: Isolate immediately", "Block network access"]
            elif risk_score >= 60:
                recommendations = ["HIGH: Detailed analysis needed", "Review logs"]
            elif risk_score >= 40:
                recommendations = ["MEDIUM: Monitor activity"]
            else:
                recommendations = ["File appears safe"]
            
            result = AnalysisResult(
                file_info=file_info,
                threat_assessment={'threat_score': risk_score, 'threat_level': risk_level},
                behavioral_analysis=behavioral_result,
                ml_prediction=ml_result,
                security_validation={'is_valid': True},
                performance_metrics={
                    'analysis_time_seconds': analysis_time,
                    'file_size_mb': len(file_data) / (1024 * 1024)
                },
                recommendations=recommendations,
                confidence_score=0.8,
                overall_risk_level=risk_level,
                analysis_timestamp=datetime.now().isoformat()
            )
            return result
            
        except Exception as e:
            return self._create_error_result(filepath, str(e), start_time)
    
    def _create_error_result(self, filepath: str, error: str, start_time: float):
        return AnalysisResult(
            file_info={'filepath': filepath, 'filename': os.path.basename(filepath)},
            threat_assessment={'error': error},
            behavioral_analysis={'error': error},
            ml_prediction={'error': error},
            security_validation={'error': error},
            performance_metrics={'analysis_time_seconds': time.time() - start_time},
            recommendations=[f"Error: {error}"],
            confidence_score=0.0,
            overall_risk_level='ERROR',
            analysis_timestamp=datetime.now().isoformat()
        )
    
    def get_engine_status(self) -> Dict[str, Any]:
        """Get engine status and statistics"""
        return {
            'components': {
                'advanced_detector': 'enabled' if (HAS_ADVANCED and self.advanced_detector) else 'disabled',
                'streaming_parser': 'enabled' if (HAS_STREAMING and self.streaming_parser) else 'disabled',
                'ml_classifier': 'enabled' if (HAS_ML and self.ml_classifier) else 'disabled',
                'parallel_processing': 'disabled'
            },
            'cache_size': len(self.analysis_cache),
            'training_data_size': len(self.ml_classifier.training_data) if self.ml_classifier else 0,
            'configuration': {}
        }

# Global engine instance
advanced_engine = AdvancedAnalysisEngine()
