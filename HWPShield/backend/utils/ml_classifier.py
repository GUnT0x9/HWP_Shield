"""
Machine Learning Assisted Threat Detection
Lightweight ML models for threat pattern recognition
"""
import os
import json
import pickle
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from collections import defaultdict, Counter
import hashlib
import struct

# Make numpy optional
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    # Simple fallback for numpy functions
    class MockNp:
        @staticmethod
        def var(data):
            if not data:
                return 0.0
            mean = sum(data) / len(data)
            return sum((x - mean) ** 2 for x in data) / len(data)
        
        @staticmethod
        def mean(data):
            if not data:
                return 0.0
            return sum(data) / len(data)
        
        @staticmethod
        def log(x):
            import math
            return math.log(x) if x > 0 else 0.0
    
    np = MockNp()

@dataclass
class FeatureVector:
    """Feature vector for ML classification"""
    file_hash: str
    features: Dict[str, float]
    label: Optional[str] = None
    confidence: float = 0.0

class LightweightThreatClassifier:
    """Lightweight ML classifier for threat detection"""
    
    def __init__(self):
        self.feature_extractors = self._init_feature_extractors()
        self.model_weights = self._load_default_weights()
        self.feature_importance = {}
        self.training_data = []
        
    def _init_feature_extractors(self) -> Dict[str, callable]:
        """Initialize feature extraction functions"""
        return {
            'file_structure_features': self._extract_file_structure_features,
            'entropy_features': self._extract_entropy_features,
            'pattern_features': self._extract_pattern_features,
            'stream_features': self._extract_stream_features,
            'byte_frequency_features': self._extract_byte_frequency_features,
            'string_features': self._extract_string_features,
            'api_features': self._extract_api_features,
            'obfuscation_features': self._extract_obfuscation_features
        }
    
    def _load_default_weights(self) -> Dict[str, float]:
        """Load default model weights (pre-trained)"""
        # These would normally be trained on a dataset
        # For now, using heuristic weights based on security expertise
        return {
            # File structure features
            'has_pe_structure': 0.85,
            'has_ole_structure': 0.15,
            'file_size_ratio': 0.25,
            'stream_count': 0.20,
            
            # Entropy features
            'mean_entropy': 0.70,
            'entropy_variance': 0.60,
            'high_entropy_ratio': 0.75,
            'entropy_peaks': 0.65,
            
            # Pattern features
            'mz_pattern_count': 0.40,
            'eps_pattern_count': 0.80,
            'api_pattern_count': 0.70,
            'suspicious_string_count': 0.55,
            
            # Stream features
            'compressed_streams': 0.45,
            'binary_streams': 0.60,
            'script_streams': 0.75,
            'executable_streams': 0.90,
            
            # Byte frequency features
            'null_byte_ratio': 0.35,
            'printable_ratio': 0.25,
            'ascii_ratio': 0.20,
            'control_char_ratio': 0.40,
            
            # String features
            'url_count': 0.65,
            'path_count': 0.55,
            'command_count': 0.80,
            'registry_count': 0.60,
            
            # API features
            'process_api_count': 0.85,
            'file_api_count': 0.50,
            'network_api_count': 0.75,
            'registry_api_count': 0.65,
            
            # Obfuscation features
            'xor_indicators': 0.70,
            'base64_indicators': 0.55,
            'encoding_indicators': 0.60,
            'compression_indicators': 0.45
        }
    
    def extract_features(self, file_data: bytes, streams: Dict[str, bytes], 
                        parse_result: Dict[str, Any]) -> FeatureVector:
        """Extract comprehensive feature vector"""
        file_hash = hashlib.sha256(file_data).hexdigest()
        features = {}
        
        # Extract all feature types
        for feature_name, extractor in self.feature_extractors.items():
            try:
                extracted = extractor(file_data, streams, parse_result)
                features.update(extracted)
            except Exception as e:
                print(f"Error extracting {feature_name}: {e}")
                continue
        
        return FeatureVector(
            file_hash=file_hash,
            features=features,
            label=None,
            confidence=0.0
        )
    
    def _extract_file_structure_features(self, file_data: bytes, streams: Dict[str, bytes], 
                                        parse_result: Dict[str, Any]) -> Dict[str, float]:
        """Extract file structure features"""
        features = {}
        
        # PE structure
        has_pe = False
        if len(file_data) > 64:
            try:
                e_lfanew = struct.unpack('<I', file_data[60:64])[0]
                pe_offset = 60 + e_lfanew
                if pe_offset + 4 < len(file_data):
                    if file_data[pe_offset:pe_offset + 4] == b'PE\0\0':
                        has_pe = True
            except:
                pass
        
        features['has_pe_structure'] = float(has_pe)
        
        # OLE structure
        has_ole = file_data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
        features['has_ole_structure'] = float(has_ole)
        
        # File size ratio (log scale)
        file_size = len(file_data)
        max_size = 50 * 1024 * 1024  # 50MB
        features['file_size_ratio'] = min(1.0, np.log(file_size + 1) / np.log(max_size + 1))
        
        # Stream count
        stream_count = len(streams)
        features['stream_count'] = min(1.0, stream_count / 100.0)  # Normalize to 0-1
        
        return features
    
    def _extract_entropy_features(self, file_data: bytes, streams: Dict[str, bytes], 
                                parse_result: Dict[str, Any]) -> Dict[str, float]:
        """Extract entropy-based features"""
        features = {}
        
        # Calculate entropy for entire file
        file_entropy = self._calculate_entropy(file_data)
        features['mean_entropy'] = file_entropy / 8.0  # Normalize to 0-1
        
        # Calculate entropy for chunks
        chunk_size = 1024
        entropies = []
        
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i+chunk_size]
            if len(chunk) >= 512:  # Only meaningful chunks
                chunk_entropy = self._calculate_entropy(chunk)
                entropies.append(chunk_entropy)
        
        if entropies:
            features['entropy_variance'] = np.var(entropies) / 64.0  # Normalize variance
            features['high_entropy_ratio'] = sum(1 for e in entropies if e > 6.0) / len(entropies)
            
            # Count entropy peaks
            mean_entropy = np.mean(entropies)
            features['entropy_peaks'] = sum(1 for e in entropies if e > mean_entropy + 2.0) / len(entropies)
        else:
            features['entropy_variance'] = 0.0
            features['high_entropy_ratio'] = 0.0
            features['entropy_peaks'] = 0.0
        
        return features
    
    def _extract_pattern_features(self, file_data: bytes, streams: Dict[str, bytes], 
                                parse_result: Dict[str, Any]) -> Dict[str, float]:
        """Extract pattern-based features"""
        features = {}
        
        # Count various patterns
        patterns = {
            'mz_pattern_count': b'MZ',
            'eps_pattern_count': b'eqproc',
            'api_pattern_count': b'ShellExecute|CreateProcess|VirtualAlloc',
            'suspicious_string_count': b'%TEMP%|powershell|cmd.exe'
        }
        
        for feature_name, pattern in patterns.items():
            if b'|' in pattern:
                # Multiple patterns
                count = sum(len(list(re.finditer(p, file_data, re.IGNORECASE))) 
                           for p in pattern.split(b'|'))
            else:
                count = len(list(re.finditer(pattern, file_data, re.IGNORECASE)))
            
            # Normalize
            features[feature_name] = min(1.0, count / 10.0)
        
        return features
    
    def _extract_stream_features(self, file_data: bytes, streams: Dict[str, bytes], 
                               parse_result: Dict[str, Any]) -> Dict[str, float]:
        """Extract stream-based features"""
        features = {}
        
        if not streams:
            return {'compressed_streams': 0.0, 'binary_streams': 0.0, 
                   'script_streams': 0.0, 'executable_streams': 0.0}
        
        # Analyze stream types
        compressed_count = 0
        binary_count = 0
        script_count = 0
        executable_count = 0
        
        for stream_name, stream_data in streams.items():
            # Check for compression
            if stream_data.startswith(b'\x78\x9c') or stream_data.startswith(b'\x78\xda'):
                compressed_count += 1
            
            # Check for binary content
            entropy = self._calculate_entropy(stream_data)
            if entropy > 6.0:
                binary_count += 1
            
            # Check for script content
            script_indicators = [b'<script', b'javascript:', b'vbscript']
            if any(indicator in stream_data.lower() for indicator in script_indicators):
                script_count += 1
            
            # Check for executable content
            if stream_data.startswith(b'MZ') or b'PE\0\0' in stream_data:
                executable_count += 1
        
        total_streams = len(streams)
        features['compressed_streams'] = compressed_count / total_streams
        features['binary_streams'] = binary_count / total_streams
        features['script_streams'] = script_count / total_streams
        features['executable_streams'] = executable_count / total_streams
        
        return features
    
    def _extract_byte_frequency_features(self, file_data: bytes, streams: Dict[str, bytes], 
                                        parse_result: Dict[str, Any]) -> Dict[str, float]:
        """Extract byte frequency features"""
        features = {}
        
        if not file_data:
            return {'null_byte_ratio': 0.0, 'printable_ratio': 0.0, 
                   'ascii_ratio': 0.0, 'control_char_ratio': 0.0}
        
        # Count byte types
        null_count = file_data.count(b'\x00')
        printable_count = sum(1 for b in file_data if 32 <= b <= 126)
        ascii_count = sum(1 for b in file_data if b < 128)
        control_count = sum(1 for b in file_data if b < 32 or b == 127)
        
        total_bytes = len(file_data)
        features['null_byte_ratio'] = null_count / total_bytes
        features['printable_ratio'] = printable_count / total_bytes
        features['ascii_ratio'] = ascii_count / total_bytes
        features['control_char_ratio'] = control_count / total_bytes
        
        return features
    
    def _extract_string_features(self, file_data: bytes, streams: Dict[str, bytes], 
                               parse_result: Dict[str, Any]) -> Dict[str, float]:
        """Extract string-based features"""
        features = {}
        
        # Extract strings
        strings = self._extract_strings(file_data, min_length=4)
        string_text = ' '.join(strings).lower()
        
        # Count suspicious string types
        url_pattern = rb'https?://[^\s<>"]+|www\.[^\s<>"]+'
        path_pattern = rb'[a-zA-Z]:\\[^\\*\?"<>|]*|[\\]/[^\\*\?"<>|]*'
        command_pattern = rb'cmd\.exe|powershell|wscript\.exe|cscript\.exe|rundll32\.exe'
        registry_pattern = rb'HKEY_[A-Z_]+|\\\\Software\\\\'
        
        features['url_count'] = min(1.0, len(re.findall(url_pattern, file_data)) / 5.0)
        features['path_count'] = min(1.0, len(re.findall(path_pattern, file_data)) / 10.0)
        features['command_count'] = min(1.0, len(re.findall(command_pattern, file_data)) / 3.0)
        features['registry_count'] = min(1.0, len(re.findall(registry_pattern, file_data)) / 5.0)
        
        return features
    
    def _extract_api_features(self, file_data: bytes, streams: Dict[str, bytes], 
                            parse_result: Dict[str, Any]) -> Dict[str, float]:
        """Extract API-related features"""
        features = {}
        
        # API patterns
        process_apis = rb'CreateProcess|CreateThread|VirtualAlloc|WriteProcessMemory'
        file_apis = rb'CreateFile|WriteFile|ReadFile|DeleteFile|MoveFile'
        network_apis = rb'InternetOpen|HttpSendRequest|URLDownloadToFile|Connect'
        registry_apis = rb'RegOpenKey|RegSetValue|RegCreateKey|RegDeleteKey'
        
        features['process_api_count'] = min(1.0, len(re.findall(process_apis, file_data)) / 3.0)
        features['file_api_count'] = min(1.0, len(re.findall(file_apis, file_data)) / 5.0)
        features['network_api_count'] = min(1.0, len(re.findall(network_apis, file_data)) / 3.0)
        features['registry_api_count'] = min(1.0, len(re.findall(registry_apis, file_data)) / 3.0)
        
        return features
    
    def _extract_obfuscation_features(self, file_data: bytes, streams: Dict[str, bytes], 
                                   parse_result: Dict[str, Any]) -> Dict[str, float]:
        """Extract obfuscation-related features"""
        features = {}
        
        # XOR indicators
        xor_indicators = 0
        for key_size in range(1, 17):
            for key_byte in range(256):
                try:
                    test_data = file_data[:256]
                    xored = bytes(b ^ key_byte for b in test_data)
                    if xored.startswith(b'MZ') or xored.startswith(b'PE\0\0'):
                        xor_indicators += 1
                        break
                except:
                    continue
            if xor_indicators > 0:
                break
        
        features['xor_indicators'] = min(1.0, xor_indicators / 5.0)
        
        # Base64 indicators
        base64_pattern = rb'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = len(re.findall(base64_pattern, file_data))
        features['base64_indicators'] = min(1.0, base64_matches / 10.0)
        
        # Encoding indicators
        encoding_patterns = [b'-enc', b'-encodedcommand', b'FromBase64String', b'Convert.FromBase64']
        encoding_matches = sum(len(re.findall(pattern, file_data, re.IGNORECASE)) 
                               for pattern in encoding_patterns)
        features['encoding_indicators'] = min(1.0, encoding_matches / 3.0)
        
        # Compression indicators
        compression_patterns = [b'\x78\x9c', b'\x78\xda', b'PK\x03\x04', b'\x1f\x8b']
        compression_matches = sum(len(re.findall(pattern, file_data)) 
                                 for pattern in compression_patterns)
        features['compression_indicators'] = min(1.0, compression_matches / 3.0)
        
        return features
    
    def predict_threat_score(self, feature_vector: FeatureVector) -> Dict[str, Any]:
        """Predict threat score using weighted features"""
        features = feature_vector.features
        score = 0.0
        feature_contributions = {}
        
        # Calculate weighted score
        for feature_name, feature_value in features.items():
            if feature_name in self.model_weights:
                weight = self.model_weights[feature_name]
                contribution = weight * feature_value
                score += contribution
                feature_contributions[feature_name] = contribution
        
        # Normalize score to 0-100
        normalized_score = min(100.0, score * 10)  # Scale to 0-100
        
        # Calculate confidence based on feature consistency
        confidence = self._calculate_prediction_confidence(features, feature_contributions)
        
        # Determine threat level
        if normalized_score >= 80:
            threat_level = "CRITICAL"
        elif normalized_score >= 60:
            threat_level = "HIGH"
        elif normalized_score >= 40:
            threat_level = "MEDIUM"
        elif normalized_score >= 20:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"
        
        return {
            'threat_score': normalized_score,
            'threat_level': threat_level,
            'confidence': confidence,
            'feature_contributions': feature_contributions,
            'top_features': self._get_top_features(feature_contributions, 5)
        }
    
    def _calculate_prediction_confidence(self, features: Dict[str, float], 
                                       contributions: Dict[str, float]) -> float:
        """Calculate confidence in prediction"""
        if not contributions:
            return 0.0
        
        # Confidence based on number of significant features
        significant_features = sum(1 for contrib in contributions.values() if abs(contrib) > 0.1)
        confidence = min(1.0, significant_features / len(contributions))
        
        # Boost confidence if features are consistent
        positive_contributions = sum(1 for contrib in contributions.values() if contrib > 0)
        if positive_contributions > len(contributions) * 0.7:
            confidence = min(1.0, confidence + 0.2)
        
        return confidence
    
    def _get_top_features(self, contributions: Dict[str, float], top_n: int) -> List[Dict[str, Any]]:
        """Get top contributing features"""
        sorted_features = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)
        
        return [
            {
                'feature': name,
                'contribution': contribution,
                'weight': self.model_weights.get(name, 0.0),
                'value': 0.0  # Would need to pass original features
            }
            for name, contribution in sorted_features[:top_n]
        ]
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                freq = count / data_len
                entropy -= freq * (freq.bit_length() - 1)
        
        return entropy
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Add final string if valid
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def train_from_feedback(self, feature_vector: FeatureVector, actual_label: str):
        """Update model based on user feedback"""
        # Simple online learning - adjust weights based on feedback
        predicted = self.predict_threat_score(feature_vector)
        predicted_level = predicted['threat_level']
        
        # Convert levels to numeric for comparison
        level_to_score = {
            'CLEAN': 0, 'LOW': 25, 'MEDIUM': 50, 'HIGH': 75, 'CRITICAL': 100
        }
        
        predicted_score = level_to_score.get(predicted_level, 0)
        actual_score = level_to_score.get(actual_label, 0)
        
        # Simple weight adjustment
        error = actual_score - predicted_score
        adjustment_factor = 0.01  # Learning rate
        
        for feature_name, feature_value in feature_vector.features.items():
            if feature_name in self.model_weights:
                # Adjust weight based on prediction error
                weight_adjustment = error * feature_value * adjustment_factor
                self.model_weights[feature_name] += weight_adjustment
                
                # Keep weights in reasonable range
                self.model_weights[feature_name] = max(0.0, min(1.0, self.model_weights[feature_name]))
        
        # Store training example
        feature_vector.label = actual_label
        self.training_data.append(feature_vector)
        
        # Limit training data size
        if len(self.training_data) > 1000:
            self.training_data = self.training_data[-1000:]
    
    def save_model(self, filepath: str):
        """Save trained model"""
        model_data = {
            'weights': self.model_weights,
            'training_data': self.training_data,
            'feature_importance': self.feature_importance
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_model(self, filepath: str):
        """Load trained model"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model_weights = model_data.get('weights', self.model_weights)
            self.training_data = model_data.get('training_data', [])
            self.feature_importance = model_data.get('feature_importance', {})
            
        except Exception as e:
            print(f"Error loading model: {e}")
            # Keep default weights

# Global classifier instance
ml_classifier = LightweightThreatClassifier()
