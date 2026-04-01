"""
Advanced Threat Detection Engine
Implements sophisticated threat detection with ML-inspired features
"""
import os
import re
import struct
import zlib
import hashlib
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass
from collections import defaultdict, Counter
import math

@dataclass
class ThreatSignature:
    """Advanced threat signature with context"""
    pattern: bytes
    weight: float
    context_required: bool
    description: str
    category: str
    heuristics: Dict[str, Any]

@dataclass
class BehavioralIndicator:
    """Behavioral threat indicator"""
    behavior_type: str
    confidence: float
    evidence: List[str]
    risk_score: float
    description: str

class AdvancedThreatDetector:
    """Advanced threat detection with heuristics and behavioral analysis"""
    
    def __init__(self):
        self.threat_signatures = self._load_advanced_signatures()
        self.behavioral_patterns = self._load_behavioral_patterns()
        self.obfuscation_detectors = self._init_obfuscation_detectors()
        
    def _load_advanced_signatures(self) -> List[ThreatSignature]:
        """Load advanced threat signatures with heuristics"""
        signatures = [
            # Advanced EPS exploits
            ThreatSignature(
                pattern=b'eqproc',
                weight=0.8,
                context_required=True,
                description="EPS eqproc operator",
                category="eps_exploit",
                heuristics={
                    "eps_context_markers": [b'%!PS-Adobe', b'%%BoundingBox', b'/findfont'],
                    "required_markers": 2,
                    "proximity_range": 200
                }
            ),
            
            # Shell execution patterns
            ThreatSignature(
                pattern=b'ShellExecute',
                weight=0.9,
                context_required=False,
                description="Windows Shell API",
                category="shell_execution",
                heuristics={
                    "suspicious_params": [b'%TEMP%', b'cmd.exe', b'powershell'],
                    "risk_boost": 0.3
                }
            ),
            
            # PowerShell execution
            ThreatSignature(
                pattern=b'powershell',
                weight=0.7,
                context_required=False,
                description="PowerShell execution",
                category="powershell",
                heuristics={
                    "suspicious_commands": [b'Invoke-Expression', b'Start-Process', b'DownloadFile'],
                    "encoded_patterns": [b'-enc', b'-encodedcommand']
                }
            ),
            
            # Process creation
            ThreatSignature(
                pattern=b'CreateProcess',
                weight=0.8,
                context_required=False,
                description="Process creation API",
                category="process_creation",
                heuristics={
                    "suspicious_processes": [b'cmd.exe', b'powershell.exe', b'wscript.exe'],
                    "param_injection": [b'%TEMP%', b'%APPDATA%', b'%USERPROFILE%']
                }
            ),
            
            # URL download
            ThreatSignature(
                pattern=b'URLDownloadToFile',
                weight=0.9,
                context_required=False,
                description="URL download API",
                category="url_download",
                heuristics={
                    "suspicious_domains": [b'bit.ly', b'tinyurl.com', b'pastebin.com'],
                    "file_extensions": [b'.exe', b'.scr', b'.bat', b'.ps1']
                }
            ),
            
            # Registry manipulation
            ThreatSignature(
                pattern=b'RegSetValue',
                weight=0.6,
                context_required=False,
                description="Registry manipulation",
                category="registry_abuse",
                heuristics={
                    "persistence_keys": [b'\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'],
                    "suspicious_values": [b'shell.exe', b'powershell.exe']
                }
            ),
            
            # Service installation
            ThreatSignature(
                pattern=b'CreateService',
                weight=0.8,
                context_required=False,
                description="Service installation",
                category="service_abuse",
                heuristics={
                    "malicious_service_types": [b'kernel', b'system', b'windows'],
                    "persistence_indicators": True
                }
            ),
            
            # Scheduled task
            ThreatSignature(
                pattern=b'SchTasksCreate',
                weight=0.7,
                context_required=False,
                description="Scheduled task creation",
                category="persistence",
                heuristics={
                    "triggers": [b'ONLOGON', b'ONSTART', b'DAILY'],
                    "suspicious_actions": [b'powershell', b'cmd.exe']
                }
            )
        ]
        return signatures
    
    def _load_behavioral_patterns(self) -> Dict[str, Dict]:
        """Load behavioral threat patterns"""
        return {
            "dropper_behavior": {
                "indicators": [
                    (b'%TEMP%', 0.8),
                    (b'URLDownloadToFile', 0.9),
                    (b'ShellExecute', 0.8),
                    (b'CreateProcess', 0.7)
                ],
                "required_count": 2,
                "base_score": 60,
                "description": "Dropper behavior pattern"
            },
            
            "persistence_mechanism": {
                "indicators": [
                    (b'RegSetValue', 0.7),
                    (b'CreateService', 0.8),
                    (b'SchTasksCreate', 0.7),
                    (b'WriteFile', 0.5)
                ],
                "required_count": 2,
                "base_score": 50,
                "description": "Persistence mechanism"
            },
            
            "lateral_movement": {
                "indicators": [
                    (b'WNetAddConnection', 0.8),
                    (b'CreateProcessWithLogon', 0.9),
                    (b'LogonUser', 0.7),
                    (b'ImpersonateLoggedOnUser', 0.8)
                ],
                "required_count": 2,
                "base_score": 70,
                "description": "Lateral movement attempt"
            },
            
            "data_exfiltration": {
                "indicators": [
                    (b'InternetOpen', 0.6),
                    (b'HttpSendRequest', 0.8),
                    (b'CreateFile', 0.5),
                    (b'WriteFile', 0.5)
                ],
                "required_count": 3,
                "base_score": 60,
                "description": "Data exfiltration pattern"
            },
            
            "defense_evasion": {
                "indicators": [
                    (b'VirtualAlloc', 0.7),
                    (b'CreateThread', 0.8),
                    (b'WriteProcessMemory', 0.9),
                    (b'SetThreadContext', 0.8)
                ],
                "required_count": 2,
                "base_score": 80,
                "description": "Defense evasion techniques"
            }
        }
    
    def _init_obfuscation_detectors(self) -> Dict[str, Any]:
        """Initialize obfuscation detection algorithms"""
        return {
            "xor_detection": self._detect_xor_obfuscation,
            "base64_detection": self._detect_base64_obfuscation,
            "entropy_analysis": self._analyze_entropy_segments,
            "compression_detection": self._detect_compression,
            "string_obfuscation": self._detect_string_obfuscation
        }
    
    def analyze_advanced_threats(self, data: bytes, streams: Dict[str, bytes]) -> Dict[str, Any]:
        """Comprehensive advanced threat analysis"""
        analysis = {
            "threat_score": 0.0,
            "threat_level": "CLEAN",
            "signatures_detected": [],
            "behavioral_indicators": [],
            "obfuscation_evidence": [],
            "advanced_patterns": [],
            "confidence_score": 0.0,
            "risk_factors": []
        }
        
        # 1. Signature-based detection with context
        signature_results = self._analyze_signatures_with_context(data)
        analysis["signatures_detected"] = signature_results
        
        # 2. Behavioral analysis
        behavioral_results = self._analyze_behavioral_patterns(data)
        analysis["behavioral_indicators"] = behavioral_results
        
        # 3. Obfuscation detection
        obfuscation_results = self._detect_obfuscation(data)
        analysis["obfuscation_evidence"] = obfuscation_results
        
        # 4. Advanced pattern recognition
        pattern_results = self._recognize_advanced_patterns(data, streams)
        analysis["advanced_patterns"] = pattern_results
        
        # 5. Calculate composite threat score
        analysis["threat_score"] = self._calculate_composite_score(
            signature_results, behavioral_results, obfuscation_results, pattern_results
        )
        
        # 6. Determine threat level
        analysis["threat_level"] = self._determine_threat_level(analysis["threat_score"])
        
        # 7. Calculate confidence
        analysis["confidence_score"] = self._calculate_confidence(analysis)
        
        # 8. Identify risk factors
        analysis["risk_factors"] = self._identify_risk_factors(analysis)
        
        return analysis
    
    def _analyze_signatures_with_context(self, data: bytes) -> List[Dict[str, Any]]:
        """Analyze signatures with context validation"""
        detected = []
        
        for signature in self.threat_signatures:
            pattern = signature.pattern
            matches = list(re.finditer(pattern, data, re.IGNORECASE))
            
            for match in matches:
                position = match.start()
                
                # Context validation if required
                context_valid = True
                context_evidence = []
                
                if signature.context_required:
                    context_valid, context_evidence = self._validate_context(
                        data, position, signature.heuristics
                    )
                
                if context_valid:
                    # Calculate confidence based on context and additional heuristics
                    confidence = self._calculate_signature_confidence(
                        data, position, signature, context_evidence
                    )
                    
                    detected.append({
                        "signature": signature.description,
                        "category": signature.category,
                        "position": position,
                        "confidence": confidence,
                        "weight": signature.weight,
                        "context_evidence": context_evidence,
                        "risk_contribution": signature.weight * confidence
                    })
        
        return detected
    
    def _validate_context(self, data: bytes, position: int, heuristics: Dict) -> Tuple[bool, List[str]]:
        """Validate context for signature"""
        evidence = []
        
        # Check for required context markers
        if "eps_context_markers" in heuristics:
            markers = heuristics["eps_context_markers"]
            required = heuristics.get("required_markers", 2)
            proximity = heuristics.get("proximity_range", 200)
            
            window_start = max(0, position - proximity)
            window_end = min(len(data), position + proximity)
            context_window = data[window_start:window_end]
            
            found_markers = sum(1 for marker in markers if marker in context_window)
            if found_markers >= required:
                evidence.append(f"EPS context: {found_markers}/{len(markers)} markers")
            else:
                return False, evidence
        
        # Check for suspicious parameters
        if "suspicious_params" in heuristics:
            params = heuristics["suspicious_params"]
            proximity = heuristics.get("param_proximity", 100)
            
            window_start = max(0, position - proximity)
            window_end = min(len(data), position + proximity)
            context_window = data[window_start:window_end]
            
            found_params = [param.decode('utf-8', errors='ignore') 
                           for param in params if param in context_window]
            if found_params:
                evidence.append(f"Suspicious params: {found_params}")
        
        return True, evidence
    
    def _calculate_signature_confidence(self, data: bytes, position: int, 
                                     signature: ThreatSignature, context_evidence: List[str]) -> float:
        """Calculate confidence score for signature detection"""
        base_confidence = 0.5
        
        # Context evidence boosts confidence
        if context_evidence:
            base_confidence += 0.3
        
        # Check for additional heuristics
        if "risk_boost" in signature.heuristics:
            boost = signature.heuristics["risk_boost"]
            base_confidence += boost
        
        # Position-based confidence (header vs random location)
        if position < 1024:  # In header
            base_confidence += 0.1
        elif position > len(data) * 0.9:  # Near end
            base_confidence += 0.05
        
        return min(1.0, base_confidence)
    
    def _analyze_behavioral_patterns(self, data: bytes) -> List[BehavioralIndicator]:
        """Analyze behavioral threat patterns"""
        indicators = []
        
        for behavior_name, pattern_info in self.behavioral_patterns.items():
            found_indicators = []
            total_weight = 0.0
            
            for indicator_pattern, weight in pattern_info["indicators"]:
                matches = list(re.finditer(indicator_pattern, data, re.IGNORECASE))
                if matches:
                    found_indicators.extend([
                        f"{indicator_pattern.decode('utf-8', errors='ignore')} at pos {m.start()}"
                        for m in matches
                    ])
                    total_weight += weight
            
            if len(found_indicators) >= pattern_info["required_count"]:
                confidence = min(1.0, total_weight / len(pattern_info["indicators"]))
                risk_score = pattern_info["base_score"] * confidence
                
                indicator = BehavioralIndicator(
                    behavior_type=behavior_name,
                    confidence=confidence,
                    evidence=found_indicators,
                    risk_score=risk_score,
                    description=pattern_info["description"]
                )
                indicators.append(indicator)
        
        return indicators
    
    def _detect_obfuscation(self, data: bytes) -> Dict[str, Any]:
        """Detect various obfuscation techniques"""
        evidence = {
            "xor_obfuscation": False,
            "base64_obfuscation": False,
            "high_entropy_segments": [],
            "compressed_sections": [],
            "string_obfuscation": False,
            "overall_obfuscation_score": 0.0
        }
        
        # XOR obfuscation detection
        xor_result = self._detect_xor_obfuscation(data)
        evidence["xor_obfuscation"] = xor_result["detected"]
        
        # Base64 obfuscation detection
        base64_result = self._detect_base64_obfuscation(data)
        evidence["base64_obfuscation"] = base64_result["detected"]
        
        # Entropy analysis
        entropy_result = self._analyze_entropy_segments(data)
        evidence["high_entropy_segments"] = entropy_result["high_entropy_segments"]
        
        # Compression detection
        compression_result = self._detect_compression(data)
        evidence["compressed_sections"] = compression_result["sections"]
        
        # String obfuscation
        string_result = self._detect_string_obfuscation(data)
        evidence["string_obfuscation"] = string_result["detected"]
        
        # Calculate overall obfuscation score
        score_components = [
            xor_result["score"],
            base64_result["score"],
            entropy_result["score"],
            compression_result["score"],
            string_result["score"]
        ]
        evidence["overall_obfuscation_score"] = sum(score_components) / len(score_components)
        
        return evidence
    
    def _detect_xor_obfuscation(self, data: bytes) -> Dict[str, Any]:
        """Detect XOR obfuscation patterns"""
        result = {"detected": False, "score": 0.0, "patterns": []}
        
        # Look for repeating XOR patterns
        for key_size in range(1, 17):  # Try XOR keys 1-16 bytes
            for key_byte in range(256):
                try:
                    # Try to XOR first 256 bytes with this key
                    test_data = data[:256]
                    xored = bytes(b ^ key_byte for b in test_data)
                    
                    # Check if result looks like plaintext/PE
                    if (xored.startswith(b'MZ') or 
                        xored.startswith(b'PE\0\0') or
                        any(32 <= b <= 126 for b in xored[:50])):  # Printable chars
                        
                        # Verify pattern consistency
                        if self._verify_xor_pattern(data, key_byte):
                            result["detected"] = True
                            result["score"] = 0.8
                            result["patterns"].append(f"XOR key: 0x{key_byte:02x}")
                            break
                except:
                    continue
            
            if result["detected"]:
                break
        
        return result
    
    def _verify_xor_pattern(self, data: bytes, key_byte: int) -> bool:
        """Verify XOR pattern consistency"""
        try:
            sample_size = min(1024, len(data))
            sample = data[:sample_size]
            xored = bytes(b ^ key_byte for b in sample)
            
            # Check for high entropy (typical of encrypted data)
            entropy = self._calculate_entropy(xored)
            if entropy < 3.0:  # Too low, probably not XOR encrypted
                return False
            
            # Check for repeating patterns
            chunks = [xored[i:i+16] for i in range(0, len(xored), 16)]
            unique_chunks = len(set(chunks))
            
            # If too many unique chunks with high entropy, likely XOR encrypted
            return entropy > 6.0 and unique_chunks > len(chunks) * 0.8
        except:
            return False
    
    def _detect_base64_obfuscation(self, data: bytes) -> Dict[str, Any]:
        """Detect Base64 obfuscation"""
        result = {"detected": False, "score": 0.0, "samples": []}
        
        # Look for Base64 patterns
        base64_pattern = rb'[A-Za-z0-9+/]{20,}={0,2}'
        matches = list(re.finditer(base64_pattern, data))
        
        for match in matches:
            try:
                encoded_str = match.group().decode('ascii')
                decoded = base64.b64decode(encoded_str)
                
                # Check if decoded data is meaningful
                if len(decoded) > 10:
                    # Check for PE header or printable text
                    if (decoded.startswith(b'MZ') or 
                        decoded.startswith(b'PE\0\0') or
                        any(32 <= b <= 126 for b in decoded[:50])):
                        
                        result["detected"] = True
                        result["score"] = 0.6
                        result["samples"].append({
                            "position": match.start(),
                            "length": len(encoded_str),
                            "decoded_size": len(decoded)
                        })
            except:
                continue
        
        return result
    
    def _analyze_entropy_segments(self, data: bytes) -> Dict[str, Any]:
        """Analyze entropy of data segments"""
        result = {"high_entropy_segments": [], "score": 0.0}
        
        chunk_size = 1024
        high_entropy_threshold = 7.0
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            if len(chunk) < 512:  # Skip small chunks
                continue
            
            entropy = self._calculate_entropy(chunk)
            
            if entropy > high_entropy_threshold:
                result["high_entropy_segments"].append({
                    "start": i,
                    "end": i + len(chunk),
                    "entropy": entropy,
                    "size": len(chunk)
                })
        
        # Calculate score based on percentage of high-entropy data
        total_high_entropy = sum(seg["size"] for seg in result["high_entropy_segments"])
        if len(data) > 0:
            high_entropy_ratio = total_high_entropy / len(data)
            result["score"] = min(1.0, high_entropy_ratio * 2)  # Cap at 1.0
        
        return result
    
    def _detect_compression(self, data: bytes) -> Dict[str, Any]:
        """Detect compressed data sections"""
        result = {"sections": [], "score": 0.0}
        
        # Check for common compression headers
        compression_signatures = {
            b'PK\x03\x04': "ZIP",
            b'\x1f\x8b': "GZIP", 
            b'BZ': "BZIP2",
            b'\x78\x9c': "ZLIB",
            b'\x78\xda': "ZLIB",
            b'\x78\x5e': "ZLIB"
        }
        
        for signature, comp_type in compression_signatures.items():
            positions = []
            start = 0
            while True:
                pos = data.find(signature, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + len(signature)
            
            for pos in positions:
                # Try to decompress small sample
                try:
                    if comp_type == "ZLIB":
                        sample = data[pos:pos+512]
                        decompressed = zlib.decompress(sample)
                        if len(decompressed) > 0:
                            result["sections"].append({
                                "type": comp_type,
                                "position": pos,
                                "decompressed_size": len(decompressed)
                            })
                except:
                    continue
        
        # Calculate score
        result["score"] = min(1.0, len(result["sections"]) * 0.3)
        
        return result
    
    def _detect_string_obfuscation(self, data: bytes) -> Dict[str, Any]:
        """Detect string obfuscation techniques"""
        result = {"detected": False, "score": 0.0, "techniques": []}
        
        # Look for character array patterns
        char_array_pattern = rb'[\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF]{10,}'
        matches = list(re.finditer(char_array_pattern, data))
        
        suspicious_arrays = 0
        for match in matches:
            array_data = match.group()
            
            # Check if it looks like obfuscated string
            if self._is_obfuscated_string(array_data):
                suspicious_arrays += 1
        
        if suspicious_arrays >= 3:
            result["detected"] = True
            result["score"] = 0.5
            result["techniques"].append(f"Character arrays: {suspicious_arrays}")
        
        return result
    
    def _is_obfuscated_string(self, data: bytes) -> bool:
        """Check if data looks like obfuscated string"""
        if len(data) < 10:
            return False
        
        # Check for printable characters with null bytes
        printable_chars = sum(1 for b in data if 32 <= b <= 126)
        null_bytes = data.count(b'\x00')
        
        # If mostly printable with many nulls, likely obfuscated string
        return (printable_chars / len(data) > 0.6 and 
                null_bytes / len(data) > 0.2)
    
    def _recognize_advanced_patterns(self, data: bytes, streams: Dict[str, bytes]) -> List[Dict[str, Any]]:
        """Recognize advanced attack patterns"""
        patterns = []
        
        # Multi-stage attack pattern
        if self._detect_multi_stage_attack(data, streams):
            patterns.append({
                "type": "multi_stage_attack",
                "description": "Multi-stage attack pattern detected",
                "confidence": 0.8,
                "risk_score": 70
            })
        
        # Living off the land pattern
        if self._detect_lolbas_usage(data):
            patterns.append({
                "type": "lolbas",
                "description": "Living off the land binaries usage",
                "confidence": 0.7,
                "risk_score": 60
            })
        
        # Process injection pattern
        if self._detect_process_injection(data):
            patterns.append({
                "type": "process_injection",
                "description": "Process injection techniques",
                "confidence": 0.9,
                "risk_score": 80
            })
        
        # Memory evasion pattern
        if self._detect_memory_evasion(data):
            patterns.append({
                "type": "memory_evasion",
                "description": "Memory evasion techniques",
                "confidence": 0.7,
                "risk_score": 65
            })
        
        return patterns
    
    def _detect_multi_stage_attack(self, data: bytes, streams: Dict[str, bytes]) -> bool:
        """Detect multi-stage attack patterns"""
        indicators = [
            b'URLDownloadToFile',
            b'InternetOpen',
            b'ShellExecute',
            b'CreateProcess'
        ]
        
        found_indicators = sum(1 for indicator in indicators if indicator in data)
        return found_indicators >= 3
    
    def _detect_lolbas_usage(self, data: bytes) -> bool:
        """Detect living off the land binaries usage"""
        lolbas_patterns = [
            b'certutil.exe',
            b'bitsadmin.exe',
            b'wmic.exe',
            b'powershell.exe',
            b'cmd.exe',
            b'rundll32.exe'
        ]
        
        return sum(1 for pattern in lolbas_patterns if pattern in data) >= 2
    
    def _detect_process_injection(self, data: bytes) -> bool:
        """Detect process injection patterns"""
        injection_apis = [
            b'VirtualAlloc',
            b'WriteProcessMemory',
            b'CreateThread',
            b'SetThreadContext',
            b'QueueUserAPC'
        ]
        
        return sum(1 for api in injection_apis if api in data) >= 2
    
    def _detect_memory_evasion(self, data: bytes) -> bool:
        """Detect memory evasion techniques"""
        evasion_patterns = [
            b'VirtualProtect',
            b'VirtualAllocEx',
            b'NtUnmapViewOfSection',
            b'NtMapViewOfSection'
        ]
        
        return sum(1 for pattern in evasion_patterns if pattern in data) >= 1
    
    def _calculate_composite_score(self, signatures: List[Dict], 
                                  behavioral: List[BehavioralIndicator],
                                  obfuscation: Dict, patterns: List[Dict]) -> float:
        """Calculate composite threat score"""
        score = 0.0
        
        # Signature contributions
        signature_score = sum(sig["risk_contribution"] for sig in signatures) * 20
        score += signature_score
        
        # Behavioral contributions
        behavioral_score = sum(behavior.risk_score for behavior in behavioral)
        score += behavioral_score
        
        # Obfuscation bonus
        obfuscation_bonus = obfuscation["overall_obfuscation_score"] * 15
        score += obfuscation_bonus
        
        # Pattern contributions
        pattern_score = sum(pattern["risk_score"] for pattern in patterns)
        score += pattern_score
        
        return min(100.0, score)
    
    def _determine_threat_level(self, score: float) -> str:
        """Determine threat level from score"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "CLEAN"
    
    def _calculate_confidence(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall confidence score"""
        factors = []
        
        # Signature detection confidence
        if analysis["signatures_detected"]:
            sig_confidence = sum(sig["confidence"] for sig in analysis["signatures_detected"])
            sig_confidence /= len(analysis["signatures_detected"])
            factors.append(sig_confidence)
        
        # Behavioral confidence
        if analysis["behavioral_indicators"]:
            beh_confidence = sum(beh.confidence for beh in analysis["behavioral_indicators"])
            beh_confidence /= len(analysis["behavioral_indicators"])
            factors.append(beh_confidence)
        
        # Pattern confidence
        if analysis["advanced_patterns"]:
            pat_confidence = sum(pat["confidence"] for pat in analysis["advanced_patterns"])
            pat_confidence /= len(analysis["advanced_patterns"])
            factors.append(pat_confidence)
        
        # Obfuscation confidence
        factors.append(analysis["obfuscation_evidence"]["overall_obfuscation_score"])
        
        return sum(factors) / len(factors) if factors else 0.0
    
    def _identify_risk_factors(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify key risk factors"""
        factors = []
        
        if analysis["signatures_detected"]:
            factors.append(f"Signature-based threats: {len(analysis['signatures_detected'])}")
        
        if analysis["behavioral_indicators"]:
            factors.append(f"Behavioral indicators: {len(analysis['behavioral_indicators'])}")
        
        if analysis["obfuscation_evidence"]["overall_obfuscation_score"] > 0.5:
            factors.append("High obfuscation detected")
        
        if analysis["advanced_patterns"]:
            factors.append(f"Advanced patterns: {len(analysis['advanced_patterns'])}")
        
        return factors
    
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
