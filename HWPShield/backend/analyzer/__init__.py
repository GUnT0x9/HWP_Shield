"""
HWPShield Analyzer Package

This package provides malware detection modules for HWP (Hangul Word Processor) files.
"""
from .hwp_parser import HWPParser, HWPHeader
from .eps_detector import EPSDetector, DetectionResult
from .ole_detector import OLEDetector
from .script_detector import ScriptDetector
from .ioc_extractor import IOCExtractor
from .steg_detector import StegDetector
from .structural_analyzer import StructuralAnalyzer
from .scorer import RiskScorer, RiskLevel, ScoringResult

__all__ = [
    'HWPParser',
    'HWPHeader',
    'EPSDetector',
    'OLEDetector',
    'ScriptDetector',
    'IOCExtractor',
    'StegDetector',
    'StructuralAnalyzer',
    'RiskScorer',
    'RiskLevel',
    'DetectionResult',
    'ScoringResult',
]
