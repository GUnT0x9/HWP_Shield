"""
Enhanced PE Structure Analyzer
Implements accurate EXE detection with PE header validation
"""
import struct
from typing import Dict, List, Optional, Tuple

class PEAnalyzer:
    """Accurate PE structure analyzer to reduce false positives"""
    
    @staticmethod
    def validate_pe_structure(data: bytes, mz_offset: int) -> Tuple[bool, Dict]:
        """
        Validate PE structure at given MZ offset
        
        Returns:
            (is_valid_pe, analysis_details)
        """
        if mz_offset + 64 > len(data):
            return False, {"error": "MZ offset too close to end"}
        
        # Get PE header offset (e_lfanew at offset 60)
        try:
            e_lfanew = struct.unpack_from('<I', data, mz_offset + 60)[0]
        except:
            return False, {"error": "Failed to read e_lfanew"}
        
        # Calculate PE header position
        pe_offset = mz_offset + e_lfanew
        
        # Validate PE header bounds
        if pe_offset + 4 > len(data):
            return False, {"error": "PE header out of bounds"}
        
        # Check PE signature
        pe_signature = data[pe_offset:pe_offset + 4]
        if pe_signature != b'PE\0\0':
            return False, {
                "error": "Invalid PE signature",
                "signature": pe_signature.hex()
            }
        
        # Parse COFF header (immediately after PE signature)
        if pe_offset + 24 > len(data):
            return False, {"error": "COFF header out of bounds"}
        
        try:
            machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
            num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
            timestamp = struct.unpack_from('<I', data, pe_offset + 8)[0]
            optional_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
        except:
            return False, {"error": "Failed to parse COFF header"}
        
        # Validate reasonable values
        if num_sections == 0 or num_sections > 96:  # Max sections in PE
            return False, {"error": f"Invalid section count: {num_sections}"}
        
        # Parse optional header if exists
        pe_type = "UNKNOWN"
        entry_point = 0
        
        if optional_header_size > 0:
            if pe_offset + 24 + optional_header_size > len(data):
                return False, {"error": "Optional header out of bounds"}
            
            try:
                # Check magic to determine PE type
                magic = struct.unpack_from('<H', data, pe_offset + 24)[0]
                if magic == 0x10b:  # PE32
                    pe_type = "PE32"
                    entry_point = struct.unpack_from('<I', data, pe_offset + 28)[0]
                elif magic == 0x20b:  # PE32+
                    pe_type = "PE32+"
                    entry_point = struct.unpack_from('<I', data, pe_offset + 32)[0]
                else:
                    return False, {"error": f"Invalid PE magic: 0x{magic:04x}"}
            except:
                return False, {"error": "Failed to parse optional header"}
        
        # Validate section table
        section_table_offset = pe_offset + 24 + optional_header_size
        if section_table_offset + 40 * num_sections > len(data):
            return False, {"error": "Section table out of bounds"}
        
        # Parse sections
        sections = []
        for i in range(num_sections):
            section_offset = section_table_offset + i * 40
            if section_offset + 40 > len(data):
                break
            
            try:
                name = data[section_offset:section_offset + 8].rstrip(b'\0').decode('ascii', errors='ignore')
                virtual_size = struct.unpack_from('<I', data, section_offset + 8)[0]
                virtual_address = struct.unpack_from('<I', data, section_offset + 12)[0]
                raw_size = struct.unpack_from('<I', data, section_offset + 16)[0]
                raw_offset = struct.unpack_from('<I', data, section_offset + 20)[0]
                characteristics = struct.unpack_from('<I', data, section_offset + 36)[0]
                
                sections.append({
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_offset": raw_offset,
                    "characteristics": characteristics
                })
            except:
                continue
        
        # Check for executable characteristics
        has_code = any(
            section["characteristics"] & 0x20  # IMAGE_SCN_CNT_CODE
            for section in sections
        )
        
        has_executable = any(
            section["characteristics"] & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
            for section in sections
        )
        
        # Validate entry point
        valid_entry = False
        if entry_point > 0:
            for section in sections:
                if section["virtual_address"] <= entry_point < section["virtual_address"] + section["virtual_size"]:
                    if section["characteristics"] & 0x20000000:  # Executable
                        valid_entry = True
                    break
        
        # Determine if this is likely a real executable
        is_real_exe = (
            pe_type in ["PE32", "PE32+"] and
            len(sections) > 0 and
            (has_code or has_executable) and
            valid_entry
        )
        
        return is_real_exe, {
            "pe_type": pe_type,
            "machine": machine,
            "num_sections": num_sections,
            "timestamp": timestamp,
            "entry_point": entry_point,
            "valid_entry": valid_entry,
            "has_code": has_code,
            "has_executable": has_executable,
            "sections": sections[:5],  # First 5 sections
            "is_real_exe": is_real_exe
        }
    
    @staticmethod
    def find_mz_signatures(data: bytes) -> List[Tuple[int, Dict]]:
        """
        Find all MZ signatures and validate PE structure
        
        Returns:
            List of (offset, validation_result) tuples
        """
        results = []
        
        # Find all MZ signatures
        start = 0
        while True:
            mz_pos = data.find(b'MZ', start)
            if mz_pos == -1:
                break
            
            # Validate PE structure at this position
            is_valid, details = PEAnalyzer.validate_pe_structure(data, mz_pos)
            results.append((mz_pos, {
                "is_valid_pe": is_valid,
                "details": details
            }))
            
            start = mz_pos + 2  # Skip past this MZ
        
        return results
    
    @staticmethod
    def analyze_exe_embeddings(data: bytes) -> Dict:
        """
        Comprehensive analysis of potential EXE embeddings
        
        Returns:
            Analysis results with reduced false positives
        """
        mz_signatures = PEAnalyzer.find_mz_signatures(data)
        
        # Count valid PEs
        valid_pes = [result for offset, result in mz_signatures if result["is_valid_pe"]]
        false_positives = [result for offset, result in mz_signatures if not result["is_valid_pe"]]
        
        # Analyze patterns
        analysis = {
            "total_mz_signatures": len(mz_signatures),
            "valid_pe_count": len(valid_pes),
            "false_positive_count": len(false_positives),
            "has_real_executable": len(valid_pes) > 0,
            "mz_details": []
        }
        
        # Add details for each MZ signature
        for i, (offset, result) in enumerate(mz_signatures):
            detail = {
                "offset": offset,
                "is_valid_pe": result["is_valid_pe"],
                "pe_type": result["details"].get("pe_type", "UNKNOWN") if result["is_valid_pe"] else None,
                "sections": len(result["details"].get("sections", [])) if result["is_valid_pe"] else 0,
                "error": result["details"].get("error") if not result["is_valid_pe"] else None
            }
            analysis["mz_details"].append(detail)
        
        # Determine threat level
        if len(valid_pes) >= 1:
            analysis["threat_level"] = "HIGH"
            analysis["reason"] = f"Valid PE structure found: {len(valid_pes)} executable(s)"
        elif len(false_positives) >= 5:
            analysis["threat_level"] = "MEDIUM"
            analysis["reason"] = f"Multiple MZ patterns without PE structure: {len(false_positives)} potential obfuscation"
        elif len(false_positives) >= 1:
            analysis["threat_level"] = "LOW"
            analysis["reason"] = f"Few MZ patterns, likely false positives: {len(false_positives)}"
        else:
            analysis["threat_level"] = "CLEAN"
            analysis["reason"] = "No executable patterns found"
        
        return analysis
