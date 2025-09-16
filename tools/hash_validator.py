#!/usr/bin/env python3
"""
Rekap Hash Validator
Specialized tool for validating and analyzing file hashes
"""

import re
import hashlib
import argparse
from pathlib import Path
from colorama import init, Fore, Style
from datetime import datetime

init(autoreset=True)

class HashValidator:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.hashes_db = self.load_hashes_database()
    
    def load_hashes_database(self):
        """Load malware hashes from database file"""
        hashes = {}
        try:
            with open(self.data_dir / "malware-hashes.txt", "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            parts = line.split(":")
                            if len(parts) >= 7:
                                md5, sha1, sha256 = parts[0], parts[1], parts[2]
                                hash_info = {
                                    "md5": md5,
                                    "sha1": sha1,
                                    "sha256": sha256,
                                    "malware_family": parts[3],
                                    "confidence": parts[4],
                                    "date_added": parts[5],
                                    "description": parts[6],
                                    "line_number": line_num
                                }
                                # Index by all three hash types
                                hashes[md5.lower()] = hash_info
                                hashes[sha1.lower()] = hash_info
                                hashes[sha256.lower()] = hash_info
                        except Exception as e:
                            print(f"{Fore.YELLOW}Warning: Skipping malformed line {line_num}: {e}")
        except FileNotFoundError:
            print(f"{Fore.RED}Error: malware-hashes.txt not found in {self.data_dir}")
        return hashes
    
    def identify_hash_type(self, hash_string):
        """Identify hash type based on length and format"""
        hash_string = hash_string.strip().lower()
        
        # Remove common prefixes
        prefixes = ['md5:', 'sha1:', 'sha256:', '0x']
        for prefix in prefixes:
            if hash_string.startswith(prefix):
                hash_string = hash_string[len(prefix):]
        
        hash_types = {
            32: "MD5",
            40: "SHA1", 
            64: "SHA256",
            128: "SHA512"  # Not in our DB but good to identify
        }
        
        length = len(hash_string)
        if length in hash_types:
            # Validate hex format
            if re.match(r'^[a-f0-9]+$', hash_string):
                return hash_types[length], hash_string
        
        return None, hash_string
    
    def calculate_file_hashes(self, file_path):
        """Calculate MD5, SHA1, SHA256 hashes of a file"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return None, f"File not found: {file_path}"
            
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            return {
                "file_path": str(file_path),
                "file_size": file_path.stat().st_size,
                "md5": md5_hash.hexdigest(),
                "sha1": sha1_hash.hexdigest(),
                "sha256": sha256_hash.hexdigest()
            }, None
            
        except Exception as e:
            return None, f"Error calculating hashes: {e}"
    
    def validate_hash(self, hash_string):
        """Validate hash and check against malware database"""
        hash_type, cleaned_hash = self.identify_hash_type(hash_string)
        
        result = {
            "original_input": hash_string,
            "cleaned_hash": cleaned_hash,
            "hash_type": hash_type,
            "is_valid": hash_type is not None,
            "malware_match": None,
            "validation_time": datetime.now().isoformat()
        }
        
        if result["is_valid"] and cleaned_hash in self.hashes_db:
            result["malware_match"] = self.hashes_db[cleaned_hash].copy()
        
        return result
    
    def bulk_validate(self, hash_list):
        """Validate multiple hashes"""
        results = []
        for hash_item in hash_list:
            result = self.validate_hash(hash_item.strip())
            results.append(result)
        return results
    
    def print_hash_result(self, result):
        """Print formatted hash validation result"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}Hash Validation Results")
        print(f"{Fore.CYAN}{'='*70}")
        
        print(f"{Fore.YELLOW}Original Input: {result['original_input']}")
        print(f"{Fore.YELLOW}Cleaned Hash:  {result['cleaned_hash']}")
        
        if result["is_valid"]:
            print(f"{Fore.GREEN}✓ Valid {result['hash_type']} hash")
        else:
            print(f"{Fore.RED}✗ Invalid hash format")
            return
        
        if result["malware_match"]:
            match = result["malware_match"]
            print(f"\n{Fore.RED}🚨 MALWARE DETECTED!")
            print(f"{Fore.WHITE}Malware Family: {Fore.RED}{match['malware_family']}")
            print(f"{Fore.WHITE}Confidence: {self._get_confidence_color(match['confidence'])}{match['confidence']}")
            print(f"{Fore.WHITE}Date Added: {match['date_added']}")
            print(f"{Fore.WHITE}Description: {match['description']}")
            print(f"\n{Fore.WHITE}All Hashes for this malware:")
            print(f"  MD5:    {match['md5']}")
            print(f"  SHA1:   {match['sha1']}")
            print(f"  SHA256: {match['sha256']}")
        else:
            print(f"\n{Fore.GREEN}✓ Clean - No malware match found in database")
    
    def print_file_analysis(self, hashes_info, error):
        """Print file hash analysis results"""
        if error:
            print(f"{Fore.RED}Error: {error}")
            return
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}File Hash Analysis")
        print(f"{Fore.CYAN}{'='*70}")
        
        print(f"{Fore.YELLOW}File: {hashes_info['file_path']}")
        print(f"{Fore.YELLOW}Size: {hashes_info['file_size']:,} bytes")
        print(f"\n{Fore.WHITE}Calculated Hashes:")
        print(f"  MD5:    {hashes_info['md5']}")
        print(f"  SHA1:   {hashes_info['sha1']}")
        print(f"  SHA256: {hashes_info['sha256']}")
        
        # Check each hash against database
        threats_found = []
        for hash_type in ['md5', 'sha1', 'sha256']:
            hash_value = hashes_info[hash_type]
            if hash_value in self.hashes_db:
                threats_found.append((hash_type.upper(), self.hashes_db[hash_value]))
        
        if threats_found:
            print(f"\n{Fore.RED}🚨 MALWARE DETECTED!")
            for hash_type, match in threats_found:
                print(f"\n{Fore.RED}Match found via {hash_type} hash:")
                print(f"{Fore.WHITE}  Malware Family: {Fore.RED}{match['malware_family']}")
                print(f"{Fore.WHITE}  Confidence: {self._get_confidence_color(match['confidence'])}{match['confidence']}")
                print(f"{Fore.WHITE}  Description: {match['description']}")
        else:
            print(f"\n{Fore.GREEN}✓ Clean - File not found in malware database")
    
    def _get_confidence_color(self, confidence):
        """Get color for confidence level"""
        if confidence.lower() == "high":
            return Fore.RED
        elif confidence.lower() == "medium":
            return Fore.YELLOW
        else:
            return Fore.WHITE
    
    def export_results(self, results, output_file):
        """Export results to file"""
        try:
            with open(output_file, "w") as f:
                f.write("# Rekap Hash Validation Results\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write("# Format: hash,hash_type,is_valid,malware_family,confidence,description\n\n")
                
                for result in results:
                    malware_info = result.get("malware_match", {})
                    line = f"{result['cleaned_hash']},{result.get('hash_type', 'unknown')},{result['is_valid']},{malware_info.get('malware_family', '')},{malware_info.get('confidence', '')},{malware_info.get('description', '')}\n"
                    f.write(line)
            
            print(f"{Fore.GREEN}Results exported to: {output_file}")
        except Exception as e:
            print(f"{Fore.RED}Error exporting results: {e}")

def main():
    parser = argparse.ArgumentParser(description="Rekap Hash Validator")
    parser.add_argument("--hash", help="Single hash to validate")
    parser.add_argument("--file", help="Calculate and validate hashes of file")
    parser.add_argument("--bulk", help="File containing list of hashes to validate")
    parser.add_argument("--export", help="Export results to file")
    parser.add_argument("--data-dir", default="data", help="Data directory path")
    
    args = parser.parse_args()
    
    if not any([args.hash, args.file, args.bulk]):
        parser.print_help()
        return
    
    validator = HashValidator(args.data_dir)
    
    if args.hash:
        result = validator.validate_hash(args.hash)
        validator.print_hash_result(result)
        
        if args.export:
            validator.export_results([result], args.export)
    
    elif args.file:
        hashes_info, error = validator.calculate_file_hashes(args.file)
        validator.print_file_analysis(hashes_info, error)
    
    elif args.bulk:
        try:
            with open(args.bulk, "r") as f:
                hash_list = [line.strip() for line in f if line.strip()]
            
            print(f"{Fore.CYAN}Validating {len(hash_list)} hashes...")
            results = validator.bulk_validate(hash_list)
            
            malware_count = sum(1 for r in results if r.get("malware_match"))
            print(f"\n{Fore.YELLOW}Summary: {malware_count}/{len(results)} hashes matched malware database")
            
            if args.export:
                validator.export_results(results, args.export)
            else:
                # Print detailed results for each hash
                for result in results:
                    validator.print_hash_result(result)
        
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File not found: {args.bulk}")
        except Exception as e:
            print(f"{Fore.RED}Error processing bulk file: {e}")

if __name__ == "__main__":
    main()