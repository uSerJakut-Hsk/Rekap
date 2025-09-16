#!/usr/bin/env python3
"""
Rekap IOC Checker
Checks Indicators of Compromise against the Rekap database
"""

import json
import re
import ipaddress
import argparse
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style
import urllib.parse

init(autoreset=True)

class IOCChecker:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.iocs_data = self.load_iocs()
        self.domains_data = self.load_domains()
        self.hashes_data = self.load_hashes()
    
    def load_iocs(self):
        """Load IOCs from JSON file"""
        try:
            with open(self.data_dir / "iocs.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"{Fore.RED}Error: iocs.json not found in {self.data_dir}")
            return {}
    
    def load_domains(self):
        """Load suspicious domains from text file"""
        domains = {}
        try:
            with open(self.data_dir / "suspicious-domains.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split(":")
                        if len(parts) >= 5:
                            domain = parts[0]
                            domains[domain] = {
                                "category": parts[1],
                                "confidence": parts[2],
                                "date_added": parts[3],
                                "description": parts[4]
                            }
        except FileNotFoundError:
            print(f"{Fore.RED}Error: suspicious-domains.txt not found")
        return domains
    
    def load_hashes(self):
        """Load malware hashes from text file"""
        hashes = {}
        try:
            with open(self.data_dir / "malware-hashes.txt", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split(":")
                        if len(parts) >= 7:
                            md5, sha1, sha256 = parts[0], parts[1], parts[2]
                            hash_data = {
                                "malware_family": parts[3],
                                "confidence": parts[4],
                                "date_added": parts[5],
                                "description": parts[6]
                            }
                            hashes[md5] = hash_data
                            hashes[sha1] = hash_data
                            hashes[sha256] = hash_data
        except FileNotFoundError:
            print(f"{Fore.RED}Error: malware-hashes.txt not found")
        return hashes
    
    def is_valid_ip(self, ip):
        """Check if string is valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def is_valid_domain(self, domain):
        """Check if string is valid domain"""
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        return re.match(pattern, domain) is not None
    
    def is_valid_hash(self, hash_str):
        """Check if string is valid hash (MD5, SHA1, SHA256)"""
        hash_patterns = {
            32: r'^[a-fA-F0-9]{32}$',  # MD5
            40: r'^[a-fA-F0-9]{40}$',  # SHA1
            64: r'^[a-fA-F0-9]{64}$'   # SHA256
        }
        hash_len = len(hash_str)
        if hash_len in hash_patterns:
            return re.match(hash_patterns[hash_len], hash_str) is not None
        return False
    
    def check_ip(self, ip):
        """Check IP against malicious IP database"""
        results = []
        
        # Check in JSON IOCs
        for ip_entry in self.iocs_data.get("malicious_ips", []):
            if ip_entry.get("ip") == ip:
                results.append({
                    "source": "Rekap IOCs Database",
                    "status": "MALICIOUS",
                    "confidence": ip_entry.get("confidence", "unknown"),
                    "type": ip_entry.get("type", "unknown"),
                    "malware_family": ip_entry.get("malware_family", "unknown"),
                    "description": ip_entry.get("description", "No description"),
                    "first_seen": ip_entry.get("first_seen", "unknown"),
                    "tags": ip_entry.get("tags", [])
                })
        
        return results
    
    def check_domain(self, domain):
        """Check domain against suspicious domain database"""
        results = []
        
        # Check in JSON IOCs
        for domain_entry in self.iocs_data.get("malicious_domains", []):
            if domain_entry.get("domain") == domain:
                results.append({
                    "source": "Rekap IOCs Database",
                    "status": "MALICIOUS",
                    "confidence": domain_entry.get("confidence", "unknown"),
                    "type": domain_entry.get("type", "unknown"),
                    "target": domain_entry.get("target", "unknown"),
                    "description": domain_entry.get("description", "No description"),
                    "first_seen": domain_entry.get("first_seen", "unknown"),
                    "tags": domain_entry.get("tags", [])
                })
        
        # Check in text file
        if domain in self.domains_data:
            entry = self.domains_data[domain]
            results.append({
                "source": "Rekap Suspicious Domains",
                "status": "SUSPICIOUS",
                "confidence": entry["confidence"],
                "type": entry["category"],
                "description": entry["description"],
                "date_added": entry["date_added"]
            })
        
        return results
    
    def check_hash(self, hash_str):
        """Check hash against malware hash database"""
        results = []
        
        if hash_str.lower() in self.hashes_data:
            entry = self.hashes_data[hash_str.lower()]
            results.append({
                "source": "Rekap Malware Hashes",
                "status": "MALICIOUS",
                "confidence": entry["confidence"],
                "malware_family": entry["malware_family"],
                "description": entry["description"],
                "date_added": entry["date_added"]
            })
        
        return results
    
    def check_url(self, url):
        """Check URL by extracting domain and checking it"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc
            if domain:
                return self.check_domain(domain)
        except:
            pass
        return []
    
    def print_results(self, ioc, ioc_type, results):
        """Print formatted results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}IOC Check Results")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}IOC: {ioc}")
        print(f"{Fore.YELLOW}Type: {ioc_type.upper()}")
        print(f"{Fore.YELLOW}Check Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if not results:
            print(f"\n{Fore.GREEN}✓ CLEAN - No threats detected in Rekap database")
            return
        
        print(f"\n{Fore.RED}⚠ THREAT DETECTED - {len(results)} match(es) found:")
        
        for i, result in enumerate(results, 1):
            print(f"\n{Fore.WHITE}Match #{i}:")
            print(f"  Source: {result.get('source', 'Unknown')}")
            
            status = result.get('status', 'UNKNOWN')
            status_color = Fore.RED if status == 'MALICIOUS' else Fore.YELLOW
            print(f"  Status: {status_color}{status}")
            
            print(f"  Confidence: {result.get('confidence', 'Unknown')}")
            print(f"  Type: {result.get('type', 'Unknown')}")
            
            if 'malware_family' in result:
                print(f"  Malware Family: {result['malware_family']}")
            if 'target' in result:
                print(f"  Target: {result['target']}")
            if 'first_seen' in result:
                print(f"  First Seen: {result['first_seen']}")
            if 'date_added' in result:
                print(f"  Date Added: {result['date_added']}")
            if 'tags' in result and result['tags']:
                print(f"  Tags: {', '.join(result['tags'])}")
            
            print(f"  Description: {result.get('description', 'No description')}")
    
    def check_ioc(self, ioc):
        """Auto-detect IOC type and check"""
        ioc = ioc.strip()
        
        if self.is_valid_ip(ioc):
            return self.check_ip(ioc), "ip"
        elif self.is_valid_domain(ioc):
            return self.check_domain(ioc), "domain"
        elif self.is_valid_hash(ioc):
            return self.check_hash(ioc), "hash"
        elif ioc.startswith(('http://', 'https://')):
            return self.check_url(ioc), "url"
        else:
            return [], "unknown"

def main():
    parser = argparse.ArgumentParser(description="Rekap IOC Checker")
    parser.add_argument("--ip", help="Check IP address")
    parser.add_argument("--domain", help="Check domain")
    parser.add_argument("--hash", help="Check file hash")
    parser.add_argument("--url", help="Check URL")
    parser.add_argument("--ioc", help="Auto-detect and check IOC")
    parser.add_argument("--data-dir", default="data", help="Data directory path")
    
    args = parser.parse_args()
    
    if not any([args.ip, args.domain, args.hash, args.url, args.ioc]):
        parser.print_help()
        return
    
    checker = IOCChecker(args.data_dir)
    
    if args.ip:
        results, ioc_type = checker.check_ip(args.ip), "ip"
        checker.print_results(args.ip, ioc_type, results)
    elif args.domain:
        results, ioc_type = checker.check_domain(args.domain), "domain"
        checker.print_results(args.domain, ioc_type, results)
    elif args.hash:
        results, ioc_type = checker.check_hash(args.hash), "hash"
        checker.print_results(args.hash, ioc_type, results)
    elif args.url:
        results, ioc_type = checker.check_url(args.url), "url"
        checker.print_results(args.url, ioc_type, results)
    elif args.ioc:
        results, ioc_type = checker.check_ioc(args.ioc)
        checker.print_results(args.ioc, ioc_type, results)

if __name__ == "__main__":
    main()