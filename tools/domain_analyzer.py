#!/usr/bin/env python3
"""
Rekap Domain Analyzer
Advanced domain reputation and analysis tool
"""

import dns.resolver
import whois
import socket
import ssl
import requests
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from colorama import init, Fore, Style
import re
import json

init(autoreset=True)

class DomainAnalyzer:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.suspicious_domains = self.load_suspicious_domains()
        self.iocs_data = self.load_iocs()
        
    def load_suspicious_domains(self):
        """Load suspicious domains database"""
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
            print(f"{Fore.YELLOW}Warning: suspicious-domains.txt not found")
        return domains
    
    def load_iocs(self):
        """Load IOCs from JSON file"""
        try:
            with open(self.data_dir / "iocs.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"{Fore.YELLOW}Warning: iocs.json not found")
            return {}
    
    def dns_lookup(self, domain):
        """Perform DNS lookups"""
        results = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": []
        }
        
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for answer in answers:
                    results[record_type].append(str(answer))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
                pass
            except Exception as e:
                results[record_type] = [f"Error: {str(e)}"]
        
        return results
    
    def whois_lookup(self, domain):
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(domain)
            return {
                "registrar": getattr(w, 'registrar', 'Unknown'),
                "creation_date": getattr(w, 'creation_date', 'Unknown'),
                "expiration_date": getattr(w, 'expiration_date', 'Unknown'),
                "updated_date": getattr(w, 'updated_date', 'Unknown'),
                "name_servers": getattr(w, 'name_servers', []),
                "status": getattr(w, 'status', []),
                "emails": getattr(w, 'emails', []),
                "country": getattr(w, 'country', 'Unknown')
            }
        except Exception as e:
            return {"error": str(e)}
    
    def ssl_certificate_check(self, domain):
        """Check SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "alt_names": [name[1] for name in cert.get('subjectAltName', [])]
                    }
        except Exception as e:
            return {"error": str(e)}
    
    def check_reputation(self, domain):
        """Check domain reputation against databases"""
        reputation_results = {
            "rekap_database": "clean",
            "threat_level": "low",
            "categories": [],
            "confidence": "unknown",
            "description": ""
        }
        
        # Check against Rekap suspicious domains
        if domain in self.suspicious_domains:
            entry = self.suspicious_domains[domain]
            reputation_results.update({
                "rekap_database": "suspicious",
                "threat_level": "high" if entry["confidence"] == "high" else "medium",
                "categories": [entry["category"]],
                "confidence": entry["confidence"],
                "description": entry["description"]
            })
        
        # Check against IOCs JSON
        for domain_entry in self.iocs_data.get("malicious_domains", []):
            if domain_entry.get("domain") == domain:
                reputation_results.update({
                    "rekap_database": "malicious",
                    "threat_level": "high",
                    "categories": [domain_entry.get("type", "unknown")],
                    "confidence": domain_entry.get("confidence", "unknown"),
                    "description": domain_entry.get("description", "")
                })
                break
        
        return reputation_results
    
    def analyze_domain_age(self, whois_data):
        """Analyze domain age and registration patterns"""
        if "error" in whois_data:
            return {"error": whois_data["error"]}
        
        try:
            creation_date = whois_data.get("creation_date")
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date and creation_date != "Unknown":
                if isinstance(creation_date, str):
                    # Try to parse string date
                    try:
                        creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
                    except:
                        return {"error": "Could not parse creation date"}
                
                age_days = (datetime.now() - creation_date).days
                age_analysis = {
                    "age_days": age_days,
                    "age_category": "new" if age_days < 30 else "recent" if age_days < 365 else "established",
                    "creation_date": creation_date.isoformat(),
                    "risk_level": "high" if age_days < 30 else "medium" if age_days < 90 else "low"
                }
                
                return age_analysis
        except Exception as e:
            return {"error": f"Date analysis failed: {str(e)}"}
        
        return {"error": "No creation date available"}
    
    def check_typosquatting(self, domain):
        """Check for typosquatting against popular domains"""
        popular_domains = [
            "google.com", "facebook.com", "microsoft.com", "amazon.com",
            "paypal.com", "apple.com", "netflix.com", "youtube.com",
            "instagram.com", "twitter.com", "linkedin.com", "github.com",
            "bni.co.id", "mandiri.co.id", "bca.co.id", "bri.co.id"
        ]
        
        potential_targets = []
        domain_lower = domain.lower()
        
        for popular in popular_domains:
            # Simple edit distance check for typos
            if self._is_similar_domain(domain_lower, popular.lower()):
                potential_targets.append(popular)
        
        return {
            "is_potential_typosquatting": len(potential_targets) > 0,
            "potential_targets": potential_targets,
            "risk_score": len(potential_targets) * 2
        }
    
    def _is_similar_domain(self, domain1, domain2):
        """Simple similarity check for typosquatting detection"""
        # Remove TLD for comparison
        d1_base = domain1.split('.')[0]
        d2_base = domain2.split('.')[0]
        
        # Check for single character differences
        if abs(len(d1_base) - len(d2_base)) <= 1:
            differences = sum(c1 != c2 for c1, c2 in zip(d1_base, d2_base))
            if differences <= 2:
                return True
        
        # Check for common typo patterns
        common_typos = {
            'o': '0', '0': 'o', 'i': '1', '1': 'i', 
            'g': 'q', 'q': 'g', 'm': 'n', 'n': 'm'
        }
        
        for char, typo in common_typos.items():
            if d1_base.replace(char, typo) == d2_base:
                return True
        
        return False
    
    def comprehensive_analysis(self, domain):
        """Perform comprehensive domain analysis"""
        print(f"{Fore.CYAN}Starting comprehensive analysis of: {domain}")
        
        analysis_results = {
            "domain": domain,
            "analysis_timestamp": datetime.now().isoformat(),
            "dns_records": {},
            "whois_info": {},
            "ssl_certificate": {},
            "reputation": {},
            "age_analysis": {},
            "typosquatting": {}
        }
        
        # DNS Analysis
        print(f"{Fore.YELLOW}[1/6] DNS Resolution...")
        analysis_results["dns_records"] = self.dns_lookup(domain)
        
        # WHOIS Analysis  
        print(f"{Fore.YELLOW}[2/6] WHOIS Lookup...")
        analysis_results["whois_info"] = self.whois_lookup(domain)
        
        # SSL Certificate Analysis
        print(f"{Fore.YELLOW}[3/6] SSL Certificate Check...")
        analysis_results["ssl_certificate"] = self.ssl_certificate_check(domain)
        
        # Reputation Check
        print(f"{Fore.YELLOW}[4/6] Reputation Analysis...")
        analysis_results["reputation"] = self.check_reputation(domain)
        
        # Domain Age Analysis
        print(f"{Fore.YELLOW}[5/6] Domain Age Analysis...")
        analysis_results["age_analysis"] = self.analyze_domain_age(analysis_results["whois_info"])
        
        # Typosquatting Check
        print(f"{Fore.YELLOW}[6/6] Typosquatting Detection...")
        analysis_results["typosquatting"] = self.check_typosquatting(domain)
        
        return analysis_results
    
    def print_analysis_results(self, results):
        """Print formatted analysis results"""
        domain = results["domain"]
        
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}Domain Analysis Report: {domain}")
        print(f"{Fore.CYAN}{'='*80}")
        
        # Reputation Summary
        reputation = results["reputation"]
        threat_level = reputation.get("threat_level", "unknown")
        
        if threat_level == "high":
            print(f"{Fore.RED}🚨 HIGH RISK DOMAIN")
        elif threat_level == "medium":
            print(f"{Fore.YELLOW}⚠️  MEDIUM RISK DOMAIN")
        else:
            print(f"{Fore.GREEN}✓ LOW RISK DOMAIN")
        
        print(f"Database Status: {reputation.get('rekap_database', 'unknown')}")
        print(f"Confidence: {reputation.get('confidence', 'unknown')}")
        if reputation.get("description"):
            print(f"Description: {reputation['description']}")
        
        # DNS Information
        print(f"\n{Fore.WHITE}DNS Records:")
        dns_records = results["dns_records"]
        for record_type, records in dns_records.items():
            if records:
                print(f"  {record_type}: {', '.join(records[:3])}")  # Limit output
        
        # WHOIS Information
        print(f"\n{Fore.WHITE}WHOIS Information:")
        whois_info = results["whois_info"]
        if "error" not in whois_info:
            print(f"  Registrar: {whois_info.get('registrar', 'Unknown')}")
            print(f"  Creation Date: {whois_info.get('creation_date', 'Unknown')}")
            print(f"  Country: {whois_info.get('country', 'Unknown')}")
        else:
            print(f"  Error: {whois_info['error']}")
        
        # Domain Age Analysis
        print(f"\n{Fore.WHITE}Domain Age Analysis:")
        age_analysis = results["age_analysis"]
        if "error" not in age_analysis:
            print(f"  Age: {age_analysis.get('age_days', 'Unknown')} days")
            print(f"  Category: {age_analysis.get('age_category', 'Unknown')}")
            print(f"  Risk Level: {age_analysis.get('risk_level', 'Unknown')}")
        else:
            print(f"  Error: {age_analysis['error']}")
        
        # SSL Certificate
        print(f"\n{Fore.WHITE}SSL Certificate:")
        ssl_cert = results["ssl_certificate"]
        if "error" not in ssl_cert:
            subject = ssl_cert.get("subject", {})
            issuer = ssl_cert.get("issuer", {})
            print(f"  Subject CN: {subject.get('commonName', 'Unknown')}")
            print(f"  Issuer: {issuer.get('organizationName', 'Unknown')}")
            print(f"  Valid Until: {ssl_cert.get('not_after', 'Unknown')}")
        else:
            print(f"  Error: {ssl_cert['error']}")
        
        # Typosquatting Analysis
        print(f"\n{Fore.WHITE}Typosquatting Analysis:")
        typo = results["typosquatting"]
        if typo.get("is_potential_typosquatting"):
            print(f"  {Fore.RED}⚠️  Potential typosquatting detected!")
            print(f"  Possible targets: {', '.join(typo['potential_targets'])}")
            print(f"  Risk Score: {typo['risk_score']}/10")
        else:
            print(f"  {Fore.GREEN}✓ No typosquatting patterns detected")
    
    def export_results(self, results, output_file):
        """Export analysis results to JSON file"""
        try:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2, default=str)
            print(f"{Fore.GREEN}Analysis results exported to: {output_file}")
        except Exception as e:
            print(f"{Fore.RED}Error exporting results: {e}")

def main():
    parser = argparse.ArgumentParser(description="Rekap Domain Analyzer")
    parser.add_argument("--domain", required=True, help="Domain to analyze")
    parser.add_argument("--export", help="Export results to JSON file")
    parser.add_argument("--data-dir", default="data", help="Data directory path")
    parser.add_argument("--quick", action="store_true", help="Quick reputation check only")
    
    args = parser.parse_args()
    
    analyzer = DomainAnalyzer(args.data_dir)
    
    if args.quick:
        # Quick reputation check only
        reputation = analyzer.check_reputation(args.domain)
        print(f"\n{Fore.CYAN}Quick Reputation Check: {args.domain}")
        print(f"Status: {reputation['rekap_database']}")
        print(f"Threat Level: {reputation['threat_level']}")
        print(f"Confidence: {reputation['confidence']}")
        if reputation['description']:
            print(f"Description: {reputation['description']}")
    else:
        # Full comprehensive analysis
        results = analyzer.comprehensive_analysis(args.domain)
        analyzer.print_analysis_results(results)
        
        if args.export:
            analyzer.export_results(results, args.export)

if __name__ == "__main__":
    main()