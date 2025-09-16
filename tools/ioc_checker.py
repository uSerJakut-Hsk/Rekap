#!/usr/bin/env python3
"""
Rekap IOC Checker - Modern Implementation 2025
Indonesia Threat Intelligence Repository

Enhanced IOC checker with modern Python practices, async support,
and improved error handling.
"""

import asyncio
import ipaddress
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from urllib.parse import urlparse

import aiohttp
import click
import httpx
from pydantic import BaseModel, ValidationError, field_validator
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

# Initialize rich console
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/rekap.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class IOCResult(BaseModel):
    """Pydantic model for IOC check results"""
    ioc: str
    ioc_type: str
    threat_detected: bool
    threat_count: int = 0
    confidence: Optional[str] = None
    threat_types: List[str] = []
    description: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = []
    sources: List[str] = []
    check_timestamp: datetime = datetime.now()

    @field_validator('ioc_type')
    @classmethod
    def validate_ioc_type(cls, v):
        valid_types = ['ip', 'domain', 'hash', 'url']
        if v not in valid_types:
            raise ValueError(f'IOC type must be one of {valid_types}')
        return v


class ThreatDatabase:
    """Modern threat database handler with async support"""
    
    def __init__(self, data_dir: Path = Path("data")):
        self.data_dir = data_dir
        self.iocs_data = {}
        self.malware_hashes = {}
        self.suspicious_domains = {}
        self.malicious_ips = {}
        
    async def load_databases(self):
        """Load all threat databases asynchronously"""
        try:
            await asyncio.gather(
                self._load_iocs(),
                self._load_malware_hashes(),
                self._load_suspicious_domains(),
                return_exceptions=True
            )
            console.print("✅ Threat databases loaded successfully", style="green")
        except Exception as e:
            console.print(f"❌ Error loading databases: {e}", style="red")
            logger.error(f"Database loading error: {e}")
    
    async def _load_iocs(self):
        """Load IOCs from JSON file"""
        iocs_file = self.data_dir / "iocs.json"
        if iocs_file.exists():
            with open(iocs_file, 'r', encoding='utf-8') as f:
                self.iocs_data = json.load(f)
    
    async def _load_malware_hashes(self):
        """Load malware hashes from text file"""
        hashes_file = self.data_dir / "malware-hashes.txt"
        if hashes_file.exists():
            with open(hashes_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split(':')
                        if len(parts) >= 6:
                            md5, sha1, sha256, family, confidence, date_added = parts[:6]
                            description = ':'.join(parts[6:]) if len(parts) > 6 else ""
                            
                            # Store all hash types
                            hash_data = {
                                'malware_family': family,
                                'confidence': confidence,
                                'date_added': date_added,
                                'description': description,
                                'md5': md5,
                                'sha1': sha1,
                                'sha256': sha256
                            }
                            
                            self.malware_hashes[md5.lower()] = hash_data
                            self.malware_hashes[sha1.lower()] = hash_data
                            self.malware_hashes[sha256.lower()] = hash_data
    
    async def _load_suspicious_domains(self):
        """Load suspicious domains from text file"""
        domains_file = self.data_dir / "suspicious-domains.txt"
        if domains_file.exists():
            with open(domains_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split(':')
                        if len(parts) >= 5:
                            domain, category, confidence, date_added, description = parts
                            self.suspicious_domains[domain.lower()] = {
                                'category': category,
                                'confidence': confidence,
                                'date_added': date_added,
                                'description': description
                            }


class IOCChecker:
    """Modern IOC checker with async support and improved validation"""
    
    def __init__(self, data_dir: Path = Path("data")):
        self.db = ThreatDatabase(data_dir)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.db.load_databases()
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'Rekap-ThreatIntel/2025'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def detect_ioc_type(self, ioc: str) -> str:
        """Detect IOC type using modern validation"""
        ioc = ioc.strip().lower()
        
        # Check if it's an IP address
        try:
            ipaddress.ip_address(ioc)
            return "ip"
        except ValueError:
            pass
        
        # Check if it's a hash
        if len(ioc) == 32 and all(c in '0123456789abcdef' for c in ioc):
            return "hash"  # MD5
        elif len(ioc) == 40 and all(c in '0123456789abcdef' for c in ioc):
            return "hash"  # SHA1
        elif len(ioc) == 64 and all(c in '0123456789abcdef' for c in ioc):
            return "hash"  # SHA256
        
        # Check if it's a URL
        if ioc.startswith(('http://', 'https://', 'ftp://')):
            return "url"
        
        # Default to domain
        if '.' in ioc and not ioc.startswith('/'):
            return "domain"
        
        return "unknown"
    
    async def check_ioc(self, ioc: str, ioc_type: Optional[str] = None) -> IOCResult:
        """Check IOC against threat databases"""
        if not ioc_type:
            ioc_type = self.detect_ioc_type(ioc)
        
        ioc_normalized = ioc.strip().lower()
        
        # Initialize result
        result = IOCResult(
            ioc=ioc,
            ioc_type=ioc_type,
            threat_detected=False
        )
        
        try:
            if ioc_type == "ip":
                await self._check_ip(ioc_normalized, result)
            elif ioc_type == "domain":
                await self._check_domain(ioc_normalized, result)
            elif ioc_type == "hash":
                await self._check_hash(ioc_normalized, result)
            elif ioc_type == "url":
                await self._check_url(ioc, result)
        
        except Exception as e:
            logger.error(f"Error checking IOC {ioc}: {e}")
            
        return result
    
    async def _check_ip(self, ip: str, result: IOCResult):
        """Check IP against malicious IPs database"""
        # Check in IOCs JSON
        if 'malicious_ips' in self.db.iocs_data:
            for ip_entry in self.db.iocs_data['malicious_ips']:
                if ip_entry.get('ip', '').lower() == ip:
                    result.threat_detected = True
                    result.threat_count += 1
                    result.confidence = ip_entry.get('confidence', 'unknown')
                    result.threat_types.append(ip_entry.get('type', 'unknown'))
                    result.description = ip_entry.get('description', '')
                    result.first_seen = ip_entry.get('first_seen', '')
                    result.last_seen = ip_entry.get('last_seen', '')
                    result.tags.extend(ip_entry.get('tags', []))
                    result.sources.append('Rekap IOCs Database')
    
    async def _check_domain(self, domain: str, result: IOCResult):
        """Check domain against suspicious domains database"""
        # Check in suspicious domains
        if domain in self.db.suspicious_domains:
            domain_data = self.db.suspicious_domains[domain]
            result.threat_detected = True
            result.threat_count += 1
            result.confidence = domain_data.get('confidence', 'unknown')
            result.threat_types.append(domain_data.get('category', 'suspicious'))
            result.description = domain_data.get('description', '')
            result.first_seen = domain_data.get('date_added', '')
            result.sources.append('Rekap Suspicious Domains')
        
        # Check in IOCs JSON
        if 'malicious_domains' in self.db.iocs_data:
            for domain_entry in self.db.iocs_data['malicious_domains']:
                if domain_entry.get('domain', '').lower() == domain:
                    result.threat_detected = True
                    result.threat_count += 1
                    result.confidence = domain_entry.get('confidence', 'unknown')
                    result.threat_types.append(domain_entry.get('type', 'unknown'))
                    result.description = domain_entry.get('description', '')
                    result.first_seen = domain_entry.get('first_seen', '')
                    result.tags.extend(domain_entry.get('tags', []))
                    result.sources.append('Rekap IOCs Database')
    
    async def _check_hash(self, hash_value: str, result: IOCResult):
        """Check hash against malware database"""
        if hash_value in self.db.malware_hashes:
            hash_data = self.db.malware_hashes[hash_value]
            result.threat_detected = True
            result.threat_count += 1
            result.confidence = hash_data.get('confidence', 'unknown')
            result.threat_types.append('malware')
            result.description = hash_data.get('description', '')
            result.first_seen = hash_data.get('date_added', '')
            result.tags.append(hash_data.get('malware_family', 'unknown'))
            result.sources.append('Rekap Malware Database')
    
    async def _check_url(self, url: str, result: IOCResult):
        """Check URL against malicious URLs database"""
        if 'malicious_urls' in self.db.iocs_data:
            for url_entry in self.db.iocs_data['malicious_urls']:
                if url_entry.get('url', '').lower() == url.lower():
                    result.threat_detected = True
                    result.threat_count += 1
                    result.confidence = url_entry.get('confidence', 'unknown')
                    result.threat_types.append(url_entry.get('type', 'unknown'))
                    result.description = url_entry.get('description', '')
                    result.first_seen = url_entry.get('first_seen', '')
                    result.tags.extend(url_entry.get('tags', []))
                    result.sources.append('Rekap IOCs Database')


def display_result(result: IOCResult):
    """Display IOC check result with rich formatting"""
    
    # Create title
    title = f"IOC Analysis: {result.ioc}"
    
    if result.threat_detected:
        panel_style = "red"
        status = "🚨 THREAT DETECTED"
        status_style = "bold red"
    else:
        panel_style = "green"
        status = "✅ CLEAN"
        status_style = "bold green"
    
    # Create main table
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", style="white")
    
    table.add_row("IOC", result.ioc)
    table.add_row("Type", result.ioc_type.upper())
    table.add_row("Status", status)
    table.add_row("Check Time", result.check_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    
    if result.threat_detected:
        table.add_row("Threat Count", str(result.threat_count))
        table.add_row("Confidence", result.confidence or "Unknown")
        
        if result.threat_types:
            table.add_row("Threat Types", ", ".join(result.threat_types))
        
        if result.tags:
            table.add_row("Tags", ", ".join(result.tags))
        
        if result.description:
            table.add_row("Description", result.description)
        
        if result.first_seen:
            table.add_row("First Seen", result.first_seen)
        
        if result.sources:
            table.add_row("Sources", ", ".join(result.sources))
    
    # Display panel
    console.print(Panel(table, title=title, style=panel_style, padding=(1, 2)))


@click.command()
@click.option('--ioc', help='IOC to check (auto-detects type)')
@click.option('--ip', help='IP address to check')
@click.option('--domain', help='Domain to check')
@click.option('--hash', 'hash_value', help='File hash to check')
@click.option('--url', help='URL to check')
@click.option('--data-dir', default='data', help='Path to data directory')
@click.option('--export', help='Export results to file (JSON format)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def main(ioc, ip, domain, hash_value, url, data_dir, export, verbose):
    """
    Rekap IOC Checker - Modern Implementation 2025
    
    Check indicators of compromise against Indonesian threat intelligence database.
    """
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Collect IOCs to check
    iocs_to_check = []
    
    if ioc:
        iocs_to_check.append((ioc, None))
    if ip:
        iocs_to_check.append((ip, 'ip'))
    if domain:
        iocs_to_check.append((domain, 'domain'))
    if hash_value:
        iocs_to_check.append((hash_value, 'hash'))
    if url:
        iocs_to_check.append((url, 'url'))
    
    if not iocs_to_check:
        console.print("❌ No IOCs provided. Use --ioc, --ip, --domain, --hash, or --url", style="red")
        sys.exit(1)
    
    async def check_all_iocs():
        results = []
        
        async with IOCChecker(Path(data_dir)) as checker:
            for ioc_value, ioc_type in iocs_to_check:
                result = await checker.check_ioc(ioc_value, ioc_type)
                results.append(result)
                display_result(result)
                
                if len(iocs_to_check) > 1:
                    console.print()  # Add spacing between results
        
        # Export results if requested
        if export:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'total_iocs': len(results),
                'threats_detected': sum(1 for r in results if r.threat_detected),
                'results': [r.model_dump(mode='json') for r in results]
            }
            
            with open(export, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            
            console.print(f"✅ Results exported to {export}", style="green")
    
    # Run async function
    try:
        asyncio.run(check_all_iocs())
    except KeyboardInterrupt:
        console.print("\n❌ Operation cancelled by user", style="red")
        sys.exit(1)
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        logger.error(f"Main execution error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()