#!/usr/bin/env python3
"""
Rekap Domain Analyzer - Modern Implementation 2025
Indonesia Threat Intelligence Repository

Advanced domain analysis with DNS resolution, WHOIS lookup,
SSL certificate analysis, and typosquatting detection.
"""

import asyncio
import json
import socket
import ssl
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse
import re

import aiohttp
import click
import dns.resolver
import dns.reversename
from pydantic import BaseModel, field_validator
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import print as rprint
import whois

from ioc_checker import IOCChecker, IOCResult

console = Console()
logger = logging.getLogger(__name__)


class DNSRecord(BaseModel):
    """DNS record information"""
    record_type: str
    value: str
    ttl: Optional[int] = None


class SSLCertInfo(BaseModel):
    """SSL certificate information"""
    subject_cn: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    is_valid: bool = False
    is_expired: bool = True
    days_until_expiry: Optional[int] = None


class WhoisInfo(BaseModel):
    """WHOIS information"""
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    registrant_country: Optional[str] = None
    name_servers: List[str] = []
    status: List[str] = []


class DomainRiskAssessment(BaseModel):
    """Domain risk assessment"""
    risk_score: int = 0  # 0-10 scale
    risk_level: str = "unknown"
    risk_factors: List[str] = []
    is_newly_registered: bool = False
    is_suspicious_tld: bool = False
    has_typosquatting_indicators: bool = False


class TyposquattingResult(BaseModel):
    """Typosquatting analysis result"""
    is_potential_typosquatting: bool = False
    similarity_score: float = 0.0
    possible_targets: List[str] = []
    distance_analysis: Dict[str, int] = {}


class DomainAnalysisResult(BaseModel):
    """Complete domain analysis result"""
    domain: str
    analysis_timestamp: datetime = datetime.now()
    
    # Basic validation
    is_valid_domain: bool = True
    validation_error: Optional[str] = None
    
    # DNS information
    dns_records: List[DNSRecord] = []
    dns_resolution_successful: bool = False
    
    # WHOIS information
    whois_info: Optional[WhoisInfo] = None
    whois_lookup_successful: bool = False
    
    # SSL certificate
    ssl_cert_info: Optional[SSLCertInfo] = None
    ssl_analysis_successful: bool = False
    
    # Threat intelligence
    threat_result: Optional[IOCResult] = None
    
    # Risk assessment
    risk_assessment: DomainRiskAssessment = DomainRiskAssessment()
    
    # Typosquatting analysis
    typosquatting_result: TyposquattingResult = TyposquattingResult()
    
    # Additional metadata
    domain_age_days: Optional[int] = None
    is_subdomain: bool = False
    parent_domain: Optional[str] = None


class DomainAnalyzer:
    """Advanced domain analyzer with multiple analysis capabilities"""
    
    def __init__(self, data_dir: Path = Path("data")):
        self.data_dir = data_dir
        self.ioc_checker: Optional[IOCChecker] = None
        self.popular_domains = self._load_popular_domains()
        
    def _load_popular_domains(self) -> Set[str]:
        """Load popular domains for typosquatting detection"""
        # Popular Indonesian and international domains
        popular = {
            # Indonesian
            'google.co.id', 'detik.com', 'kompas.com', 'liputan6.com', 'tribunnews.com',
            'bni.co.id', 'mandiri.co.id', 'bca.co.id', 'bri.co.id', 'cimb.co.id',
            'tokopedia.com', 'shopee.co.id', 'blibli.com', 'bukalapak.com', 'lazada.co.id',
            
            # International
            'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'netflix.com', 'twitter.com', 'instagram.com', 'linkedin.com',
            'github.com', 'stackoverflow.com', 'reddit.com', 'youtube.com', 'whatsapp.com'
        }
        return popular
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.ioc_checker = IOCChecker(self.data_dir)
        await self.ioc_checker.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.ioc_checker:
            await self.ioc_checker.__aexit__(exc_type, exc_val, exc_tb)
    
    def _validate_domain(self, domain: str) -> tuple[bool, Optional[str]]:
        """Validate domain format"""
        # Basic domain regex
        domain_regex = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if not domain or len(domain) > 253:
            return False, "Domain too long or empty"
        
        if not domain_regex.match(domain):
            return False, "Invalid domain format"
        
        return True, None
    
    async def analyze_domain(self, domain: str, quick_mode: bool = False) -> DomainAnalysisResult:
        """Comprehensive domain analysis"""
        result = DomainAnalysisResult(domain=domain.lower())
        
        # Validate domain format
        is_valid, error = self._validate_domain(domain)
        result.is_valid_domain = is_valid
        result.validation_error = error
        
        if not is_valid:
            return result
        
        # Determine if subdomain
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            result.is_subdomain = True
            result.parent_domain = '.'.join(domain_parts[-2:])
        
        # Run analysis tasks
        tasks = []
        
        # DNS analysis
        tasks.append(self._analyze_dns(domain, result))
        
        # Threat intelligence check
        tasks.append(self._check_threat_intelligence(domain, result))
        
        if not quick_mode:
            # WHOIS analysis (slower)
            tasks.append(self._analyze_whois(domain, result))
            
            # SSL certificate analysis
            tasks.append(self._analyze_ssl_certificate(domain, result))
            
            # Typosquatting analysis
            tasks.append(self._analyze_typosquatting(domain, result))
        
        # Execute all tasks
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Generate risk assessment
        self._assess_risk(result)
        
        return result
    
    async def _analyze_dns(self, domain: str, result: DomainAnalysisResult):
        """Analyze DNS records"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 30
            
            # Record types to query
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    for answer in answers:
                        result.dns_records.append(DNSRecord(
                            record_type=record_type,
                            value=str(answer),
                            ttl=answers.ttl
                        ))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    continue
                except Exception as e:
                    logger.debug(f"DNS query error for {record_type}: {e}")
            
            result.dns_resolution_successful = len(result.dns_records) > 0
            
        except Exception as e:
            logger.error(f"DNS analysis error for {domain}: {e}")
    
    async def _analyze_whois(self, domain: str, result: DomainAnalysisResult):
        """Analyze WHOIS information"""
        try:
            # Run WHOIS lookup in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, whois.whois, domain)
            
            if whois_data:
                result.whois_info = WhoisInfo(
                    registrar=whois_data.registrar if hasattr(whois_data, 'registrar') else None,
                    creation_date=whois_data.creation_date[0] if isinstance(whois_data.creation_date, list) else whois_data.creation_date if hasattr(whois_data, 'creation_date') else None,
                    expiration_date=whois_data.expiration_date[0] if isinstance(whois_data.expiration_date, list) else whois_data.expiration_date if hasattr(whois_data, 'expiration_date') else None,
                    updated_date=whois_data.updated_date[0] if isinstance(whois_data.updated_date, list) else whois_data.updated_date if hasattr(whois_data, 'updated_date') else None,
                    registrant_country=whois_data.country if hasattr(whois_data, 'country') else None,
                    name_servers=whois_data.name_servers if hasattr(whois_data, 'name_servers') and whois_data.name_servers else [],
                    status=whois_data.status if hasattr(whois_data, 'status') and whois_data.status else []
                )
                
                # Calculate domain age
                if result.whois_info.creation_date:
                    age_delta = datetime.now() - result.whois_info.creation_date
                    result.domain_age_days = age_delta.days
                
                result.whois_lookup_successful = True
                
        except Exception as e:
            logger.debug(f"WHOIS analysis error for {domain}: {e}")
    
    async def _analyze_ssl_certificate(self, domain: str, result: DomainAnalysisResult):
        """Analyze SSL certificate"""
        try:
            # Get SSL certificate info
            context = ssl.create_default_context()
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=context),
                timeout=aiohttp.ClientTimeout(total=10)
            ) as session:
                try:
                    async with session.get(f"https://{domain}", allow_redirects=True) as response:
                        # Get certificate info from connection
                        ssl_info = response.connection.transport.get_extra_info('ssl_object')
                        if ssl_info:
                            cert = ssl_info.getpeercert()
                            
                            # Parse certificate dates
                            valid_from = None
                            valid_until = None
                            
                            if 'notBefore' in cert:
                                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                            
                            if 'notAfter' in cert:
                                valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                            
                            # Calculate validity
                            now = datetime.now(timezone.utc)
                            is_valid = valid_from <= now <= valid_until if (valid_from and valid_until) else False
                            is_expired = valid_until < now if valid_until else True
                            days_until_expiry = (valid_until - now).days if valid_until else None
                            
                            result.ssl_cert_info = SSLCertInfo(
                                subject_cn=cert.get('subject', [[]])[0][0][1] if cert.get('subject') else None,
                                issuer=cert.get('issuer', [[]])[0][0][1] if cert.get('issuer') else None,
                                valid_from=valid_from,
                                valid_until=valid_until,
                                is_valid=is_valid,
                                is_expired=is_expired,
                                days_until_expiry=days_until_expiry
                            )
                            
                            result.ssl_analysis_successful = True
                
                except Exception as e:
                    logger.debug(f"SSL certificate analysis error for {domain}: {e}")
                    
        except Exception as e:
            logger.debug(f"SSL analysis setup error for {domain}: {e}")
    
    async def _check_threat_intelligence(self, domain: str, result: DomainAnalysisResult):
        """Check domain against threat intelligence"""
        try:
            if self.ioc_checker:
                threat_result = await self.ioc_checker.check_ioc(domain, "domain")
                result.threat_result = threat_result
        except Exception as e:
            logger.error(f"Threat intelligence check error for {domain}: {e}")
    
    async def _analyze_typosquatting(self, domain: str, result: DomainAnalysisResult):
        """Analyze potential typosquatting"""
        try:
            typo_result = TyposquattingResult()
            
            # Check against popular domains
            for popular_domain in self.popular_domains:
                similarity = self._calculate_domain_similarity(domain, popular_domain)
                
                if similarity > 0.7 and similarity < 1.0:  # High similarity but not exact match
                    typo_result.is_potential_typosquatting = True
                    typo_result.possible_targets.append(popular_domain)
                    typo_result.distance_analysis[popular_domain] = self._levenshtein_distance(domain, popular_domain)
                    
                    if similarity > typo_result.similarity_score:
                        typo_result.similarity_score = similarity
            
            result.typosquatting_result = typo_result
            
        except Exception as e:
            logger.error(f"Typosquatting analysis error for {domain}: {e}")
    
    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains"""
        # Remove TLD for comparison
        d1 = domain1.split('.')[0]
        d2 = domain2.split('.')[0]
        
        # Calculate Levenshtein similarity
        distance = self._levenshtein_distance(d1, d2)
        max_len = max(len(d1), len(d2))
        
        if max_len == 0:
            return 1.0
        
        return 1.0 - (distance / max_len)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _assess_risk(self, result: DomainAnalysisResult):
        """Generate risk assessment for domain"""
        risk_assessment = DomainRiskAssessment()
        risk_score = 0
        risk_factors = []
        
        # Threat intelligence findings
        if result.threat_result and result.threat_result.threat_detected:
            risk_score += 8
            risk_factors.append("Listed in threat intelligence database")
        
        # Domain age analysis
        if result.domain_age_days is not None:
            if result.domain_age_days < 30:
                risk_score += 3
                risk_factors.append("Very recently registered domain")
                risk_assessment.is_newly_registered = True
            elif result.domain_age_days < 90:
                risk_score += 2
                risk_factors.append("Recently registered domain")
        
        # Typosquatting indicators
        if result.typosquatting_result.is_potential_typosquatting:
            risk_score += 4
            risk_factors.append("Potential typosquatting detected")
            risk_assessment.has_typosquatting_indicators = True
        
        # Suspicious TLD analysis
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.click', '.download', '.site', '.online'}
        domain_tld = '.' + result.domain.split('.')[-1]
        if domain_tld in suspicious_tlds:
            risk_score += 2
            risk_factors.append("Suspicious top-level domain")
            risk_assessment.is_suspicious_tld = True
        
        # SSL certificate issues
        if result.ssl_cert_info:
            if result.ssl_cert_info.is_expired:
                risk_score += 2
                risk_factors.append("Expired SSL certificate")
            elif not result.ssl_cert_info.is_valid:
                risk_score += 1
                risk_factors.append("Invalid SSL certificate")
        elif result.ssl_analysis_successful is False:
            risk_score += 1
            risk_factors.append("No SSL certificate found")
        
        # DNS resolution issues
        if not result.dns_resolution_successful:
            risk_score += 1
            risk_factors.append("DNS resolution issues")
        
        # Determine risk level
        if risk_score >= 8:
            risk_level = "high"
        elif risk_score >= 5:
            risk_level = "medium"
        elif risk_score >= 2:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        risk_assessment.risk_score = min(risk_score, 10)  # Cap at 10
        risk_assessment.risk_level = risk_level
        risk_assessment.risk_factors = risk_factors
        
        result.risk_assessment = risk_assessment


def display_domain_analysis(result: DomainAnalysisResult, show_detailed: bool = True):
    """Display comprehensive domain analysis results"""
    
    # Main title with risk indication
    risk_color = {
        "high": "red",
        "medium": "yellow", 
        "low": "blue",
        "minimal": "green",
        "unknown": "white"
    }.get(result.risk_assessment.risk_level, "white")
    
    risk_emoji = {
        "high": "🚨",
        "medium": "⚠️",
        "low": "⚡",
        "minimal": "✅",
        "unknown": "❓"
    }.get(result.risk_assessment.risk_level, "❓")
    
    title = f"Domain Analysis: {result.domain}"
    
    # Main info table
    main_table = Table(show_header=False, box=None, padding=(0, 1))
    main_table.add_column("Field", style="cyan", width=25)
    main_table.add_column("Value", style="white")
    
    main_table.add_row("Domain", result.domain)
    main_table.add_row("Analysis Time", result.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    main_table.add_row("Valid Domain", "✅ Yes" if result.is_valid_domain else f"❌ No - {result.validation_error}")
    
    # Risk assessment
    risk_display = f"[{risk_color}]{risk_emoji} {result.risk_assessment.risk_level.upper()} ({result.risk_assessment.risk_score}/10)[/{risk_color}]"
    main_table.add_row("Risk Level", risk_display)
    
    # Domain characteristics
    if result.is_subdomain:
        main_table.add_row("Type", f"Subdomain of {result.parent_domain}")
    else:
        main_table.add_row("Type", "Root domain")
    
    if result.domain_age_days is not None:
        age_years = result.domain_age_days // 365
        age_days = result.domain_age_days % 365
        age_str = f"{age_years} years, {age_days} days" if age_years > 0 else f"{age_days} days"
        main_table.add_row("Domain Age", age_str)
    
    console.print(Panel(main_table, title=title, style=risk_color, padding=(1, 2)))
    console.print()
    
    # Threat Intelligence Results
    if result.threat_result:
        threat_table = Table(title="🛡️  Threat Intelligence", show_header=False, box=None)
        threat_table.add_column("Field", style="cyan", width=20)
        threat_table.add_column("Value", style="white")
        
        if result.threat_result.threat_detected:
            threat_table.add_row("Status", "[red]🚨 THREAT DETECTED[/red]")
            threat_table.add_row("Confidence", result.threat_result.confidence or "Unknown")
            
            if result.threat_result.threat_types:
                threat_table.add_row("Threat Types", ", ".join(result.threat_result.threat_types))
            
            if result.threat_result.description:
                threat_table.add_row("Description", result.threat_result.description)
            
            if result.threat_result.tags:
                threat_table.add_row("Tags", ", ".join(result.threat_result.tags))
        else:
            threat_table.add_row("Status", "[green]✅ CLEAN[/green]")
        
        console.print(Panel(threat_table, style="blue", padding=(1, 2)))
        console.print()
    
    if not show_detailed:
        return
    
    # DNS Records
    if result.dns_records:
        dns_table = Table(title="🌐 DNS Records", show_header=True)
        dns_table.add_column("Type", style="cyan", width=8)
        dns_table.add_column("Value", style="white")
        dns_table.add_column("TTL", justify="right", style="yellow", width=8)
        
        # Group by record type
        dns_by_type = {}
        for record in result.dns_records:
            if record.record_type not in dns_by_type:
                dns_by_type[record.record_type] = []
            dns_by_type[record.record_type].append(record)
        
        for record_type in sorted(dns_by_type.keys()):
            for i, record in enumerate(dns_by_type[record_type]):
                type_display = record_type if i == 0 else ""
                ttl_display = str(record.ttl) if record.ttl else "N/A"
                dns_table.add_row(type_display, record.value, ttl_display)
        
        console.print(Panel(dns_table, style="blue", padding=(1, 2)))
        console.print()
    
    # WHOIS Information
    if result.whois_info:
        whois_table = Table(title="📋 WHOIS Information", show_header=False, box=None)
        whois_table.add_column("Field", style="cyan", width=20)
        whois_table.add_column("Value", style="white")
        
        if result.whois_info.registrar:
            whois_table.add_row("Registrar", result.whois_info.registrar)
        
        if result.whois_info.creation_date:
            whois_table.add_row("Created", result.whois_info.creation_date.strftime("%Y-%m-%d"))
        
        if result.whois_info.expiration_date:
            whois_table.add_row("Expires", result.whois_info.expiration_date.strftime("%Y-%m-%d"))
        
        if result.whois_info.registrant_country:
            whois_table.add_row("Country", result.whois_info.registrant_country)
        
        if result.whois_info.name_servers:
            ns_list = ", ".join(result.whois_info.name_servers[:3])  # Show first 3
            if len(result.whois_info.name_servers) > 3:
                ns_list += f" (+{len(result.whois_info.name_servers) - 3} more)"
            whois_table.add_row("Name Servers", ns_list)
        
        console.print(Panel(whois_table, style="blue", padding=(1, 2)))
        console.print()
    
    # SSL Certificate
    if result.ssl_cert_info:
        ssl_table = Table(title="🔒 SSL Certificate", show_header=False, box=None)
        ssl_table.add_column("Field", style="cyan", width=20)
        ssl_table.add_column("Value", style="white")
        
        if result.ssl_cert_info.subject_cn:
            ssl_table.add_row("Subject CN", result.ssl_cert_info.subject_cn)
        
        if result.ssl_cert_info.issuer:
            ssl_table.add_row("Issuer", result.ssl_cert_info.issuer)
        
        if result.ssl_cert_info.valid_from:
            ssl_table.add_row("Valid From", result.ssl_cert_info.valid_from.strftime("%Y-%m-%d %H:%M:%S UTC"))
        
        if result.ssl_cert_info.valid_until:
            ssl_table.add_row("Valid Until", result.ssl_cert_info.valid_until.strftime("%Y-%m-%d %H:%M:%S UTC"))
        
        # Validity status
        if result.ssl_cert_info.is_valid:
            status = "[green]✅ Valid[/green]"
        elif result.ssl_cert_info.is_expired:
            status = "[red]❌ Expired[/red]"
        else:
            status = "[yellow]⚠️  Invalid[/yellow]"
        
        ssl_table.add_row("Status", status)
        
        if result.ssl_cert_info.days_until_expiry is not None:
            if result.ssl_cert_info.days_until_expiry < 0:
                expiry_str = f"[red]Expired {abs(result.ssl_cert_info.days_until_expiry)} days ago[/red]"
            elif result.ssl_cert_info.days_until_expiry < 30:
                expiry_str = f"[yellow]Expires in {result.ssl_cert_info.days_until_expiry} days[/yellow]"
            else:
                expiry_str = f"[green]Expires in {result.ssl_cert_info.days_until_expiry} days[/green]"
            ssl_table.add_row("Expiry", expiry_str)
        
        console.print(Panel(ssl_table, style="blue", padding=(1, 2)))
        console.print()
    
    # Typosquatting Analysis
    if result.typosquatting_result.is_potential_typosquatting:
        typo_table = Table(title="⚠️  Typosquatting Analysis", show_header=True)
        typo_table.add_column("Possible Target", style="yellow")
        typo_table.add_column("Distance", justify="right", style="cyan")
        typo_table.add_column("Similarity", justify="right", style="green")
        
        for target in result.typosquatting_result.possible_targets:
            distance = result.typosquatting_result.distance_analysis.get(target, 0)
            similarity = (1.0 - distance / max(len(result.domain), len(target))) * 100
            typo_table.add_row(target, str(distance), f"{similarity:.1f}%")
        
        console.print(Panel(typo_table, style="yellow", padding=(1, 2)))
        console.print()
    
    # Risk Factors
    if result.risk_assessment.risk_factors:
        risk_tree = Tree("🎯 Risk Factors")
        for factor in result.risk_assessment.risk_factors:
            risk_tree.add(f"[red]•[/red] {factor}")
        
        console.print(Panel(risk_tree, style=risk_color, padding=(1, 2)))


async def export_domain_analysis(result: DomainAnalysisResult, export_path: str):
    """Export domain analysis results to JSON"""
    export_data = {
        "metadata": {
            "export_timestamp": datetime.now().isoformat(),
            "tool": "Rekap Domain Analyzer 2025",
            "version": "2.0.0"
        },
        "analysis": result.model_dump(mode='json')
    }
    
    with open(export_path, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)


@click.command()
@click.option('--domain', required=True, help='Domain to analyze')
@click.option('--quick', is_flag=True, help='Quick analysis (skip WHOIS, SSL, typosquatting)')
@click.option('--data-dir', default='data', help='Path to threat data directory')
@click.option('--export', help='Export results to JSON file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--summary-only', is_flag=True, help='Show only summary (no detailed tables)')
def main(domain, quick, data_dir, export, verbose, summary_only):
    """
    Rekap Domain Analyzer - Modern Implementation 2025
    
    Comprehensive domain analysis including DNS, WHOIS, SSL certificates,
    threat intelligence, and typosquatting detection.
    """
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        console.print("🔍 Verbose logging enabled", style="blue")
    
    async def analyze_domain_main():
        console.print(f"🔍 Analyzing domain: [cyan]{domain}[/cyan]")
        
        if quick:
            console.print("⚡ Quick mode enabled (basic analysis only)")
        
        console.print()
        
        async with DomainAnalyzer(Path(data_dir)) as analyzer:
            # Perform analysis
            result = await analyzer.analyze_domain(domain, quick_mode=quick)
            
            # Display results
            display_domain_analysis(result, show_detailed=not summary_only)
            
            # Export if requested
            if export:
                try:
                    await export_domain_analysis(result, export)
                    console.print(f"\n✅ Analysis exported to [cyan]{export}[/cyan]", style="green")
                except Exception as e:
                    console.print(f"\n❌ Export failed: {e}", style="red")
    
    # Run analysis
    try:
        asyncio.run(analyze_domain_main())
    except KeyboardInterrupt:
        console.print("\n❌ Analysis cancelled by user", style="red")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n❌ Analysis failed: {e}", style="red")
        logger.error(f"Domain analysis error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()