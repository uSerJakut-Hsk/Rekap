#!/usr/bin/env python3
"""
Rekap Hash Validator - Modern Implementation 2025
Indonesia Threat Intelligence Repository

Advanced malware hash validation with file analysis,
threat intelligence lookup, and multi-format support.
"""

import asyncio
import hashlib
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Set, Any
import aiofiles

import click
from pydantic import BaseModel, field_validator
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich import print as rprint

from ioc_checker import IOCChecker, IOCResult, ThreatDatabase

console = Console()
logger = logging.getLogger(__name__)


class HashInfo(BaseModel):
    """Hash information structure"""
    hash_value: str
    hash_type: str  # md5, sha1, sha256, sha384, sha512
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    
    @field_validator('hash_type')
    @classmethod
    def validate_hash_type(cls, v):
        valid_types = ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
        if v not in valid_types:
            raise ValueError(f'Hash type must be one of {valid_types}')
        return v


class MalwareInfo(BaseModel):
    """Malware information from database"""
    malware_family: str
    confidence: str
    date_added: str
    description: str
    all_hashes: Dict[str, str] = {}  # hash_type -> hash_value
    tags: List[str] = []


class HashValidationResult(BaseModel):
    """Hash validation result"""
    hash_info: HashInfo
    validation_timestamp: datetime = datetime.now()
    
    # Validation status
    is_valid_format: bool = True
    format_error: Optional[str] = None
    
    # File analysis (if applicable)
    file_exists: bool = False
    file_readable: bool = False
    calculated_hashes: Dict[str, str] = {}  # hash_type -> calculated_value
    
    # Threat intelligence
    threat_result: Optional[IOCResult] = None
    malware_info: Optional[MalwareInfo] = None
    
    # Analysis metadata
    is_malware: bool = False
    threat_level: str = "unknown"  # clean, suspicious, malicious
    analysis_sources: List[str] = []


class HashValidator:
    """Modern hash validator with multi-source analysis"""
    
    def __init__(self, data_dir: Path = Path("data")):
        self.data_dir = data_dir
        self.ioc_checker: Optional[IOCChecker] = None
        self.threat_db: Optional[ThreatDatabase] = None
        
        # Hash algorithms
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.ioc_checker = IOCChecker(self.data_dir)
        await self.ioc_checker.__aenter__()
        
        self.threat_db = ThreatDatabase(self.data_dir)
        await self.threat_db.load_databases()
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.ioc_checker:
            await self.ioc_checker.__aexit__(exc_type, exc_val, exc_tb)
    
    def detect_hash_type(self, hash_value: str) -> Optional[str]:
        """Detect hash type based on length and format"""
        hash_clean = hash_value.lower().strip()
        
        # Check if it's a valid hex string
        if not all(c in '0123456789abcdef' for c in hash_clean):
            return None
        
        # Determine type by length
        length_to_type = {
            32: 'md5',
            40: 'sha1',
            64: 'sha256',
            96: 'sha384',
            128: 'sha512'
        }
        
        return length_to_type.get(len(hash_clean))
    
    def validate_hash_format(self, hash_value: str, expected_type: Optional[str] = None) -> tuple[bool, Optional[str], Optional[str]]:
        """Validate hash format and return (is_valid, error_message, detected_type)"""
        if not hash_value or not hash_value.strip():
            return False, "Hash value is empty", None
        
        hash_clean = hash_value.lower().strip()
        detected_type = self.detect_hash_type(hash_clean)
        
        if not detected_type:
            if not all(c in '0123456789abcdef' for c in hash_clean):
                return False, "Hash contains invalid characters (not hexadecimal)", None
            else:
                return False, f"Hash length {len(hash_clean)} doesn't match any known hash type", None
        
        if expected_type and expected_type != detected_type:
            return False, f"Hash type mismatch: expected {expected_type}, detected {detected_type}", detected_type
        
        return True, None, detected_type
    
    async def calculate_file_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate multiple hashes for a file asynchronously"""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")
        
        # Initialize hash objects
        hash_objects = {name: algo() for name, algo in self.hash_algorithms.items()}
        
        # Read file in chunks to handle large files
        chunk_size = 64 * 1024  # 64KB chunks
        
        async with aiofiles.open(file_path, 'rb') as f:
            while True:
                chunk = await f.read(chunk_size)
                if not chunk:
                    break
                
                # Update all hash objects
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)
        
        # Return calculated hashes
        return {name: hash_obj.hexdigest() for name, hash_obj in hash_objects.items()}
    
    async def validate_hash(self, hash_value: str, hash_type: Optional[str] = None, file_path: Optional[Path] = None) -> HashValidationResult:
        """Validate hash with comprehensive analysis"""
        
        # Format validation
        is_valid, format_error, detected_type = self.validate_hash_format(hash_value, hash_type)
        actual_type = hash_type or detected_type
        
        # Create hash info
        hash_info = HashInfo(
            hash_value=hash_value.lower().strip(),
            hash_type=actual_type or "unknown",
            file_path=str(file_path) if file_path else None
        )
        
        # Create result
        result = HashValidationResult(
            hash_info=hash_info,
            is_valid_format=is_valid,
            format_error=format_error
        )
        
        if not is_valid:
            return result
        
        # File analysis (if file provided)
        if file_path:
            await self._analyze_file(file_path, result)
        
        # Threat intelligence lookup
        await self._check_threat_intelligence(hash_info.hash_value, result)
        
        # Database lookup for malware info
        await self._lookup_malware_database(hash_info.hash_value, result)
        
        # Final assessment
        self._assess_threat_level(result)
        
        return result
    
    async def _analyze_file(self, file_path: Path, result: HashValidationResult):
        """Analyze file and calculate hashes"""
        try:
            result.hash_info.file_path = str(file_path)
            result.file_exists = file_path.exists()
            
            if not result.file_exists:
                return
            
            # Check if file is readable
            try:
                result.file_readable = os.access(file_path, os.R_OK)
                if result.file_readable:
                    result.hash_info.file_size = file_path.stat().st_size
            except Exception as e:
                logger.debug(f"Error checking file permissions: {e}")
                result.file_readable = False
                return
            
            # Calculate hashes
            if result.file_readable:
                try:
                    result.calculated_hashes = await self.calculate_file_hashes(file_path)
                    result.analysis_sources.append("File Analysis")
                except Exception as e:
                    logger.error(f"Error calculating file hashes: {e}")
                    
        except Exception as e:
            logger.error(f"File analysis error: {e}")
    
    async def _check_threat_intelligence(self, hash_value: str, result: HashValidationResult):
        """Check hash against threat intelligence"""
        try:
            if self.ioc_checker:
                threat_result = await self.ioc_checker.check_ioc(hash_value, "hash")
                result.threat_result = threat_result
                
                if threat_result.threat_detected:
                    result.is_malware = True
                    result.analysis_sources.append("Rekap Threat Intelligence")
                    
        except Exception as e:
            logger.error(f"Threat intelligence check error: {e}")
    
    async def _lookup_malware_database(self, hash_value: str, result: HashValidationResult):
        """Lookup hash in malware database"""
        try:
            if self.threat_db and hash_value in self.threat_db.malware_hashes:
                malware_data = self.threat_db.malware_hashes[hash_value]
                
                result.malware_info = MalwareInfo(
                    malware_family=malware_data.get('malware_family', 'Unknown'),
                    confidence=malware_data.get('confidence', 'unknown'),
                    date_added=malware_data.get('date_added', 'Unknown'),
                    description=malware_data.get('description', ''),
                    all_hashes={
                        'md5': malware_data.get('md5', ''),
                        'sha1': malware_data.get('sha1', ''),
                        'sha256': malware_data.get('sha256', '')
                    }
                )
                
                result.is_malware = True
                result.analysis_sources.append("Rekap Malware Database")
                
        except Exception as e:
            logger.error(f"Malware database lookup error: {e}")
    
    def _assess_threat_level(self, result: HashValidationResult):
        """Assess overall threat level"""
        if result.is_malware:
            # Determine threat level based on confidence
            if result.malware_info:
                confidence = result.malware_info.confidence
                if confidence == "high":
                    result.threat_level = "malicious"
                elif confidence == "medium":
                    result.threat_level = "suspicious"
                else:
                    result.threat_level = "suspicious"
            elif result.threat_result and result.threat_result.confidence:
                confidence = result.threat_result.confidence
                if confidence == "high":
                    result.threat_level = "malicious"
                elif confidence == "medium":
                    result.threat_level = "suspicious"
                else:
                    result.threat_level = "suspicious"
            else:
                result.threat_level = "suspicious"
        else:
            result.threat_level = "clean"


def display_hash_validation_result(result: HashValidationResult, show_detailed: bool = True):
    """Display hash validation results with rich formatting"""
    
    # Determine display colors and icons
    if result.threat_level == "malicious":
        status_color = "red"
        status_icon = "🚨"
        status_text = "MALWARE DETECTED"
    elif result.threat_level == "suspicious":
        status_color = "yellow"
        status_icon = "⚠️"
        status_text = "SUSPICIOUS"
    elif result.threat_level == "clean":
        status_color = "green"
        status_icon = "✅"
        status_text = "CLEAN"
    else:
        status_color = "blue"
        status_icon = "❓"
        status_text = "UNKNOWN"
    
    # Main information table
    main_table = Table(show_header=False, box=None, padding=(0, 1))
    main_table.add_column("Field", style="cyan", width=20)
    main_table.add_column("Value", style="white")
    
    main_table.add_row("Hash", result.hash_info.hash_value)
    main_table.add_row("Type", result.hash_info.hash_type.upper())
    main_table.add_row("Status", f"[{status_color}]{status_icon} {status_text}[/{status_color}]")
    main_table.add_row("Analysis Time", result.validation_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    
    if not result.is_valid_format:
        main_table.add_row("Format Error", f"[red]{result.format_error}[/red]")
    
    if result.hash_info.file_path:
        main_table.add_row("File Path", result.hash_info.file_path)
        
        if result.file_exists:
            main_table.add_row("File Exists", "✅ Yes")
            if result.hash_info.file_size is not None:
                # Format file size
                if result.hash_info.file_size < 1024:
                    size_str = f"{result.hash_info.file_size} bytes"
                elif result.hash_info.file_size < 1024 * 1024:
                    size_str = f"{result.hash_info.file_size / 1024:.1f} KB"
                else:
                    size_str = f"{result.hash_info.file_size / (1024 * 1024):.1f} MB"
                main_table.add_row("File Size", size_str)
        else:
            main_table.add_row("File Exists", "❌ No")
    
    if result.analysis_sources:
        main_table.add_row("Sources", ", ".join(result.analysis_sources))
    
    title = f"Hash Validation: {result.hash_info.hash_type.upper()}"
    console.print(Panel(main_table, title=title, style=status_color, padding=(1, 2)))
    console.print()
    
    # Malware information
    if result.malware_info:
        malware_table = Table(title="🦠 Malware Information", show_header=False, box=None)
        malware_table.add_column("Field", style="cyan", width=20)
        malware_table.add_column("Value", style="white")
        
        malware_table.add_row("Family", result.malware_info.malware_family)
        malware_table.add_row("Confidence", result.malware_info.confidence.title())
        malware_table.add_row("Date Added", result.malware_info.date_added)
        
        if result.malware_info.description:
            desc = result.malware_info.description
            if len(desc) > 60:
                desc = desc[:60] + "..."
            malware_table.add_row("Description", desc)
        
        console.print(Panel(malware_table, style="red", padding=(1, 2)))
        console.print()
    
    # File hash comparison (if file was analyzed)
    if result.calculated_hashes and show_detailed:
        hash_table = Table(title="🔍 Calculated File Hashes", show_header=True)
        hash_table.add_column("Algorithm", style="cyan", width=10)
        hash_table.add_column("Calculated Hash", style="white")
        hash_table.add_column("Match", justify="center", style="green", width=8)
        
        for algo, calculated_hash in result.calculated_hashes.items():
            # Check if this matches the input hash
            is_match = calculated_hash.lower() == result.hash_info.hash_value.lower()
            match_icon = "✅" if is_match else "❌"
            
            hash_table.add_row(
                algo.upper(),
                calculated_hash,
                match_icon
            )
        
        console.print(Panel(hash_table, style="blue", padding=(1, 2)))
        console.print()
    
    # Related hashes (if available from malware database)
    if result.malware_info and result.malware_info.all_hashes and show_detailed:
        related_table = Table(title="🔗 Related Hashes", show_header=True)
        related_table.add_column("Algorithm", style="cyan", width=10)
        related_table.add_column("Hash Value", style="white")
        
        for algo, hash_val in result.malware_info.all_hashes.items():
            if hash_val and hash_val.strip():
                # Highlight the current hash
                if hash_val.lower() == result.hash_info.hash_value.lower():
                    hash_display = f"[yellow]{hash_val}[/yellow] [dim](current)[/dim]"
                else:
                    hash_display = hash_val
                
                related_table.add_row(algo.upper(), hash_display)
        
        console.print(Panel(related_table, style="blue", padding=(1, 2)))


async def process_bulk_hashes(validator: HashValidator, hashes: List[str], show_progress: bool = True) -> List[HashValidationResult]:
    """Process multiple hashes with progress tracking"""
    results = []
    
    if show_progress:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("🔍 Validating hashes", total=len(hashes))
            
            for hash_value in hashes:
                result = await validator.validate_hash(hash_value.strip())
                results.append(result)
                progress.advance(task)
    else:
        for hash_value in hashes:
            result = await validator.validate_hash(hash_value.strip())
            results.append(result)
    
    return results


def display_bulk_summary(results: List[HashValidationResult]):
    """Display summary of bulk hash validation"""
    total = len(results)
    malware_count = sum(1 for r in results if r.is_malware)
    clean_count = sum(1 for r in results if r.threat_level == "clean")
    suspicious_count = sum(1 for r in results if r.threat_level == "suspicious")
    malicious_count = sum(1 for r in results if r.threat_level == "malicious")
    format_errors = sum(1 for r in results if not r.is_valid_format)
    
    # Summary table
    summary_table = Table(title="📊 Bulk Validation Summary", show_header=False, box=None)
    summary_table.add_column("Metric", style="cyan", width=25)
    summary_table.add_column("Count", style="white", justify="right", width=10)
    summary_table.add_column("Percentage", style="yellow", justify="right", width=12)
    
    summary_table.add_row("Total Hashes", str(total), "100.0%")
    summary_table.add_row("Format Errors", f"[red]{format_errors}[/red]", f"{format_errors/total*100:.1f}%" if total > 0 else "0%")
    summary_table.add_row("Clean", f"[green]{clean_count}[/green]", f"{clean_count/total*100:.1f}%" if total > 0 else "0%")
    summary_table.add_row("Suspicious", f"[yellow]{suspicious_count}[/yellow]", f"{suspicious_count/total*100:.1f}%" if total > 0 else "0%")
    summary_table.add_row("Malicious", f"[red]{malicious_count}[/red]", f"{malicious_count/total*100:.1f}%" if total > 0 else "0%")
    
    console.print(Panel(summary_table, style="blue", padding=(1, 2)))
    console.print()
    
    # Hash types breakdown
    hash_types = {}
    for result in results:
        if result.is_valid_format:
            hash_type = result.hash_info.hash_type
            hash_types[hash_type] = hash_types.get(hash_type, 0) + 1
    
    if hash_types:
        types_table = Table(title="📋 Hash Types", show_header=True)
        types_table.add_column("Type", style="cyan")
        types_table.add_column("Count", justify="right", style="white")
        types_table.add_column("Percentage", justify="right", style="yellow")
        
        for hash_type, count in sorted(hash_types.items()):
            percentage = count / total * 100 if total > 0 else 0
            types_table.add_row(hash_type.upper(), str(count), f"{percentage:.1f}%")
        
        console.print(Panel(types_table, style="blue", padding=(1, 2)))


async def export_hash_results(results: List[HashValidationResult], export_path: str, export_format: str = "json"):
    """Export hash validation results"""
    if export_format.lower() == "json":
        await export_hash_json(results, export_path)
    elif export_format.lower() == "csv":
        await export_hash_csv(results, export_path)
    else:
        raise ValueError(f"Unsupported export format: {export_format}")


async def export_hash_json(results: List[HashValidationResult], export_path: str):
    """Export results to JSON"""
    export_data = {
        "metadata": {
            "export_timestamp": datetime.now().isoformat(),
            "tool": "Rekap Hash Validator 2025",
            "version": "2.0.0",
            "total_hashes": len(results)
        },
        "summary": {
            "total": len(results),
            "malware_detected": sum(1 for r in results if r.is_malware),
            "clean": sum(1 for r in results if r.threat_level == "clean"),
            "format_errors": sum(1 for r in results if not r.is_valid_format)
        },
        "results": [result.model_dump(mode='json') for result in results]
    }
    
    async with aiofiles.open(export_path, 'w', encoding='utf-8') as f:
        await f.write(json.dumps(export_data, indent=2, ensure_ascii=False, default=str))


async def export_hash_csv(results: List[HashValidationResult], export_path: str):
    """Export results to CSV"""
    fieldnames = [
        'hash_value', 'hash_type', 'threat_level', 'is_malware', 
        'malware_family', 'confidence', 'description', 'file_path', 
        'file_size', 'analysis_sources', 'validation_timestamp'
    ]
    
    csv_data = []
    for result in results:
        csv_row = {
            'hash_value': result.hash_info.hash_value,
            'hash_type': result.hash_info.hash_type,
            'threat_level': result.threat_level,
            'is_malware': result.is_malware,
            'malware_family': result.malware_info.malware_family if result.malware_info else '',
            'confidence': result.malware_info.confidence if result.malware_info else '',
            'description': result.malware_info.description if result.malware_info else '',
            'file_path': result.hash_info.file_path or '',
            'file_size': result.hash_info.file_size or '',
            'analysis_sources': '; '.join(result.analysis_sources),
            'validation_timestamp': result.validation_timestamp.isoformat()
        }
        csv_data.append(csv_row)
    
    # Write CSV
    async with aiofiles.open(export_path, 'w', encoding='utf-8') as f:
        # Header
        await f.write(','.join(fieldnames) + '\n')
        
        # Data rows
        for row in csv_data:
            csv_row = []
            for field in fieldnames:
                value = str(row.get(field, ''))
                # Escape quotes and commas
                if ',' in value or '"' in value:
                    value = '"' + value.replace('"', '""') + '"'
                csv_row.append(value)
            await f.write(','.join(csv_row) + '\n')


@click.command()
@click.option('--hash', 'hash_value', help='Single hash to validate')
@click.option('--file', 'file_path', help='File to calculate hashes for')
@click.option('--bulk', 'bulk_file', help='File containing list of hashes')
@click.option('--hash-type', type=click.Choice(['md5', 'sha1', 'sha256', 'sha384', 'sha512']), 
              help='Expected hash type (auto-detected if not specified)')
@click.option('--data-dir', default='data', help='Path to threat data directory')
@click.option('--export', help='Export results to file')
@click.option('--export-format', default='json', type=click.Choice(['json', 'csv']), 
              help='Export format')
@click.option('--show-clean', is_flag=True, help='Show clean hashes in bulk mode')
@click.option('--show-malware-only', is_flag=True, help='Show only malware detections')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--summary-only', is_flag=True, help='Show only summary in bulk mode')
def main(hash_value, file_path, bulk_file, hash_type, data_dir, export, 
         export_format, show_clean, show_malware_only, verbose, summary_only):
    """
    Rekap Hash Validator - Modern Implementation 2025
    
    Validate file hashes against malware databases with comprehensive analysis.
    Supports single hash validation, file analysis, and bulk processing.
    """
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        console.print("🔍 Verbose logging enabled", style="blue")
    
    # Validate inputs
    input_count = sum(1 for x in [hash_value, file_path, bulk_file] if x)
    if input_count != 1:
        console.print("❌ Specify exactly one: --hash, --file, or --bulk", style="red")
        sys.exit(1)
    
    if show_clean and show_malware_only:
        console.print("❌ Cannot use both --show-clean and --show-malware-only", style="red")
        sys.exit(1)
    
    async def validate_hashes():
        async with HashValidator(Path(data_dir)) as validator:
            
            # Single hash validation
            if hash_value:
                console.print(f"🔍 Validating hash: [cyan]{hash_value}[/cyan]")
                console.print()
                
                result = await validator.validate_hash(hash_value, hash_type)
                display_hash_validation_result(result, show_detailed=True)
                
                if export:
                    await export_hash_results([result], export, export_format)
                    console.print(f"\n✅ Results exported to [cyan]{export}[/cyan]", style="green")
            
            # File analysis
            elif file_path:
                file_obj = Path(file_path)
                console.print(f"📁 Analyzing file: [cyan]{file_path}[/cyan]")
                console.print()
                
                if not file_obj.exists():
                    console.print("❌ File not found", style="red")
                    sys.exit(1)
                
                # Calculate all hashes and validate each
                try:
                    calculated_hashes = await validator.calculate_file_hashes(file_obj)
                    console.print("✅ File hashes calculated successfully")
                    console.print()
                    
                    # Display all calculated hashes first
                    hash_table = Table(title="📋 Calculated Hashes", show_header=True)
                    hash_table.add_column("Algorithm", style="cyan", width=10)
                    hash_table.add_column("Hash Value", style="white")
                    
                    for algo, hash_val in calculated_hashes.items():
                        hash_table.add_row(algo.upper(), hash_val)
                    
                    console.print(Panel(hash_table, style="blue", padding=(1, 2)))
                    console.print()
                    
                    # Validate primary hash (SHA256 preferred, or first available)
                    primary_hash = calculated_hashes.get('sha256') or list(calculated_hashes.values())[0]
                    primary_type = 'sha256' if 'sha256' in calculated_hashes else list(calculated_hashes.keys())[0]
                    
                    result = await validator.validate_hash(primary_hash, primary_type, file_obj)
                    display_hash_validation_result(result, show_detailed=True)
                    
                    if export:
                        await export_hash_results([result], export, export_format)
                        console.print(f"\n✅ Results exported to [cyan]{export}[/cyan]", style="green")
                        
                except Exception as e:
                    console.print(f"❌ File analysis failed: {e}", style="red")
                    sys.exit(1)
            
            # Bulk validation
            elif bulk_file:
                bulk_path = Path(bulk_file)
                console.print(f"📋 Processing bulk file: [cyan]{bulk_file}[/cyan]")
                
                if not bulk_path.exists():
                    console.print("❌ Bulk file not found", style="red")
                    sys.exit(1)
                
                # Read hashes from file
                try:
                    async with aiofiles.open(bulk_path, 'r', encoding='utf-8') as f:
                        lines = await f.readlines()
                    
                    hashes = []
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            hashes.append(line)
                    
                    if not hashes:
                        console.print("❌ No valid hashes found in file", style="red")
                        sys.exit(1)
                    
                    console.print(f"📊 Found {len(hashes):,} hashes to validate")
                    console.print()
                    
                    # Process hashes
                    results = await process_bulk_hashes(validator, hashes, show_progress=True)
                    
                    # Display summary
                    console.print()
                    display_bulk_summary(results)
                    
                    # Display individual results if requested
                    if not summary_only:
                        console.print()
                        
                        # Filter results based on flags
                        display_results = results
                        if show_malware_only:
                            display_results = [r for r in results if r.is_malware]
                        elif not show_clean:
                            display_results = [r for r in results if r.is_malware or not r.is_valid_format]
                        
                        if display_results:
                            for result in display_results:
                                display_hash_validation_result(result, show_detailed=False)
                                console.print()
                    
                    # Export if requested
                    if export:
                        await export_hash_results(results, export, export_format)
                        console.print(f"✅ Results exported to [cyan]{export}[/cyan] ({export_format.upper()} format)", style="green")
                    
                except Exception as e:
                    console.print(f"❌ Bulk processing failed: {e}", style="red")
                    sys.exit(1)
    
    # Run validation
    try:
        asyncio.run(validate_hashes())
    except KeyboardInterrupt:
        console.print("\n❌ Operation cancelled by user", style="red")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n❌ Validation failed: {e}", style="red")
        logger.error(f"Hash validation error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()