#!/usr/bin/env python3
"""
Rekap Bulk IOC Checker - Modern Async Implementation 2025
Indonesia Threat Intelligence Repository

High-performance bulk IOC checking with async processing,
progress tracking, and multiple export formats.
"""

import asyncio
import csv
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Union, AsyncIterator
import aiofiles

import click
from pydantic import BaseModel
from rich.console import Console
from rich.progress import Progress, TaskID, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

# Import our modern IOC checker
from ioc_checker import IOCChecker, IOCResult, ThreatDatabase

console = Console()
logger = logging.getLogger(__name__)


class BulkCheckSummary(BaseModel):
    """Summary statistics for bulk checking operation"""
    total_iocs: int = 0
    threats_detected: int = 0
    clean_iocs: int = 0
    errors: int = 0
    processing_time: float = 0.0
    threat_percentage: float = 0.0
    ioc_types: Dict[str, int] = {}
    threat_types: Dict[str, int] = {}
    confidence_levels: Dict[str, int] = {}


class BulkIOCChecker:
    """High-performance bulk IOC checker with async processing"""
    
    def __init__(self, data_dir: Path, max_workers: int = 100):
        self.data_dir = data_dir
        self.max_workers = max_workers
        self.checker: Optional[IOCChecker] = None
        self.semaphore = asyncio.Semaphore(max_workers)
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.checker = IOCChecker(self.data_dir)
        await self.checker.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.checker:
            await self.checker.__aexit__(exc_type, exc_val, exc_tb)
    
    async def read_iocs_from_file(self, file_path: Path) -> AsyncIterator[str]:
        """Read IOCs from various file formats asynchronously"""
        file_extension = file_path.suffix.lower()
        
        if file_extension == '.json':
            async for ioc in self._read_json_file(file_path):
                yield ioc
        elif file_extension == '.csv':
            async for ioc in self._read_csv_file(file_path):
                yield ioc
        else:  # Treat as text file
            async for ioc in self._read_text_file(file_path):
                yield ioc
    
    async def _read_text_file(self, file_path: Path) -> AsyncIterator[str]:
        """Read IOCs from text file (one per line)"""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                async for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        yield line
        except Exception as e:
            logger.error(f"Error reading text file {file_path}: {e}")
    
    async def _read_csv_file(self, file_path: Path) -> AsyncIterator[str]:
        """Read IOCs from CSV file (first column)"""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                # Process CSV in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    csv_reader = csv.reader(content.splitlines())
                    for row in csv_reader:
                        if row and not row[0].startswith('#'):
                            yield row[0].strip()
        except Exception as e:
            logger.error(f"Error reading CSV file {file_path}: {e}")
    
    async def _read_json_file(self, file_path: Path) -> AsyncIterator[str]:
        """Read IOCs from JSON file"""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                data = json.loads(content)
                
                # Handle different JSON structures
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            yield item.strip()
                        elif isinstance(item, dict) and 'ioc' in item:
                            yield item['ioc'].strip()
                elif isinstance(data, dict):
                    if 'iocs' in data:
                        for ioc in data['iocs']:
                            yield ioc.strip()
        except Exception as e:
            logger.error(f"Error reading JSON file {file_path}: {e}")
    
    async def check_single_ioc(self, ioc: str) -> IOCResult:
        """Check single IOC with semaphore for rate limiting"""
        async with self.semaphore:
            try:
                return await self.checker.check_ioc(ioc)
            except Exception as e:
                logger.error(f"Error checking IOC {ioc}: {e}")
                # Return error result
                return IOCResult(
                    ioc=ioc,
                    ioc_type="unknown",
                    threat_detected=False,
                    description=f"Error: {str(e)}"
                )
    
    async def process_iocs_batch(
        self,
        iocs: List[str],
        progress: Optional[Progress] = None,
        task_id: Optional[TaskID] = None,
        show_threats_only: bool = False,
        show_clean_only: bool = False,
        min_confidence: Optional[str] = None
    ) -> List[IOCResult]:
        """Process batch of IOCs with progress tracking"""
        
        # Create tasks for all IOCs
        tasks = [self.check_single_ioc(ioc) for ioc in iocs]
        
        results = []
        completed = 0
        
        # Process tasks and update progress
        for task in asyncio.as_completed(tasks):
            result = await task
            completed += 1
            
            # Apply filters
            should_include = True
            
            if show_threats_only and not result.threat_detected:
                should_include = False
            
            if show_clean_only and result.threat_detected:
                should_include = False
            
            if min_confidence and result.confidence:
                confidence_levels = {'low': 1, 'medium': 2, 'high': 3}
                min_level = confidence_levels.get(min_confidence, 0)
                result_level = confidence_levels.get(result.confidence, 0)
                if result_level < min_level:
                    should_include = False
            
            if should_include:
                results.append(result)
            
            # Update progress
            if progress and task_id:
                progress.update(task_id, advance=1)
        
        return results


def generate_summary(results: List[IOCResult], processing_time: float) -> BulkCheckSummary:
    """Generate summary statistics from results"""
    summary = BulkCheckSummary()
    summary.total_iocs = len(results)
    summary.processing_time = processing_time
    
    for result in results:
        # Count threats
        if result.threat_detected:
            summary.threats_detected += 1
        else:
            summary.clean_iocs += 1
        
        # Count IOC types
        ioc_type = result.ioc_type
        summary.ioc_types[ioc_type] = summary.ioc_types.get(ioc_type, 0) + 1
        
        # Count threat types
        for threat_type in result.threat_types:
            summary.threat_types[threat_type] = summary.threat_types.get(threat_type, 0) + 1
        
        # Count confidence levels
        if result.confidence:
            confidence = result.confidence
            summary.confidence_levels[confidence] = summary.confidence_levels.get(confidence, 0) + 1
    
    # Calculate percentage
    if summary.total_iocs > 0:
        summary.threat_percentage = (summary.threats_detected / summary.total_iocs) * 100
    
    return summary


def display_summary(summary: BulkCheckSummary):
    """Display summary statistics with rich formatting"""
    
    # Main summary table
    table = Table(title="📊 Bulk Check Summary", show_header=False, box=None, padding=(0, 1))
    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Value", style="white")
    
    table.add_row("Total IOCs Processed", f"{summary.total_iocs:,}")
    table.add_row("Threats Detected", f"[red]{summary.threats_detected:,}[/red]")
    table.add_row("Clean IOCs", f"[green]{summary.clean_iocs:,}[/green]")
    table.add_row("Processing Time", f"{summary.processing_time:.2f} seconds")
    table.add_row("Threat Percentage", f"{summary.threat_percentage:.1f}%")
    
    console.print(table)
    console.print()
    
    # IOC Types breakdown
    if summary.ioc_types:
        ioc_table = Table(title="📋 IOC Types", show_header=True)
        ioc_table.add_column("Type", style="cyan")
        ioc_table.add_column("Count", justify="right", style="white")
        ioc_table.add_column("Percentage", justify="right", style="yellow")
        
        for ioc_type, count in sorted(summary.ioc_types.items()):
            percentage = (count / summary.total_iocs) * 100
            ioc_table.add_row(ioc_type.upper(), f"{count:,}", f"{percentage:.1f}%")
        
        console.print(ioc_table)
        console.print()
    
    # Threat Types breakdown
    if summary.threat_types:
        threat_table = Table(title="🚨 Threat Types", show_header=True)
        threat_table.add_column("Type", style="red")
        threat_table.add_column("Count", justify="right", style="white")
        threat_table.add_column("Percentage", justify="right", style="yellow")
        
        total_threats = summary.threats_detected
        for threat_type, count in sorted(summary.threat_types.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_threats) * 100 if total_threats > 0 else 0
            threat_table.add_row(threat_type.title(), f"{count:,}", f"{percentage:.1f}%")
        
        console.print(threat_table)
        console.print()
    
    # Confidence levels breakdown
    if summary.confidence_levels:
        conf_table = Table(title="🎯 Confidence Levels", show_header=True)
        conf_table.add_column("Level", style="blue")
        conf_table.add_column("Count", justify="right", style="white")
        conf_table.add_column("Percentage", justify="right", style="yellow")
        
        confidence_order = ['high', 'medium', 'low']
        for confidence in confidence_order:
            if confidence in summary.confidence_levels:
                count = summary.confidence_levels[confidence]
                percentage = (count / summary.threats_detected) * 100 if summary.threats_detected > 0 else 0
                style = "bold green" if confidence == "high" else "yellow" if confidence == "medium" else "dim"
                conf_table.add_row(f"[{style}]{confidence.upper()}[/{style}]", f"{count:,}", f"{percentage:.1f}%")
        
        console.print(conf_table)


def display_individual_results(results: List[IOCResult], show_threats_only: bool = False, show_clean_only: bool = False):
    """Display individual IOC results"""
    
    if not results:
        console.print("No results to display", style="yellow")
        return
    
    results_table = Table(show_header=True, header_style="bold cyan")
    results_table.add_column("IOC", style="white", width=30)
    results_table.add_column("Type", justify="center", width=8)
    results_table.add_column("Status", justify="center", width=12)
    results_table.add_column("Confidence", justify="center", width=10)
    results_table.add_column("Threat Types", width=20)
    results_table.add_column("Description", width=40)
    
    for result in results:
        # Status styling
        if result.threat_detected:
            status = "[red]THREAT[/red]"
            ioc_style = "red"
        else:
            status = "[green]CLEAN[/green]"
            ioc_style = "green"
        
        # Confidence styling
        conf_color = {
            "high": "bold green",
            "medium": "yellow", 
            "low": "dim red"
        }.get(result.confidence, "white")
        
        confidence_display = f"[{conf_color}]{result.confidence or 'N/A'}[/{conf_color}]"
        
        # Threat types
        threat_types_str = ", ".join(result.threat_types) if result.threat_types else "N/A"
        
        # Description (truncated)
        description = result.description or "N/A"
        if len(description) > 37:
            description = description[:37] + "..."
        
        results_table.add_row(
            f"[{ioc_style}]{result.ioc}[/{ioc_style}]",
            result.ioc_type.upper(),
            status,
            confidence_display,
            threat_types_str,
            description
        )
    
    console.print(results_table)


async def export_results(
    results: List[IOCResult], 
    summary: BulkCheckSummary, 
    export_path: str, 
    export_format: str = "json"
):
    """Export results to file in specified format"""
    
    export_file = Path(export_path)
    
    if export_format.lower() == "json":
        await export_json(results, summary, export_file)
    elif export_format.lower() == "csv":
        await export_csv(results, export_file)
    elif export_format.lower() == "txt":
        await export_txt(results, export_file)
    else:
        raise ValueError(f"Unsupported export format: {export_format}")


async def export_json(results: List[IOCResult], summary: BulkCheckSummary, export_file: Path):
    """Export results to JSON format"""
    export_data = {
        "metadata": {
            "export_timestamp": datetime.now().isoformat(),
            "tool": "Rekap Bulk Checker 2025",
            "version": "2.0.0"
        },
        "summary": summary.model_dump(),
        "results": [result.model_dump(mode='json') for result in results]
    }
    
    async with aiofiles.open(export_file, 'w', encoding='utf-8') as f:
        await f.write(json.dumps(export_data, indent=2, ensure_ascii=False, default=str))


async def export_csv(results: List[IOCResult], export_file: Path):
    """Export results to CSV format"""
    fieldnames = [
        'ioc', 'ioc_type', 'threat_detected', 'threat_count', 
        'confidence', 'threat_types', 'description', 'first_seen', 
        'tags', 'sources', 'check_timestamp'
    ]
    
    # Convert results to CSV-friendly format
    csv_data = []
    for result in results:
        csv_row = {
            'ioc': result.ioc,
            'ioc_type': result.ioc_type,
            'threat_detected': result.threat_detected,
            'threat_count': result.threat_count,
            'confidence': result.confidence or '',
            'threat_types': '; '.join(result.threat_types),
            'description': result.description or '',
            'first_seen': result.first_seen or '',
            'tags': '; '.join(result.tags),
            'sources': '; '.join(result.sources),
            'check_timestamp': result.check_timestamp.isoformat()
        }
        csv_data.append(csv_row)
    
    # Write CSV file
    async with aiofiles.open(export_file, 'w', encoding='utf-8', newline='') as f:
        content = []
        
        # Header
        content.append(','.join(fieldnames))
        
        # Data rows
        for row in csv_data:
            csv_row = []
            for field in fieldnames:
                value = str(row.get(field, ''))
                # Escape quotes and commas
                if ',' in value or '"' in value:
                    value = '"' + value.replace('"', '""') + '"'
                csv_row.append(value)
            content.append(','.join(csv_row))
        
        await f.write('\n'.join(content))


async def export_txt(results: List[IOCResult], export_file: Path):
    """Export results to plain text format"""
    async with aiofiles.open(export_file, 'w', encoding='utf-8') as f:
        await f.write("Rekap Bulk Check Results\n")
        await f.write("=" * 50 + "\n\n")
        await f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        await f.write(f"Total IOCs: {len(results)}\n\n")
        
        threats = [r for r in results if r.threat_detected]
        clean = [r for r in results if not r.threat_detected]
        
        await f.write(f"THREATS DETECTED ({len(threats)}):\n")
        await f.write("-" * 30 + "\n")
        for result in threats:
            await f.write(f"{result.ioc} - {result.ioc_type.upper()} - {result.confidence}\n")
            if result.description:
                await f.write(f"  Description: {result.description}\n")
            await f.write("\n")
        
        await f.write(f"\nCLEAN IOCs ({len(clean)}):\n")
        await f.write("-" * 20 + "\n")
        for result in clean:
            await f.write(f"{result.ioc} - {result.ioc_type.upper()}\n")


@click.command()
@click.option('--file', 'file_path', required=True, help='Input file containing IOCs')
@click.option('--workers', default=50, help='Number of concurrent workers')
@click.option('--data-dir', default='data', help='Path to threat data directory')
@click.option('--export', help='Export results to file')
@click.option('--export-format', default='json', type=click.Choice(['json', 'csv', 'txt']), help='Export format')
@click.option('--show-threats', is_flag=True, help='Show only threats in output')
@click.option('--show-clean', is_flag=True, help='Show only clean IOCs in output')
@click.option('--min-confidence', type=click.Choice(['low', 'medium', 'high']), help='Minimum confidence level')
@click.option('--quiet', is_flag=True, help='Show only summary (no individual results)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--batch-size', default=1000, help='Batch size for processing')
def main(file_path, workers, data_dir, export, export_format, show_threats, 
         show_clean, min_confidence, quiet, verbose, batch_size):
    """
    Rekap Bulk IOC Checker - Modern Async Implementation 2025
    
    Process multiple IOCs from files with high performance async processing.
    Supports JSON, CSV, and text file formats.
    """
    
    # Setup logging
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        console.print("🔍 Verbose logging enabled", style="blue")
    
    # Validate inputs
    input_file = Path(file_path)
    if not input_file.exists():
        console.print(f"❌ Input file not found: {file_path}", style="red")
        sys.exit(1)
    
    if show_threats and show_clean:
        console.print("❌ Cannot use both --show-threats and --show-clean", style="red")
        sys.exit(1)
    
    async def process_file():
        start_time = datetime.now()
        
        # Initialize checker
        async with BulkIOCChecker(Path(data_dir), workers) as bulk_checker:
            console.print(f"📁 Processing file: [cyan]{file_path}[/cyan]")
            console.print(f"⚡ Using {workers} concurrent workers")
            console.print()
            
            # Read all IOCs first to get total count
            iocs = []
            try:
                async for ioc in bulk_checker.read_iocs_from_file(input_file):
                    iocs.append(ioc)
            except Exception as e:
                console.print(f"❌ Error reading file: {e}", style="red")
                return
            
            if not iocs:
                console.print("❌ No valid IOCs found in file", style="red")
                return
            
            console.print(f"📊 Found {len(iocs):,} IOCs to process")
            console.print()
            
            # Process IOCs with progress tracking
            all_results = []
            
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                
                # Process in batches
                total_batches = (len(iocs) + batch_size - 1) // batch_size
                main_task = progress.add_task("🔍 Processing IOCs", total=len(iocs))
                
                for i in range(0, len(iocs), batch_size):
                    batch = iocs[i:i + batch_size]
                    batch_results = await bulk_checker.process_iocs_batch(
                        batch, progress, main_task, show_threats, show_clean, min_confidence
                    )
                    all_results.extend(batch_results)
            
            # Calculate processing time
            end_time = datetime.now()
            processing_time = (end_time - start_time).total_seconds()
            
            console.print()
            console.print("✅ Processing completed!", style="green")
            console.print()
            
            # Generate and display summary
            summary = generate_summary(all_results, processing_time)
            display_summary(summary)
            
            # Display individual results if not quiet
            if not quiet and all_results:
                console.print()
                display_individual_results(all_results, show_threats, show_clean)
            
            # Export results if requested
            if export:
                try:
                    await export_results(all_results, summary, export, export_format)
                    console.print(f"\n✅ Results exported to [cyan]{export}[/cyan] ({export_format.upper()} format)", style="green")
                except Exception as e:
                    console.print(f"\n❌ Export failed: {e}", style="red")
            
            # Performance statistics
            console.print(f"\n📈 Performance: {len(iocs)/processing_time:.1f} IOCs/second", style="blue")
    
    # Run async processing
    try:
        asyncio.run(process_file())
    except KeyboardInterrupt:
        console.print("\n❌ Operation cancelled by user", style="red")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n❌ Fatal error: {e}", style="red")
        logger.error(f"Fatal error in bulk checker: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()