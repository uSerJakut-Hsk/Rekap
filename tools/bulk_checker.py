#!/usr/bin/env python3
"""
Rekap Bulk Checker
Batch processing tool for checking multiple IOCs
"""

import csv
import json
import argparse
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style
from tqdm import tqdm
import concurrent.futures
import threading

# Import other Rekap tools
from ioc_checker import IOCChecker
from hash_validator import HashValidator
from domain_analyzer import DomainAnalyzer

init(autoreset=True)

class BulkChecker:
    def __init__(self, data_dir="data", max_workers=10):
        self.data_dir = Path(data_dir)
        self.max_workers = max_workers
        
        # Initialize individual checkers
        self.ioc_checker = IOCChecker(data_dir)
        self.hash_validator = HashValidator(data_dir)
        self.domain_analyzer = DomainAnalyzer(data_dir)
        
        # Thread lock for thread-safe operations
        self.lock = threading.Lock()
        
    def load_indicators_from_file(self, file_path):
        """Load indicators from various file formats"""
        file_path = Path(file_path)
        indicators = []
        
        try:
            if file_path.suffix.lower() == '.csv':
                indicators = self._load_csv(file_path)
            elif file_path.suffix.lower() == '.json':
                indicators = self._load_json(file_path)
            else:  # Treat as plain text
                indicators = self._load_text(file_path)
        except Exception as e:
            print(f"{Fore.RED}Error loading file {file_path}: {e}")
            return []
        
        return indicators
    
    def _load_csv(self, file_path):
        """Load indicators from CSV file"""
        indicators = []
        with open(file_path, 'r', encoding='utf-8') as f:
            # Try to detect if first row is header
            sample = f.read(1024)
            f.seek(0)
            
            sniffer = csv.Sniffer()
            has_header = sniffer.has_header(sample)
            
            reader = csv.reader(f)
            if has_header:
                headers = next(reader)
                print(f"{Fore.CYAN}CSV Headers detected: {headers}")
            
            for row_num, row in enumerate(reader, 1):
                if row and len(row) > 0:
                    # Take first column as IOC, additional columns as metadata
                    ioc = row[0].strip()
                    metadata = {}
                    
                    if len(row) > 1 and has_header and len(headers) > 1:
                        for i, value in enumerate(row[1:], 1):
                            if i < len(headers):
                                metadata[headers[i]] = value.strip()
                    
                    indicators.append({
                        'ioc': ioc,
                        'source_line': row_num,
                        'metadata': metadata
                    })
        
        return indicators
    
    def _load_json(self, file_path):
        """Load indicators from JSON file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        indicators = []
        
        if isinstance(data, list):
            # List of IOCs
            for i, item in enumerate(data):
                if isinstance(item, str):
                    indicators.append({
                        'ioc': item.strip(),
                        'source_line': i + 1,
                        'metadata': {}
                    })
                elif isinstance(item, dict) and 'ioc' in item:
                    indicators.append({
                        'ioc': item['ioc'].strip(),
                        'source_line': i + 1,
                        'metadata': {k: v for k, v in item.items() if k != 'ioc'}
                    })
        elif isinstance(data, dict):
            # Dictionary with IOCs in different categories
            line_num = 1
            for category, ioc_list in data.items():
                if isinstance(ioc_list, list):
                    for ioc in ioc_list:
                        indicators.append({
                            'ioc': str(ioc).strip(),
                            'source_line': line_num,
                            'metadata': {'category': category}
                        })
                        line_num += 1
        
        return indicators
    
    def _load_text(self, file_path):
        """Load indicators from plain text file"""
        indicators = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    indicators.append({
                        'ioc': line,
                        'source_line': line_num,
                        'metadata': {}
                    })
        
        return indicators
    
    def check_single_ioc(self, indicator_data):
        """Check single IOC using appropriate checker"""
        ioc = indicator_data['ioc']
        metadata = indicator_data.get('metadata', {})
        
        try:
            # Use IOC checker for auto-detection and checking
            results, ioc_type = self.ioc_checker.check_ioc(ioc)
            
            return {
                'ioc': ioc,
                'ioc_type': ioc_type,
                'source_line': indicator_data.get('source_line'),
                'metadata': metadata,
                'results': results,
                'threat_detected': len(results) > 0,
                'check_timestamp': datetime.now().isoformat(),
                'status': 'completed'
            }
        
        except Exception as e:
            return {
                'ioc': ioc,
                'source_line': indicator_data.get('source_line'),
                'metadata': metadata,
                'error': str(e),
                'status': 'error',
                'check_timestamp': datetime.now().isoformat()
            }
    
    def bulk_check(self, indicators, show_progress=True):
        """Perform bulk checking with threading"""
        results = []
        
        if show_progress:
            progress_bar = tqdm(
                total=len(indicators),
                desc="Checking IOCs",
                unit="IOC",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
            )
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_indicator = {
                executor.submit(self.check_single_ioc, indicator): indicator
                for indicator in indicators
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_indicator):
                result = future.result()
                
                with self.lock:
                    results.append(result)
                    if show_progress:
                        progress_bar.update(1)
        
        if show_progress:
            progress_bar.close()
        
        return results
    
    def generate_summary(self, results):
        """Generate summary statistics"""
        total_iocs = len(results)
        threats_detected = sum(1 for r in results if r.get('threat_detected', False))
        errors = sum(1 for r in results if r.get('status') == 'error')
        
        # Count by IOC type
        ioc_types = {}
        threat_types = {}
        confidence_levels = {}
        
        for result in results:
            if result.get('status') == 'completed':
                ioc_type = result.get('ioc_type', 'unknown')
                ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
                
                if result.get('threat_detected'):
                    for threat_result in result.get('results', []):
                        threat_type = threat_result.get('type', 'unknown')
                        threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                        
                        confidence = threat_result.get('confidence', 'unknown')
                        confidence_levels[confidence] = confidence_levels.get(confidence, 0) + 1
        
        return {
            'total_iocs': total_iocs,
            'threats_detected': threats_detected,
            'clean_iocs': total_iocs - threats_detected - errors,
            'errors': errors,
            'threat_percentage': (threats_detected / total_iocs * 100) if total_iocs > 0 else 0,
            'ioc_types': ioc_types,
            'threat_types': threat_types,
            'confidence_levels': confidence_levels,
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def print_summary(self, summary):
        """Print formatted summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Bulk Check Summary")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"{Fore.YELLOW}Total IOCs Processed: {summary['total_iocs']:,}")
        print(f"{Fore.RED}Threats Detected: {summary['threats_detected']:,}")
        print(f"{Fore.GREEN}Clean IOCs: {summary['clean_iocs']:,}")
        print(f"{Fore.YELLOW}Errors: {summary['errors']:,}")
        print(f"{Fore.WHITE}Threat Percentage: {summary['threat_percentage']:.1f}%")
        
        if summary['ioc_types']:
            print(f"\n{Fore.WHITE}IOC Types:")
            for ioc_type, count in summary['ioc_types'].items():
                print(f"  {ioc_type}: {count:,}")
        
        if summary['threat_types']:
            print(f"\n{Fore.WHITE}Threat Types:")
            for threat_type, count in summary['threat_types'].items():
                print(f"  {threat_type}: {count:,}")
        
        if summary['confidence_levels']:
            print(f"\n{Fore.WHITE}Confidence Levels:")
            for confidence, count in summary['confidence_levels'].items():
                color = Fore.RED if confidence == 'high' else Fore.YELLOW if confidence == 'medium' else Fore.WHITE
                print(f"  {color}{confidence}: {count:,}")
    
    def export_results(self, results, summary, output_file, format_type='json'):
        """Export results to file"""
        output_path = Path(output_file)
        
        try:
            if format_type.lower() == 'json':
                export_data = {
                    'summary': summary,
                    'results': results
                }
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, default=str)
            
            elif format_type.lower() == 'csv':
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = [
                        'ioc', 'ioc_type', 'threat_detected', 'threat_count',
                        'highest_confidence', 'threat_types', 'source_line', 'status'
                    ]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for result in results:
                        threat_results = result.get('results', [])
                        row = {
                            'ioc': result.get('ioc', ''),
                            'ioc_type': result.get('ioc_type', ''),
                            'threat_detected': result.get('threat_detected', False),
                            'threat_count': len(threat_results),
                            'highest_confidence': '',
                            'threat_types': '',
                            'source_line': result.get('source_line', ''),
                            'status': result.get('status', '')
                        }
                        
                        if threat_results:
                            confidences = [r.get('confidence', '') for r in threat_results]
                            types = [r.get('type', '') for r in threat_results]
                            
                            # Determine highest confidence
                            if 'high' in confidences:
                                row['highest_confidence'] = 'high'
                            elif 'medium' in confidences:
                                row['highest_confidence'] = 'medium'
                            elif 'low' in confidences:
                                row['highest_confidence'] = 'low'
                            
                            row['threat_types'] = '; '.join(set(types))
                        
                        writer.writerow(row)
            
            print(f"{Fore.GREEN}Results exported to: {output_path}")
            
        except Exception as e:
            print(f"{Fore.RED}Error exporting results: {e}")
    
    def filter_results(self, results, show_clean=False, show_threats=True, min_confidence='low'):
        """Filter results based on criteria"""
        confidence_order = {'low': 0, 'medium': 1, 'high': 2}
        min_conf_level = confidence_order.get(min_confidence.lower(), 0)
        
        filtered = []
        
        for result in results:
            if result.get('status') == 'error':
                continue
            
            is_threat = result.get('threat_detected', False)
            
            if is_threat and show_threats:
                # Check confidence level
                threat_results = result.get('results', [])
                max_confidence = 0
                
                for threat in threat_results:
                    conf = threat.get('confidence', 'low').lower()
                    conf_level = confidence_order.get(conf, 0)
                    max_confidence = max(max_confidence, conf_level)
                
                if max_confidence >= min_conf_level:
                    filtered.append(result)
            
            elif not is_threat and show_clean:
                filtered.append(result)
        
        return filtered

def main():
    parser = argparse.ArgumentParser(description="Rekap Bulk IOC Checker")
    parser.add_argument("--file", required=True, help="Input file containing IOCs")
    parser.add_argument("--format", choices=['auto', 'csv', 'json', 'txt'], default='auto', help="Input file format")
    parser.add_argument("--export", help="Export results to file")
    parser.add_argument("--export-format", choices=['json', 'csv'], default='json', help="Export format")
    parser.add_argument("--workers", type=int, default=10, help="Number of worker threads")
    parser.add_argument("--show-clean", action="store_true", help="Show clean IOCs in detailed output")
    parser.add_argument("--show-threats", action="store_true", default=True, help="Show threat IOCs in detailed output")
    parser.add_argument("--min-confidence", choices=['low', 'medium', 'high'], default='low', help="Minimum confidence level to show")
    parser.add_argument("--data-dir", default="data", help="Data directory path")
    parser.add_argument("--quiet", action="store_true", help="Suppress detailed output, show summary only")
    
    args = parser.parse_args()
    
    if not Path(args.file).exists():
        print(f"{Fore.RED}Error: Input file not found: {args.file}")
        return
    
    # Initialize bulk checker
    checker = BulkChecker(args.data_dir, args.workers)
    
    print(f"{Fore.CYAN}Loading indicators from: {args.file}")
    indicators = checker.load_indicators_from_file(args.file)
    
    if not indicators:
        print(f"{Fore.RED}No indicators found in file")
        return
    
    print(f"{Fore.GREEN}Loaded {len(indicators):,} indicators")
    
    # Perform bulk checking
    results = checker.bulk_check(indicators, show_progress=not args.quiet)
    
    # Generate and print summary
    summary = checker.generate_summary(results)
    checker.print_summary(summary)
    
    # Show detailed results if requested
    if not args.quiet:
        filtered_results = checker.filter_results(
            results, 
            show_clean=args.show_clean,
            show_threats=args.show_threats,
            min_confidence=args.min_confidence
        )
        
        if filtered_results:
            print(f"\n{Fore.CYAN}Detailed Results:")
            for result in filtered_results[:20]:  # Limit to first 20 for display
                ioc = result['ioc']
                status = "THREAT" if result.get('threat_detected') else "CLEAN"
                color = Fore.RED if status == "THREAT" else Fore.GREEN
                print(f"{color}{status}: {ioc}")
                
                if result.get('threat_detected') and result.get('results'):
                    for threat in result['results'][:2]:  # Show up to 2 threat details
                        print(f"  └─ {threat.get('type', 'unknown')} ({threat.get('confidence', 'unknown')})")
            
            if len(filtered_results) > 20:
                print(f"\n{Fore.YELLOW}... and {len(filtered_results) - 20} more results")
    
    # Export results if requested
    if args.export:
        checker.export_results(results, summary, args.export, args.export_format)

if __name__ == "__main__":
    main()