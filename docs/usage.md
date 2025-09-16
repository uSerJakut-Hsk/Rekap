# Usage Guide

Complete guide for using Rekap threat intelligence tools.

## Quick Reference

| Tool | Purpose | Basic Usage |
|------|---------|-------------|
| `ioc_checker.py` | Check individual IOCs | `python tools/ioc_checker.py --ioc <indicator>` |
| `hash_validator.py` | Validate file hashes | `python tools/hash_validator.py --hash <hash>` |
| `domain_analyzer.py` | Analyze domains | `python tools/domain_analyzer.py --domain <domain>` |
| `bulk_checker.py` | Process multiple IOCs | `python tools/bulk_checker.py --file <file>` |

## IOC Checker

The main tool for checking indicators against the Rekap database.

### Basic Usage

```bash
# Check IP address
python tools/ioc_checker.py --ip 192.168.1.100

# Check domain
python tools/ioc_checker.py --domain malicious-site.com

# Check file hash
python tools/ioc_checker.py --hash d41d8cd98f00b204e9800998ecf8427e

# Check URL
python tools/ioc_checker.py --url https://suspicious-site.com/malware.exe

# Auto-detect IOC type
python tools/ioc_checker.py --ioc 185.220.101.182
```

### Advanced Options

```bash
# Use custom data directory
python tools/ioc_checker.py --ioc 1.2.3.4 --data-dir /path/to/custom/data

# Multiple checks
python tools/ioc_checker.py --ip 1.2.3.4 --domain evil.com
```

### Output Examples

**Clean IOC:**
```
============================================================
IOC Check Results
============================================================
IOC: google.com
Type: DOMAIN
Check Time: 2024-09-16 10:30:15

✓ CLEAN - No threats detected in Rekap database
```

**Malicious IOC:**
```
============================================================
IOC Check Results
============================================================
IOC: malicious-site.com
Type: DOMAIN
Check Time: 2024-09-16 10:30:15

⚠ THREAT DETECTED - 1 match(es) found:

Match #1:
  Source: Rekap IOCs Database
  Status: MALICIOUS
  Confidence: high
  Type: phishing
  Target: banking
  First Seen: 2024-09-10
  Tags: phishing, banking
  Description: Fake banking update targeting Indonesian banks
```

## Hash Validator

Specialized tool for malware hash analysis.

### Basic Usage

```bash
# Validate single hash
python tools/hash_validator.py --hash d41d8cd98f00b204e9800998ecf8427e

# Calculate hashes of local file
python tools/hash_validator.py --file /path/to/suspicious/file.exe

# Bulk validate from file
python tools/hash_validator.py --bulk hash_list.txt

# Export results
python tools/hash_validator.py --bulk hash_list.txt --export results.csv
```

### Hash Formats Supported

- **MD5:** 32 hex characters
- **SHA1:** 40 hex characters  
- **SHA256:** 64 hex characters

### File Analysis Example

```bash
python tools/hash_validator.py --file suspicious_file.exe
```

Output:
```
======================================================================
File Hash Analysis
======================================================================
File: suspicious_file.exe
Size: 245,760 bytes

Calculated Hashes:
  MD5:    8b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e
  SHA1:   1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
  SHA256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

🚨 MALWARE DETECTED!

Match found via MD5 hash:
  Malware Family: RemcosRAT
  Confidence: high
  Description: RemcosRAT variant with enhanced evasion
```

## Domain Analyzer

Comprehensive domain reputation and technical analysis.

### Basic Usage

```bash
# Quick reputation check
python tools/domain_analyzer.py --domain suspicious-site.com --quick

# Full analysis
python tools/domain_analyzer.py --domain suspicious-site.com

# Export results to JSON
python tools/domain_analyzer.py --domain evil.com --export analysis.json
```

### Analysis Components

1. **DNS Records** - A, AAAA, MX, NS, TXT, CNAME
2. **WHOIS Information** - Registration data, registrar, age
3. **SSL Certificate** - Certificate details and validity
4. **Reputation Check** - Against Rekap databases
5. **Age Analysis** - Domain age and risk assessment
6. **Typosquatting Detection** - Similarity to popular domains

### Full Analysis Example

```bash
python tools/domain_analyzer.py --domain bni-mobile-security.net
```

Output:
```
================================================================================
Domain Analysis Report: bni-mobile-security.net
================================================================================
🚨 HIGH RISK DOMAIN
Database Status: suspicious
Confidence: high
Description: Phishing site impersonating BNI mobile banking

DNS Records:
  A: 45.89.173.245
  NS: ns1.namecheap.com, ns2.namecheap.com

WHOIS Information:
  Registrar: NameCheap
  Creation Date: 2024-09-11
  Country: Unknown

Domain Age Analysis:
  Age: 5 days
  Category: new
  Risk Level: high

SSL Certificate:
  Subject CN: bni-mobile-security.net
  Issuer: Let's Encrypt
  Valid Until: 2024-12-11

Typosquatting Analysis:
  ⚠️ Potential typosquatting detected!
  Possible targets: bni.co.id
  Risk Score: 8/10
```

## Bulk Checker

Process multiple IOCs from files with parallel processing.

### Supported File Formats

- **Text files** (`.txt`) - One IOC per line
- **CSV files** (`.csv`) - IOCs in first column
- **JSON files** (`.json`) - Array of IOCs or structured data

### Basic Usage

```bash
# Process text file
python tools/bulk_checker.py --file ioc_list.txt

# Process CSV file
python tools/bulk_checker.py --file indicators.csv

# Export results
python tools/bulk_checker.py --file ioc_list.txt --export results.json

# Control worker threads
python tools/bulk_checker.py --file large_list.txt --workers 20
```

### Advanced Options

```bash
# Show only threats (hide clean IOCs)
python tools/bulk_checker.py --file iocs.txt --show-threats

# Show only clean IOCs  
python tools/bulk_checker.py --file iocs.txt --show-clean

# Filter by confidence level
python tools/bulk_checker.py --file iocs.txt --min-confidence high

# Export as CSV
python tools/bulk_checker.py --file iocs.txt --export results.csv --export-format csv

# Quiet mode (summary only)
python tools/bulk_checker.py --file iocs.txt --quiet
```

### Input File Examples

**Text File (iocs.txt):**
```
192.168.1.100
malicious-domain.com
d41d8cd98f00b204e9800998ecf8427e
https://evil-site.com/payload.exe
```

**CSV File (indicators.csv):**
```csv
ioc,source,category
192.168.1.100,honeypot,c2_server
evil-domain.com,manual,phishing
d41d8cd98f00b204e9800998ecf8427e,sandbox,malware
```

**JSON File (threats.json):**
```json
[
  "192.168.1.100",
  "malicious-domain.com", 
  "d41d8cd98f00b204e9800998ecf8427e"
]
```

### Bulk Processing Output

```
============================================================
Bulk Check Summary
============================================================
Total IOCs Processed: 1,247
Threats Detected: 156
Clean IOCs: 1,078
Errors: 13
Threat Percentage: 12.5%

IOC Types:
  ip: 445
  domain: 623
  hash: 179

Threat Types:
  phishing: 67
  malware: 45
  c2_server: 32
  botnet: 12

Confidence Levels:
  high: 89
  medium: 45
  low: 22
```

## Configuration

### API Integration

Add API keys to `config/api-keys.env`:

```bash
# VirusTotal integration
VIRUSTOTAL_API_KEY=your_key_here

# Enhanced analysis with external sources
OTX_API_KEY=your_otx_key
SHODAN_API_KEY=your_shodan_key
```

### Custom Data Sources

Edit `config/sources.yaml` to:
- Enable/disable threat feeds
- Adjust update frequencies  
- Configure validation rules
- Set confidence thresholds

## Tips & Best Practices

### Performance Optimization

```bash
# For large datasets, adjust workers
python tools/bulk_checker.py --file huge_list.txt --workers 50

# Use SSD storage for better I/O
# Enable caching in config/sources.yaml

# Process in smaller batches
split -l 1000 huge_list.txt batch_
```

### Accuracy Improvement

```bash
# Use multiple validation sources
python tools/ioc_checker.py --ioc suspicious-domain.com

# Cross-reference with domain analyzer
python tools/domain_analyzer.py --domain suspicious-domain.com

# Verify file hashes with hash validator
python tools/hash_validator.py --hash suspected_malware_hash
```

### Automation Scripts

**Daily IOC Check:**
```bash
#!/bin/bash
# daily_check.sh
python tools/bulk_checker.py --file daily_iocs.txt --export "results_$(date +%Y%m%d).json" --quiet
```

**Weekly Report Generation:**
```bash
#!/bin/bash
# weekly_report.sh
python tools/bulk_checker.py --file week_indicators.txt --export weekly_analysis.csv --export-format csv
```

## Integration Examples

### SIEM Integration

```bash
# Export for Splunk
python tools/bulk_checker.py --file network_logs.txt --export splunk_threats.json --show-threats

# Export for ELK Stack  
python tools/bulk_checker.py --file firewall_ips.txt --export elk_indicators.json --min-confidence medium
```

### Incident Response

```bash
# Quick triage of artifacts
python tools/hash_validator.py --bulk incident_hashes.txt --export ir_analysis.csv

# Domain reputation check
python tools/domain_analyzer.py --domain attacker-c2.com --export domain_intel.json
```

### Threat Hunting

```bash
# Hunt for specific malware family
grep -i "emotet" data/malware-hashes.txt

# Search IOC database
python tools/ioc_checker.py --ioc suspected_ip

# Bulk validation of hunting results
python tools/bulk_checker.py --file hunt_results.txt --min-confidence high
```

## Error Handling

### Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `FileNotFoundError` | Missing data files | Run `git pull` to update database |
| `ConnectionError` | Network issues | Check internet connection |
| `RateLimitError` | API limits exceeded | Add API keys or reduce workers |
| `ValidationError` | Invalid IOC format | Check IOC syntax and format |

### Debug Mode

```bash
# Enable detailed logging
export LOG_LEVEL=DEBUG
python tools/ioc_checker.py --ioc test

# Check log files
tail -f logs/rekap.log
```

## Output Formats

### JSON Export
```json
{
  "summary": {
    "total_iocs": 100,
    "threats_detected": 15,
    "threat_percentage": 15.0
  },
  "results": [
    {
      "ioc": "malicious-ip.com",
      "threat_detected": true,
      "confidence": "high"
    }
  ]
}
```

### CSV Export
```csv
ioc,ioc_type,threat_detected,threat_count,highest_confidence,threat_types
malicious-ip.com,domain,true,1,high,phishing
clean-domain.com,domain,false,0,,,
```

---

**Need More Help?**
- 📖 [Installation Guide](installation.md)
- 🤝 [Contributing Guide](contributing.md)
- 💬 [Community Discord](https://discord.gg/rekap)
- 📧 Email: support@rekap-project.id