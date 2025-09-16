# Installation Guide

This guide will help you install and set up Rekap on your system.

## System Requirements

### Minimum Requirements
- **Python:** 3.8 or higher
- **RAM:** 2GB minimum, 4GB recommended
- **Storage:** 1GB free space
- **Network:** Internet connection for threat feed updates
- **OS:** Windows 10+, macOS 10.15+, Linux (Ubuntu 18.04+)

### Recommended Requirements
- **Python:** 3.9+ with pip
- **RAM:** 8GB for bulk processing
- **Storage:** 5GB for extended IOC database
- **CPU:** Multi-core for concurrent checking

## Installation Methods

### Method 1: Git Clone (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/Rekap.git
cd Rekap

# Create virtual environment (recommended)
python -m venv rekap-env

# Activate virtual environment
# On Linux/macOS:
source rekap-env/bin/activate
# On Windows:
rekap-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Method 2: Download ZIP

1. Download ZIP from GitHub repository
2. Extract to your preferred location
3. Open terminal/command prompt in extracted folder
4. Follow the virtual environment and pip install steps above

## Configuration

### 1. API Keys Setup (Optional)

```bash
# Copy the example configuration
cp config/api-keys.example config/api-keys.env

# Edit the file with your favorite editor
nano config/api-keys.env  # Linux/macOS
notepad config/api-keys.env  # Windows
```

Add your API keys:
```bash
VIRUSTOTAL_API_KEY=your_actual_virustotal_key
OTX_API_KEY=your_otx_api_key
SHODAN_API_KEY=your_shodan_api_key
```

**Getting API Keys:**
- **VirusTotal:** [Sign up](https://www.virustotal.com/gui/join-us) → Profile → API Key
- **AlienVault OTX:** [Register](https://otx.alienvault.com/signup) → Settings → API Integration
- **Shodan:** [Create account](https://account.shodan.io/register) → Account → API Key

### 2. Configure Sources (Optional)

```bash
# Edit source configuration
nano config/sources.yaml

# Enable/disable specific threat feeds
# Adjust update frequencies
# Configure validation rules
```

### 3. Directory Structure

Ensure you have the correct directory structure:
```
Rekap/
├── data/           # IOC databases
├── tools/          # Analysis tools
├── config/         # Configuration files
├── reports/        # Threat reports
├── logs/          # Log files (created automatically)
└── exports/       # Export outputs (created automatically)
```

## Verification

### Test Basic Installation

```bash
# Test IOC checker
python tools/ioc_checker.py --ioc google.com

# Test hash validator
python tools/hash_validator.py --hash d41d8cd98f00b204e9800998ecf8427e

# Test domain analyzer (quick check)
python tools/domain_analyzer.py --domain google.com --quick
```

Expected output should show tool information and "CLEAN" status for google.com.

### Test Bulk Checker

Create a test file:
```bash
echo "google.com" > test_iocs.txt
echo "1.1.1.1" >> test_iocs.txt
echo "d41d8cd98f00b204e9800998ecf8427e" >> test_iocs.txt

# Run bulk check
python tools/bulk_checker.py --file test_iocs.txt
```

## Troubleshooting

### Common Issues

#### 1. Python Version Error
```
Error: Python 3.8+ required
```
**Solution:** Install Python 3.8 or higher from [python.org](https://www.python.org/downloads/)

#### 2. Module Not Found Error
```
ModuleNotFoundError: No module named 'requests'
```
**Solution:** 
```bash
# Ensure virtual environment is activated
pip install -r requirements.txt
```

#### 3. Permission Denied
```
PermissionError: [Errno 13] Permission denied
```
**Solution:**
```bash
# On Linux/macOS - fix permissions
chmod +x tools/*.py

# Or run with python explicitly
python tools/ioc_checker.py --help
```

#### 4. DNS Resolution Issues
```
Error: [Errno 11001] getaddrinfo failed
```
**Solution:** Check internet connection and DNS settings

#### 5. API Rate Limiting
```
Error: API rate limit exceeded
```
**Solution:** 
- Wait for rate limit reset
- Add API keys to increase limits
- Reduce concurrent workers: `--workers 2`

### Performance Issues

#### Slow Processing
- **Reduce worker threads:** `--workers 5`
- **Use SSD storage** for database files
- **Increase available RAM**
- **Enable caching** in config

#### High Memory Usage
- **Process smaller batches**
- **Disable detailed logging**
- **Close other applications**

### Getting Help

1. **Check logs:** `logs/rekap.log`
2. **Enable debug mode:** Set `LOG_LEVEL=DEBUG` in config
3. **GitHub Issues:** [Report bugs](https://github.com/yourusername/Rekap/issues)
4. **Community:** Join our [Discord](https://discord.gg/rekap) or [Telegram](https://t.me/RekAPIntel)

## Updating Rekap

### Update from Git

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Check for breaking changes
python tools/ioc_checker.py --help
```

### Manual Update

1. Download latest ZIP
2. Backup your `config/` directory
3. Extract new version
4. Restore your configuration
5. Update dependencies

## Advanced Installation

### Docker Installation (Coming Soon)

```bash
# Build Docker image
docker build -t rekap .

# Run container
docker run -it rekap python tools/ioc_checker.py --help
```

### System Service Setup

For automatic threat feed updates, set up as system service:

#### Linux (systemd)
```bash
# Create service file
sudo nano /etc/systemd/system/rekap-updater.service

# Enable and start
sudo systemctl enable rekap-updater
sudo systemctl start rekap-updater
```

#### Windows (Task Scheduler)
1. Open Task Scheduler
2. Create Basic Task
3. Set trigger for daily updates
4. Action: Start program → `python.exe`
5. Arguments: `tools/bulk_updater.py`

## Security Considerations

### File Permissions
```bash
# Restrict config file access
chmod 600 config/api-keys.env

# Make tools executable
chmod +x tools/*.py
```

### Network Security
- **Use HTTPS** for all API calls
- **Configure firewall** to allow outbound connections
- **Monitor API usage** for unusual activity

### Data Protection
- **Encrypt sensitive configs**
- **Regular backups** of custom IOCs
- **Secure API key storage**

## Next Steps

After successful installation:

1. [Read Usage Guide](usage.md) for tool documentation
2. [Check Contributing Guide](contributing.md) to add your IOCs
3. Join our community channels for updates
4. Set up automated threat feed updates

---

**Need Help?** 
- 📧 Email: support@rekap-project.id
- 💬 Discord: [Rekap Community](https://discord.gg/rekap)
- 📱 Telegram: [@RekAPIntel](https://t.me/RekAPIntel)