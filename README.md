# Rekap 🔍
**Indonesia Threat Intelligence Repository**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)

> *"Rekap semua ancaman cyber untuk keamanan yang lebih baik"*

Rekap adalah repository threat intelligence yang dikembangkan khusus untuk komunitas cybersecurity Indonesia. Kami menyediakan database Indicators of Compromise (IOCs), tools untuk analisis threat, dan laporan berkala tentang landscape ancaman cyber.

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/Rekap.git
cd Rekap

# Install dependencies
pip install -r requirements.txt

# Check single IOC
python tools/ioc_checker.py --ioc 192.168.1.100

# Check file hash
python tools/hash_validator.py --hash d41d8cd98f00b204e9800998ecf8427e

# Analyze domain
python tools/domain_analyzer.py --domain suspicious-site.com
```

## 📊 Database Statistics

| IOC Type | Count | Last Updated |
|----------|-------|--------------|
| Malicious IPs | 15,259 | 2024-09-16 |
| Suspicious Domains | 8,847 | 2024-09-16 |
| Malware Hashes | 12,456 | 2024-09-16 |
| Malicious URLs | 3,221 | 2024-09-16 |

## 🛠️ Tools

- **`ioc_checker.py`** - Check IPs, domains, hashes, URLs against threat database
- **`hash_validator.py`** - Specialized malware hash validation and analysis
- **`domain_analyzer.py`** - Comprehensive domain reputation analysis  
- **`bulk_checker.py`** - Batch processing for multiple IOCs

## 📈 Features

✅ **IOC Database** - Comprehensive collection of malicious indicators  
✅ **Automated Analysis** - Tools for threat validation and enrichment  
✅ **Weekly Reports** - Regular threat landscape summaries  
✅ **Community Driven** - Contributions from Indonesian security community  
✅ **Multiple Formats** - Support for JSON, CSV, STIX, MISP formats  
✅ **API Integration** - Connect with VirusTotal, OTX, Shodan, etc.

## 📝 Recent Threats

**This Week's Top Threats:**
- 🚨 Indonesian Banking Phishing Wave (HIGH)
- 🔍 RemcosRAT Evolution (MEDIUM-HIGH) 
- ⚠️ Cryptominer Resurgence (MEDIUM)

[📄 Read Full Weekly Report](reports/weekly-summary.md)

## 🤝 Contributing

Kami welcome kontribusi dari security community Indonesia!

```bash
# Fork repository
git clone https://github.com/yourusername/Rekap.git

# Add your IOCs/tools
git add data/new-indicators.json

# Commit and push
git commit -m "Add new banking phishing IOCs"
git push origin feature/new-indicators

# Create pull request
```

**Contribution Guidelines:**
- Pastikan IOCs sudah terverifikasi
- Include source dan confidence level  
- Follow existing data format
- Add proper documentation

## ⚖️ Legal Disclaimer

Repository ini **HANYA** untuk tujuan:
- ✅ Defensive security research
- ✅ Educational purposes
- ✅ Threat hunting dan incident response  
- ✅ Security awareness

**TIDAK untuk:**
- ❌ Malicious activities
- ❌ Unauthorized access
- ❌ Illegal hacking activities

## 📞 Contact

- **Email:** intel@rekap-project.id
- **Telegram:** [@RekAPIntel](https://t.me/RekAPIntel)  
- **Discord:** [Rekap Community Server](https://discord.gg/rekap)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**"Bersama kita kuat, bersama kita aman"** 🇮🇩