
### 📄 README.md

````markdown
# Rekap 🔍
**Indonesia Threat Intelligence Repository**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)

> *"Rekap semua ancaman cyber untuk keamanan yang lebih baik"*

Rekap adalah repository threat intelligence yang dikembangkan khusus untuk komunitas cybersecurity Indonesia.  
Kami menyediakan database Indicators of Compromise (IOCs), tools untuk analisis threat, dan laporan berkala tentang landscape ancaman cyber.

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/uSerJakut-Hsk/Rekap.git
cd Rekap

# Install dependencies
pip install -r requirements.txt

# Check single IOC
python tools/ioc_checker.py --ioc 192.168.1.100

# Check file hash
python tools/hash_validator.py --hash d41d8cd98f00b204e9800998ecf8427e

# Analyze domain
python tools/domain_analyzer.py --domain suspicious-site.com
````

## 📊 Database Statistics

| IOC Type           | Count  | Last Updated |
| ------------------ | ------ | ------------ |
| Malicious IPs      | 15,259 | 2024-09-16   |
| Suspicious Domains | 8,847  | 2024-09-16   |
| Malware Hashes     | 12,456 | 2024-09-16   |
| Malicious URLs     | 3,221  | 2024-09-16   |

## 🛠️ Tools

* **`ioc_checker.py`** - Check IPs, domains, hashes, URLs against threat database
* **`hash_validator.py`** - Specialized malware hash validation and analysis
* **`domain_analyzer.py`** - Comprehensive domain reputation analysis
* **`bulk_checker.py`** - Batch processing for multiple IOCs

## 📈 Features

✅ **IOC Database** - Comprehensive collection of malicious indicators
✅ **Automated Analysis** - Tools for threat validation and enrichment
✅ **Weekly Reports** - Regular threat landscape summaries
✅ **Community Driven** - Contributions from Indonesian security community
✅ **Multiple Formats** - Support for JSON, CSV, STIX, MISP formats
✅ **API Integration** - Connect with VirusTotal, OTX, Shodan, etc.

## 📝 Recent Threats

**This Week's Top Threats:**

* 🚨 Indonesian Banking Phishing Wave (HIGH)
* 🔍 RemcosRAT Evolution (MEDIUM-HIGH)
* ⚠️ Cryptominer Resurgence (MEDIUM)

[📄 Read Full Weekly Report](reports/weekly-summary.md)

## 🤝 Contributing

Kami welcome kontribusi dari security community Indonesia!

```bash
# Fork repository
git clone https://github.com/uSerJakut-Hsk/Rekap.git

# Add your IOCs/tools
git add data/new-indicators.json

# Commit and push
git commit -m "Add new banking phishing IOCs"
git push origin feature/new-indicators

# Create pull request
```

**Contribution Guidelines:**

* Pastikan IOCs sudah terverifikasi
* Sertakan source & confidence level
* Ikuti format data yang ada
* Tambahkan dokumentasi yang jelas

## ⚖️ Legal Disclaimer

Repository ini **HANYA** untuk tujuan:

* ✅ Defensive security research
* ✅ Educational purposes
* ✅ Threat hunting dan incident response
* ✅ Security awareness

**TIDAK untuk:**

* ❌ Malicious activities
* ❌ Unauthorized access
* ❌ Illegal hacking activities

## 📞 Contact

* **Email:** *(kosong)*
* **Telegram:** *(kosong)*
* **Discord:** *(kosong)*

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/uSerJakut-Hsk/Rekap/blob/main/LICENSE) file for details.

---

**"Bersama kita kuat, bersama kita aman"** 🇮🇩

````

---

### 📄 LICENSE

```text
MIT License

Copyright (c) 2025 uSerJakut-Hsk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all  
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  
SOFTWARE.
````