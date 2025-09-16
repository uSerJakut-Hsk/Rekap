# Contributing to Rekap

Terima kasih atas minat Anda untuk berkontribusi pada Rekap! Panduan ini akan membantu Anda memahami cara berkontribusi secara efektif pada proyek threat intelligence Indonesia ini.

## 🎯 Cara Berkontribusi

Ada beberapa cara untuk berkontribusi pada Rekap:

1. **🚨 Melaporkan IOCs baru**
2. **🛠️ Mengembangkan tools**
3. **📖 Memperbaiki dokumentasi**
4. **🐛 Melaporkan bugs**
5. **💡 Memberikan ide fitur**
6. **📊 Membuat analysis reports**

## 🚨 Kontribusi IOCs

### Format IOC yang Diterima

**Malicious IPs:**
```json
{
  "ip": "192.168.1.100",
  "type": "c2_server",
  "malware_family": "emotet",
  "confidence": "high",
  "first_seen": "2024-09-16",
  "country": "RU",
  "asn": "AS12345",
  "hosting_provider": "Example Hosting",
  "port": 443,
  "protocol": "HTTPS",
  "tags": ["banking_trojan", "botnet", "active_c2"],
  "description": "Emotet C2 server observed serving banking module",
  "source": "honeypot_analysis",
  "analyst": "security_researcher_id",
  "campaign": "emotet_wave_q3_2024",
  "related_iocs": ["related_ip_1", "related_domain"],
  "ttps": ["T1071.001", "T1573.001"],
  "yara_rule": "rule_name_if_applicable"
}
```

## 🔍 Research & Analysis

### Campaign Tracking

Ketika melaporkan IOCs yang terkait campaign:

```markdown
## Campaign: Indonesian Banking Phishing Wave Q3 2024

### Overview
- **Start Date:** 2024-09-10
- **Status:** Active
- **Targets:** Indonesian banks (BNI, Mandiri, BCA, BRI)
- **Vectors:** SMS, Email, Social Media

### IOCs
- **Domains:** 15 phishing domains
- **IPs:** 8 hosting servers
- **Hashes:** 5 malware samples

### TTPs
- Initial Access: T1566.002 (Spearphishing Link)
- Defense Evasion: T1036.005 (Match Legitimate Name)
- Credential Access: T1539 (Steal Web Session Cookie)

### Attribution
- **Threat Actor:** Unknown (under investigation)
- **Confidence:** Low
- **Similar Campaigns:** [Link to previous analysis]
```

### Malware Analysis Reports

```markdown
## Malware Analysis: RemcosRAT Variant

### Basic Information
- **File Hash:** 8b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e
- **File Type:** PE32 Executable
- **Size:** 245,760 bytes
- **Compilation:** 2024-09-10 14:23:15 UTC

### Analysis Summary
- **Family:** RemcosRAT
- **Version:** 3.1.2 (modified)
- **Capabilities:** Keylogging, screen capture, file theft
- **Anti-Analysis:** Packing, VM detection, sandbox evasion

### C2 Communication
- **Primary C2:** remote-support-center.biz:8080
- **Backup C2:** 103.245.167.89:443
- **Protocol:** Custom over HTTPS
- **Encryption:** XOR with rotating key

### IOCs
[Include all related indicators]

### Recommendations
[Defensive measures and detection rules]
```

## 🤝 Community Guidelines

### Communication

**Professional & Respectful:**
- Gunakan bahasa yang sopan dan profesional
- Respect different opinions dan approaches
- Provide constructive feedback
- Be patient dengan contributors baru

**Collaborative:**
- Share knowledge dan findings
- Help others understand complex topics  
- Credit contributions dari orang lain
- Foster inclusive environment

### Code of Conduct

**Do:**
- ✅ Verify IOCs before submission
- ✅ Provide clear documentation
- ✅ Follow established formats
- ✅ Respect privacy dan legal boundaries
- ✅ Help newcomers learn

**Don't:**
- ❌ Submit false positives intentionally
- ❌ Share personal/private data
- ❌ Use offensive language
- ❌ Spam or flood dengan submissions
- ❌ Violate terms of service

## 📚 Resources untuk Contributors

### Learning Resources

**Threat Intelligence:**
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [STIX/TAXII Standards](https://oasis-open.github.io/cti-documentation/)
- [Threat Intelligence Fundamentals](https://www.sans.org/white-papers/)

**Malware Analysis:**
- [Practical Malware Analysis](https://practicalmalwareanalysis.com/)
- [Malware Analysis Tutorials](https://malwareunicorn.org/)
- [YARA Rules Writing](https://yara.readthedocs.io/)

**Tools & Platforms:**
- [VirusTotal](https://www.virustotal.com/)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [Any.run](https://any.run/)
- [Shodan](https://www.shodan.io/)

### Indonesian Cybersecurity Community

**Organizations:**
- [ID-CERT](https://www.cert.or.id/)
- [BSSN](https://bssn.go.id/)
- [CyberSecurity Indonesia](https://cybersecurity.or.id/)

**Communities:**
- [Indonesian Security Community Discord](#)
- [InfoSec Indonesia Telegram](#) 
- [Security Meetups Jakarta](#)

## 🏆 Recognition

### Contributor Levels

**Bronze Contributors** (1-10 verified IOCs):
- Name in contributors list
- Bronze badge on GitHub
- Access to contributor channel

**Silver Contributors** (11-50 verified IOCs):
- Featured in monthly reports
- Silver badge dan special recognition
- Early access to new features

**Gold Contributors** (51+ verified IOCs):
- Core contributor status
- Gold badge dan special privileges
- Direct communication channel
- Influence in project direction

**Special Recognition:**
- **Most Active:** Monthly most active contributor
- **Quality Champion:** Best quality submissions
- **Analysis Expert:** Best analysis reports
- **Community Helper:** Most helpful to newcomers

### Hall of Fame

Contributors yang memberikan impact significant:

```markdown
## Rekap Hall of Fame

### Founding Contributors
- @SecurityExpert_ID - 150+ IOCs, campaign analysis
- @MalwareHunter_ID - Advanced malware analysis
- @ThreatIntel_SEA - Regional threat tracking

### Top Contributors This Quarter
- @BankingSecurity - Banking sector threats
- @AndroidAnalyst - Mobile malware focus  
- @PhishingHunter - Email threat analysis

### Community Champions
- @HelpfulMentor - New contributor guidance
- @DocumentationGuru - Documentation improvements
- @QualityAssurance - Data validation expert
```

## 🚀 Getting Started Checklist

Untuk new contributors:

### Before First Contribution
- [ ] Read this contributing guide completely
- [ ] Join community Discord/Telegram
- [ ] Introduce yourself in #introductions
- [ ] Review existing IOCs untuk understand format
- [ ] Set up development environment

### First Contribution Ideas
- [ ] Add 1-3 verified IOCs with proper documentation
- [ ] Fix typos in documentation
- [ ] Improve tool help messages
- [ ] Add test cases for existing functions
- [ ] Contribute to weekly threat summary

### After First Contribution  
- [ ] Respond to review feedback promptly
- [ ] Join contributor discussions
- [ ] Help review other contributions
- [ ] Share project dalam community
- [ ] Plan next contributions

## ❓ FAQ

### General Questions

**Q: Apakah saya perlu expertise tinggi untuk berkontribusi?**
A: Tidak! Kami welcome contributors dari semua levels. Bahkan typo fixes atau documentation improvements sangat valuable.

**Q: Bagaimana saya tahu IOC saya valid?**
A: Gunakan multiple sources untuk verification, test dengan tools kami, dan follow validation guidelines di atas.

**Q: Bisakah saya submit IOCs dari public sources?**
A: Ya, tapi pastikan untuk proper attribution dan verify bahwa IOCs masih relevant.

### Technical Questions

**Q: Format mana yang harus saya gunakan?**
A: Follow existing formats dalam data files. Lihat examples di usage guide.

**Q: Bagaimana cara test changes saya?**
A: Run validation scripts dan test dengan tools sebelum submit PR.

**Q: Bisakah saya add tools baru?**
A: Absolutely! Pastikan untuk include documentation dan tests.

### Process Questions

**Q: Berapa lama review process?**
A: Usually 2-7 hari, depending on complexity dan reviewer availability.

**Q: Apa yang terjadi jika PR saya ditolak?**
A: Reviewers akan provide feedback. Address the issues dan resubmit.

**Q: Bisakah saya submit anonymous contributions?**
A: Ya, tapi kami encourage attribution untuk recognition dan accountability.

## 📞 Contact Contributors Team

**Questions tentang contributing:**
- 📧 contributors@rekap-project.id
- 💬 Discord: #contributors channel
- 📱 Telegram: @RekAPContributors

**Technical Support:**
- 🛠️ GitHub Issues: [Technical questions](https://github.com/yourusername/Rekap/issues)
- 💻 Discord: #development channel

**Content Questions:**
- 🔍 Email: intel@rekap-project.id
- 📊 Discord: #threat-intelligence channel

---

**Terima kasih telah berkontribusi pada keamanan cyber Indonesia! 🇮🇩**

*Together we are stronger, together we are safer.*
  "tags": ["banking_trojan", "botnet"],
  "description": "Emotet C2 server observed in recent campaigns",
  "source": "honeypot_analysis"
}
```

**Suspicious Domains:**
```
malicious-domain.com:phishing:high:2024-09-16:Fake banking site targeting Indonesian banks
```

**Malware Hashes:**
```
d41d8cd98f00b204e9800998ecf8427e:da39a3ee5e6b4b0d3255bfef95601890afd80709:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:emotet:high:2024-09-16:Emotet banking trojan variant
```

### Validasi IOC

Sebelum submit, pastikan IOC Anda:
- ✅ **Verified**: Sudah diverifikasi sebagai malicious
- ✅ **Recent**: Masih aktif atau relevant
- ✅ **Sourced**: Ada source yang jelas
- ✅ **Accurate**: Format dan data benar
- ✅ **Legal**: Diperoleh secara legal dan ethical

### Confidence Levels

- **High**: Multiple sources, direct analysis, atau observed in attacks
- **Medium**: Single reliable source atau indirect evidence
- **Low**: Unverified reports atau automated detection

## 📝 Process Kontribusi

### 1. Fork & Clone

```bash
# Fork repository di GitHub
# Clone fork Anda
git clone https://github.com/YOUR_USERNAME/Rekap.git
cd Rekap

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/Rekap.git
```

### 2. Create Branch

```bash
# Create feature branch
git checkout -b add-banking-phishing-iocs

# Or bug fix branch  
git checkout -b fix-hash-validation-bug
```

### 3. Make Changes

**Menambah IOCs:**
```bash
# Edit data files
nano data/iocs.json
nano data/suspicious-domains.txt
nano data/malware-hashes.txt

# Validate format
python tools/validate_data.py
```

**Mengembangkan tools:**
```bash
# Create new tool
touch tools/new_analyzer.py
chmod +x tools/new_analyzer.py

# Update requirements if needed
echo "new-dependency==1.0.0" >> requirements.txt
```

### 4. Test Changes

```bash
# Test IOC checker
python tools/ioc_checker.py --ioc your_new_ioc

# Test bulk processing
python tools/bulk_checker.py --file test_data.txt

# Run validation
python scripts/validate_all_data.py
```

### 5. Commit & Push

```bash
# Stage changes
git add data/iocs.json data/suspicious-domains.txt

# Commit with clear message
git commit -m "Add 15 banking phishing IOCs targeting Indonesian banks

- Added domains impersonating BNI, Mandiri, BCA
- All IOCs verified through honeypot analysis  
- High confidence indicators with active C2 servers
- Source: Community incident response team

Fixes #123"

# Push to your fork
git push origin add-banking-phishing-iocs
```

### 6. Create Pull Request

1. Go to GitHub repository
2. Click "New Pull Request"
3. Fill PR template completely
4. Wait for review

## 📋 Pull Request Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] IOC additions
- [ ] Bug fix  
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## IOC Details (if applicable)
- **Total IOCs added:** X
- **IOC types:** IPs, domains, hashes, URLs
- **Confidence levels:** high/medium/low breakdown
- **Sources:** Where IOCs were obtained
- **Verification method:** How IOCs were validated

## Testing
- [ ] Tested with ioc_checker.py
- [ ] Tested with bulk_checker.py  
- [ ] Data validation passed
- [ ] No conflicts with existing data

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass
- [ ] Commit messages are clear

## Additional Notes
Any additional context or screenshots.
```

## 🛠️ Development Guidelines

### Code Style

**Python:**
```python
# Use clear function names
def validate_ip_address(ip_string):
    """Validate IP address format and return boolean."""
    pass

# Add docstrings
def check_domain_reputation(domain):
    """
    Check domain against reputation databases.
    
    Args:
        domain (str): Domain name to check
        
    Returns:
        dict: Reputation analysis results
    """
    pass

# Use type hints where appropriate
from typing import List, Dict, Optional

def process_iocs(iocs: List[str]) -> Dict[str, bool]:
    """Process list of IOCs and return results."""
    pass
```

**File Organization:**
```
tools/
├── core/           # Core functionality
├── analyzers/      # Analysis modules  
├── exporters/      # Export utilities
└── validators/     # Data validation
```

### Testing

```bash
# Create test file
touch tests/test_new_feature.py

# Basic test structure
import unittest
from tools.new_analyzer import NewAnalyzer

class TestNewAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = NewAnalyzer()
    
    def test_basic_analysis(self):
        result = self.analyzer.analyze("test_input")
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)

# Run tests
python -m pytest tests/
```

## 📊 Data Quality Standards

### IOC Validation Checklist

**IP Addresses:**
- [ ] Valid IPv4/IPv6 format
- [ ] Not in private ranges (unless specified)
- [ ] Geo-location data included
- [ ] Associated malware family identified

**Domains:**
- [ ] Valid domain format
- [ ] DNS resolution checked
- [ ] WHOIS data reviewed
- [ ] Typosquatting patterns identified

**File Hashes:**
- [ ] Valid MD5/SHA1/SHA256 format
- [ ] Malware family identified
- [ ] File size and type noted
- [ ] Analysis source provided

**URLs:**
- [ ] Valid URL format
- [ ] HTTP response code noted
- [ ] Final redirect destination checked
- [ ] Payload type identified

### Data Enrichment

Berikan informasi tambahan sebanyak mungkin:
```json
{
  "ip": "192.168.1.100",
  "type": "c2_server",
  "malware_family": "emotet",
  "confidence": "high",
  "first_seen": "2024-09-16",
  "last_seen": "2024-09-20",
  "country": "RU",
  "as