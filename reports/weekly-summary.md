# Rekap Weekly Threat Intelligence Summary
**Week 38, 2024 (September 16-22, 2024)**

---

## 📊 Executive Summary

This week saw a **45% increase** in phishing campaigns targeting Indonesian banking customers, with threat actors leveraging sophisticated social engineering techniques and typosquatting domains. A new variant of the **RemcosRAT** was discovered with enhanced evasion capabilities, while cryptocurrency mining malware showed signs of resurgence.

**Key Metrics:**
- 🚨 **127 new IOCs** added to database
- 🎯 **23 phishing domains** targeting Indonesian banks
- 🔍 **15 new malware samples** analyzed
- ⚠️ **8 active campaigns** being monitored

---

## 🎯 Top Threats This Week

### 1. Indonesian Banking Phishing Wave
**Threat Level:** 🔴 **HIGH**
**Status:** Active
**First Detected:** September 10, 2024

A coordinated phishing campaign targeting major Indonesian banks (BNI, Mandiri, BCA, BRI) using sophisticated SMS and email vectors. Attackers are using newly registered domains with SSL certificates to appear legitimate.

**New Indicators:**
- `bni-mobile-security.net` - Phishing (High Confidence)
- `mandiri-token-update.org` - Phishing (High Confidence)
- `bca-secure-login.info` - Phishing (Medium Confidence)

**Recommendation:** Block listed domains, implement email security filters, conduct user awareness training.

### 2. RemcosRAT Evolution
**Threat Level:** 🟡 **MEDIUM-HIGH**
**Status:** Under Investigation

New RemcosRAT variant discovered with enhanced anti-analysis and persistence mechanisms. The malware is being distributed through fake WhatsApp Web update pages.

**Sample Hash:** `8b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e`
**C2 Servers:** `103.245.167.89`, `remote-support-center.biz`

### 3. Cryptominer Resurgence
**Threat Level:** 🟡 **MEDIUM**
**Status:** Monitoring

23% increase in cryptomining malware detected, primarily targeting compromised websites and distributed through malicious advertisements.

---

## 📈 Trend Analysis

### Phishing Campaigns
- **↗️ +45%** Banking-themed phishing
- **↗️ +32%** Government impersonation
- **↗️ +18%** WhatsApp/Social media themes

### Malware Families
- **RemcosRAT:** 15 new samples
- **NjRAT:** 8 new samples  
- **Emotet:** 5 new samples
- **AsyncRAT:** 3 new samples

### Geographic Distribution
- **Indonesia:** 68% of targeted campaigns
- **Southeast Asia:** 22% regional targeting
- **Global:** 10% widespread campaigns

---

## 🆕 New IOCs This Week

### Malicious IPs
```
185.220.101.182 - Emotet C2 Server (High)
45.142.214.123 - TrickBot Host (High)  
103.245.167.89 - NjRAT C2 Server (High)
194.31.98.124 - Phishing Host (Medium)
```

### Malicious Domains
```
bni-mobile-security.net - Banking Phishing (High)
mandiri-token-update.org - Banking Phishing (High)
whatsapp-web-update.info - Malware Distribution (Medium)
covid-relief-gov.net - Government Phishing (High)
```

### Malware Hashes
```
8b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e - RemcosRAT (High)
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 - NjRAT Variant (High)
9f8e7d6c5b4a3928374656849302847d - Cryptominer (Medium)
```

---

## 🛡️ Defensive Recommendations

### Immediate Actions
1. **Block IOCs:** Add new indicators to security tools (firewall, DNS, email security)
2. **User Training:** Conduct phishing awareness session focusing on banking themes
3. **Email Filters:** Update email security rules for banking-related keywords
4. **DNS Monitoring:** Watch for typosquatting domains of local banks

### Medium-term Strategies
1. **Threat Hunting:** Proactively search for RemcosRAT indicators in environment
2. **Incident Response:** Review and update IR procedures for banking phishing
3. **Third-party Assessment:** Evaluate security of banking partners and vendors
4. **Security Awareness:** Implement regular phishing simulation exercises

---

## 📊 Statistics

### IOC Database Growth
| Category | This Week | Total Database |
|----------|-----------|----------------|
| Malicious IPs | +12 | 15,259 |
| Domains | +23 | 8,847 |
| File Hashes | +15 | 12,456 |
| URLs | +8 | 3,221 |

### Detection Efficacy
- **True Positives:** 94.2%
- **False Positives:** 2.8%  
- **Coverage:** 87.5% of known threats
- **Response Time:** Average 4.2 hours

---

## 🔍 Campaign Spotlight: "Indonesian Banking Phishing Wave"

### Campaign Overview
A sophisticated, multi-vector phishing campaign specifically targeting Indonesian banking customers. The campaign demonstrates advanced social engineering tactics and technical sophistication.

### Attack Vectors
1. **SMS Phishing:** Fake security alerts claiming compromised accounts
2. **Email Phishing:** Professional-looking emails mimicking bank communications  
3. **Social Media:** Fake customer service accounts on Facebook/Instagram
4. **Typosquatting:** Domains closely resembling legitimate banking sites

### Technical Analysis
- **Infrastructure:** 15 domains registered across 5 different registrars
- **SSL Certificates:** All phishing sites use valid SSL certificates
- **Hosting:** Distributed across multiple cloud providers
- **Evasion:** Geo-filtering to avoid security researcher detection

### Attribution
Based on TTPs and infrastructure analysis, this campaign shows similarities to previous operations attributed to **financially-motivated threat actors** operating in Southeast Asia. However, definitive attribution requires additional investigation.

---

## 🚨 Alerts & Advisories

### ID-CERT Advisory
Indonesia's Computer Emergency Response Team issued advisory **ID-CERT-2024-038** regarding the banking phishing campaign. Organizations are advised to implement recommended countermeasures.

### BSSN Threat Alert
National Cyber Security Agency raised threat level to **ELEVATED** for financial sector due to increased targeting of Indonesian banks.

---

## 📅 Upcoming Week Focus

### Threat Hunting Priorities
1. Search for RemcosRAT persistence mechanisms
2. Monitor for new banking phishing infrastructure
3. Track cryptocurrency miner distribution methods
4. Investigate potential supply chain compromises

### Research Projects
1. Analysis of RemcosRAT anti-analysis techniques
2. Banking phishing campaign attribution research
3. Cryptominer infrastructure mapping
4. Mobile banking security assessment

---

## 🤝 Community Contributions

Special thanks to community members who contributed IOCs and analysis this week:

- **@SecurityResearcher_ID** - Provided 8 phishing domains
- **@MalwareHunter** - Shared RemcosRAT sample analysis
- **@BankingCISO** - Reported phishing campaign targeting customers
- **@ThreatIntel_SEA** - Contributed cryptocurrency miner IOCs

---

## 📞 Contact & Feedback

**Rekap Team:**
- 📧 intel@rekap-project.id
- 🔗 Telegram: @RekAPIntel
- 💬 Discord: Rekap Community Server

**Emergency Threat Reports:**
- 📧 urgent@rekap-project.id
- 📱 WhatsApp: +62-xxx-xxx-xxxx (24/7)

---

*This report is produced by the Rekap Threat Intelligence team. For questions about specific IOCs or threats, please contact our team. All IOCs are provided for defensive purposes only.*

**Next Report:** September 29, 2024
**Report Classification:** TLP:WHITE (Unrestricted sharing)