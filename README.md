# 🔍 TwinSanity Recon

<div align="center">
  <img src="twinsanity-recon-logo.png" alt="TwinSanity Recon Logo" width="600">
</div>

A comprehensive cybersecurity reconnaissance tool for subdomain discovery, vulnerability scanning, and automated threat analysis.

## 📋 Overview

TwinSanity Recon is a multi-threaded reconnaissance framework designed for security professionals and penetration testers. It combines subdomain enumeration, certificate transparency monitoring, CVE analysis, and AI-powered reporting to provide comprehensive target assessment capabilities.

### ✨ Key Features

- **🚀 Multi-threaded Subdomain Discovery**: Fast subdomain enumeration using various techniques
- **🔒 Certificate Transparency Integration**: Leverages CT logs for comprehensive domain discovery
- **🛡️ CVE Analysis**: Automated vulnerability detection with multiple data sources
- **🤖 AI-Powered Reporting**: Generates detailed HTML reports with threat analysis
- **🔀 Proxy Support**: Built-in proxy rotation for operational security
- **📊 Multiple Data Sources**: Integrates with Shodan, NVD, and CIRCL for comprehensive coverage
- **📈 Professional Reporting**: Generates structured HTML and JSON reports

## ⚙️ Installation

### 📋 Prerequisites

- Python 3.8 or higher
- pip package manager
- Git

### 🚀 Setup

1. **Clone the repository:**
```bash
git clone https://github.com/MustafaCyb/TwinSanity-Recon.git
cd TwinSanity-Recon
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure environment variables:**
```bash
cp .env.example .env
# Edit .env with your API keys
```

### 🤖 Optional: Local AI Setup

For enhanced analysis with local AI models, install Ollama:

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Download recommended model
ollama pull nous-hermes2:latest
```

**🔗 Ollama Resources:**
- [Official Download](https://ollama.com/download)
- [Model Library](https://ollama.com/library)
- [GitHub Repository](https://github.com/ollama/ollama)

## ⚙️ Configuration

### 🔑 Environment Variables

Create a `.env` file with the following API keys:

```env
SHODAN_API_KEY=your_shodan_api_key
GEMINI_API_KEY=your_gemini_api_key
NVD_API_KEY=your_nvd_api_key
OLLAMA_API_KEY=your_ollama_api_key
```

### 🗝️ API Key Sources

| Service | Purpose | Registration Link |
|---------|---------|-------------------|
| 🔥 **Shodan** | Internet device scanning | [Shodan Account](https://account.shodan.io/register) |
| ⭐ **Google Gemini** | AI vulnerability analysis | [Gemini API](https://aistudio.google.com/app/apikey) |
| 🛡️ **NVD** | CVE database access (optional) | [NVD API](https://nvd.nist.gov/developers/request-an-api-key) |
| ☁️ **Ollama Cloud** | Cloud-based LLM processing | [Ollama Cloud](https://ollama.com/settings/keys) |

> **💡 Note:** NVD API key is optional but recommended for enhanced rate limits and faster CVE lookups.

## 🎯 Usage

### 🔰 Basic Usage

```bash
# Basic subdomain enumeration
python TwinSanity_Recon.py -d example.com -o results/
```

### 🚀 Advanced Usage

```bash
# Comprehensive scan with AI analysis
python TwinSanity_Recon.py -d target.com -o output/ \
    --use-shodan --run-agent --report-name "security_report.html"
```

### 💥 Full Feature Set

```bash
# Complete reconnaissance with all features
python TwinSanity_Recon.py \
    -d target-domain.com \
    -o "results/" \
    --bruteforce \
    --wordlist "wordlists/subdomains.txt" \
    --use-shodan \
    --run-agent \
    --concurrency 20 \
    --cve-sources all \
    --delay 0.5
```

### 🥷 Stealth Mode

```bash
# Low-profile scanning with proxy rotation
python TwinSanity_Recon.py \
    -d target.com \
    -o "stealth_results/" \
    --proxies-file "proxies.txt" \
    --proxy-rotate \
    --delay 2.0 \
    --concurrency 5
```

## 🛠️ Command Line Options

### 🎯 Target Specification
- `-d, --domain`: Target domain for reconnaissance
- `-i, --input`: Input file containing list of targets
- `--input-as-domains`: Treat each line in input file as separate domain

### 📁 Output Configuration
- `-o, --output`: Output directory for results
- `--report-name`: Custom name for HTML report
- `--save-host-files`: Save individual files for each discovered host

### ⚡ Performance Settings
- `-c, --concurrency`: Number of concurrent threads (default: 20)
- `--timeout`: Request timeout in seconds (default: 15)
- `--delay`: Delay between requests in seconds
- `--bruteforce`: Enable brute force subdomain discovery
- `-w, --wordlist`: Path to custom wordlist file

### 📊 Data Sources
- `--use-shodan`: Enable Shodan integration
- `--cve-sources`: CVE data sources (circl, nvd, shodan, all)
- `--max-cve-workers-*`: Control CVE worker thread counts

### 🔀 Proxy Configuration
- `-P, --proxies-file`: File containing proxy list
- `-PR, --proxy-rotate`: Enable proxy rotation

### 🤖 AI Analysis
- `--run-agent`: Enable AI-powered analysis and reporting
- `--report-only`: Generate report from existing data without scanning

## 📂 Output Structure

```
results/
├── 📋 results_all.json          # Complete scan results
├── 📊 summary.csv               # Summary of findings
├── 💾 cve_cache.json           # CVE database cache
├── 📁 individual_targets/       # Per-target detailed results
├── 📈 REPORTS/
│   ├── 🤖 aggregated_results.json  # AI analysis data
│   └── 📄 security_report.html     # Final HTML report
└── 📝 agent.log                # Analysis log
```

## 🧠 AI Analysis Engine

TwinSanity Recon includes an AI-powered analysis engine with multiple fallback options:

### 🏆 AI Model Hierarchy
1. **⭐ Google Gemini** (Primary)
2. **☁️ Ollama Cloud** (Secondary)
3. **🏠 Ollama Local** (Fallback)

### 🔧 Standalone AI Analysis

```bash
python agent.py \
    --json "scan_results.json" \
    --output "analysis_report.html" \
    --chunk-size 8 \
    --cloud-model "gpt-oss:120b" \
    --local-model "nous-hermes2:latest" \
    --gemini-model "gemini-2.0-flash"
```

## 🎯 Use Cases

### 🏢 Enterprise Security Assessment
```bash
python TwinSanity_Recon.py \
    -d "company.com" \
    -o "enterprise_assessment/" \
    --bruteforce \
    --wordlist "wordlists/enterprise.txt" \
    --use-shodan \
    --run-agent \
    --concurrency 30 \
    --report-name "enterprise_security_report.html"
```

### 🕵️ Stealth Penetration Testing
```bash
python TwinSanity_Recon.py \
    -d "target.com" \
    -o "pentest_results/" \
    --proxies-file "proxy_list.txt" \
    --proxy-rotate \
    --delay 3.0 \
    --concurrency 5 \
    --cve-sources "circl,nvd"
```

### 📊 Bulk Assessment
```bash
python TwinSanity_Recon.py \
    -i "target_list.txt" \
    --input-as-domains \
    -o "bulk_assessment/" \
    --use-shodan \
    --run-agent \
    --concurrency 50
```

## 🔧 Troubleshooting

### ⚠️ Common Issues

**🚦 Rate Limiting**
- Reduce `--concurrency` value
- Increase `--delay` between requests
- Use proxy rotation with `--proxy-rotate`

**❌ CVE Fetch Failures**
- Try different `--cve-sources` options
- Check API key configuration
- Verify network connectivity

**💾 Memory Issues**
- Reduce `--chunk-size` for AI analysis
- Lower concurrency settings
- Process targets in smaller batches

**🔀 Proxy Issues**
- Verify proxy list format (one proxy per line)
- Test proxy connectivity manually
- Check proxy authentication if required

## 🔒 Security Considerations

### ✅ Responsible Use
- Only scan systems you own or have explicit permission to test
- Store API keys securely in environment files
- Implement appropriate delays to avoid overwhelming target systems
- Consider using proxy rotation for sensitive assessments

### 🛡️ Data Protection
- Secure storage of scan results
- Regular cleanup of temporary files
- Proper handling of sensitive discovery data

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **🔥 Shodan.io** - For comprehensive internet device data
- **🔒 Certificate Transparency** - For domain discovery capabilities
- **🛡️ CIRCL & NVD** - For vulnerability database access
- **🤖 Ollama** - For local AI model support

## ⚠️ Disclaimer

**This tool is intended for legitimate security testing and research purposes only.** Users are responsible for ensuring they have proper authorization before scanning any systems. The developers assume no liability for misuse of this tool.

## 💬 Support

For issues, feature requests, or questions, please create an issue on the GitHub repository.
