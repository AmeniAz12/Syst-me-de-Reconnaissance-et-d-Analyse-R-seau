# Cyber Network Scanner

A simplified Nmap-like tool for educational purposes that demonstrates network scanning concepts and cybersecurity techniques.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-Educational%20Only-red.svg)
![Status](https://img.shields.io/badge/status-Production%20Ready-green.svg)

## 🎯 Objective

Create a Python-based network scanning tool that simulates professional security assessment tools while remaining educational and safe. This project demonstrates fundamental cybersecurity concepts including port scanning, service detection, banner grabbing, and network reconnaissance.

## ⚠️ SECURITY DISCLAIMER

**IMPORTANT**: This tool is for **EDUCATIONAL PURPOSES ONLY**. 

- ❌ **DO NOT** scan networks you don't own
- ❌ **DO NOT** scan without explicit written permission
- ❌ **DO NOT** use for malicious activities
- ✅ **ONLY** scan your own networks or authorized test environments

**Unauthorized network scanning is illegal and unethical.** Use responsibly and in compliance with all applicable laws and regulations.

## 🚀 Features

### Core Scanning Capabilities
- **Port Scanning**: TCP connect scan with open/closed/filtered detection
- **Multi-threading**: Configurable concurrent scanning for performance
- **Service Detection**: Automatic service identification based on port numbers
- **Banner Grabbing**: Extract service information and version details
- **Host Discovery**: Identify alive hosts in network segments
- **Subnet Scanning**: Scan entire CIDR networks (e.g., 192.168.1.0/24)

### Advanced Features
- **Stealth Mode**: Configurable delays between scans
- **Flexible Port Ranges**: Single ports, ranges, or common port scanning
- **Multiple Export Formats**: JSON, TXT, CSV with detailed reports
- **Security Recommendations**: Automated vulnerability assessment
- **Progress Tracking**: Real-time scan progress and statistics

## 📋 Requirements

- Python 3.7 or higher
- No external dependencies (uses Python standard library only)
- Administrative privileges may be required for some scans

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/network-scanner.git
   cd network-scanner
   ```

2. **Verify Python version**
   ```bash
   python --version  # Should be 3.7+
   ```

3. **Optional: Install dependencies** (for enhanced features)
   ```bash
   pip install -r requirements.txt
   ```

4. **Run tests to verify installation**
   ```bash
   python -m pytest tests/ -v
   ```

## 🎮 Usage

### Basic Commands

#### Quick Scan (Common Ports)
```bash
python main.py 192.168.1.1
```

#### Port Range Scan
```bash
python main.py 192.168.1.1 -p 80-443
```

#### Full Port Scan
```bash
python main.py 192.168.1.1 --full -t 200
```

#### Host Discovery
```bash
python main.py 192.168.1.0/24 --discover
```

#### Export Results
```bash
python main.py 192.168.1.1 --export json
python main.py 192.168.1.1 --export all
```

### Advanced Options

#### Stealth Scanning
```bash
python main.py 192.168.1.1 -p 1-1000 --stealth 0.5
```

#### Custom Thread Count
```bash
python main.py 192.168.1.1 -p 1-65535 -t 500
```

#### Skip Banner Grabbing
```bash
python main.py 192.168.1.1 --no-banner
```

#### Verbose Output
```bash
python main.py 192.168.1.1 -v
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP or CIDR network | Required |
| `-p, --ports` | Port range (80, 80-443, common, full) | `common` |
| `-t, --threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout in seconds | `3.0` |
| `--stealth` | Delay between scans (seconds) | `0.0` |
| `--fast` | Fast scan (common ports only) | `False` |
| `--full` | Full scan (ports 1-1000) | `False` |
| `--discover` | Host discovery mode | `False` |
| `--export` | Export format (json, txt, csv, all) | None |
| `--no-banner` | Skip banner grabbing | `False` |
| `--verbose` | Verbose output | `False` |
| `--info` | Show network information | `False` |

## 📊 Output Examples

### Console Output
```
CYBER NETWORK SCANNER v1.0.0
============================================================
SECURITY DISCLAIMER: This tool is for educational purposes only.
Only scan networks you own or have explicit permission to test.
Unauthorized scanning is illegal and unethical.
============================================================

[*] Starting scan on 192.168.1.1
[*] Scan type: Fast
[*] Threads: 100, Timeout: 3.0s
============================================================
[*] Performing fast scan on common ports for 192.168.1.1
[+] Port 22/ssh - OPEN
[+] Port 80/http - OPEN
[+] Port 443/https - OPEN

============================================================
SCAN RESULTS FOR: 192.168.1.1
============================================================
Total ports scanned: 20
Open ports: 3
Closed ports: 15
Filtered ports: 2

OPEN PORTS:
----------------------------------------
Port    22/ssh            
Port    80/http            - Apache/2.4.41
Port   443/https           
```

### Exported JSON Report
```json
{
  "scan_metadata": {
    "timestamp": "2024-01-15T10:30:00",
    "target": "192.168.1.1",
    "scanner": "Cyber Network Scanner v1.0",
    "scan_type": "common_ports"
  },
  "scan_results": {
    "target": "192.168.1.1",
    "open_ports": [
      {
        "port": 80,
        "status": "open",
        "service": "http",
        "banner": "Apache/2.4.41"
      }
    ],
    "open_count": 1,
    "total_scanned": 20
  },
  "summary": {
    "success_rate": 95.0,
    "security_recommendations": [
      "Port 80 (HTTP) open but 443 (HTTPS) not detected - Consider implementing HTTPS"
    ]
  }
}
```

## 🔧 Project Structure

```
network-scanner/
│
├── main.py                 # Main CLI interface
├── scanner/                # Core scanner modules
│   ├── __init__.py        # Package initialization
│   ├── port_scanner.py    # Port scanning engine
│   ├── banner.py          # Banner grabbing functionality
│   ├── services.py        # Service detection database
│   ├── utils.py           # Utility functions
│   └── exporter.py        # Result export module
│
├── tests/                  # Test suite
│   └── test_scanner.py    # Comprehensive tests
│
├── requirements.txt        # Dependencies
├── README.md              # This file
├── .gitignore            # Git ignore rules
└── scan_results/         # Exported results (auto-created)
```

## 🔒 Security Concepts Explained

### Port Scanning
**What it is**: Port scanning is the process of checking network ports on a target system to identify which ports are open, closed, or filtered. This helps attackers and security professionals understand what services are running.

**Why attackers use it**: 
- Identify vulnerable services
- Map network topology
- Find entry points for exploitation
- Gather intelligence for targeted attacks

**How defenders detect it**:
- Monitor for unusual connection patterns
- Implement intrusion detection systems (IDS)
- Log and analyze connection attempts
- Use rate limiting and connection throttling

### Service Detection
**What it is**: The process of identifying what specific service is running on an open port, often including version information.

**Security implications**: Knowing the exact service and version helps identify known vulnerabilities and potential exploits.

### Banner Grabbing
**What it is**: Extracting service identification information (banners) from open ports to determine software versions and configurations.

**Information disclosure risk**: Many services reveal too much information in their banners, which can aid attackers in exploitation.

### Reconnaissance
**What it is**: The information gathering phase of cybersecurity assessments where attackers map target networks and systems.

**Defensive measures**: 
- Network segmentation
- Access control lists
- Security monitoring
- Regular vulnerability assessments

## 🧪 Testing

### Run All Tests
```bash
python -m pytest tests/ -v
```

### Run Specific Test Categories
```bash
# Test utility functions
python -m pytest tests/test_scanner.py::TestUtils -v

# Test port scanner
python -m pytest tests/test_scanner.py::TestPortScanner -v

# Test export functionality
python -m pytest tests/test_scanner.py::TestExporter -v
```

### Test Coverage
```bash
python -m pytest tests/ --cov=scanner --cov-report=html
```

## 📈 Performance

### Benchmarks
- **Common ports scan**: ~2-5 seconds
- **Full port scan (1-1000)**: ~30-60 seconds
- **Subnet discovery (/24)**: ~2-10 minutes
- **Memory usage**: <50MB for typical scans

### Optimization Tips
- Increase thread count for faster scanning: `-t 200`
- Use stealth mode to avoid detection: `--stealth 0.5`
- Limit port ranges for targeted scans: `-p 80-443`
- Skip banner grabbing for speed: `--no-banner`

## 🛡️ Security Best Practices

### For Users
1. **Legal Compliance**: Always obtain written permission before scanning
2. **Network Safety**: Test in isolated environments first
3. **Data Protection**: Secure exported scan results
4. **Responsible Disclosure**: Report vulnerabilities responsibly

### For System Administrators
1. **Monitor Scans**: Implement IDS/IPS solutions
2. **Limit Exposure**: Use firewalls and network segmentation
3. **Secure Services**: Disable unnecessary services
4. **Regular Updates**: Keep systems patched and updated

### For Developers
1. **Input Validation**: Validate all user inputs
2. **Error Handling**: Implement proper error handling
3. **Rate Limiting**: Prevent abuse and DoS attacks
4. **Logging**: Maintain audit trails

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Run with administrator privileges
sudo python main.py 192.168.1.1
```

#### Connection Timeouts
```bash
# Increase timeout
python main.py 192.168.1.1 --timeout 10
```

#### Slow Scanning
```bash
# Increase thread count
python main.py 192.168.1.1 -t 500
```

#### No Results
```bash
# Check if host is alive
python main.py 192.168.1.1 --discover
```

### Debug Mode
```bash
# Enable verbose output
python main.py 192.168.1.1 -v --export txt
```

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Code Style
- Follow PEP 8 guidelines
- Use meaningful variable names
- Add comprehensive docstrings
- Write tests for new features

### Submitting Changes
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📚 Educational Resources

### Network Security Fundamentals
- [Nmap Official Guide](https://nmap.org/book/)
- [OWASP Port Scanning](https://owasp.org/www-community/attacks/Port_Scanning)
- [SANS Port Scanning Essentials](https://www.sans.org/white-papers/1208/)

### Python Network Programming
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)
- [Python Concurrency](https://docs.python.org/3/library/concurrent.futures.html)
- [Python IP Address Module](https://docs.python.org/3/library/ipaddress.html)

### Cybersecurity Learning
- [TryHackMe](https://tryhackme.com/)
- [HackTheBox](https://www.hackthebox.com/)
- [Cybrary](https://www.cybrary.it/)

## 📄 License

This project is provided for **EDUCATIONAL PURPOSES ONLY**. 

- ✅ **Allowed**: Learning, research, authorized security testing
- ❌ **Prohibited**: Malicious use, unauthorized scanning, commercial exploitation

## 🙏 Acknowledgments

- **Nmap Project**: Inspiration for port scanning techniques
- **Python Community**: Excellent networking libraries
- **Security Researchers**: For vulnerability databases and methodologies
- **Educational Institutions**: For promoting ethical cybersecurity education

## 📞 Contact

- **Author**: Ameni Azouz
- **Year**: 2026
- **Purpose**: Educational cybersecurity portfolio project
- **Disclaimer**: Use responsibly and ethically

---

**Remember**: With great power comes great responsibility. Use this tool to learn, protect, and secure - never to harm or exploit. 🛡️
