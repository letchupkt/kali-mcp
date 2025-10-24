#  MCP Kali Server - Bug Hunting Arsenal

**Author: LAKSHMIKANTHAN K (letchupkt)**  

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#️-installation)
- [Usage Methods](#-usage-methods)
- [Bug Hunting Workflows](#-bug-hunting-workflows)
- [Tool Categories](#️-tool-categories)
- [Advanced Examples](#-advanced-examples)
- [Troubleshooting](#-troubleshooting)
- [Credits & License](#-credits--license)

---

## 🌟 Overview

** Kali MCP Server** is a revolutionary AI-powered cybersecurity platform that bridges the gap between artificial intelligence and penetration testing. This comprehensive system provides direct integration with 25+ professional security tools through multiple AI interfaces.

**🔗 Repository**: https://github.com/letchupkt/kali-mcp.git

### 🎯 What Makes This Special?

- **AI-Driven Security Testing**: Let AI models intelligently chain security tools for comprehensive assessments
- **Multiple AI Interfaces**: Support for Claude Desktop, 5ire, and direct Ollama integration
- **Professional Arsenal**: 25+ industry-standard tools for bug hunting and penetration testing
- **Real-time Execution**: Direct command execution with formatted results and analysis
- **Intelligent Workflows**: AI automatically suggests and executes appropriate tool combinations

### 🔍 Use Cases

- **Bug Bounty Hunting**: Automated reconnaissance and vulnerability discovery
- **Penetration Testing**: AI-assisted security assessments and exploitation
- **CTF Challenges**: Real-time problem solving with AI guidance
- **Red Team Operations**: Streamlined attack surface mapping and exploitation
- **Security Research**: Rapid prototyping and testing of security concepts

---

## 🚀 Features

### 🧠 AI Integration Capabilities
- **Multi-Platform Support**: Claude Desktop, 5ire, Ollama, and custom MCP clients
- **Natural Language Processing**: Convert plain English to security tool execution
- **Intelligent Parameter Extraction**: Automatically parse targets, options, and configurations
- **Contextual Tool Selection**: AI suggests appropriate tools based on objectives
- **Result Analysis**: AI interprets and explains tool outputs

### 🛡️ Security Arsenal
- **25+ Professional Tools**: Industry-standard security testing utilities
- **Real-time Execution**: Direct command execution with live output streaming
- **Comprehensive Coverage**: From reconnaissance to exploitation
- **Automated Workflows**: Chain multiple tools for complete assessments
- **Custom Tool Integration**: Easy addition of new security tools

### 🔧 Technical Features
- **RESTful API**: Clean, documented API for all tool interactions
- **Health Monitoring**: Real-time tool availability and status checking
- **Error Handling**: Graceful handling of timeouts and failures
- **Logging**: Comprehensive logging for audit and debugging
- **Cross-Platform**: Works on Linux, Windows, and macOS clients

---

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI Client     │    │   MCP Server    │    │  Kali Server    │
│                 │    │                 │    │                 │
│ • Claude        │◄──►│ • Tool Mapping  │◄──►│ • Tool Execution│
│ • 5ire          │    │ • Parameter     │    │ • Result        │
│ • Ollama        │    │   Processing    │    │   Processing    │
│ • Custom        │    │ • Result        │    │ • Health Check  │
│                 │    │   Formatting    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Component Breakdown

1. **AI Client Layer**: Interfaces with various AI models and platforms
2. **MCP Server Layer**: Translates AI requests to tool-specific API calls
3. **Kali Server Layer**: Executes security tools and returns formatted results

---

## 🛠️ Installation

### Prerequisites

- **Linux Machine** (Kali Linux recommended)
- **Python 3.8+**
- **Git**
- **Internet Connection** (for tool downloads)

### Step 1: Clone Repository

```bash
git clone https://github.com/letchupkt/kali-mcp.git
cd kali-mcp
```

### Step 2: Install Security Tools

```bash
# Make installation script executable
chmod +x install_tools.sh

# Run comprehensive tool installation (takes 15-30 minutes)
sudo ./install_tools.sh
```

**What gets installed:**
- **Go Environment**: Required for modern security tools
- **Subdomain Tools**: subfinder, sublister, amass, assetfinder
- **HTTP Tools**: httpx, katana, gospider
- **Content Discovery**: ffuf, feroxbuster, dirsearch
- **Vulnerability Scanners**: nuclei, nikto, wpscan, dalfox
- **Port Scanners**: masscan, rustscan
- **And many more...**

### Step 3: Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### Step 4: Start the Kali Server

```bash
python3 kali_server.py
```

**Expected Output:**
```
======================================================================
🚀 ENHANCED KALI LINUX API SERVER - BUG HUNTING ARSENAL
👨‍💻 Author: LAKSHMIKANTHAN K (letchupkt)
© 2025 LAKSHMIKANTHAN K (letchupkt)
======================================================================
INFO:__main__:Starting Enhanced Kali Linux Tools API Server on port 5000
INFO:__main__:25+ Security tools ready for bug hunting and penetration testing
======================================================================
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.1.100:5000
```

---

## 🎮 Usage Methods

### Method 1: Claude Desktop Integration

**Setup:**
1. Edit Claude Desktop configuration:
   ```bash
   # Windows
   C:\Users\USERNAME\AppData\Roaming\Claude\claude_desktop_config.json
   
   # macOS
   ~/Library/Application Support/Claude/claude_desktop_config.json
   ```

2. Add MCP server configuration:
   ```json
   {
       "mcpServers": {
           "enhanced_kali_mcp": {
               "command": "python3",
               "args": [
                   "/absolute/path/to/mcp_server.py",
                   "--server",
                   "http://KALI_IP:5000"
               ]
           }
       }
   }
   ```

3. Restart Claude Desktop

**Usage Example:**
```
You: "Perform comprehensive subdomain enumeration for example.com"

Claude: I'll help you enumerate subdomains for example.com using multiple tools.

[Executes subfinder_scan, sublister_scan, amass_scan, assetfinder_scan]

Results show 47 unique subdomains discovered across all tools...
```

### Method 2: 5ire Desktop Integration

**Setup:**
1. Open 5ire Desktop
2. Navigate to MCP Settings
3. Add new MCP server:
   ```
   Command: python3 /absolute/path/to/mcp_server.py http://KALI_IP:5000
   ```

### Method 3: Direct Ollama Integration (Recommended)

**Setup:**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a capable model
ollama pull llama3.2
# or for better performance:
ollama pull codellama:13b

# Start the  Ollama client
python3 ollama_client.py --kali-server http://KALI_IP:5000 --model llama3.2
```

**Interactive Session:**
```
======================================================================
🚀 ENHANCED KALI MCP SERVER - BUG HUNTING ARSENAL
👨‍💻 Author: LAKSHMIKANTHAN K (letchupkt)
© 2025 LAKSHMIKANTHAN K (letchupkt)
======================================================================
🤖 Model: llama3.2
🔗 Kali Server: http://192.168.1.100:5000
======================================================================
🎯 Enhanced Bug Hunting Arsenal Ready!
📋 Type 'help' to see available tools and examples
🔧 Type 'tools' to list all available security tools
❌ Type 'exit' or 'quit' to end the session
======================================================================

🎯 You: Enumerate subdomains for example.com and check for takeovers

🔧 Executing detected tools...

⚡ Running subfinder with parameters: {'domain': 'example.com'}
🔧 **SUBFINDER Results**
==================================================
📋 **Output:**
```
admin.example.com
api.example.com
blog.example.com
dev.example.com
mail.example.com
...
```

⚡ Running subzy with parameters: {'target': 'example.com'}
🔧 **SUBZY Results**
==================================================
📋 **Output:**
```
[VULNERABLE] dev.example.com - GitHub Pages takeover possible
[SAFE] admin.example.com - No takeover detected
...
```

🤖 Assistant: I've discovered 23 subdomains for example.com and found 1 potential subdomain takeover vulnerability on dev.example.com pointing to GitHub Pages. Here's what you should do next:

1. Verify the GitHub Pages takeover by checking if the repository exists
2. Probe the live subdomains with httpx for technology detection
3. Run nuclei scans on the active services

Would you like me to continue with these next steps?
```

---

## 🎯 Bug Hunting Workflows

### Workflow 1: Complete Reconnaissance

**AI Prompt:**
```
"Perform complete reconnaissance on target.com including subdomain enumeration, 
HTTP probing, content discovery, and vulnerability scanning"
```

**Execution Flow:**
1. **Subdomain Discovery**
   - `subfinder -d target.com`
   - `sublister -d target.com`
   - `amass enum -d target.com`
   - `assetfinder target.com`

2. **HTTP Service Probing**
   - `httpx -l subdomains.txt -title -tech-detect -status-code`
   - `katana -u target.com -depth 3`

3. **Content Discovery**
   - `ffuf -u https://target.com/FUZZ -w wordlist.txt`
   - `feroxbuster -u https://target.com`
   - `gobuster dir -u https://target.com`

4. **Vulnerability Scanning**
   - `nuclei -l live_urls.txt -t cves,exposures`
   - `nikto -h target.com`

### Workflow 2: Subdomain Takeover Hunt

**AI Prompt:**
```
"Check target.com for subdomain takeover vulnerabilities"
```

**Execution Flow:**
1. **Subdomain Enumeration**
   - Multiple subdomain discovery tools
   - Consolidate unique results

2. **Takeover Detection**
   - `subzy run --targets subdomains.txt`
   - `subjack -w subdomains.txt -t 100 -timeout 30 -o results.txt`

3. **Verification**
   - Manual verification of flagged subdomains
   - Service identification and exploitation assessment

### Workflow 3: Web Application Security Assessment

**AI Prompt:**
```
"Test https://webapp.com for web application vulnerabilities"
```

**Execution Flow:**
1. **Crawling & Spidering**
   - `katana -u https://webapp.com`
   - `gospider -s https://webapp.com`

2. **Parameter Discovery**
   - `arjun -u https://webapp.com`
   - `paramspider -d webapp.com`

3. **Vulnerability Testing**
   - `dalfox url https://webapp.com` (XSS)
   - `sqlmap -u https://webapp.com/page?id=1` (SQLi)
   - `nuclei -u https://webapp.com -t web-vulnerabilities`

---

## 🛠️ Tool Categories

### 🔍 Reconnaissance & Subdomain Enumeration

#### Subfinder
- **Purpose**: Fast subdomain discovery using passive sources
- **Usage**: `subfinder -d example.com`
- **Features**: Multiple data sources, fast execution, JSON output

#### Sublister (Sublist3r)
- **Purpose**: Subdomain enumeration using OSINT techniques
- **Usage**: `sublist3r -d example.com`
- **Features**: Search engine enumeration, brute force capability

#### OWASP Amass
- **Purpose**: Network mapping and attack surface discovery
- **Usage**: `amass enum -d example.com`
- **Features**: Active/passive enumeration, DNS resolution

#### Assetfinder
- **Purpose**: Find domains and subdomains related to a given domain
- **Usage**: `assetfinder example.com`
- **Features**: Simple, fast, effective for basic enumeration

### 🎯 Subdomain Takeover Detection

#### Subzy
- **Purpose**: Check for subdomain takeover vulnerabilities
- **Usage**: `subzy run --targets subdomains.txt`
- **Features**: Multiple service detection, verification capabilities

#### Subjack
- **Purpose**: Subdomain takeover vulnerability scanner
- **Usage**: `subjack -w subdomains.txt`
- **Features**: Fast scanning, custom fingerprints

### 🌐 HTTP Analysis & Probing

#### Httpx
- **Purpose**: Fast HTTP toolkit for probing services
- **Usage**: `httpx -l subdomains.txt -title -tech-detect`
- **Features**: Technology detection, screenshot capture, custom headers

#### Katana
- **Purpose**: Next-generation web crawler
- **Usage**: `katana -u https://example.com -depth 3`
- **Features**: JavaScript parsing, deep crawling, URL extraction

#### GoSpider
- **Purpose**: Fast web spider for crawling websites
- **Usage**: `gospider -s https://example.com`
- **Features**: Concurrent crawling, link extraction

### 📁 Content & Directory Discovery

#### Ffuf
- **Purpose**: Fast web fuzzer (Fuzz Faster U Fool)
- **Usage**: `ffuf -u https://example.com/FUZZ -w wordlist.txt`
- **Features**: Multiple fuzzing modes, filtering options, high performance

#### Feroxbuster
- **Purpose**: Fast content discovery tool
- **Usage**: `feroxbuster -u https://example.com`
- **Features**: Recursive scanning, wildcard detection

#### Dirsearch
- **Purpose**: Web path scanner
- **Usage**: `dirsearch -u https://example.com -e php,html,js`
- **Features**: Multiple extensions, threading, reporting

### 🛡️ Vulnerability Scanning

#### Nuclei
- **Purpose**: Fast vulnerability scanner with community templates
- **Usage**: `nuclei -u https://example.com -t cves,exposures`
- **Features**: Template-based scanning, community templates, high accuracy

#### Nikto
- **Purpose**: Web server scanner
- **Usage**: `nikto -h https://example.com`
- **Features**: Comprehensive checks, plugin system

#### DalFox
- **Purpose**: XSS scanner and parameter analysis tool
- **Usage**: `dalfox url https://example.com/search?q=test`
- **Features**: Advanced XSS detection, parameter analysis

### 🔗 Parameter & URL Discovery

#### Arjun
- **Purpose**: HTTP parameter discovery suite
- **Usage**: `arjun -u https://example.com`
- **Features**: Multiple methods, custom wordlists

#### ParamSpider
- **Purpose**: Parameter mining from web archives
- **Usage**: `paramspider -d example.com`
- **Features**: Archive mining, parameter extraction

#### Waybackurls
- **Purpose**: Fetch URLs from Wayback Machine
- **Usage**: `echo "example.com" | waybackurls`
- **Features**: Historical URL discovery

#### Gau (Get All URLs)
- **Purpose**: Get All URLs from multiple sources
- **Usage**: `echo "example.com" | gau`
- **Features**: Multiple data sources, comprehensive coverage

### 🔍 Port Scanning & Network Discovery

#### Nmap
- **Purpose**: Network discovery and security auditing
- **Usage**: `nmap -sCV target.com`
- **Features**: Service detection, OS fingerprinting, script engine

#### Masscan
- **Purpose**: High-speed port scanner
- **Usage**: `masscan 192.168.1.0/24 -p1-65535 --rate=1000`
- **Features**: Extremely fast, large-scale scanning

#### RustScan
- **Purpose**: Modern fast port scanner
- **Usage**: `rustscan -a 192.168.1.1`
- **Features**: Fast scanning, Nmap integration

---

## 🎨 Advanced Examples

### Example 1: Complete Bug Bounty Reconnaissance

**Scenario**: You're testing `target.com` for a bug bounty program.

**AI Conversation:**
```
You: "I'm starting a bug bounty assessment on target.com. Perform comprehensive reconnaissance including subdomain enumeration, HTTP probing, content discovery, and vulnerability scanning. Focus on finding high-impact vulnerabilities."

AI: I'll perform a comprehensive bug bounty reconnaissance on target.com. Let me start with subdomain enumeration using multiple tools for maximum coverage.

[Executes subfinder, sublister, amass, assetfinder]

Found 127 unique subdomains. Now probing for live HTTP services...

[Executes httpx with technology detection]

Discovered 89 live HTTP services. Interesting findings:
- admin.target.com (Apache 2.4.41)
- api.target.com (Nginx 1.18.0) 
- dev.target.com (GitHub Pages - potential takeover!)

Let me check for subdomain takeovers...

[Executes subzy and subjack]

🚨 CRITICAL: dev.target.com is vulnerable to subdomain takeover via GitHub Pages!

Now performing content discovery on high-value targets...

[Executes ffuf, feroxbuster on key subdomains]

Found several interesting endpoints:
- admin.target.com/backup/ (403 Forbidden)
- api.target.com/v1/users (200 OK)
- api.target.com/swagger.json (200 OK)

Running vulnerability scans...

[Executes nuclei with comprehensive templates]

🚨 HIGH: SQL injection detected on api.target.com/v1/search
🚨 MEDIUM: XSS vulnerability on blog.target.com/search
🚨 LOW: Information disclosure via server headers

Summary of findings:
1. Subdomain takeover: dev.target.com
2. SQL injection: api.target.com/v1/search  
3. XSS: blog.target.com/search
4. Exposed API documentation: api.target.com/swagger.json
5. Backup directory: admin.target.com/backup/

Recommended next steps:
1. Exploit the subdomain takeover for maximum impact
2. Test the SQL injection for data extraction
3. Verify XSS exploitability
4. Analyze API documentation for additional endpoints
```

### Example 2: CTF Web Challenge Solution

**Scenario**: You have a CTF web challenge at `http://ctf.example.com:8080`

**AI Conversation:**
```
You: "I have a CTF web challenge at http://ctf.example.com:8080. Help me find the flag by analyzing the application, finding hidden content, and testing for vulnerabilities."

AI: I'll help you solve this CTF challenge systematically. Let me start by crawling the application to understand its structure.

[Executes katana and gospider]

Application structure discovered:
- /login (login form)
- /register (registration form)  
- /dashboard (requires authentication)
- /admin (403 Forbidden)
- /robots.txt (found!)

Let me check robots.txt and perform content discovery...

[Executes httpx to fetch robots.txt, then ffuf for hidden directories]

robots.txt reveals:
- /secret_backup/
- /dev_notes.txt

Content discovery found:
- /.git/ (exposed Git repository!)
- /backup.sql (database backup)
- /config.php.bak (backup config file)

🚨 CRITICAL: Exposed .git repository detected!

Let me extract the Git repository and analyze the source code...

[Executes git dumper equivalent via custom command]

Source code analysis reveals:
- SQL injection in login form (username parameter)
- Hardcoded admin credentials in config.php.bak
- Flag location: /admin/flag.txt

Let me test the SQL injection...

[Executes sqlmap]

SQL injection confirmed! Database extracted:
- Admin username: admin
- Admin password hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 (SHA1 of 'password')

Now accessing admin panel with credentials admin:password...

[Executes httpx with authentication]

Successfully accessed /admin/flag.txt!

🏁 FLAG FOUND: CTF{g1t_r3p0s_4r3_d4ng3r0us_wh3n_3xp0s3d}

Solution summary:
1. Crawled application structure
2. Found exposed .git repository via content discovery
3. Extracted source code revealing vulnerabilities
4. Exploited SQL injection to extract credentials
5. Used hardcoded credentials to access admin panel
6. Retrieved flag from /admin/flag.txt
```

---

## 🔧 Troubleshooting

### Common Installation Issues

#### Tool Not Found Errors
```bash
# Check if tool is installed
which subfinder
which nuclei

# Verify PATH includes Go binaries
echo $PATH | grep go

# Manually add to PATH
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Make permanent
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### Permission Denied Errors
```bash
# Fix script permissions
chmod +x install_tools.sh

# Fix tool permissions
sudo chmod +x /usr/local/bin/subfinder
sudo chmod +x /usr/local/bin/nuclei

# Check tool ownership
ls -la /usr/local/bin/ | grep subfinder
```

### Common Runtime Issues

#### Tool Execution Timeouts
```python
# Default timeout in kali_server.py
COMMAND_TIMEOUT = 600  # 10 minutes default
# Long-running tools (nuclei, amass, masscan, nmap, ffuf, feroxbuster) get 15 minutes

# Or use additional_args for tool-specific timeouts
nuclei_scan(target="example.com", additional_args="--timeout 120")
```

#### Rate Limiting Issues
```bash
# Add delays to avoid rate limiting
subfinder_scan(domain="example.com", additional_args="--rate-limit 10")
httpx_scan(target="urls.txt", additional_args="--rate-limit 100")
```

### Health Check and Diagnostics

#### Server Health Check
```python
# Use the health endpoint
server_health()

# Expected response:
{
    "status": "healthy",
    "message": "Kali Linux Tools API Server is running",
    "tools_status": {
        "nmap": true,
        "subfinder": true,
        "nuclei": false,  # Not installed
        ...
    },
    "all_essential_tools_available": false
}
```

---

## 📚 API Reference

### Health Endpoint
```http
GET /health
```

**Response:**
```json
{
    "status": "healthy",
    "message": "Kali Linux Tools API Server is running",
    "tools_status": {
        "nmap": true,
        "subfinder": true,
        "nuclei": true
    },
    "all_essential_tools_available": true
}
```

### Tool Execution Endpoints

#### Subdomain Enumeration
```http
POST /api/tools/subfinder
Content-Type: application/json

{
    "domain": "example.com",
    "additional_args": "-sources censys,shodan"
}
```

#### Vulnerability Scanning
```http
POST /api/tools/nuclei
Content-Type: application/json

{
    "target": "https://example.com",
    "templates": "cves,exposures",
    "additional_args": "-severity critical,high"
}
```

---

## 📝 Credits & License

### Author Information
**Author:** LAKSHMIKANTHAN K (letchupkt)  
**Enhanced Version:** Bug Hunting Arsenal Integration  
**© 2025 LAKSHMIKANTHAN K (letchupkt)**

### Acknowledgments
- **Original MCP Framework**: Anthropic and the MCP community
- **Security Tools**: Individual tool developers and maintainers
- **Inspiration**: Various open-source security projects and researchers
- **Testing**: Bug bounty community and ethical hackers

### License
This project is released under the MIT License. See LICENSE file for details.

---

## ⚠️ Legal Disclaimer

### Important Notice
This project is intended **solely for educational and ethical testing purposes**. Any misuse of the information or tools provided — including unauthorized access, exploitation, or malicious activity — is **strictly prohibited**.

### Responsible Use
- ✅ **Only test systems you own** or have explicit written permission to test
- ✅ **Respect scope limitations** defined in testing agreements
- ✅ **Follow responsible disclosure** for any vulnerabilities found
- ✅ **Comply with local laws** and regulations regarding security testing
- ✅ **Use appropriate rate limiting** to avoid service disruption

### Liability
The author assumes **no responsibility** for misuse of this software. Users are solely responsible for ensuring their activities comply with applicable laws and regulations.

**Always ensure you have proper authorization before testing any systems.**

---

**Happy Bug Hunting! 🎯**

*Remember: With great power comes great responsibility. Use these tools ethically and legally.*

**© 2025 LAKSHMIKANTHAN K (letchupkt) -  MCP Kali Server**
---


## 📞 Support and Contact

### 🔗 GitHub Repository
- **Main Repository**: https://github.com/letchupkt/kali-mcp
- **Issues & Bug Reports**: https://github.com/letchupkt/kali-mcp/issues
- **Feature Requests**: https://github.com/letchupkt/kali-mcp/issues/new
- **Discussions**: https://github.com/letchupkt/kali-mcp/discussions

### 🤝 Getting Help
- **GitHub Issues**: Report bugs or request features at https://github.com/letchupkt/kali-mcp/issues
- **Documentation**: Check this comprehensive README and inline code comments
- **Community**: Join security-focused Discord servers and forums
- **Email**: Contact LAKSHMIKANTHAN K (letchupkt) for direct support

### 🚀 Feature Requests
Have ideas for new tools or improvements? We'd love to hear them!
1. Check existing issues: https://github.com/letchupkt/kali-mcp/issues
2. Provide detailed use cases and requirements
3. Consider contributing the implementation

### 🤝 Contributing
Contributions are welcome! Please:
1. **Fork the repository**: https://github.com/letchupkt/kali-mcp
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Submit a pull request** with detailed description
6. **Ensure all tests pass** and tools are properly integrated

### 🐛 Security Issues
Found a security vulnerability in the tool itself?
- **DO NOT** open a public issue
- Contact LAKSHMIKANTHAN K (letchupkt) directly for responsible disclosure
- Provide detailed reproduction steps and impact assessment

### 📊 Project Stats
- **25+ Security Tools** integrated
- **3 AI Interface Methods** supported
- **Cross-Platform** compatibility
- **Active Development** and maintenance

---

## 🌟 Star History

If you find this project useful, please consider giving it a star on GitHub!

[![Star History Chart](https://api.star-history.com/svg?repos=letchupkt/kali-mcp&type=Date)](https://star-history.com/#letchupkt/kali-mcp&Date)

---

## 🔄 Updates and Roadmap

### Recent Updates
- ✅ Enhanced MCP server with 25+ security tools
- ✅ Direct Ollama integration
- ✅ Comprehensive documentation
- ✅ Automated installation script
- ✅ Advanced workflow examples

### Upcoming Features
- 🔄 Web-based dashboard interface
- 🔄 Docker containerization
- 🔄 Additional AI model integrations
- 🔄 Real-time collaboration features
- 🔄 Advanced reporting and analytics

### Version History
- **v2.0.0** - Enhanced Bug Hunting Arsenal (Current)
- **v1.0.0** - Initial MCP Kali Server release

---

**🎯 Happy Bug Hunting!**

*Remember: With great power comes great responsibility. Use these tools ethically and legally.*

**🔗 Repository**: https://github.com/letchupkt/kali-mcp  
**👨‍💻 Author**: LAKSHMIKANTHAN K (letchupkt)  
