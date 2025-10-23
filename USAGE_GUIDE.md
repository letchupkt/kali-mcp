# MCP Kali Server - Usage Guide

This guide provides examples of how to use the enhanced MCP Kali Server with AI for bug hunting and penetration testing.

## 🎯 Bug Hunting Workflow Examples

### 1. Subdomain Enumeration Workflow

```
AI Prompt: "Perform comprehensive subdomain enumeration for example.com"

The AI will execute:
1. subfinder_scan(domain="example.com")
2. sublister_scan(domain="example.com") 
3. amass_scan(domain="example.com", mode="enum")
4. assetfinder_scan(domain="example.com")
```

### 2. Subdomain Takeover Detection

```
AI Prompt: "Check for subdomain takeover vulnerabilities on the discovered subdomains"

The AI will execute:
1. subzy_scan(target="subdomains.txt")
2. subjack_scan(target="subdomains.txt")
```

### 3. HTTP Service Discovery

```
AI Prompt: "Probe all discovered subdomains for HTTP services and gather information"

The AI will execute:
1. httpx_scan(target="subdomains.txt", additional_args="-title -tech-detect -status-code")
2. nuclei_scan(target="live_urls.txt", templates="http")
```

### 4. Content Discovery

```
AI Prompt: "Perform directory brute-forcing on https://target.com"

The AI will execute:
1. gobuster_scan(url="https://target.com", mode="dir")
2. ffuf_scan(url="https://target.com/FUZZ", wordlist="/usr/share/wordlists/dirb/common.txt")
3. feroxbuster_scan(url="https://target.com")
```

### 5. Parameter Discovery

```
AI Prompt: "Find parameters for target.com from web archives and test them"

The AI will execute:
1. waybackurls_scan(domain="target.com")
2. gau_scan(domain="target.com")
3. paramspider_scan(domain="target.com")
4. arjun_scan(url="https://target.com/endpoint")
```

### 6. Vulnerability Scanning

```
AI Prompt: "Scan https://target.com for common vulnerabilities"

The AI will execute:
1. nuclei_scan(target="https://target.com")
2. nikto_scan(target="https://target.com")
3. dalfox_scan(url="https://target.com/search?q=test")
```

## 🔧 Advanced Usage Examples

### Port Scanning Workflow
```
AI Prompt: "Perform comprehensive port scanning on 192.168.1.100"

1. masscan_scan(target="192.168.1.100", ports="1-65535")
2. nmap_scan(target="192.168.1.100", scan_type="-sCV", ports="discovered_ports")
3. rustscan_scan(target="192.168.1.100")
```

### Web Application Testing
```
AI Prompt: "Test the web application at https://webapp.com for common vulnerabilities"

1. katana_crawl(url="https://webapp.com")
2. gospider_crawl(url="https://webapp.com")
3. nuclei_scan(target="https://webapp.com", templates="web")
4. sqlmap_scan(url="https://webapp.com/login", data="username=admin&password=test")
```

### URL Pattern Analysis
```
AI Prompt: "Analyze URLs for potential XSS and SQL injection points"

1. waybackurls_scan(domain="target.com")
2. gf_patterns(input_data="urls.txt", pattern="xss")
3. gf_patterns(input_data="urls.txt", pattern="sqli")
4. dalfox_scan(url="filtered_xss_urls.txt")
```

## 🎨 Creative AI Prompts

### Automated Reconnaissance
```
"Perform a complete reconnaissance on example.com including:
- Subdomain enumeration using multiple tools
- Check for subdomain takeovers
- Probe for live HTTP services
- Discover hidden directories and files
- Scan for common vulnerabilities
- Generate a summary report"
```

### CTF Web Challenge Solver
```
"I have a CTF web challenge at http://ctf.example.com:8080. 
Help me find the flag by:
1. Crawling the application
2. Finding hidden directories
3. Looking for parameters
4. Testing for common web vulnerabilities
5. Analyzing the source code for clues"
```

### Bug Bounty Automation
```
"I'm testing target.com for a bug bounty program. 
Perform a comprehensive security assessment:
1. Map the attack surface
2. Find all subdomains and services
3. Discover hidden endpoints
4. Test for OWASP Top 10 vulnerabilities
5. Look for subdomain takeovers
6. Check for exposed sensitive files"
```

## 📋 Tool-Specific Examples

### Nuclei Templates
```python
# Scan with specific templates
nuclei_scan(target="https://target.com", templates="cves,exposures")

# Scan with custom severity
nuclei_scan(target="https://target.com", additional_args="-severity critical,high")
```

### Ffuf Advanced Usage
```python
# Directory fuzzing
ffuf_scan(url="https://target.com/FUZZ", wordlist="/usr/share/wordlists/dirb/big.txt")

# Virtual host discovery
ffuf_scan(url="https://target.com", additional_args="-H 'Host: FUZZ.target.com' -w /path/to/subdomains.txt")

# Parameter fuzzing
ffuf_scan(url="https://target.com/search?FUZZ=test", wordlist="/path/to/parameters.txt")
```

### Httpx Advanced Probing
```python
# Technology detection
httpx_scan(target="subdomains.txt", additional_args="-tech-detect -title -status-code")

# Screenshot capture
httpx_scan(target="urls.txt", additional_args="-screenshot -store-response-dir output/")
```

## 🚨 Security Considerations

1. **Authorization**: Only test systems you own or have explicit permission to test
2. **Rate Limiting**: Use appropriate delays and rate limiting to avoid overwhelming targets
3. **Logging**: All activities are logged for accountability
4. **Scope**: Stay within the defined scope of your testing engagement

## 🔍 Troubleshooting

### Common Issues

1. **Tool Not Found**: Run the installation script to ensure all tools are installed
2. **Permission Denied**: Some tools may require elevated privileges
3. **Network Issues**: Check firewall settings and network connectivity
4. **Rate Limiting**: Reduce scan speed if encountering rate limits

### Checking Tool Installation
```python
# Use the health check to verify tool installation
server_health()
```

This will show which tools are installed and available for use.