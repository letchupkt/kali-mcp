# MCP Kali Server

**Kali MCP Server** is a lightweight API bridge that connects MCP Clients (e.g: Claude Desktop, [5ire](https://github.com/nanbingxyz/5ire)) to the API server which allows excuting commands on a Linux terminal.

This allows the MCP to run terminal commands like `nmap`, `nxc` or any other tool, interact with web applications using tools like `curl`, `wget`, `gobuster`. 
 And perform **AI-assisted penetration testing**, solving **CTF web challenge** in real time, helping in **solving machines from HTB or THM**.

## My Medium Article on This Tool

[![How MCP is Revolutionizing Offensive Security](https://miro.medium.com/v2/resize:fit:828/format:webp/1*g4h-mIpPEHpq_H63W7Emsg.png)](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

👉 [**How MCP is Revolutionizing Offensive Security**](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

---

## 🔍 Use Case

The goal is to enable AI-driven offensive security testing by:

- Letting the MCP interact with AI endpoints like OpenAI, Claude, DeepSeek, or any other models.
- Exposing an API to execute commands on a Kali machine.
- Using AI to suggest and run terminal commands to solve CTF challenges or automate recon/exploitation tasks.
- Allowing MCP apps to send custom requests (e.g., `curl`, `nmap`, `ffuf`, etc.) and receive structured outputs.

Here are some example for my testing (I used google's AI `gemini 2.0 flash`)

### Example solving my web CTF challenge in RamadanCTF
https://github.com/user-attachments/assets/dc93b71d-9a4a-4ad5-8079-2c26c04e5397

### Trying to solve machine "code" from HTB
https://github.com/user-attachments/assets/3ec06ff8-0bdf-4ad5-be71-2ec490b7ee27


---

## 🚀 Features

- 🧠 **AI Endpoint Integration**: Connect your kali to any MCP of your liking such as claude desktop or 5ier.
- 🖥️ **Command Execution API**: Exposes a controlled API to execute terminal commands on your Kali Linux machine.
- 🕸️ **Web Challenge Support**: AI can interact with websites and APIs, capture flags via `curl` and any other tool AI the needs.
- 🔐 **Designed for Offensive Security Professionals**: Ideal for red teamers, bug bounty hunters, or CTF players automating common tasks.
- 🎯 **Comprehensive Bug Hunting Arsenal**: Includes 25+ specialized tools for reconnaissance, vulnerability scanning, and exploitation.

### 🛠️ Integrated Tools

**Reconnaissance & Subdomain Enumeration:**
- `subfinder` - Fast subdomain discovery
- `sublist3r` - Subdomain enumeration using OSINT
- `amass` - Network mapping and attack surface discovery
- `assetfinder` - Find domains and subdomains

**Subdomain Takeover Detection:**
- `subzy` - Subdomain takeover vulnerability checker
- `subjack` - Subdomain takeover tool

**HTTP Analysis & Probing:**
- `httpx` - Fast HTTP toolkit for probing
- `katana` - Web crawler for spidering websites
- `gospider` - Fast web spider

**Content & Directory Discovery:**
- `gobuster` - Directory/file & DNS busting tool
- `dirb` - Web content scanner
- `ffuf` - Fast web fuzzer
- `feroxbuster` - Fast content discovery tool
- `dirsearch` - Web path scanner

**Vulnerability Scanning:**
- `nuclei` - Vulnerability scanner with templates
- `nikto` - Web server scanner
- `wpscan` - WordPress vulnerability scanner
- `dalfox` - XSS scanner and parameter analysis

**Parameter & URL Discovery:**
- `arjun` - HTTP parameter discovery
- `paramspider` - Parameter mining from web archives
- `waybackurls` - Fetch URLs from Wayback Machine
- `gau` - Get All URLs from multiple sources
- `gf` - Grep-like tool for filtering with patterns

**Port Scanning:**
- `nmap` - Network discovery and security auditing
- `masscan` - High-speed port scanner
- `rustscan` - Fast port scanner

**Password & Authentication:**
- `hydra` - Password cracking tool
- `john` - John the Ripper password cracker
- `sqlmap` - SQL injection detection and exploitation

**Network Enumeration:**
- `enum4linux` - Windows/Samba enumeration tool

---

## 🛠️ Installation

### On your Linux Machine (Will act as MCP Server)
```bash
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server

# Install all required tools (run this first!)
chmod +x install_tools.sh
sudo ./install_tools.sh

# Start the server
python3 kali_server.py
```

### On your MCP Client (You can run on Windows or Linux)
- You will want to run `python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000`

#### Configuration for claude desktop:
edit (C:\Users\USERNAME\AppData\Roaming\Claude\claude_desktop_config.json)

```json
{
    "mcpServers": {
        "kali_mcp": {
            "command": "python3",
            "args": [
                "/absolute/path/to/mcp_server.py",
                "--server",
                "http://LINUX_IP:5000/"
            ]
        }
    }
}
```

#### Configuration for [5ire](https://github.com/nanbingxyz/5ire) Desktop Application:
- Simply add an MCP with the command `python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000` and it will automatically generate the needed configuration files.

## 🔮 Other Possibilities

There are more possibilites than described since the AI model can now execute commands on the terminal. Here are some example:

- Memory forensics using Volatility
  - Automating memory analysis tasks such as process enumeration, DLL injection checks, and registry extraction from memory dumps.

- Disk forensics with SleuthKit
  - Automating analysis from disk images, timeline generation, file carving, and hash comparisons.


## ⚠️ Disclaimer:
This project is intended solely for educational and ethical testing purposes. Any misuse of the information or tools provided — including unauthorized access, exploitation, or malicious activity — is strictly prohibited.
The author assumes no responsibility for misuse.
