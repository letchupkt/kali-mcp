# MCP Kali Server

**Kali MCP Server** — by **Lakshmikanthan (Letchu)** — GitHub: `letchupkt`
Lightweight API bridge that connects MCP Clients (examples: Claude Desktop, [5ire](https://github.com/nanbingxyz/5ire)) to a Kali Linux terminal. It enables MCPs to execute terminal commands, interact with web applications, and run AI-assisted offensive security workflows.

---

## 🔍 Overview

Kali MCP Server exposes a controlled API that allows authorized MCP clients to remotely run commands (e.g. `nmap`, `curl`, `gobuster`) and receive structured output. The project is designed to accelerate automated penetration testing, CTF solving, and AI-driven reconnaissance by combining Kali tooling with local or remote LLMs.

Use-cases include:

* AI-assisted penetration testing and bug hunting.
* Solving web CTF challenges in real time (useful for HTB/THM/CTF practice).
* Orchestrating recon/exploit chains through a single MCP interface.

---

## 🚀 Key Features

* 🧠 **AI Endpoint Integration** — connect the Kali host to any MCP or LLM endpoint (OpenAI, Claude, DeepSeek, or other local models).
* 🖥️ **Command Execution API** — run terminal tools remotely and get structured responses.
* 🕸️ **Web Challenge & CTF Support** — AI agents can interact with target web apps (via `curl`, `wget`, fuzzers) and attempt to capture flags or findings.
* 🔐 **Built for Offensive Security Practitioners** — red teamers, bug bounty hunters and CTF players in mind.
* 🎯 **Large Toolset** — ships with (or can install) 25+ specialized tools for reconnaissance, scanning, and exploitation.

---

## 🛠️ Integrated Tools

**Recon & Subdomain Discovery:** `subfinder`, `sublist3r`, `amass`, `assetfinder`
**Subdomain Takeover:** `subzy`, `subjack`
**HTTP Probing & Crawling:** `httpx`, `katana`, `gospider`
**Content / Dir Discovery:** `gobuster`, `dirb`, `ffuf`, `feroxbuster`, `dirsearch`
**Vuln Scanners:** `nuclei`, `nikto`, `wpscan`, `dalfox`
**Param / URL Discovery:** `arjun`, `paramspider`, `waybackurls`, `gau`, `gf`
**Port Scanners:** `nmap`, `masscan`, `rustscan`
**Auth / Passwords:** `hydra`, `john`, `sqlmap`
**Network Enumeration:** `enum4linux`

> This list is configurable — tools can be added/removed depending on your Kali environment and permitted scope.

---

## 🛠️ Quick Install (Kali host)

```bash
# clone the project
git clone https://github.com/letchupkt/kali-mcp.git
cd kali-mcp

# make installer executable and run it (installs tools)
chmod +x install_tools.sh
sudo ./install_tools.sh

# start the server
python3 kali_server.py
```

**Note:** `install_tools.sh` will try to install many common pentest binaries. Inspect it and run it inside a VM or disposable Kali box if you prefer.

---

## 🖥️ Client Configuration (MCP Clients)

Clients simply invoke the MCP script with the Kali host URL. Example command used by MCP clients:

```bash
python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000
```

### Claude Desktop

Edit `%APPDATA%\Claude\claude_desktop_config.json` and add an MCP entry:

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

### 5ire Desktop

Add an MCP using the same `python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000` command — 5ire will generate the needed configuration automatically.

---

## 🧩 Example Workflows

1. **CTF Web Challenge (high-level):**

   * Client sends challenge URL + scope to MCP.
   * MCP runs `httpx`/`gobuster`/`ffuf` and returns parsed results.
   * Model suggests follow-up fuzzing or `sqlmap` commands.
   * Operator reviews and executes exploit steps, MCP logs outputs.

2. **HTB-like Machine (non-destructive recon):**

   * Run `nmap`/`rustscan` then `enum4linux` for SMB.
   * Save and store findings in local vector DB for the AI to reason over.

---

## ⚙️ Suggested Architecture & Safety

* **Orchestration layer**: Use a small Python service to call system tools and normalize outputs to JSON.
* **RAG & State**: Store scan results and evidence in a local DB (e.g., SQLite + FAISS) and pass concise context to the LLM.
* **Sandboxing**: Run scans/exploits inside VMs/containers with strict network egress control.
* **Authorization checks**: Add a required authorization token and a pre-flight scope/consent checklist for every automated run.

---

## 🔒 Legal & Ethical Notice

**Only run this server against systems you own or explicitly have written authorization to test.** Automated pentesting can cause service disruption and legal consequences. This repository is intended for education, defensive research, and authorized testing only.

---

## 🔮 Other Possibilities

* Memory forensics with Volatility (automated workflows).
* Disk forensics (SleuthKit / timelines / carving).
* Integration with alerting pipelines (Slack, Signal, email) for findings.
* Local LLM orchestration (run quantized LLMs for on-device reasoning — tell me your hardware and I can recommend exact models and setup commands).

---

## Contributing

PRs welcome. If you add tools or workflows, include tests and updated docs. Please keep contributions scoped to legal, ethical tooling.

---

## Author & Contact

**Lakshmikanthan (Letchu)** — GitHub: `letchupkt`
Portfolio: [https://letchupkt.netlify.app](https://letchupkt.vgrow.tech)
Instagram: [@letchu_pkt](https://instagram.com/letchu_pkt)
---

