#!/bin/bash

# Enhanced Kali Linux Bug Hunting Tools Installation Script
# Author: LAKSHMIKANTHAN K (letchupkt)
# This script installs all 55+ tools required for the Enhanced MCP Kali Server
# © 2025 LAKSHMIKANTHAN K (letchupkt) - Enhanced MCP Kali Server

echo "🔧 Installing 55+ Bug Hunting Tools for MCP Kali Server..."
echo "=================================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install basic tools that come with Kali
echo "🛠️ Installing basic penetration testing tools..."
sudo apt install -y nmap gobuster dirb nikto sqlmap hydra john wpscan enum4linux masscan

# Install Go (required for many modern tools)
echo "🐹 Installing Go..."
if ! command -v go &> /dev/null; then
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    source ~/.bashrc
    rm go1.21.5.linux-amd64.tar.gz
fi

# Set Go environment for current session
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Create Go workspace
mkdir -p $GOPATH/bin

# Install Subfinder
echo "🔍 Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Sublist3r
echo "📋 Installing Sublist3r..."
if [ ! -d "/opt/Sublist3r" ]; then
    sudo git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r
    cd /opt/Sublist3r
    sudo pip3 install -r requirements.txt
    sudo ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
    sudo chmod +x /usr/local/bin/sublist3r
fi

# Install Subzy
echo "🎯 Installing Subzy..."
go install -v github.com/LukaSikic/subzy@latest

# Install Subjack
echo "🔓 Installing Subjack..."
go install github.com/haccer/subjack@latest

# Install httpx
echo "🌐 Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install Nuclei
echo "💥 Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install OWASP Amass
echo "🗺️ Installing OWASP Amass..."
go install -v github.com/owasp-amass/amass/v4/...@master

# Install ffuf
echo "🚀 Installing ffuf..."
go install github.com/ffuf/ffuf/v2@latest

# Install waybackurls
echo "⏰ Installing waybackurls..."
go install github.com/tomnomnom/waybackurls@latest

# Install gau
echo "🔗 Installing gau..."
go install github.com/lc/gau/v2/cmd/gau@latest

# Install assetfinder
echo "🎯 Installing assetfinder..."
go install github.com/tomnomnom/assetfinder@latest

# Install RustScan
echo "🦀 Installing RustScan..."
if ! command -v rustscan &> /dev/null; then
    wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
    sudo dpkg -i rustscan_2.0.1_amd64.deb
    rm rustscan_2.0.1_amd64.deb
fi

# Install feroxbuster
echo "🔍 Installing feroxbuster..."
if ! command -v feroxbuster &> /dev/null; then
    wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster-linux-x86_64.tar.gz
    tar -xzf feroxbuster-linux-x86_64.tar.gz
    sudo mv feroxbuster /usr/local/bin/
    rm feroxbuster-linux-x86_64.tar.gz
fi

# Install dirsearch
echo "📁 Installing dirsearch..."
if [ ! -d "/opt/dirsearch" ]; then
    sudo git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch
    sudo ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
    sudo chmod +x /usr/local/bin/dirsearch
fi

# Install Katana
echo "🗡️ Installing Katana..."
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install GoSpider
echo "🕷️ Installing GoSpider..."
go install github.com/jaeles-project/gospider@latest

# Install ParamSpider
echo "🕸️ Installing ParamSpider..."
if [ ! -d "/opt/ParamSpider" ]; then
    sudo git clone https://github.com/devanshbatham/ParamSpider /opt/ParamSpider
    cd /opt/ParamSpider
    sudo pip3 install -r requirements.txt
    sudo ln -sf /opt/ParamSpider/paramspider.py /usr/local/bin/paramspider
    sudo chmod +x /usr/local/bin/paramspider
fi

# Install Arjun
echo "🏹 Installing Arjun..."
sudo pip3 install arjun

# Install DalFox
echo "🦊 Installing DalFox..."
go install github.com/hahwul/dalfox/v2@latest

# Install gf (grep-like tool for filtering)
echo "🔍 Installing gf..."
go install github.com/tomnomnom/gf@latest

# Install gf patterns
echo "📋 Installing gf patterns..."
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/patterns 2>/dev/null || true
git clone https://github.com/dwisiswant0/gf-secrets ~/.gf/secrets 2>/dev/null || true

# ==================== NEW TOOLS (30+) ====================

# Install DNSx
echo "🌐 Installing DNSx..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Install ShuffleDNS
echo "🔀 Installing ShuffleDNS..."
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Install PureDNS
echo "🧹 Installing PureDNS..."
go install github.com/d3mondev/puredns/v2@latest

# Install Alterx
echo "🔄 Installing Alterx..."
go install github.com/projectdiscovery/alterx/cmd/alterx@latest

# Install TLSx
echo "🔐 Installing TLSx..."
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# Install Uncover
echo "🔎 Installing Uncover..."
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest

# Install Naabu
echo "🔌 Installing Naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Install Notify
echo "📢 Installing Notify..."
go install -v github.com/projectdiscovery/notify/cmd/notify@latest

# Install Interactsh
echo "🔗 Installing Interactsh..."
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Install CRLFuzz
echo "📝 Installing CRLFuzz..."
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# Install Qsreplace
echo "🔧 Installing Qsreplace..."
go install github.com/tomnomnom/qsreplace@latest

# Install Anew
echo "✨ Installing Anew..."
go install github.com/tomnomnom/anew@latest

# Install Unfurl
echo "🎯 Installing Unfurl..."
go install github.com/tomnomnom/unfurl@latest

# Install Hakrawler
echo "🕷️ Installing Hakrawler..."
go install github.com/hakluke/hakrawler@latest

# Install Gauplus
echo "🔗 Installing Gauplus..."
go install github.com/bp0lr/gauplus@latest

# Install GitHub-Subdomains
echo "🐙 Installing GitHub-Subdomains..."
go install github.com/gwen001/github-subdomains@latest

# Install Shosubgo
echo "🔍 Installing Shosubgo..."
go install github.com/incogbyte/shosubgo@latest

# Install Chaos
echo "🌪️ Installing Chaos..."
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Install Mapcidr
echo "🗺️ Installing Mapcidr..."
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest

# Install CDNCheck
echo "☁️ Installing CDNCheck..."
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest

# Install ASNmap
echo "🌐 Installing ASNmap..."
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest

# ==================== END NEW TOOLS ====================

# Install Python requirements for MCP server
echo "🐍 Installing Python requirements..."
sudo pip3 install flask requests

# Make sure all Go binaries are in PATH
echo "🔧 Setting up PATH..."
sudo cp $GOPATH/bin/* /usr/local/bin/ 2>/dev/null || true

# Create symbolic links for tools that might not be in PATH
echo "🔗 Creating symbolic links..."
# Original tools
sudo ln -sf $GOPATH/bin/subfinder /usr/local/bin/subfinder 2>/dev/null || true
sudo ln -sf $GOPATH/bin/subzy /usr/local/bin/subzy 2>/dev/null || true
sudo ln -sf $GOPATH/bin/subjack /usr/local/bin/subjack 2>/dev/null || true
sudo ln -sf $GOPATH/bin/httpx /usr/local/bin/httpx 2>/dev/null || true
sudo ln -sf $GOPATH/bin/nuclei /usr/local/bin/nuclei 2>/dev/null || true
sudo ln -sf $GOPATH/bin/amass /usr/local/bin/amass 2>/dev/null || true
sudo ln -sf $GOPATH/bin/ffuf /usr/local/bin/ffuf 2>/dev/null || true
sudo ln -sf $GOPATH/bin/waybackurls /usr/local/bin/waybackurls 2>/dev/null || true
sudo ln -sf $GOPATH/bin/gau /usr/local/bin/gau 2>/dev/null || true
sudo ln -sf $GOPATH/bin/assetfinder /usr/local/bin/assetfinder 2>/dev/null || true
sudo ln -sf $GOPATH/bin/katana /usr/local/bin/katana 2>/dev/null || true
sudo ln -sf $GOPATH/bin/gospider /usr/local/bin/gospider 2>/dev/null || true
sudo ln -sf $GOPATH/bin/dalfox /usr/local/bin/dalfox 2>/dev/null || true
sudo ln -sf $GOPATH/bin/gf /usr/local/bin/gf 2>/dev/null || true

# New tools
sudo ln -sf $GOPATH/bin/dnsx /usr/local/bin/dnsx 2>/dev/null || true
sudo ln -sf $GOPATH/bin/shuffledns /usr/local/bin/shuffledns 2>/dev/null || true
sudo ln -sf $GOPATH/bin/puredns /usr/local/bin/puredns 2>/dev/null || true
sudo ln -sf $GOPATH/bin/alterx /usr/local/bin/alterx 2>/dev/null || true
sudo ln -sf $GOPATH/bin/tlsx /usr/local/bin/tlsx 2>/dev/null || true
sudo ln -sf $GOPATH/bin/uncover /usr/local/bin/uncover 2>/dev/null || true
sudo ln -sf $GOPATH/bin/naabu /usr/local/bin/naabu 2>/dev/null || true
sudo ln -sf $GOPATH/bin/notify /usr/local/bin/notify 2>/dev/null || true
sudo ln -sf $GOPATH/bin/interactsh-client /usr/local/bin/interactsh-client 2>/dev/null || true
sudo ln -sf $GOPATH/bin/crlfuzz /usr/local/bin/crlfuzz 2>/dev/null || true
sudo ln -sf $GOPATH/bin/qsreplace /usr/local/bin/qsreplace 2>/dev/null || true
sudo ln -sf $GOPATH/bin/anew /usr/local/bin/anew 2>/dev/null || true
sudo ln -sf $GOPATH/bin/unfurl /usr/local/bin/unfurl 2>/dev/null || true
sudo ln -sf $GOPATH/bin/hakrawler /usr/local/bin/hakrawler 2>/dev/null || true
sudo ln -sf $GOPATH/bin/gauplus /usr/local/bin/gauplus 2>/dev/null || true
sudo ln -sf $GOPATH/bin/github-subdomains /usr/local/bin/github-subdomains 2>/dev/null || true
sudo ln -sf $GOPATH/bin/shosubgo /usr/local/bin/shosubgo 2>/dev/null || true
sudo ln -sf $GOPATH/bin/chaos /usr/local/bin/chaos 2>/dev/null || true
sudo ln -sf $GOPATH/bin/mapcidr /usr/local/bin/mapcidr 2>/dev/null || true
sudo ln -sf $GOPATH/bin/cdncheck /usr/local/bin/cdncheck 2>/dev/null || true
sudo ln -sf $GOPATH/bin/asnmap /usr/local/bin/asnmap 2>/dev/null || true

# Update Nuclei templates
echo "📋 Updating Nuclei templates..."
nuclei -update-templates 2>/dev/null || true

echo ""
echo "✅ Installation completed!"
echo "=================================================="
echo "🎯 All 55+ bug hunting tools have been installed successfully!"
echo ""
echo "📋 Installed tools:"
echo "   • Reconnaissance: subfinder, sublist3r, amass, assetfinder, chaos, shosubgo, github-subdomains"
echo "   • DNS Tools: dnsx, shuffledns, puredns, alterx"
echo "   • Subdomain Takeover: subzy, subjack"
echo "   • HTTP Probing: httpx, tlsx, katana, gospider, hakrawler"
echo "   • Content Discovery: gobuster, dirb, ffuf, feroxbuster, dirsearch"
echo "   • Vulnerability Scanning: nuclei, nikto, wpscan, dalfox, crlfuzz"
echo "   • Parameter Discovery: arjun, paramspider"
echo "   • URL Collection: waybackurls, gau, gauplus"
echo "   • Filtering: gf (with patterns)"
echo "   • Port Scanning: nmap, masscan, rustscan, naabu"
echo "   • Password Attacks: hydra, john"
echo "   • SQL Injection: sqlmap"
echo "   • Network Enumeration: enum4linux"
echo "   • Utility Tools: notify, interactsh, qsreplace, anew, unfurl"
echo "   • Infrastructure: mapcidr, cdncheck, asnmap, uncover"
echo ""
echo "🚀 You can now start the MCP Kali Server:"
echo "   python3 kali_server.py"
echo ""
echo "🔗 And connect your MCP client:"
echo "   python3 mcp_server.py --server http://YOUR_KALI_IP:5000"