#!/bin/bash

# Kali Linux Bug Hunting Tools Installation Script
# This script installs all the tools required for the MCP Kali Server

echo "🔧 Installing Bug Hunting Tools for MCP Kali Server..."
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

# Install Python requirements for MCP server
echo "🐍 Installing Python requirements..."
sudo pip3 install flask requests

# Make sure all Go binaries are in PATH
echo "🔧 Setting up PATH..."
sudo cp $GOPATH/bin/* /usr/local/bin/ 2>/dev/null || true

# Create symbolic links for tools that might not be in PATH
echo "🔗 Creating symbolic links..."
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

# Update Nuclei templates
echo "📋 Updating Nuclei templates..."
nuclei -update-templates 2>/dev/null || true

echo ""
echo "✅ Installation completed!"
echo "=================================================="
echo "🎯 All bug hunting tools have been installed successfully!"
echo ""
echo "📋 Installed tools:"
echo "   • Reconnaissance: subfinder, sublist3r, amass, assetfinder"
echo "   • Subdomain Takeover: subzy, subjack"
echo "   • HTTP Probing: httpx, katana, gospider"
echo "   • Content Discovery: gobuster, dirb, ffuf, feroxbuster, dirsearch"
echo "   • Vulnerability Scanning: nuclei, nikto, wpscan"
echo "   • Parameter Discovery: arjun, paramspider"
echo "   • XSS Testing: dalfox"
echo "   • URL Collection: waybackurls, gau"
echo "   • Filtering: gf (with patterns)"
echo "   • Port Scanning: nmap, masscan, rustscan"
echo "   • Password Attacks: hydra, john"
echo "   • SQL Injection: sqlmap"
echo "   • Network Enumeration: enum4linux"
echo ""
echo "🚀 You can now start the MCP Kali Server:"
echo "   python3 kali_server.py"
echo ""
echo "🔗 And connect your MCP client:"
echo "   python3 mcp_server.py --server http://YOUR_KALI_IP:5000"