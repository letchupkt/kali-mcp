#!/usr/bin/env python3
"""
Ollama Client for Enhanced Kali Linux MCP Server

This script provides an interface between a locally deployed Ollama LLM and
the enhanced Kali Linux MCP Server, allowing direct interaction with 25+ security tools.

Author: LAKSHMIKANTHAN K (letchupkt)
Enhanced Version: Bug Hunting Arsenal Integration

Usage:
    python3 ollama_client.py [--kali-server URL] [--model MODEL_NAME] [--debug]

Requirements:
    - Python 3.8+
    - ollama (locally installed)
    - ollama Python client library
    - requests

Features:
    - Direct integration with 25+ Kali security tools
    - Intelligent tool parameter extraction
    - Conversation history management
    - Automated bug hunting workflows
    - Real-time tool execution and results

© 2025 LAKSHMIKANTHAN K (letchupkt) - Enhanced MCP Kali Server
"""

import argparse
import json
import logging
import os
import re
import sys
import time
import requests
from typing import Dict, List, Any, Optional

try:
    from ollama import Client
except ImportError:
    print("Error: ollama Python client not found. Install with: pip install ollama")
    print("You also need to have Ollama installed locally: https://ollama.com/download")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ollama_kali_client.log")
    ]
)
logger = logging.getLogger(__name__)

# Configuration
DEFAULT_KALI_SERVER = "http://localhost:5000"
DEFAULT_MODEL = "llama3.2"  # Updated default model
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")

# Enhanced Kali Linux tools mapped to their API endpoints
KALI_TOOLS = {
    # Original tools
    "nmap": "/api/tools/nmap",
    "gobuster": "/api/tools/gobuster", 
    "dirb": "/api/tools/dirb",
    "nikto": "/api/tools/nikto",
    "sqlmap": "/api/tools/sqlmap",
    "metasploit": "/api/tools/metasploit",
    "hydra": "/api/tools/hydra",
    "john": "/api/tools/john",
    "wpscan": "/api/tools/wpscan",
    "enum4linux": "/api/tools/enum4linux",
    
    # Enhanced bug hunting tools
    "subfinder": "/api/tools/subfinder",
    "sublister": "/api/tools/sublister",
    "subzy": "/api/tools/subzy",
    "subjack": "/api/tools/subjack",
    "httpx": "/api/tools/httpx",
    "nuclei": "/api/tools/nuclei",
    "amass": "/api/tools/amass",
    "ffuf": "/api/tools/ffuf",
    "waybackurls": "/api/tools/waybackurls",
    "gau": "/api/tools/gau",
    "assetfinder": "/api/tools/assetfinder",
    "masscan": "/api/tools/masscan",
    "rustscan": "/api/tools/rustscan",
    "feroxbuster": "/api/tools/feroxbuster",
    "dirsearch": "/api/tools/dirsearch",
    "katana": "/api/tools/katana",
    "gospider": "/api/tools/gospider",
    "paramspider": "/api/tools/paramspider",
    "arjun": "/api/tools/arjun",
    "dalfox": "/api/tools/dalfox",
    "gf": "/api/tools/gf"
}

class OllamaKaliClient:
    """Enhanced Ollama client for Kali Linux MCP Server with bug hunting capabilities."""
    
    def __init__(self, kali_server_url: str = DEFAULT_KALI_SERVER, model_name: str = DEFAULT_MODEL):
        """Initialize Ollama client and connect to Kali MCP server."""
        self.kali_server_url = kali_server_url.rstrip("/")
        self.model_name = model_name
        self.client = Client()
        self.conversation = []
        self.tools_info = self._get_enhanced_tools_info()
        
        logger.info(f"Initialized Ollama Kali client with model: {model_name}")
        logger.info(f"Connecting to Kali MCP server: {kali_server_url}")
        
        # Check Kali MCP server health
        self._check_server_health()
    
    def _check_server_health(self):
        """Check if the Kali MCP server is responsive and get tool status."""
        try:
            health_response = requests.get(f"{self.kali_server_url}/health", timeout=30)
            if health_response.status_code == 200:
                health_data = health_response.json()
                logger.info("Successfully connected to Kali MCP Server")
                
                # Check tool availability
                tools_status = health_data.get("tools_status", {})
                available_tools = [tool for tool, status in tools_status.items() if status]
                unavailable_tools = [tool for tool, status in tools_status.items() if not status]
                
                logger.info(f"Available tools: {len(available_tools)}")
                if unavailable_tools:
                    logger.warning(f"Unavailable tools: {', '.join(unavailable_tools)}")
                    
            else:
                logger.error(f"Kali MCP server health check failed: {health_response.status_code}")
                
        except requests.RequestException as e:
            logger.error(f"Cannot connect to Kali MCP Server: {str(e)}")
            logger.error("Make sure kali_server.py is running on the specified URL")
            sys.exit(1)
    
    def _get_enhanced_tools_info(self) -> str:
        """Create comprehensive tool descriptions for the LLM."""
        tools_description = """# Enhanced Kali Linux Security Tools Arsenal

You have access to 25+ professional security tools for comprehensive bug hunting and penetration testing.

## 🎯 Bug Hunting Workflow Categories

### 1. Subdomain Enumeration & Discovery
- **subfinder**: Fast subdomain discovery using passive sources
- **sublister**: Subdomain enumeration using OSINT techniques  
- **amass**: Network mapping and attack surface discovery
- **assetfinder**: Find domains and subdomains related to a given domain

### 2. Subdomain Takeover Detection
- **subzy**: Check for subdomain takeover vulnerabilities
- **subjack**: Subdomain takeover vulnerability scanner

### 3. HTTP Service Analysis
- **httpx**: Fast HTTP toolkit for probing services
- **katana**: Next-generation web crawler
- **gospider**: Fast web spider for crawling websites

### 4. Content & Directory Discovery
- **gobuster**: Directory/file & DNS busting tool
- **dirb**: Web content scanner
- **ffuf**: Fast web fuzzer (Fuzz Faster U Fool)
- **feroxbuster**: Fast content discovery tool
- **dirsearch**: Web path scanner

### 5. Vulnerability Scanning
- **nuclei**: Fast vulnerability scanner with community templates
- **nikto**: Web server scanner
- **wpscan**: WordPress vulnerability scanner
- **dalfox**: XSS scanner and parameter analysis tool

### 6. Parameter & URL Discovery
- **arjun**: HTTP parameter discovery suite
- **paramspider**: Parameter mining from web archives
- **waybackurls**: Fetch URLs from Wayback Machine
- **gau**: Get All URLs from multiple sources
- **gf**: Grep-like tool for filtering with patterns

### 7. Port Scanning & Network Discovery
- **nmap**: Network discovery and security auditing
- **masscan**: High-speed port scanner
- **rustscan**: Modern fast port scanner

### 8. Authentication & Password Testing
- **hydra**: Network logon cracker
- **john**: John the Ripper password cracker
- **sqlmap**: SQL injection detection and exploitation

### 9. Network Enumeration
- **enum4linux**: Windows/Samba enumeration tool

## 🚀 Example Usage Patterns

### Complete Bug Hunting Workflow:
"Perform comprehensive bug hunting on example.com including subdomain enumeration, HTTP probing, content discovery, and vulnerability scanning"

### Subdomain Takeover Assessment:
"Check example.com for subdomain takeover vulnerabilities using multiple tools"

### Web Application Security Test:
"Test https://webapp.com for common web vulnerabilities including XSS, SQLi, and directory traversal"

### Network Reconnaissance:
"Perform network reconnaissance on 192.168.1.0/24 including port scanning and service enumeration"

## 📋 Tool Parameter Examples

### Subdomain Enumeration:
```
subfinder -d example.com
sublister -d example.com -o subdomains.txt
amass enum -d example.com
assetfinder example.com
```

### HTTP Analysis:
```
httpx -l subdomains.txt -title -tech-detect -status-code
katana -u https://example.com -depth 3
```

### Content Discovery:
```
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
feroxbuster -u https://example.com -w /usr/share/wordlists/dirb/big.txt
```

### Vulnerability Scanning:
```
nuclei -u https://example.com -t cves,exposures
dalfox url https://example.com/search?q=test
```

You can execute any of these tools by asking me to run them with specific parameters.
I'll handle the execution and provide you with formatted results.
"""
        return tools_description
    
    def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a Kali Linux tool via the MCP server."""
        if tool_name not in KALI_TOOLS:
            logger.warning(f"Unknown tool requested: {tool_name}")
            return {
                "status": "error",
                "message": f"Unknown tool: {tool_name}. Available tools: {', '.join(KALI_TOOLS.keys())}"
            }
        
        logger.info(f"Executing {tool_name} with params: {params}")
        
        try:
            # Send request to Kali MCP server
            response = requests.post(
                f"{self.kali_server_url}{KALI_TOOLS[tool_name]}",
                json=params,
                timeout=600  # 10 minutes timeout for long-running tools
            )
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    logger.info(f"Tool {tool_name} executed successfully")
                    return {
                        "status": "success",
                        "tool": tool_name,
                        "results": result
                    }
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing API response: {str(e)}")
                    return {
                        "status": "error",
                        "message": f"Error parsing API response: {str(e)}",
                        "raw_response": response.text
                    }
            else:
                logger.error(f"Tool execution failed: {response.status_code}")
                return {
                    "status": "error",
                    "message": f"Tool execution failed: {response.text}",
                    "code": response.status_code
                }
                
        except requests.RequestException as e:
            logger.error(f"Error executing tool {tool_name}: {str(e)}")
            return {
                "status": "error",
                "message": f"Error executing tool: {str(e)}"
            }
    
    def _extract_tool_requests(self, message: str) -> List[Dict]:
        """Enhanced tool request extraction with better pattern matching."""
        tool_requests = []
        message_lower = message.lower()
        
        # Enhanced patterns for different tools
        patterns = {
            # Subdomain enumeration
            "subfinder": [
                r"subfinder.*?-d\s+([^\s]+)",
                r"run subfinder.*?(?:on|for)\s+([^\s]+)",
                r"enumerate subdomains.*?(?:on|for)\s+([^\s]+).*?subfinder"
            ],
            "sublister": [
                r"sublister.*?-d\s+([^\s]+)",
                r"sublist3r.*?-d\s+([^\s]+)",
                r"run sublister.*?(?:on|for)\s+([^\s]+)"
            ],
            "amass": [
                r"amass.*?enum.*?-d\s+([^\s]+)",
                r"run amass.*?(?:on|for)\s+([^\s]+)"
            ],
            "assetfinder": [
                r"assetfinder\s+([^\s]+)",
                r"run assetfinder.*?(?:on|for)\s+([^\s]+)"
            ],
            
            # HTTP analysis
            "httpx": [
                r"httpx.*?-l\s+([^\s]+)",
                r"httpx.*?(?:on|for)\s+([^\s]+)",
                r"probe.*?http.*?(?:on|for)\s+([^\s]+)"
            ],
            "katana": [
                r"katana.*?-u\s+([^\s]+)",
                r"crawl.*?([https?://[^\s]+)"
            ],
            
            # Content discovery
            "ffuf": [
                r"ffuf.*?-u\s+([^\s]+)",
                r"fuzz.*?([https?://[^\s]+)"
            ],
            "gobuster": [
                r"gobuster.*?dir.*?-u\s+([^\s]+)",
                r"directory.*?brute.*?(?:on|for)\s+([^\s]+)"
            ],
            
            # Vulnerability scanning
            "nuclei": [
                r"nuclei.*?-u\s+([^\s]+)",
                r"vulnerability.*?scan.*?(?:on|for)\s+([^\s]+)"
            ],
            "nikto": [
                r"nikto.*?-h\s+([^\s]+)",
                r"run nikto.*?(?:on|for)\s+([^\s]+)"
            ],
            
            # Port scanning
            "nmap": [
                r"nmap.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?)",
                r"port.*?scan.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?)",
                r"scan.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?)"
            ],
            "masscan": [
                r"masscan.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?)",
                r"fast.*?port.*?scan.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?)"
            ],
            "rustscan": [
                r"rustscan.*?-a\s+([^\s]+)",
                r"rust.*?scan.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
            ]
        }
        
        # Check each tool pattern
        for tool, tool_patterns in patterns.items():
            for pattern in tool_patterns:
                matches = re.findall(pattern, message_lower)
                if matches:
                    target = matches[0]
                    params = self._build_tool_params(tool, target, message)
                    if params:
                        tool_requests.append({
                            "tool": tool,
                            "params": params
                        })
                        break
        
        return tool_requests
    
    def _build_tool_params(self, tool: str, target: str, message: str) -> Dict[str, Any]:
        """Build appropriate parameters for each tool based on the target and message context."""
        params = {}
        
        # Domain-based tools
        if tool in ["subfinder", "sublister", "amass", "assetfinder", "waybackurls", "gau", "paramspider"]:
            # Clean domain from URL if needed
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            params["domain"] = domain
            
        # URL-based tools  
        elif tool in ["httpx", "katana", "gospider", "ffuf", "gobuster", "feroxbuster", "dirsearch", "nuclei", "nikto", "wpscan", "dalfox", "arjun"]:
            # Ensure URL format
            if not target.startswith(("http://", "https://")):
                target = f"http://{target}"
            
            if tool in ["gobuster", "feroxbuster", "dirsearch", "ffuf"]:
                params["url"] = target
            else:
                params["url"] = target if tool != "nikto" else target
                if tool == "nikto":
                    params["target"] = target
                    
        # IP-based tools
        elif tool in ["nmap", "masscan", "rustscan", "enum4linux", "hydra"]:
            params["target"] = target
            
        # Subdomain takeover tools
        elif tool in ["subzy", "subjack"]:
            params["target"] = target
            
        # Add common additional parameters based on context
        if "verbose" in message.lower() or "-v" in message:
            params["additional_args"] = params.get("additional_args", "") + " -v"
            
        if "output" in message.lower() or "-o" in message:
            output_match = re.search(r"-o\s+([^\s]+)", message)
            if output_match:
                params["additional_args"] = params.get("additional_args", "") + f" -o {output_match.group(1)}"
        
        return params
    
    def _format_tool_results(self, result: Dict[str, Any]) -> str:
        """Format tool execution results for display."""
        if result["status"] != "success":
            return f"❌ Tool execution failed: {result.get('message', 'Unknown error')}"
        
        tool_name = result.get("tool", "Unknown")
        results = result.get("results", {})
        
        output = f"🔧 **{tool_name.upper()} Results**\n"
        output += "=" * 50 + "\n\n"
        
        # Handle different result formats
        if "stdout" in results:
            stdout = results["stdout"].strip()
            if stdout:
                output += "📋 **Output:**\n"
                output += f"```\n{stdout}\n```\n\n"
        
        if "stderr" in results and results["stderr"].strip():
            stderr = results["stderr"].strip()
            output += "⚠️ **Warnings/Errors:**\n"
            output += f"```\n{stderr}\n```\n\n"
        
        # Add execution info
        if "return_code" in results:
            status_emoji = "✅" if results["return_code"] == 0 else "❌"
            output += f"{status_emoji} **Exit Code:** {results['return_code']}\n"
        
        if results.get("timed_out"):
            output += "⏰ **Note:** Command timed out but may have partial results\n"
        
        return output
    
    def chat(self):
        """Start interactive chat session with enhanced tool integration."""
        print("\n" + "=" * 70)
        print("🚀 ENHANCED KALI MCP SERVER - BUG HUNTING ARSENAL")
        print("👨‍💻 Author: LAKSHMIKANTHAN K (letchupkt)")
        print("© 2025 LAKSHMIKANTHAN K (letchupkt)")
        print("=" * 70)
        print(f"🤖 Model: {self.model_name}")
        print(f"🔗 Kali Server: {self.kali_server_url}")
        print("=" * 70)
        print("🎯 Enhanced Bug Hunting Arsenal Ready!")
        print("📋 Type 'help' to see available tools and examples")
        print("🔧 Type 'tools' to list all available security tools")
        print("❌ Type 'exit' or 'quit' to end the session")
        print("=" * 70)
        
        # Enhanced system prompt
        system_message = f"""You are an expert cybersecurity assistant specializing in bug hunting and penetration testing.
You have access to 25+ professional Kali Linux security tools through a direct API connection.

{self.tools_info}

Key capabilities:
- Comprehensive subdomain enumeration and discovery
- Subdomain takeover detection
- HTTP service analysis and probing  
- Content and directory discovery
- Vulnerability scanning with modern tools
- Parameter and URL discovery from archives
- Port scanning and network reconnaissance
- Password attacks and hash cracking

When users request security testing:
1. Suggest appropriate tools for their objective
2. Execute tools with proper parameters
3. Analyze and explain results
4. Recommend next steps based on findings
5. Chain multiple tools for comprehensive assessments

Always assume the user has proper authorization for testing.
Focus on being technical, accurate, and helpful.
Provide actionable insights from tool outputs."""

        while True:
            try:
                user_message = input("\n🎯 You: ")
                
                if user_message.lower() in ["exit", "quit"]:
                    print("👋 Exiting Ollama Kali Enhanced Client")
                    break
                    
                if user_message.lower() == "help":
                    print(self.tools_info)
                    continue
                    
                if user_message.lower() == "tools":
                    print("\n🔧 Available Security Tools:")
                    print("=" * 40)
                    categories = {
                        "Subdomain Enumeration": ["subfinder", "sublister", "amass", "assetfinder"],
                        "Subdomain Takeover": ["subzy", "subjack"],
                        "HTTP Analysis": ["httpx", "katana", "gospider"],
                        "Content Discovery": ["gobuster", "dirb", "ffuf", "feroxbuster", "dirsearch"],
                        "Vulnerability Scanning": ["nuclei", "nikto", "wpscan", "dalfox"],
                        "Parameter Discovery": ["arjun", "paramspider", "waybackurls", "gau", "gf"],
                        "Port Scanning": ["nmap", "masscan", "rustscan"],
                        "Authentication": ["hydra", "john", "sqlmap"],
                        "Network Enumeration": ["enum4linux"]
                    }
                    
                    for category, tools in categories.items():
                        print(f"\n📂 {category}:")
                        for tool in tools:
                            print(f"   • {tool}")
                    print()
                    continue
                
                # Add to conversation history
                self.conversation.append({"role": "user", "content": user_message})
                
                # Check for tool execution requests
                tool_requests = self._extract_tool_requests(user_message)
                
                if tool_requests:
                    print("\n🔧 Executing detected tools...")
                    
                    for tool_request in tool_requests:
                        tool_name = tool_request["tool"]
                        params = tool_request["params"]
                        
                        print(f"\n⚡ Running {tool_name} with parameters: {params}")
                        
                        # Execute the tool
                        result = self.execute_tool(tool_name, params)
                        formatted_result = self._format_tool_results(result)
                        
                        print(formatted_result)
                        
                        # Add tool result to conversation
                        self.conversation.append({
                            "role": "assistant", 
                            "content": f"Executed {tool_name}:\n{formatted_result}"
                        })
                else:
                    # Regular LLM conversation
                    print("\n🤖 Assistant: ", end="", flush=True)
                    
                    messages = [{"role": "system", "content": system_message}] + self.conversation
                    
                    assistant_message = ""
                    for chunk in self.client.chat(
                        model=self.model_name,
                        messages=messages,
                        stream=True
                    ):
                        content = chunk.get("message", {}).get("content", "")
                        if content:
                            print(content, end="", flush=True)
                            assistant_message += content
                    
                    print("\n")
                    self.conversation.append({"role": "assistant", "content": assistant_message})
                    
                    # Check if LLM suggested tool execution
                    suggested_tools = self._extract_tool_requests(assistant_message)
                    if suggested_tools:
                        confirm = input(f"\n🤔 Execute suggested tools? (y/n): ")
                        if confirm.lower() in ["y", "yes"]:
                            for tool_request in suggested_tools:
                                tool_name = tool_request["tool"]
                                params = tool_request["params"]
                                
                                print(f"\n⚡ Executing {tool_name}...")
                                result = self.execute_tool(tool_name, params)
                                formatted_result = self._format_tool_results(result)
                                print(formatted_result)
                
            except KeyboardInterrupt:
                print("\n\n👋 Exiting...")
                break
            except Exception as e:
                logger.error(f"Error in chat loop: {str(e)}")
                print(f"\n❌ Error: {str(e)}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Ollama Client for Enhanced Kali Linux MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ollama_client.py
  python3 ollama_client.py --kali-server http://192.168.1.100:5000
  python3 ollama_client.py --model llama3.2 --debug
        """
    )
    
    parser.add_argument(
        "--kali-server", 
        type=str, 
        default=DEFAULT_KALI_SERVER,
        help=f"Kali MCP server URL (default: {DEFAULT_KALI_SERVER})"
    )
    
    parser.add_argument(
        "--model", 
        type=str, 
        default=DEFAULT_MODEL,
        help=f"Ollama model to use (default: {DEFAULT_MODEL})"
    )
    
    parser.add_argument(
        "--debug", 
        action="store_true",
        help="Enable debug logging"
    )
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Configure debug mode
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
    
    try:
        # Initialize and start the client
        client = OllamaKaliClient(
            kali_server_url=args.kali_server,
            model_name=args.model
        )
        client.chat()
        
    except KeyboardInterrupt:
        print("\n👋 Exiting Ollama Kali Enhanced Client")
    except Exception as e:
        logger.error(f"Error starting client: {str(e)}")
        print(f"❌ Error: {str(e)}")
        sys.exit(1)