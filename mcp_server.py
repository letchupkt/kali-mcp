#!/usr/bin/env python3

# Enhanced MCP Kali Server - Bug Hunting Arsenal
# Author: LAKSHMIKANTHAN K (letchupkt)
# This script connects the MCP AI agent to Kali Linux terminal and API Server.
# Enhanced with 25+ bug hunting and reconnaissance tools

# Some of the original code was inspired from https://github.com/whit3rabbit0/project_astro
# Enhanced and expanded by LAKSHMIKANTHAN K (letchupkt)

# © 2025 LAKSHMIKANTHAN K (letchupkt) - Enhanced MCP Kali Server

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://localhost:5000" # change to your linux IP
DEFAULT_REQUEST_TIMEOUT = 600  # 10 minutes default timeout for API requests

class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client
        
        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic command on the Kali server
        
        Args:
            command: Command to execute
            
        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server
        
        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Set up the MCP server with all tool functions
    
    Args:
        kali_client: Initialized KaliToolsClient
        
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali-mcp")
    
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.
        
        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.
        
        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            
        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool()
    def subfinder_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subfinder for subdomain enumeration.
        
        Args:
            domain: The target domain
            additional_args: Additional Subfinder arguments
            
        Returns:
            Subdomain enumeration results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/subfinder", data)

    @mcp.tool()
    def sublister_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Sublister for subdomain enumeration.
        
        Args:
            domain: The target domain
            additional_args: Additional Sublister arguments
            
        Returns:
            Subdomain enumeration results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sublister", data)

    @mcp.tool()
    def subzy_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subzy for subdomain takeover detection.
        
        Args:
            target: Target domain or file containing subdomains
            additional_args: Additional Subzy arguments
            
        Returns:
            Subdomain takeover scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/subzy", data)

    @mcp.tool()
    def subjack_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Subjack for subdomain takeover detection.
        
        Args:
            target: Target domain or file containing subdomains
            additional_args: Additional Subjack arguments
            
        Returns:
            Subdomain takeover scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/subjack", data)

    @mcp.tool()
    def httpx_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute httpx for HTTP probing and analysis.
        
        Args:
            target: Target URL, domain, or file containing targets
            additional_args: Additional httpx arguments
            
        Returns:
            HTTP probing results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/httpx", data)

    @mcp.tool()
    def nuclei_scan(target: str, templates: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner.
        
        Args:
            target: Target URL, domain, or file containing targets
            templates: Specific templates to use
            additional_args: Additional Nuclei arguments
            
        Returns:
            Vulnerability scan results
        """
        data = {
            "target": target,
            "templates": templates,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nuclei", data)

    @mcp.tool()
    def amass_scan(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute OWASP Amass for network mapping and attack surface discovery.
        
        Args:
            domain: The target domain
            mode: Amass mode (enum, intel, viz, track, db)
            additional_args: Additional Amass arguments
            
        Returns:
            Network mapping results
        """
        data = {
            "domain": domain,
            "mode": mode,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/amass", data)

    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", mode: str = "dir", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ffuf (Fuzz Faster U Fool) for web fuzzing.
        
        Args:
            url: Target URL with FUZZ keyword
            wordlist: Path to wordlist file
            mode: Fuzzing mode (dir, vhost, param, etc.)
            additional_args: Additional ffuf arguments
            
        Returns:
            Fuzzing results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "mode": mode,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/ffuf", data)

    @mcp.tool()
    def waybackurls_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute waybackurls to fetch URLs from Wayback Machine.
        
        Args:
            domain: The target domain
            additional_args: Additional waybackurls arguments
            
        Returns:
            Historical URLs from Wayback Machine
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/waybackurls", data)

    @mcp.tool()
    def gau_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute gau (Get All URLs) to fetch URLs from multiple sources.
        
        Args:
            domain: The target domain
            additional_args: Additional gau arguments
            
        Returns:
            URLs from multiple sources
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gau", data)

    @mcp.tool()
    def assetfinder_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute assetfinder for subdomain enumeration.
        
        Args:
            domain: The target domain
            additional_args: Additional assetfinder arguments
            
        Returns:
            Subdomain enumeration results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/assetfinder", data)

    @mcp.tool()
    def masscan_scan(target: str, ports: str = "1-65535", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute masscan for high-speed port scanning.
        
        Args:
            target: Target IP or CIDR range
            ports: Port range to scan
            additional_args: Additional masscan arguments
            
        Returns:
            Port scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/masscan", data)

    @mcp.tool()
    def rustscan_scan(target: str, ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute RustScan for fast port scanning.
        
        Args:
            target: Target IP or hostname
            ports: Specific ports to scan
            additional_args: Additional RustScan arguments
            
        Returns:
            Port scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/rustscan", data)

    @mcp.tool()
    def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute feroxbuster for content discovery.
        
        Args:
            url: Target URL
            wordlist: Path to wordlist file
            additional_args: Additional feroxbuster arguments
            
        Returns:
            Content discovery results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/feroxbuster", data)

    @mcp.tool()
    def dirsearch_scan(url: str, extensions: str = "php,html,js,txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dirsearch for web path scanner.
        
        Args:
            url: Target URL
            extensions: File extensions to search for
            additional_args: Additional dirsearch arguments
            
        Returns:
            Directory/file discovery results
        """
        data = {
            "url": url,
            "extensions": extensions,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirsearch", data)

    @mcp.tool()
    def katana_crawl(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Katana web crawler for spidering websites.
        
        Args:
            url: Target URL to crawl
            additional_args: Additional Katana arguments
            
        Returns:
            Web crawling results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/katana", data)

    @mcp.tool()
    def gospider_crawl(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GoSpider web crawler.
        
        Args:
            url: Target URL to crawl
            additional_args: Additional GoSpider arguments
            
        Returns:
            Web crawling results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gospider", data)

    @mcp.tool()
    def paramspider_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ParamSpider to find parameters from web archives.
        
        Args:
            domain: Target domain
            additional_args: Additional ParamSpider arguments
            
        Returns:
            Parameter discovery results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/paramspider", data)

    @mcp.tool()
    def arjun_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Arjun for HTTP parameter discovery.
        
        Args:
            url: Target URL
            additional_args: Additional Arjun arguments
            
        Returns:
            Parameter discovery results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/arjun", data)

    @mcp.tool()
    def dalfox_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute DalFox for XSS vulnerability scanning.
        
        Args:
            url: Target URL
            additional_args: Additional DalFox arguments
            
        Returns:
            XSS vulnerability scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dalfox", data)

    @mcp.tool()
    def gf_patterns(input_data: str, pattern: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute gf (grep-like tool) with specific patterns for filtering.
        
        Args:
            input_data: Input data or file path
            pattern: Pattern to search for (xss, sqli, ssrf, etc.)
            additional_args: Additional gf arguments
            
        Returns:
            Filtered results based on pattern
        """
        data = {
            "input_data": input_data,
            "pattern": pattern,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gf", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.
        
        Returns:
            Server health information
        """
        return kali_client.check_health()
    
    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.
        
        Args:
            command: The command to execute
            
        Returns:
            Command execution results
        """
        return kali_client.execute_command(command)

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")
    
    # Set up and run the MCP server
    mcp = setup_mcp_server(kali_client)
    logger.info("Starting Kali MCP server")
    mcp.run()

if __name__ == "__main__":
    main()
