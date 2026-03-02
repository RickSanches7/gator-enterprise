"""
GATOR PRO — Tool Availability Checker
Detects which pentest tools are installed
"""

import asyncio
import subprocess
import shutil
from typing import Dict


TOOLS_CONFIG = {
    "nmap": {
        "check": ["nmap", "--version"],
        "install": "apt install nmap",
        "description": "Port scanner + service detection",
        "critical": True,
    },
    "nuclei": {
        "check": ["nuclei", "-version"],
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "description": "Web vulnerability scanner (9000+ templates)",
        "critical": True,
    },
    "nikto": {
        "check": ["nikto", "-Version"],
        "install": "apt install nikto",
        "description": "Web server scanner",
        "critical": False,
    },
    "sqlmap": {
        "check": ["sqlmap", "--version"],
        "install": "apt install sqlmap",
        "description": "SQL injection automation",
        "critical": True,
    },
    "gobuster": {
        "check": ["gobuster", "version"],
        "install": "apt install gobuster",
        "description": "Directory & DNS brute-force",
        "critical": False,
    },
    "ffuf": {
        "check": ["ffuf", "-V"],
        "install": "go install github.com/ffuf/ffuf/v2@latest",
        "description": "Fast web fuzzer",
        "critical": False,
    },
    "subfinder": {
        "check": ["subfinder", "-version"],
        "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "description": "Subdomain discovery",
        "critical": False,
    },
    "whois": {
        "check": ["whois", "--version"],
        "install": "apt install whois",
        "description": "WHOIS lookup",
        "critical": False,
    },
    "dig": {
        "check": ["dig", "-v"],
        "install": "apt install dnsutils",
        "description": "DNS enumeration",
        "critical": False,
    },
    "openssl": {
        "check": ["openssl", "version"],
        "install": "apt install openssl",
        "description": "SSL/TLS analysis",
        "critical": False,
    },
    "python_impacket": {
        "check": ["python3", "-c", "import impacket; print(impacket.__version__)"],
        "install": "pip install impacket",
        "description": "Active Directory attacks",
        "critical": False,
    },
    "sslyze": {
        "check": ["python3", "-c", "import sslyze; print(sslyze.__version__)"],
        "install": "pip install sslyze",
        "description": "Deep SSL/TLS analysis",
        "critical": False,
    },
}


def check_tool_sync(name: str, config: dict) -> dict:
    """Synchronous tool check."""
    try:
        result = subprocess.run(
            config["check"],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = (result.stdout + result.stderr).strip()[:100]
        available = result.returncode == 0 or len(output) > 0
        return {
            "available": available,
            "version": output.split("\n")[0] if output else "unknown",
            "install": config["install"],
            "description": config["description"],
            "critical": config.get("critical", False),
        }
    except FileNotFoundError:
        return {
            "available": False,
            "version": None,
            "install": config["install"],
            "description": config["description"],
            "critical": config.get("critical", False),
        }
    except Exception as e:
        return {
            "available": False,
            "version": None,
            "install": config["install"],
            "description": config["description"],
            "critical": config.get("critical", False),
            "error": str(e),
        }


async def check_all_tools() -> Dict[str, dict]:
    """Check all tools asynchronously."""
    loop = asyncio.get_event_loop()
    results = {}
    for name, config in TOOLS_CONFIG.items():
        result = await loop.run_in_executor(None, check_tool_sync, name, config)
        results[name] = result
    return results


def get_missing_critical_tools() -> list:
    """Return list of critical tools that are missing."""
    missing = []
    for name, config in TOOLS_CONFIG.items():
        if config.get("critical"):
            result = check_tool_sync(name, config)
            if not result["available"]:
                missing.append({"name": name, "install": config["install"]})
    return missing


def generate_install_script() -> str:
    """Generate bash script to install all missing tools."""
    lines = [
        "#!/bin/bash",
        "# GATOR PRO — Tool Installation Script",
        "# Run: sudo bash install_tools.sh",
        "",
        "set -e",
        "echo '=== Installing GATOR PRO Tools ==='",
        "",
        "# APT tools",
        "apt-get update -qq",
        "apt-get install -y nmap nikto sqlmap gobuster ffuf whois dnsutils openssl git curl wget",
        "",
        "# Go tools",
        "if ! command -v go &>/dev/null; then",
        "  wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz",
        "  tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz",
        "  export PATH=$PATH:/usr/local/go/bin",
        "fi",
        "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "",
        "# Python packages",
        "pip install impacket sslyze nvdlib reportlab python-docx python-telegram-bot",
        "",
        "# Update Nuclei templates",
        "nuclei -update-templates",
        "",
        "echo '=== All tools installed successfully! ==='",
    ]
    return "\n".join(lines)
