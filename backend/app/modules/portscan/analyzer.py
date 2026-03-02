"""Port scan findings analyzer — re-exported from engine."""
from app.modules.portscan.engine import analyze_ports, _cvss_to_severity, _remediation

__all__ = ["analyze_ports"]
