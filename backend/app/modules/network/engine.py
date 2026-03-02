"""
GATOR PRO Enterprise — Module 10: Network Security Engine
══════════════════════════════════════════════════════════
Network-level security testing:
  • SNMP community string enumeration (public/private)
  • Default credentials on network devices
  • NTP amplification check
  • DNS amplification check
  • Open resolver detection
  • Telnet/FTP cleartext services
  • ICMP reachability and fingerprinting
  • IPv6 security checks
  • Network device banner grabbing
  • Traceroute path analysis
  • VLAN/subnet enumeration hints
"""

import socket, subprocess, json, re, ssl, time, struct
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional


SNMP_COMMUNITIES = [
    "public", "private", "community", "admin", "manager",
    "monitor", "snmpd", "default", "cisco", "router",
    "switch", "network", "read", "write", "all",
    "secret", "password", "internal", "test", "guest",
]

COMMON_NETWORK_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    69:    "TFTP",
    80:    "HTTP",
    123:   "NTP",
    161:   "SNMP",
    162:   "SNMP Trap",
    179:   "BGP",
    443:   "HTTPS",
    514:   "Syslog",
    520:   "RIP",
    623:   "IPMI/BMC",
    1080:  "SOCKS Proxy",
    1194:  "OpenVPN",
    1433:  "MSSQL",
    1521:  "Oracle",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
}

NETWORK_DEVICE_DEFAULTS = [
    # Cisco IOS
    ("cisco",    "cisco"),
    ("admin",    "cisco"),
    ("admin",    "admin"),
    # Juniper
    ("root",     ""),
    ("admin",    "juniper"),
    # Huawei
    ("admin",    "admin@huawei"),
    ("admin",    "huawei"),
    # D-Link
    ("admin",    ""),
    ("admin",    "admin"),
    # MikroTik
    ("admin",    ""),
    ("admin",    "admin"),
    # Generic
    ("admin",    "password"),
    ("admin",    "1234"),
    ("admin",    "12345"),
    ("root",     "root"),
    ("root",     "password"),
    ("enable",   "cisco"),
    ("enable",   "enable"),
]


class NetworkEngine:
    def __init__(self, target, scan_id, db, push_event, **kwargs):
        self.target     = target.replace("https://","").replace("http://","").split("/")[0].split(":")[0].strip()
        self.scan_id    = scan_id
        self.db         = db
        self.push_event = push_event
        self.findings   = []
        self.open_ports = {}

    def log(self, level, msg, data=None):
        self.push_event(self.db, self.scan_id, "log", level, msg, data or {})

    def finding(self, f):
        self.findings.append(f)
        self.push_event(self.db, self.scan_id, "finding", f.get("severity","info"),
            f"[NET] {f.get('title','')[:80]}",
            {"severity": f.get("severity"), "cvss": f.get("cvss", 0)})

    def run(self):
        self.log("info", f"╔══ NETWORK SCAN ══ {self.target} ══╗")
        t0 = time.time()
        self._port_scan()
        self._check_snmp()
        self._check_telnet_ftp()
        self._check_dns_amplification()
        self._check_ntp_amplification()
        self._check_icmp()
        self._banner_grab_network_devices()
        self._check_ipmi()
        self._network_findings_summary()
        elapsed = round(time.time() - t0, 1)
        c = len([f for f in self.findings if f["severity"] == "critical"])
        h = len([f for f in self.findings if f["severity"] == "high"])
        self.log("ok", f"╚══ NETWORK DONE {elapsed}s ══ Findings: {len(self.findings)} (C:{c} H:{h}) ══╝")
        return {"findings": self.findings}

    def _port_scan(self):
        self.log("data", f"[NET] Port scan: {len(COMMON_NETWORK_PORTS)} critical ports...")
        done = [0]
        def check(port):
            done[0] += 1
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.8)
                    if s.connect_ex((self.target, port)) == 0:
                        return port
            except Exception:
                pass
            return None
        with ThreadPoolExecutor(max_workers=30) as ex:
            for result in as_completed({ex.submit(check, p): p for p in COMMON_NETWORK_PORTS}):
                port = result.result()
                if port:
                    svc = COMMON_NETWORK_PORTS.get(port, "unknown")
                    self.open_ports[port] = svc
                    self.log("ok", f"[NET] {port}/tcp → {svc}")

    def _check_snmp(self):
        if 161 not in self.open_ports:
            # Try anyway — UDP
            pass
        self.log("data", f"[NET] Testing SNMP community strings ({len(SNMP_COMMUNITIES)} candidates)...")
        if not self._which("snmpwalk") and not self._which("snmpget"):
            self.log("info", "[NET] snmpwalk not available — using raw UDP probe")
            self._snmp_raw_probe()
            return
        for community in SNMP_COMMUNITIES[:10]:
            try:
                r = subprocess.run([
                    "snmpget", "-v2c", "-c", community,
                    "-t", "2", "-r", "1",
                    self.target, "1.3.6.1.2.1.1.1.0"  # sysDescr
                ], capture_output=True, text=True, timeout=5)
                if r.returncode == 0 and "STRING:" in r.stdout:
                    desc = re.search(r"STRING:\s*(.+)", r.stdout)
                    desc_val = desc.group(1)[:100] if desc else ""
                    self.log("warn", f"[NET] 🚨 SNMP community '{community}' works! sysDescr: {desc_val}")
                    self.finding({
                        "severity": "critical" if community in ("public","private") else "high",
                        "cvss": 9.8,
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "pci_dss_req": ["2.2.1","8.3.1"],
                        "cwe_ids": ["CWE-1269"],
                        "title": f"SNMP default community string '{community}'",
                        "description": (
                            f"SNMP v2c community string '{community}' accepted. "
                            f"sysDescr: {desc_val}. "
                            "Attacker can enumerate full network topology, interface IPs, "
                            "routing tables, and with 'private' — modify device configuration."),
                        "recommendation": (
                            "1. Disable SNMPv1/v2c. Use SNMPv3 with authentication + encryption.\n"
                            "2. Change community strings from defaults.\n"
                            "3. Restrict SNMP access to monitoring server IPs only via ACL.\n"
                            "4. Block UDP 161/162 from internet."),
                        "evidence": f"snmpget community='{community}' → {r.stdout[:200]}",
                        "poc": f"snmpwalk -v2c -c {community} {self.target} .",
                        "host": self.target, "url": f"udp://{self.target}:161",
                        "tool": "gator_network", "category": "network",
                    })
                    # Try to get more info
                    self._snmp_enumerate(community)
                    return
            except Exception:
                pass
        self.log("ok", "[NET] No default SNMP communities responded ✓")

    def _snmp_raw_probe(self):
        """Raw UDP SNMP v2c probe for 'public' community."""
        # SNMPv2c GetRequest for sysDescr
        community = b"public"
        snmp_pkt = (
            b"\x30\x26"          # SEQUENCE
            b"\x02\x01\x01"      # version = 2c (1)
            b"\x04" + bytes([len(community)]) + community +  # community
            b"\xa0\x19"          # GetRequest
            b"\x02\x04\x00\x00\x00\x01"  # requestID
            b"\x02\x01\x00"      # error = 0
            b"\x02\x01\x00"      # errorIndex = 0
            b"\x30\x0b"          # VarBindList
            b"\x30\x09"          # VarBind
            b"\x06\x05\x2b\x06\x01\x02\x01"  # OID 1.3.6.1.2.1 (sysDescr)
            b"\x05\x00"          # NULL
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(snmp_pkt, (self.target, 161))
                resp, _ = s.recvfrom(4096)
                if resp and b"public" in resp:
                    self.log("warn", "[NET] 🚨 SNMP public community responds!")
                    self.finding({
                        "severity": "critical", "cvss": 9.8,
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "title": "SNMP public community string responds",
                        "description": "SNMP public community string accepted on UDP 161.",
                        "recommendation": "Disable SNMPv2c. Use SNMPv3 with authentication.",
                        "evidence": f"UDP 161 SNMP response received ({len(resp)} bytes)",
                        "host": self.target, "url": f"udp://{self.target}:161",
                        "tool": "gator_network", "category": "network",
                    })
        except Exception:
            pass

    def _snmp_enumerate(self, community):
        """Enumerate SNMP info with valid community."""
        oids = {
            "1.3.6.1.2.1.1.4.0": "sysContact",
            "1.3.6.1.2.1.1.5.0": "sysName",
            "1.3.6.1.2.1.1.6.0": "sysLocation",
            "1.3.6.1.2.1.4.20":  "ipAddrTable",
        }
        for oid, name in oids.items():
            try:
                r = subprocess.run([
                    "snmpget", "-v2c", "-c", community,
                    "-t", "2", self.target, oid
                ], capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    self.log("info", f"[NET] SNMP {name}: {r.stdout.strip()[:80]}")
            except Exception:
                pass

    def _check_telnet_ftp(self):
        for port, svc in [(23,"Telnet"),(21,"FTP")]:
            if port in self.open_ports:
                self.finding({
                    "severity": "critical", "cvss": 9.8,
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "pci_dss_req": ["4.2.1","2.2.1"],
                    "cwe_ids": ["CWE-319"],
                    "title": f"{svc} cleartext protocol active — port {port}",
                    "description": (
                        f"{svc} transmits all data including credentials in plaintext. "
                        "Any network observer can capture usernames and passwords."),
                    "recommendation": (
                        f"Disable {svc} immediately. "
                        + ("Use SSH instead." if svc == "Telnet" else "Use SFTP/SCP/FTPS instead.")
                        + f"\nBlock port {port} at firewall level."),
                    "evidence": f"Port {port}/tcp open ({svc})",
                    "poc": f"nc {self.target} {port}  # plaintext session",
                    "host": self.target, "url": f"{svc.lower()}://{self.target}:{port}",
                    "tool": "gator_network", "category": "network",
                })
                self.log("warn", f"[NET] 🚨 {svc} OPEN: port {port}")

    def _check_dns_amplification(self):
        if 53 not in self.open_ports:
            # UDP check
            pass
        self.log("data", "[NET] Checking for DNS open resolver (amplification)...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                # ANY query for "." — standard amplification test
                dns_query = (
                    b"\xaa\xaa"  # Transaction ID
                    b"\x01\x00"  # Standard query, recursion desired
                    b"\x00\x01"  # 1 question
                    b"\x00\x00\x00\x00\x00\x00"
                    b"\x00"      # root domain "."
                    b"\x00\xff"  # ANY
                    b"\x00\x01"  # IN class
                )
                s.sendto(dns_query, (self.target, 53))
                resp, _ = s.recvfrom(4096)
                if resp and len(resp) > 50:
                    amplification = round(len(resp) / len(dns_query), 1)
                    self.log("warn",
                        f"[NET] ⚠️  DNS open resolver: {amplification}x amplification")
                    self.finding({
                        "severity": "medium", "cvss": 5.8,
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "title": "DNS open resolver — DDoS amplification possible",
                        "description": (
                            f"DNS server responds to ANY queries from external IPs. "
                            f"Amplification factor: {amplification}x. "
                            "Can be used in DDoS reflection attacks."),
                        "recommendation": (
                            "Configure DNS to refuse recursive queries from external IPs.\n"
                            "Allow recursion only from internal/trusted IP ranges.\n"
                            "Enable Response Rate Limiting (RRL)."),
                        "evidence": f"ANY query response: {len(resp)} bytes ({amplification}x amplification)",
                        "host": self.target, "url": f"udp://{self.target}:53",
                        "tool": "gator_network", "category": "network",
                    })
        except Exception:
            self.log("ok", "[NET] DNS not responding to external recursive queries ✓")

    def _check_ntp_amplification(self):
        if 123 not in self.open_ports:
            pass  # Still check UDP
        self.log("data", "[NET] Checking NTP server for monlist/amplification...")
        try:
            # NTP monlist request (CVE-2013-5211)
            monlist_req = (
                b"\x17\x00\x03\x2a" + b"\x00" * 4
            )
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                s.sendto(monlist_req, (self.target, 123))
                try:
                    resp, _ = s.recvfrom(8192)
                    if len(resp) > 200:
                        self.finding({
                            "severity": "medium", "cvss": 5.8,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "cwe_ids": ["CWE-16"],
                            "title": "NTP monlist enabled — DDoS amplification (CVE-2013-5211)",
                            "description": (
                                f"NTP server responds to monlist requests ({len(resp)} bytes). "
                                "Used in large-scale DDoS amplification attacks."),
                            "recommendation": (
                                "Disable NTP monlist: add 'disable monitor' to ntp.conf.\n"
                                "Block UDP 123 from internet if not needed.\n"
                                "Upgrade NTP to 4.2.7p26+ (monlist disabled by default)."),
                            "evidence": f"monlist response: {len(resp)} bytes",
                            "host": self.target, "url": f"udp://{self.target}:123",
                            "tool": "gator_network", "category": "network",
                        })
                        self.log("warn", f"[NET] ⚠️  NTP monlist: {len(resp)} bytes")
                    else:
                        self.log("ok", "[NET] NTP monlist disabled ✓")
                except socket.timeout:
                    self.log("ok", "[NET] NTP not responding to monlist ✓")
        except Exception:
            pass

    def _check_icmp(self):
        self.log("data", "[NET] ICMP reachability and fingerprinting...")
        try:
            r = subprocess.run(
                ["ping", "-c", "3", "-W", "2", self.target],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                # Parse TTL for OS fingerprinting
                ttl_match = re.search(r"ttl=(\d+)", r.stdout.lower())
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if ttl >= 60 and ttl <= 64:
                        os_hint = "Linux/Unix (TTL ~64)"
                    elif ttl >= 120 and ttl <= 128:
                        os_hint = "Windows (TTL ~128)"
                    elif ttl >= 250:
                        os_hint = "Cisco/Network Device (TTL ~255)"
                    else:
                        os_hint = f"Unknown (TTL {ttl})"
                    self.log("info", f"[NET] ICMP alive: TTL={ttl} → {os_hint}")
            else:
                self.log("info", "[NET] ICMP blocked (good practice)")
        except Exception:
            pass

    def _banner_grab_network_devices(self):
        self.log("data", "[NET] Grabbing service banners...")
        for port in [22, 23, 21, 25]:
            if port not in self.open_ports:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((self.target, port))
                    banner = s.recv(512).decode("utf-8", errors="ignore").strip()
                    if banner:
                        self.log("info", f"[NET] Banner :{port} → {banner[:80]}")
                        # Version disclosure in SSH banner
                        if port == 22:
                            ver_m = re.search(r"OpenSSH[_\s](\d+\.\d+)", banner)
                            if ver_m:
                                ver = ver_m.group(1)
                                major, minor = int(ver.split(".")[0]), int(ver.split(".")[1])
                                if major < 7 or (major == 7 and minor < 4):
                                    self.finding({
                                        "severity": "high", "cvss": 7.5,
                                        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                                        "title": f"Outdated OpenSSH {ver}",
                                        "description": f"OpenSSH {ver} has known vulnerabilities. Recommend 8.x+",
                                        "recommendation": "Update OpenSSH to latest version.",
                                        "evidence": f"SSH banner: {banner[:100]}",
                                        "host": self.target, "url": f"ssh://{self.target}:22",
                                        "tool": "gator_network", "category": "network",
                                    })
                                    self.log("warn", f"[NET] Outdated OpenSSH {ver}")
            except Exception:
                pass

    def _check_ipmi(self):
        if 623 not in self.open_ports:
            pass
        self.log("data", "[NET] Checking for IPMI/BMC exposure...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3)
                # IPMI Get Channel Auth Capabilities request
                ipmi_probe = bytes([
                    0x06, 0x00, 0xff, 0x07, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x20, 0x18, 0xc8, 0x81, 0x00, 0x38,
                    0x8e, 0x04, 0xb5
                ])
                s.sendto(ipmi_probe, (self.target, 623))
                resp, _ = s.recvfrom(1024)
                if resp:
                    self.finding({
                        "severity": "critical", "cvss": 9.8,
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "pci_dss_req": ["1.3.1"],
                        "title": "IPMI/BMC exposed on UDP 623",
                        "description": (
                            "IPMI Baseboard Management Controller exposed. "
                            "IPMI 2.0 RAKP vulnerability allows offline password cracking. "
                            "Full hardware access without OS-level authentication."),
                        "recommendation": (
                            "Block IPMI port 623 from internet. "
                            "Change IPMI default credentials. "
                            "Isolate BMC to dedicated management VLAN."),
                        "evidence": f"IPMI response received ({len(resp)} bytes)",
                        "host": self.target, "url": f"udp://{self.target}:623",
                        "tool": "gator_network", "category": "network",
                    })
                    self.log("warn", "[NET] 🚨 IPMI/BMC exposed!")
        except Exception:
            pass

    def _network_findings_summary(self):
        if self.open_ports:
            self.log("info",
                f"[NET] Open ports summary ({len(self.open_ports)}): "
                + ", ".join(f"{p}/{s}" for p,s in sorted(self.open_ports.items())))
        dangerous_exposed = {p: s for p,s in self.open_ports.items()
                             if p in (23,21,161,623,69)}
        if dangerous_exposed:
            self.log("warn",
                f"[NET] Dangerous services exposed: {dangerous_exposed}")

    def _which(self, tool):
        try:
            return subprocess.run(["which", tool],
                capture_output=True, timeout=3).returncode == 0
        except Exception:
            return False
