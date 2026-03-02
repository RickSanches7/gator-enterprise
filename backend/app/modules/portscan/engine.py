"""
GATOR PRO Enterprise — Module 2: Port Scanner + CVE Engine
═══════════════════════════════════════════════════════════
Full port scanning pipeline:
  • TCP connect scan (50 threads) — works without root
  • nmap -sV integration (service version + script scan)
  • Banner grabbing on all open ports
  • Service fingerprinting (HTTP/HTTPS/SSH/FTP/SMTP/...)
  • NVD API v2 lookup — maps service version → CVE list
  • Automatic CVSS severity for each CVE
  • Detection of dangerous configurations:
      Redis/MongoDB/Elasticsearch without auth
      Docker API exposed, Kubernetes API
      Database ports accessible from internet
      Telnet/FTP cleartext protocols
  • Banking-specific dangerous port list
"""

import socket
import subprocess
import json
import re
import ssl
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional


# ─── Banking-critical port definitions ───────────────────────
BANKING_PORTS = {
    # Web / HTTPS
    80:    {"service":"HTTP",        "risk":"low",      "desc":"Web server"},
    443:   {"service":"HTTPS",       "risk":"low",      "desc":"Secure web"},
    8080:  {"service":"HTTP-Alt",    "risk":"medium",   "desc":"Alt web / admin panels"},
    8443:  {"service":"HTTPS-Alt",   "risk":"medium",   "desc":"Alt HTTPS / Spring Boot"},
    8000:  {"service":"HTTP-Dev",    "risk":"medium",   "desc":"Dev server / API"},
    8888:  {"service":"HTTP",        "risk":"medium",   "desc":"Jupyter / dev"},
    9090:  {"service":"HTTP",        "risk":"medium",   "desc":"Cockpit / Prometheus"},
    # SSH / Remote
    22:    {"service":"SSH",         "risk":"medium",   "desc":"SSH remote access"},
    23:    {"service":"Telnet",      "risk":"critical", "desc":"CLEARTEXT PROTOCOL"},
    3389:  {"service":"RDP",         "risk":"critical", "desc":"Windows Remote Desktop"},
    5900:  {"service":"VNC",         "risk":"critical", "desc":"VNC remote desktop"},
    5901:  {"service":"VNC",         "risk":"critical", "desc":"VNC remote desktop #1"},
    # Email
    25:    {"service":"SMTP",        "risk":"medium",   "desc":"Mail server"},
    110:   {"service":"POP3",        "risk":"medium",   "desc":"POP3 cleartext"},
    143:   {"service":"IMAP",        "risk":"medium",   "desc":"IMAP cleartext"},
    465:   {"service":"SMTPS",       "risk":"low",      "desc":"SMTP SSL"},
    587:   {"service":"Submission",  "risk":"low",      "desc":"Mail submission"},
    993:   {"service":"IMAPS",       "risk":"low",      "desc":"IMAP SSL"},
    995:   {"service":"POP3S",       "risk":"low",      "desc":"POP3 SSL"},
    # FTP
    21:    {"service":"FTP",         "risk":"critical", "desc":"CLEARTEXT FILE TRANSFER"},
    990:   {"service":"FTPS",        "risk":"low",      "desc":"FTP SSL"},
    # Databases — NEVER public
    1433:  {"service":"MSSQL",       "risk":"critical", "desc":"Microsoft SQL Server"},
    1521:  {"service":"Oracle DB",   "risk":"critical", "desc":"Oracle Database"},
    3306:  {"service":"MySQL",       "risk":"critical", "desc":"MySQL database"},
    5432:  {"service":"PostgreSQL",  "risk":"critical", "desc":"PostgreSQL database"},
    1830:  {"service":"Oracle DB2",  "risk":"critical", "desc":"Oracle DB alternate"},
    27017: {"service":"MongoDB",     "risk":"critical", "desc":"MongoDB — auth disabled by default"},
    27018: {"service":"MongoDB",     "risk":"critical", "desc":"MongoDB shard"},
    6379:  {"service":"Redis",       "risk":"critical", "desc":"Redis — NO AUTH by default"},
    6380:  {"service":"Redis TLS",   "risk":"high",     "desc":"Redis TLS"},
    9200:  {"service":"Elasticsearch","risk":"critical","desc":"Elasticsearch — public by default"},
    9300:  {"service":"Elasticsearch","risk":"high",    "desc":"Elasticsearch cluster"},
    5984:  {"service":"CouchDB",     "risk":"critical", "desc":"CouchDB"},
    # Docker / Kubernetes
    2375:  {"service":"Docker API",  "risk":"critical", "desc":"Docker unencrypted API — CONTAINER ESCAPE"},
    2376:  {"service":"Docker TLS",  "risk":"high",     "desc":"Docker TLS API"},
    2379:  {"service":"etcd",        "risk":"critical", "desc":"etcd — Kubernetes secrets"},
    6443:  {"service":"K8s API",     "risk":"critical", "desc":"Kubernetes API server"},
    10250: {"service":"Kubelet",     "risk":"critical", "desc":"Kubernetes kubelet API"},
    # Message queues
    5672:  {"service":"RabbitMQ",    "risk":"high",     "desc":"RabbitMQ AMQP"},
    15672: {"service":"RabbitMQ UI", "risk":"critical", "desc":"RabbitMQ management UI"},
    9092:  {"service":"Kafka",       "risk":"high",     "desc":"Apache Kafka"},
    # Monitoring / Admin
    8161: {"service":"ActiveMQ UI", "risk":"critical",  "desc":"ActiveMQ admin (default: admin/admin)"},
    61616:{"service":"ActiveMQ",    "risk":"high",      "desc":"ActiveMQ broker"},
    4848: {"service":"GlassFish",   "risk":"critical",  "desc":"GlassFish admin console"},
    7001: {"service":"WebLogic",    "risk":"critical",  "desc":"WebLogic admin console"},
    7002: {"service":"WebLogic SSL","risk":"critical",  "desc":"WebLogic admin SSL"},
    9000: {"service":"SonarQube",   "risk":"medium",    "desc":"SonarQube"},
    4040: {"service":"Spark UI",    "risk":"medium",    "desc":"Apache Spark"},
    # SNMP / Network
    161:  {"service":"SNMP",        "risk":"medium",    "desc":"SNMP — often public/private community"},
    389:  {"service":"LDAP",        "risk":"high",      "desc":"LDAP — potential info disclosure"},
    636:  {"service":"LDAPS",       "risk":"medium",    "desc":"LDAP SSL"},
    88:   {"service":"Kerberos",    "risk":"medium",    "desc":"Kerberos authentication"},
    # SWIFT / Financial
    4711: {"service":"SWIFT Alliance","risk":"critical","desc":"SWIFT Alliance Gateway"},
    # Java / App servers
    8009: {"service":"AJP",         "risk":"critical",  "desc":"Apache JServ Protocol — Ghostcat CVE-2020-1938"},
    11211:{"service":"Memcached",   "risk":"critical",  "desc":"Memcached — NO AUTH by default"},
    50070:{"service":"Hadoop",      "risk":"critical",  "desc":"Hadoop NameNode UI"},
    50075:{"service":"Hadoop DN",   "risk":"critical",  "desc":"Hadoop DataNode"},
    2181: {"service":"ZooKeeper",   "risk":"critical",  "desc":"Apache ZooKeeper"},
    # VPN / Firewall
    500:  {"service":"IKE/IPSec",   "risk":"medium",    "desc":"VPN IKE"},
    1194: {"service":"OpenVPN",     "risk":"medium",    "desc":"OpenVPN"},
    1723: {"service":"PPTP",        "risk":"high",      "desc":"PPTP VPN — broken protocol"},
}

# Default ports to scan if no range specified (banking top-100)
DEFAULT_PORTS = sorted(list(BANKING_PORTS.keys()) + [
    8081,8082,8083,8084,8085,8086,8087,8088,8089,
    9001,9002,9003,9004,9005,9010,9020,9080,9443,
    10000,10443,3000,3001,4000,4001,5000,5001,
    7070,7080,7443,6000,6001,6060,6061,
])


class PortScanEngine:
    """
    Multi-threaded port scanner with CVE lookup.
    Uses TCP connect scan (no root required).
    Falls back to nmap -sV if available.
    """

    def __init__(self, target: str, scan_id: str, db, push_event: Callable,
                 port_from: int = 1, port_to: int = 1024, **kwargs):
        self.target     = self._clean(target)
        self.scan_id    = scan_id
        self.db         = db
        self.push_event = push_event
        self.port_from  = port_from
        self.port_to    = port_to
        self.results = {
            "target":     self.target,
            "ip":         "",
            "open_ports": [],
            "closed":     0,
            "scanned":    0,
            "findings":   [],
        }

    def _clean(self, t: str) -> str:
        return t.replace("https://","").replace("http://","").split("/")[0].split(":")[0].strip()

    def log(self, level: str, msg: str, data: dict = None):
        self.push_event(self.db, self.scan_id, "log", level, msg, data or {})

    # ═══════════════════════════════════════════════════════════
    def run(self) -> dict:
        # Resolve target IP
        try:
            ip = socket.gethostbyname(self.target)
            self.results["ip"] = ip
            self.log("info", f"╔══ PORT SCAN ══ {self.target} ({ip}) ══╗")
        except Exception as e:
            self.log("err", f"[PORTS] Cannot resolve {self.target}: {e}")
            return self.results

        # Determine port list
        if self.port_from == 1 and self.port_to == 1024:
            # Use smart banking port list + range 1-1024
            ports = sorted(set(DEFAULT_PORTS + list(range(1, 1025))))
        else:
            ports = list(range(self.port_from, self.port_to + 1))
        self.results["scanned"] = len(ports)

        self.log("info",
            f"[PORTS] Scanning {len(ports)} ports on {self.target} (50 threads)...")

        # Try nmap first (much more accurate — service versions for CVE lookup)
        if self._which("nmap"):
            self.log("info","[PORTS] nmap detected — using service version detection (-sV)")
            nmap_results = self._nmap_scan(ip, ports[:200])  # nmap top ports
            if nmap_results:
                self.results["open_ports"] = nmap_results
                self.log("ok",
                    f"[PORTS] nmap: {len(nmap_results)} open ports with service info")
                # Now CVE lookup
                self._cve_lookup_all()
                return self.results

        # Fallback: pure Python TCP connect scan
        self.log("info","[PORTS] Using Python TCP connect scan (nmap not found)")
        open_ports = self._tcp_scan(self.target, ports)
        self.results["open_ports"] = open_ports
        self.log("ok",
            f"[PORTS] TCP scan: {len(open_ports)} open / {len(ports)} scanned")

        # Banner grabbing on open ports
        self._grab_banners()

        # CVE lookup based on service versions
        self._cve_lookup_all()

        self.log("info", f"╚══ PORT SCAN DONE ══ {len(self.results['open_ports'])} open ports ══╝")
        return self.results

    # ─── nmap scan ────────────────────────────────────────────
    def _nmap_scan(self, ip: str, ports: list) -> list:
        port_str = ",".join(str(p) for p in ports[:500])
        try:
            # -sV: version detection, -sC: default scripts, --open: only open
            # -T4: aggressive timing, --version-intensity 5
            cmd = [
                "nmap", "-sV", "-sC", "--open",
                "-T4", "--version-intensity", "5",
                "--script", "banner,http-title,http-server-header,ssl-cert,ftp-anon,smtp-commands",
                "-p", port_str, ip,
                "-oX", "-"  # XML output to stdout
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(r.stdout, ip)
        except subprocess.TimeoutExpired:
            self.log("warn","[PORTS] nmap timed out — falling back to TCP scan")
            return []
        except Exception as e:
            self.log("warn", f"[PORTS] nmap error: {e}")
            return []

    def _parse_nmap_xml(self, xml: str, ip: str) -> list:
        """Parse nmap XML output into structured port list."""
        ports = []
        # Extract open port blocks
        port_blocks = re.findall(
            r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>',
            xml, re.DOTALL)
        for proto, portid, block in port_blocks:
            # Check state
            state_m = re.search(r'<state state="(\w+)"', block)
            if not state_m or state_m.group(1) != "open":
                continue

            port = int(portid)
            # Service info
            svc_m = re.search(
                r'<service name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?[^>]*(?:extrainfo="([^"]*)")?',
                block)
            service = ""
            version = ""
            banner  = ""
            if svc_m:
                service = svc_m.group(1) or ""
                product = svc_m.group(2) or ""
                ver     = svc_m.group(3) or ""
                extra   = svc_m.group(4) or ""
                version = f"{product} {ver} {extra}".strip()

            # Script output (banner, title, etc)
            scripts = re.findall(r'<script id="([^"]+)" output="([^"]+)"', block)
            script_outputs = {s[0]: s[1] for s in scripts}
            banner = script_outputs.get("banner", script_outputs.get("http-title",""))[:200]

            entry = {
                "port":    port,
                "proto":   proto,
                "service": service,
                "version": version,
                "banner":  banner,
                "scripts": script_outputs,
                "source":  "nmap",
            }
            ports.append(entry)
            self.push_event(self.db, self.scan_id, "port", "ok",
                f"[OPEN] {port}/{proto} → {service} {version}",
                {"port": port, "service": service, "version": version})

        return ports

    # ─── TCP Connect Scan ─────────────────────────────────────
    def _tcp_scan(self, host: str, ports: list) -> list:
        open_ports = []
        done = [0]
        total = len(ports)

        def check(port):
            done[0] += 1
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.8)
                    if s.connect_ex((host, port)) == 0:
                        info = BANKING_PORTS.get(port, {})
                        entry = {
                            "port":    port,
                            "proto":   "tcp",
                            "service": info.get("service",""),
                            "version": "",
                            "banner":  "",
                            "source":  "tcp_connect",
                        }
                        return entry
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as ex:
            futs = {ex.submit(check, p): p for p in ports}
            for f in as_completed(futs):
                r = f.result()
                if r:
                    open_ports.append(r)
                    self.push_event(self.db, self.scan_id, "port", "ok",
                        f"[OPEN] {r['port']}/tcp → {r['service'] or 'unknown'}",
                        {"port": r["port"], "service": r["service"]})
                if done[0] % 200 == 0:
                    self.push_event(self.db, self.scan_id, "progress", "info",
                        f"[PORTS] {done[0]}/{total} | found: {len(open_ports)}",
                        {"progress": round(done[0]/total*100, 1)})

        return sorted(open_ports, key=lambda x: x["port"])

    # ─── Banner Grabbing ──────────────────────────────────────
    def _grab_banners(self):
        self.log("info","[PORTS] Grabbing service banners...")
        for entry in self.results["open_ports"]:
            if entry.get("banner"):
                continue  # already have banner from nmap
            port = entry["port"]
            banner = self._grab_banner(self.target, port)
            if banner:
                entry["banner"] = banner
                self.log("info",
                    f"[BANNER] :{port} → {banner[:80]}")

    def _grab_banner(self, host: str, port: int) -> str:
        try:
            if port in [80, 8080, 8000, 8081, 8088]:
                return self._http_banner(host, port, ssl=False)
            elif port in [443, 8443, 9443]:
                return self._http_banner(host, port, ssl=True)
            else:
                return self._raw_banner(host, port)
        except Exception:
            return ""

    def _raw_banner(self, host: str, port: int, timeout: float = 2.0) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                # Send probe depending on service
                probes = {
                    22:  b"",          # SSH sends banner first
                    21:  b"",          # FTP sends banner first
                    25:  b"EHLO x\r\n",
                    110: b"",
                    143: b"",
                    3306: b"",
                    5432: b"",
                }
                probe = probes.get(port, b"\r\n")
                if probe:
                    s.send(probe)
                data = s.recv(1024)
                return data.decode("utf-8", errors="ignore").strip()[:200]
        except Exception:
            return ""

    def _http_banner(self, host: str, port: int, ssl: bool) -> str:
        try:
            import urllib.request
            scheme = "https" if ssl else "http"
            url = f"{scheme}://{host}:{port}/"
            req = urllib.request.Request(url)
            req.add_header("User-Agent","GATOR-PRO/2.0")
            ctx = None
            if ssl:
                import ssl as ssl_mod
                ctx = ssl_mod.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_mod.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=4) as resp:
                server = resp.headers.get("Server","")
                body = resp.read(4096).decode("utf-8", errors="ignore")
                title_m = re.search(r"<title[^>]*>([^<]{1,100})</title>", body, re.IGNORECASE)
                title = title_m.group(1).strip() if title_m else ""
                return f"HTTP/{resp.status} Server:{server} Title:{title}"
        except urllib.error.HTTPError as e:
            return f"HTTP/{e.code}"
        except Exception:
            return ""

    # ─── NVD CVE API Lookup ───────────────────────────────────
    def _cve_lookup_all(self):
        self.log("info","[CVE] Looking up CVEs for discovered services (NVD API)...")
        total_cve = 0
        for entry in self.results["open_ports"]:
            version = entry.get("version","").strip()
            service = entry.get("service","").strip()
            if not version and service:
                version = service
            if not version:
                continue

            cves = self._nvd_lookup(version, entry["port"])
            if cves:
                entry["cves"] = cves
                total_cve += len(cves)
                worst = max(cves, key=lambda c: c.get("cvss",0))
                self.log("warn",
                    f"[CVE] Port {entry['port']} ({version[:30]}): "
                    f"{len(cves)} CVEs | worst: {worst['id']} CVSS {worst.get('cvss','?')}")
                self.push_event(self.db, self.scan_id, "cve", "warn",
                    f"CVE found: {entry['port']}/{service} → {len(cves)} vulns",
                    {"port": entry["port"], "cves": cves[:5]})
            time.sleep(0.5)  # NVD rate limit: 5 req/30s without API key

        self.log("ok", f"[CVE] Total CVEs found: {total_cve}")

    def _nvd_lookup(self, keyword: str, port: int) -> list:
        """Query NVD API v2 for CVEs matching service version string."""
        # Extract meaningful search terms
        # e.g. "Apache httpd 2.4.51" → "Apache httpd 2.4.51"
        # e.g. "OpenSSH 7.9p1" → "OpenSSH 7.9"
        search = self._extract_cpe_keyword(keyword)
        if not search:
            return []

        try:
            from app.core.config import settings
            api_key = settings.NVD_API_KEY or ""
        except Exception:
            api_key = ""

        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?keywordSearch={urllib.parse.quote(search)}"
               f"&resultsPerPage=10")
        try:
            import urllib.parse
            req = urllib.request.Request(url)
            req.add_header("User-Agent","GATOR-PRO/2.0")
            if api_key:
                req.add_header("apiKey", api_key)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                data = json.loads(resp.read())

            cves = []
            for item in data.get("vulnerabilities", [])[:10]:
                vuln  = item.get("cve", {})
                cve_id = vuln.get("id","")
                desc_list = vuln.get("descriptions",[])
                desc = next((d["value"] for d in desc_list if d.get("lang")=="en"), "")

                # CVSS score
                metrics = vuln.get("metrics",{})
                cvss_score = 0.0
                cvss_vector = ""
                severity = "UNKNOWN"
                for v in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                    mlist = metrics.get(v,[])
                    if mlist:
                        cvss_data = mlist[0].get("cvssData",{})
                        cvss_score = float(cvss_data.get("baseScore",0))
                        cvss_vector = cvss_data.get("vectorString","")
                        severity = cvss_data.get("baseSeverity",
                            "HIGH" if cvss_score >= 7 else "MEDIUM" if cvss_score >= 4 else "LOW")
                        break

                cves.append({
                    "id":          cve_id,
                    "description": desc[:300],
                    "cvss":        cvss_score,
                    "cvss_vector": cvss_vector,
                    "severity":    severity,
                    "port":        port,
                    "service":     keyword[:50],
                })
            return [c for c in cves if c["cvss"] > 0]

        except Exception:
            return []

    def _extract_cpe_keyword(self, version_str: str) -> str:
        """Extract searchable keyword from version string."""
        version_str = version_str.strip()
        if not version_str or len(version_str) < 3:
            return ""
        # Remove generic/unhelpful terms
        skip = {"tcp","udp","open","syn-ack","ttl","microsoft","windows"}
        words = version_str.split()
        filtered = [w for w in words if w.lower() not in skip and len(w) > 2]
        return " ".join(filtered[:4])  # max 4 words for precise search

    def _which(self, tool: str) -> bool:
        try:
            return subprocess.run(["which",tool],
                capture_output=True, timeout=3).returncode == 0
        except Exception:
            return False


# ─── Separate analyzer — generates Finding objects ───────────
def analyze_ports(port_results: dict, target: str) -> list:
    """
    Convert port scan results → structured findings with CVSS scores.
    Called by Celery task after PortScanEngine.run().
    """
    findings = []
    open_ports = port_results.get("open_ports", [])

    for entry in open_ports:
        port     = entry.get("port")
        service  = entry.get("service","")
        version  = entry.get("version","")
        banner   = entry.get("banner","")
        cves     = entry.get("cves",[])

        info = BANKING_PORTS.get(port, {})
        risk = info.get("risk","low")
        desc = info.get("desc","")

        # ── Generate CVE-based findings ──────────────────────
        for cve in cves:
            cvss = cve.get("cvss", 0)
            sev  = _cvss_to_severity(cvss)
            findings.append({
                "severity":       sev,
                "cvss":           cvss,
                "cvss_vector":    cve.get("cvss_vector",""),
                "cve_ids":        [cve["id"]],
                "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                "title":          f"{cve['id']} — {service} on port {port}",
                "description":    cve.get("description",""),
                "recommendation": (f"Update {service} to a patched version. "
                                   f"Review vendor advisories for {cve['id']}."),
                "evidence":       f"Port {port} running {version}. {cve['id']} CVSS {cvss}",
                "host":           target,
                "port":           port,
                "tool":           "nvd_api",
                "category":       "portscan",
                "pci_dss_req":    ["6.3.3","6.2.4"],
            })

        # ── Generate dangerous-service findings ──────────────
        if risk in ("critical","high") and port in BANKING_PORTS:
            cvss_map = {"critical":9.8,"high":7.5,"medium":5.0,"low":3.1}
            cvss = cvss_map.get(risk, 5.0)
            sev  = _cvss_to_severity(cvss)

            # Special cases
            title  = f"Dangerous service exposed: {service} (port {port})"
            rec    = _remediation(port, service)

            owasp  = "A05:2021-Security Misconfiguration"
            pci    = ["1.3.1","1.3.2","6.4.1"]

            if port == 23:   # Telnet
                owasp = "A02:2021-Cryptographic Failures"
                pci   = ["4.2.1","8.6.1"]
            elif port == 21:  # FTP
                owasp = "A02:2021-Cryptographic Failures"
            elif port == 3389:  # RDP
                owasp = "A05:2021-Security Misconfiguration"
                pci   = ["1.3.2","8.2.6"]
            elif port in (6379,27017,9200,5432,3306,1433,1521):  # DB
                owasp = "A01:2021-Broken Access Control"
                pci   = ["1.3.1","7.3.1","8.3.1"]

            findings.append({
                "severity":       sev,
                "cvss":           cvss,
                "owasp_category": owasp,
                "pci_dss_req":    pci,
                "title":          title,
                "description":    (f"Port {port}/tcp is open and running {service}. "
                                   f"{desc}. This service should not be publicly accessible."),
                "recommendation": rec,
                "evidence":       f"Port {port}/tcp open | Service: {service} | "
                                  f"Banner: {banner[:100] or 'N/A'}",
                "host":           target,
                "port":           port,
                "tool":           "portscan",
                "category":       "network",
            })

    # Deduplicate by title+host
    seen = set()
    unique = []
    for f in findings:
        key = f"{f['host']}:{f.get('port')}:{f['title'][:50]}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0:    return "low"
    return "info"


def _remediation(port: int, service: str) -> str:
    remediations = {
        23:    "Immediately disable Telnet. Use SSH instead. Block port 23 at firewall.",
        21:    "Disable FTP. Use SFTP or FTPS. Block port 21 at perimeter firewall.",
        3389:  "Restrict RDP access via VPN only. Enable NLA. Block port 3389 externally.",
        6379:  "Set Redis requirepass. Bind to 127.0.0.1 only. Block port 6379 at firewall.",
        27017: "Enable MongoDB authentication. Bind to localhost. Block port 27017.",
        9200:  "Enable Elasticsearch X-Pack security. Bind to localhost. Block port 9200.",
        5432:  "Restrict pg_hba.conf. Allow only app server IPs. Block from internet.",
        3306:  "Restrict MySQL bind-address. Use firewall rules. Require SSL connections.",
        1433:  "Restrict MSSQL access to app servers only. Disable sa account.",
        1521:  "Restrict Oracle listener to internal IPs. Enable audit logging.",
        2375:  "CRITICAL: Disable Docker API immediately. Use TLS (2376) with certificates.",
        2379:  "CRITICAL: Enable etcd TLS and authentication. Restrict to Kubernetes nodes.",
        8161:  "Change ActiveMQ default credentials (admin/admin). Restrict to localhost.",
        7001:  "Restrict WebLogic console to internal network. Enable SSL. Change admin password.",
        4848:  "Restrict GlassFish admin to localhost. Change admin password.",
        11211: "Bind Memcached to localhost only. Block port 11211 externally.",
    }
    return remediations.get(port,
        f"Restrict access to {service} (port {port}) via firewall rules. "
        f"Ensure strong authentication is enabled. "
        f"Consider whether this service needs to be publicly accessible.")
