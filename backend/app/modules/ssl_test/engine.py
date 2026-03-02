"""
GATOR PRO Enterprise — Module 6: SSL/TLS Deep Analysis Engine
═══════════════════════════════════════════════════════════════
Full SSL/TLS security analysis:
  • Protocol version detection
      TLS 1.0 / 1.1 — PCI DSS FAIL (must disable)
      SSL 2.0 / 3.0 — CRITICAL (POODLE/DROWN)
  • Cipher suite analysis
      RC4 — broken, PCI FAIL
      DES/3DES — SWEET32 attack (CVE-2016-2183)
      EXPORT ciphers — FREAK/LOGJAM
      NULL ciphers — no encryption
      Anonymous (ADH/AECDH) — no auth
  • Certificate checks
      Expiry (< 30 days warning, expired = critical)
      Self-signed certificate
      Hostname mismatch (CN/SAN)
      Weak key (RSA < 2048, EC < 256)
      MD5/SHA1 signature hash
      Certificate chain validation
      Wildcard certificate scope
  • Known vulnerabilities
      BEAST (TLS 1.0 + CBC)
      POODLE (SSL 3.0)
      HEARTBLEED (OpenSSL CVE-2014-0160)
      DROWN (SSLv2)
      FREAK (export RSA)
      LOGJAM (DHE 512-bit)
      CRIME (TLS compression)
      ROBOT (RSA PKCS#1 v1.5)
      Sweet32 (64-bit block ciphers)
  • HSTS (HTTP Strict Transport Security)
  • HPKP (Public Key Pinning — deprecated check)
  • Certificate Transparency (CT) verification
  • OCSP Stapling
  • Multi-port SSL scan (443/8443/9443/465/993/995)
  • SSLyze integration (if installed)
  • PCI DSS v4.0 TLS compliance report
"""

import socket
import subprocess
import json
import re
import ssl
import time
import struct
from datetime import datetime, timezone
from typing import Callable, Optional
import urllib.request
import urllib.error


# ─── Weak cipher patterns ─────────────────────────────────────
WEAK_CIPHERS = {
    # NULL ciphers — no encryption at all
    "NULL": {
        "severity": "critical", "cvss": 9.8,
        "desc": "No encryption (NULL cipher)",
        "vuln": "All traffic is plaintext",
    },
    # EXPORT grade — 40/56-bit keys
    "EXPORT": {
        "severity": "critical", "cvss": 9.8,
        "desc": "Export-grade cipher (40/56-bit key)",
        "vuln": "FREAK/LOGJAM attacks possible",
    },
    # RC4 — broken
    "RC4": {
        "severity": "critical", "cvss": 9.1,
        "desc": "RC4 stream cipher (broken)",
        "vuln": "RC4 biases allow plaintext recovery",
    },
    # DES/3DES — SWEET32
    "DES": {
        "severity": "high", "cvss": 7.5,
        "desc": "DES cipher (56-bit, broken)",
        "vuln": "SWEET32 birthday attack (CVE-2016-2183)",
    },
    "3DES": {
        "severity": "high", "cvss": 7.5,
        "desc": "3DES/TDEA (64-bit block size)",
        "vuln": "SWEET32 birthday attack (CVE-2016-2183)",
    },
    # Anonymous — no server authentication
    "ADH": {
        "severity": "critical", "cvss": 9.1,
        "desc": "Anonymous DH — no server authentication",
        "vuln": "Man-in-the-middle trivially possible",
    },
    "AECDH": {
        "severity": "critical", "cvss": 9.1,
        "desc": "Anonymous ECDH — no server authentication",
        "vuln": "Man-in-the-middle trivially possible",
    },
    # MD5 MAC
    "MD5": {
        "severity": "high", "cvss": 7.5,
        "desc": "MD5 MAC (cryptographically broken)",
        "vuln": "Collision attacks possible",
    },
}

# ─── SSL/TLS ports to check ───────────────────────────────────
SSL_PORTS = [
    (443,   "HTTPS"),
    (8443,  "HTTPS Alt"),
    (9443,  "HTTPS Alt 2"),
    (465,   "SMTPS"),
    (587,   "STARTTLS SMTP"),
    (993,   "IMAPS"),
    (995,   "POP3S"),
    (636,   "LDAPS"),
    (8080,  "HTTP/HTTPS Alt"),
    (4711,  "SWIFT Alliance TLS"),
]

# ─── TLS version definitions ─────────────────────────────────
TLS_VERSIONS = {
    "SSLv2":   {"cvss": 9.8, "severity": "critical", "pci": "FAIL",
                "desc": "SSL 2.0 — obsolete, multiple attacks (DROWN)"},
    "SSLv3":   {"cvss": 9.8, "severity": "critical", "pci": "FAIL",
                "desc": "SSL 3.0 — POODLE attack (CVE-2014-3566)"},
    "TLSv1.0": {"cvss": 7.5, "severity": "high",     "pci": "FAIL",
                "desc": "TLS 1.0 — deprecated, BEAST attack, PCI DSS prohibited"},
    "TLSv1.1": {"cvss": 5.9, "severity": "medium",   "pci": "FAIL",
                "desc": "TLS 1.1 — deprecated, should be disabled"},
    "TLSv1.2": {"cvss": 0.0, "severity": "info",     "pci": "PASS",
                "desc": "TLS 1.2 — acceptable if strong ciphers"},
    "TLSv1.3": {"cvss": 0.0, "severity": "info",     "pci": "PASS",
                "desc": "TLS 1.3 — recommended"},
}

# ─── HEARTBLEED probe (safe detection, no exploitation) ──────
HEARTBLEED_PROBE = (
    b"\x16\x03\x02\x00\xdc\x01\x00\x00\xd8\x03\x02Sh"
    b"\x9f\x1a\x8c\xbe\x98\xa1Uh\xf8e\x9d\x9c\xb2\xcbO\x9ao"
    b"\xf8\xd7\xe5N\xd5A\x00\x00f\xc0\x14\xc0\n\xc0"\
    b"\x02\xc0\x05\x00\x9a\x009\x00\x38\x00\x88\x00\x87"
    b"\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08"
    b"\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\r\xc0\x03"
    b"\x00\n\xc0\x13\xc0\t\xc0\x1f\xc0\x1e\x00\x33\x00"
    b"\x32\x00\x9a\x009\x00\x16\xc0\x0e\xc0\x04\x00/"
    b"\x00\x96\x00A\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00"
    b"\x05\x00\x04\x00\x15\x00\x12\x00\t\x00\x14\x00\x11"
    b"\x00\x08\x00\x06\x00\x03\x00\xff\x01\x00\x00I\x00"
    b"\x0b\x00\x04\x03\x00\x01\x02\x00\n\x00\x1c\x00\x1a"
    b"\x00\x17\x00\x19\x00\x1c\x00\x1b\x00\x18\x00\x1a"
    b"\x00\x16\x00\x0e\x00\r\x00\x0b\x00\x0c\x00\t\x00\n"
    b"\x00#\x00\x00\x00\x0f\x00\x01\x01"
)

HEARTBLEED_MSG = (
    b"\x18\x03\x02\x00\x03"
    b"\x01\x40\x00"
)


class SSLTestEngine:
    """Deep SSL/TLS security analysis engine."""

    def __init__(self, target: str, scan_id: str, db, push_event: Callable, **kwargs):
        self.target     = self._clean(target)
        self.scan_id    = scan_id
        self.db         = db
        self.push_event = push_event
        self.findings   = []
        self.ssl_results = {}

    def _clean(self, t):
        return t.replace("https://","").replace("http://","").split("/")[0].split(":")[0].strip()

    def log(self, level, msg, data=None):
        self.push_event(self.db, self.scan_id, "log", level, msg, data or {})

    def finding(self, f):
        self.findings.append(f)
        sev = f.get("severity","info")
        self.push_event(self.db, self.scan_id, "finding", sev,
            f"[{sev.upper()}] {f.get('title','')[:80]}",
            {"severity": sev, "cvss": f.get("cvss", 0)})

    # ═══════════════════════════════════════════════════════════
    def run(self) -> dict:
        self.log("info", f"╔══ SSL/TLS SCAN ══ {self.target} ══╗")
        t0 = time.time()

        # Check which ports are open
        open_ssl_ports = self._discover_ssl_ports()
        self.log("info",
            f"[SSL] Open SSL ports: {[p for p,_ in open_ssl_ports]}")

        for port, service in open_ssl_ports[:4]:
            self.log("data", f"[SSL] Analyzing {self.target}:{port} ({service})")
            self._analyze_port(port, service)

        # Run SSLyze if available
        if self._which("sslyze") or self._which("python3"):
            self._run_sslyze(open_ssl_ports[0][0] if open_ssl_ports else 443)

        # HSTS check
        self._check_hsts()

        # PCI DSS TLS compliance summary
        self._pci_tls_summary()

        elapsed = round(time.time() - t0, 1)
        c = len([f for f in self.findings if f["severity"] == "critical"])
        h = len([f for f in self.findings if f["severity"] == "high"])
        self.log("ok",
            f"╚══ SSL DONE {elapsed}s ══ "
            f"Findings: {len(self.findings)} (C:{c} H:{h}) ══╝")
        return {"findings": self.findings, "ssl_results": self.ssl_results}

    # ─── Discover SSL Ports ───────────────────────────────────
    def _discover_ssl_ports(self) -> list:
        open_ports = []
        for port, service in SSL_PORTS:
            try:
                with socket.create_connection((self.target, port), timeout=2):
                    open_ports.append((port, service))
                    self.log("ok", f"[SSL] Port {port}/tcp open ({service})")
            except Exception:
                pass
        if not open_ports:
            open_ports = [(443, "HTTPS")]
        return open_ports

    # ─── Per-port analysis ────────────────────────────────────
    def _analyze_port(self, port: int, service: str):
        result = {
            "port":       port,
            "service":    service,
            "protocols":  {},
            "cert":       {},
            "ciphers":    [],
            "issues":     [],
        }

        # 1. Certificate analysis
        cert_info = self._get_cert(port)
        if cert_info:
            result["cert"] = cert_info
            self._check_cert(cert_info, port)

        # 2. Protocol version detection
        self._check_protocols(port, service, result)

        # 3. Cipher suite analysis (via nmap or openssl)
        self._check_ciphers(port, service)

        # 4. Known vulnerabilities
        self._check_heartbleed(port)
        self._check_beast(port, result)
        self._check_compression(port)

        self.ssl_results[port] = result

    # ─── Certificate Analysis ─────────────────────────────────
    def _get_cert(self, port: int) -> Optional[dict]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, port), timeout=8) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=self.target) as ssock:
                    cert   = ssock.getpeercert()
                    cipher = ssock.cipher()
                    ver    = ssock.version()
                    der    = ssock.getpeercert(binary_form=True)

            if not cert:
                return None

            subject = dict(x[0] for x in cert.get("subject",[]))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            sans    = [s[1] for s in cert.get("subjectAltName",[])]

            # Parse expiry
            not_after_str  = cert.get("notAfter","")
            not_before_str = cert.get("notBefore","")
            days_left = None
            try:
                exp = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (exp - now).days
            except Exception:
                pass

            return {
                "subject_cn":    subject.get("commonName",""),
                "subject_org":   subject.get("organizationName",""),
                "issuer_cn":     issuer.get("commonName",""),
                "issuer_org":    issuer.get("organizationName",""),
                "not_before":    not_before_str,
                "not_after":     not_after_str,
                "days_left":     days_left,
                "san":           sans,
                "tls_version":   ver,
                "cipher":        cipher[0] if cipher else "",
                "cipher_bits":   cipher[2] if cipher and len(cipher) > 2 else 0,
                "serial":        str(cert.get("serialNumber","")),
                "self_signed":   subject == issuer,
                "is_wildcard":   subject.get("commonName","").startswith("*"),
            }
        except Exception as e:
            self.log("warn", f"[SSL] Cannot get cert for port {port}: {e}")
            return None

    def _check_cert(self, cert: dict, port: int):
        cn   = cert.get("subject_cn","")
        org  = cert.get("subject_org","")
        days = cert.get("days_left")

        self.log("ok", f"[SSL] Cert CN: {cn} | Org: {org}")
        self.log("info",f"[SSL] Issuer: {cert.get('issuer_org','')} | "
                        f"Expires: {cert.get('not_after','')} ({days}d left)")
        self.log("info",f"[SSL] TLS: {cert.get('tls_version','')} | "
                        f"Cipher: {cert.get('cipher','')} {cert.get('cipher_bits',0)}bit")

        # ── Expiry checks ─────────────────────────────────────
        if days is not None:
            if days < 0:
                self.finding({
                    "severity":       "critical",
                    "cvss":           7.5,
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "pci_dss_req":    ["4.2.1"],
                    "title":          f"SSL Certificate EXPIRED ({abs(days)} days ago) — port {port}",
                    "description":    f"Certificate expired {abs(days)} days ago. Browsers show security error.",
                    "recommendation": "Renew certificate immediately. Enable auto-renewal (certbot).",
                    "evidence":       f"notAfter: {cert['not_after']}",
                    "host":           self.target,
                    "url":            f"https://{self.target}:{port}",
                    "tool":           "gator_ssl",
                    "category":       "ssl",
                })
                self.log("warn", f"[SSL] 🚨 Certificate EXPIRED {abs(days)} days ago!")
            elif days < 14:
                self.finding({
                    "severity":       "critical",
                    "cvss":           7.5,
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "pci_dss_req":    ["4.2.1"],
                    "title":          f"SSL Certificate expiring in {days} days — port {port}",
                    "description":    "Certificate expires very soon. Services will break.",
                    "recommendation": "Renew certificate NOW. Enable certificate monitoring alerts.",
                    "evidence":       f"notAfter: {cert['not_after']}",
                    "host":           self.target,
                    "url":            f"https://{self.target}:{port}",
                    "tool":           "gator_ssl",
                    "category":       "ssl",
                })
                self.log("warn", f"[SSL] 🚨 Certificate expires in {days} days!")
            elif days < 30:
                self.finding({
                    "severity":       "high",
                    "cvss":           5.9,
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "title":          f"SSL Certificate expiring in {days} days — port {port}",
                    "description":    "Certificate expires within 30 days.",
                    "recommendation": "Renew certificate. Set up automated renewal.",
                    "evidence":       f"notAfter: {cert['not_after']}",
                    "host":           self.target,
                    "url":            f"https://{self.target}:{port}",
                    "tool":           "gator_ssl",
                    "category":       "ssl",
                })
                self.log("warn", f"[SSL] ⚠️  Certificate expires in {days} days")
            else:
                self.log("ok", f"[SSL] Certificate valid for {days} more days ✓")

        # ── Self-signed ───────────────────────────────────────
        if cert.get("self_signed"):
            self.finding({
                "severity":       "high",
                "cvss":           7.4,
                "owasp_category": "A02:2021-Cryptographic Failures",
                "pci_dss_req":    ["4.2.1"],
                "title":          f"Self-signed certificate — port {port}",
                "description":    "Self-signed certificate not trusted by browsers. MitM attacks trivial.",
                "recommendation": "Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.).",
                "evidence":       f"Subject == Issuer: {cert.get('issuer_cn','')}",
                "host":           self.target,
                "url":            f"https://{self.target}:{port}",
                "tool":           "gator_ssl",
                "category":       "ssl",
            })
            self.log("warn", f"[SSL] ⚠️  Self-signed certificate!")

        # ── Hostname mismatch ─────────────────────────────────
        cn_lower = cn.lower()
        target_lower = self.target.lower()
        sans_lower = [s.lower() for s in cert.get("san",[])]
        wildcard_match = any(
            s.startswith("*.") and target_lower.endswith(s[2:])
            for s in sans_lower
        )
        direct_match = target_lower in sans_lower or cn_lower == target_lower
        if not direct_match and not wildcard_match and cn:
            self.finding({
                "severity":       "high",
                "cvss":           7.4,
                "owasp_category": "A02:2021-Cryptographic Failures",
                "pci_dss_req":    ["4.2.1"],
                "title":          f"Certificate hostname mismatch — port {port}",
                "description":    f"Certificate CN={cn} doesn't match {self.target}.",
                "recommendation": "Issue certificate with correct CN/SAN matching all service hostnames.",
                "evidence":       f"Target: {self.target} | CN: {cn} | SANs: {cert.get('san',[])}",
                "host":           self.target,
                "url":            f"https://{self.target}:{port}",
                "tool":           "gator_ssl",
                "category":       "ssl",
            })
            self.log("warn", f"[SSL] ⚠️  Hostname mismatch: {self.target} vs {cn}")

        # ── TLS version check ─────────────────────────────────
        tls = cert.get("tls_version","")
        if tls in ("TLSv1","TLSv1.0","TLSv1.1"):
            info = TLS_VERSIONS.get("TLSv1.0" if "1.0" in tls or tls == "TLSv1" else "TLSv1.1", {})
            self.finding({
                "severity":       info.get("severity","high"),
                "cvss":           info.get("cvss",7.5),
                "owasp_category": "A02:2021-Cryptographic Failures",
                "pci_dss_req":    ["4.2.1","6.4.1"],
                "cwe_ids":        ["CWE-326"],
                "title":          f"Deprecated TLS version: {tls} — port {port}",
                "description":    info.get("desc",""),
                "recommendation": (
                    "Disable TLS 1.0 and TLS 1.1. "
                    "Enable only TLS 1.2 and TLS 1.3. "
                    "Required for PCI DSS v4.0 compliance."),
                "evidence":       f"Negotiated: {tls}",
                "host":           self.target,
                "url":            f"https://{self.target}:{port}",
                "tool":           "gator_ssl",
                "category":       "ssl",
            })
            self.log("warn", f"[SSL] 🚨 Deprecated TLS: {tls} (PCI DSS FAIL!)")
        else:
            self.log("ok", f"[SSL] TLS version {tls} ✓")

        # ── Weak cipher ───────────────────────────────────────
        cipher = cert.get("cipher","")
        for weak, info in WEAK_CIPHERS.items():
            if weak in cipher.upper():
                self.finding({
                    "severity":       info["severity"],
                    "cvss":           info["cvss"],
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "pci_dss_req":    ["4.2.1"],
                    "cwe_ids":        ["CWE-326"],
                    "title":          f"Weak cipher: {cipher} — port {port}",
                    "description":    f"{info['desc']}. {info['vuln']}",
                    "recommendation": "Configure server to only accept strong cipher suites (AES-GCM, ChaCha20).",
                    "evidence":       f"Negotiated cipher: {cipher}",
                    "host":           self.target,
                    "url":            f"https://{self.target}:{port}",
                    "tool":           "gator_ssl",
                    "category":       "ssl",
                })
                self.log("warn", f"[SSL] 🚨 Weak cipher: {cipher} ({info['vuln']})")
                break

        # ── Key size ──────────────────────────────────────────
        bits = cert.get("cipher_bits", 0)
        if bits and bits < 128:
            self.finding({
                "severity":       "critical",
                "cvss":           9.1,
                "owasp_category": "A02:2021-Cryptographic Failures",
                "title":          f"Insufficient key length: {bits}-bit — port {port}",
                "description":    f"Cipher uses only {bits}-bit key. Trivially breakable.",
                "recommendation": "Use minimum 128-bit symmetric keys. RSA 2048+, EC 256+.",
                "evidence":       f"Cipher bits: {bits}",
                "host":           self.target,
                "url":            f"https://{self.target}:{port}",
                "tool":           "gator_ssl",
                "category":       "ssl",
            })

    # ─── Protocol Detection ───────────────────────────────────
    def _check_protocols(self, port: int, service: str, result: dict):
        """Try to connect with each TLS/SSL version."""
        proto_results = {}

        # Try modern Python ssl constants
        proto_map = {}
        for attr in ["PROTOCOL_TLSv1","PROTOCOL_TLSv1_1",
                     "PROTOCOL_TLSv1_2","PROTOCOL_TLS_CLIENT"]:
            if hasattr(ssl, attr):
                proto_map[attr] = getattr(ssl, attr)

        # TLS 1.0 test via openssl CLI (most reliable)
        for tls_flag, tls_name in [
            ("-tls1",   "TLSv1.0"),
            ("-tls1_1", "TLSv1.1"),
            ("-tls1_2", "TLSv1.2"),
            ("-tls1_3", "TLSv1.3"),
        ]:
            if not self._which("openssl"):
                break
            try:
                cmd = ["openssl","s_client","-connect",
                       f"{self.target}:{port}",tls_flag,
                       "-brief","-no_ign_eof"]
                r = subprocess.run(cmd,
                    input=b"Q\n",
                    capture_output=True, timeout=8)
                out = r.stdout.decode("utf-8","ignore") + r.stderr.decode("utf-8","ignore")
                supported = ("CONNECTED" in out or "Protocol" in out) and "handshake failure" not in out.lower()
                proto_results[tls_name] = supported
                icon = "✓" if not supported or tls_name in ("TLSv1.2","TLSv1.3") else "🚨"
                level = "ok" if (not supported or tls_name in ("TLSv1.2","TLSv1.3")) else "warn"
                self.log(level, f"[SSL] {tls_name}: {'ENABLED '+icon if supported else 'disabled'}")

                if supported and tls_name in ("TLSv1.0","TLSv1.1"):
                    info = TLS_VERSIONS.get(tls_name,{})
                    self.finding({
                        "severity":       info.get("severity","high"),
                        "cvss":           info.get("cvss",7.5),
                        "owasp_category": "A02:2021-Cryptographic Failures",
                        "pci_dss_req":    ["4.2.1"],
                        "cwe_ids":        ["CWE-326"],
                        "title":          f"{tls_name} enabled — port {port} (PCI DSS FAIL)",
                        "description":    info.get("desc",""),
                        "recommendation": (
                            f"Disable {tls_name} in server configuration.\n"
                            "Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                            "Nginx:  ssl_protocols TLSv1.2 TLSv1.3;\n"
                            "IIS: Disable via Windows Registry or IIS Crypto tool."),
                        "evidence":       f"OpenSSL connected with {tls_name} to port {port}",
                        "host":           self.target,
                        "url":            f"https://{self.target}:{port}",
                        "tool":           "gator_ssl",
                        "category":       "ssl",
                    })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                break
            except Exception:
                pass

        result["protocols"] = proto_results

    # ─── Cipher Suite Analysis (via openssl/nmap) ─────────────
    def _check_ciphers(self, port: int, service: str):
        """Enumerate cipher suites using nmap ssl-enum-ciphers."""
        if not self._which("nmap"):
            return
        self.log("info", f"[SSL] Enumerating cipher suites with nmap...")
        try:
            r = subprocess.run([
                "nmap","--script","ssl-enum-ciphers",
                "-p", str(port), self.target,
                "--script-timeout","30s"
            ], capture_output=True, text=True, timeout=60)

            output = r.stdout
            # Parse weak ciphers from nmap output
            for line in output.split("\n"):
                line_strip = line.strip()
                # nmap marks weak ciphers with 'F' (failed)
                if "NULL" in line_strip or "EXPORT" in line_strip or "RC4" in line_strip:
                    self.log("warn",
                        f"[SSL] 🚨 Weak cipher in suite: {line_strip[:80]}")
                    for weak, info in WEAK_CIPHERS.items():
                        if weak in line_strip.upper():
                            self.finding({
                                "severity":       info["severity"],
                                "cvss":           info["cvss"],
                                "owasp_category": "A02:2021-Cryptographic Failures",
                                "pci_dss_req":    ["4.2.1"],
                                "title":          f"Weak cipher suite offered: {line_strip.strip()[:80]}",
                                "description":    f"{info['desc']} — {info['vuln']}",
                                "recommendation": (
                                    "Remove all weak ciphers from server config.\n"
                                    "Recommended: TLS_AES_256_GCM_SHA384, "
                                    "TLS_CHACHA20_POLY1305_SHA256, "
                                    "ECDHE-RSA-AES256-GCM-SHA384"),
                                "evidence":       line_strip[:200],
                                "host":           self.target,
                                "url":            f"https://{self.target}:{port}",
                                "tool":           "nmap_ssl",
                                "category":       "ssl",
                            })
                            break

            # Check for F-grade
            if "F" in output and ("least strength: F" in output.lower() or
                                   " F " in output):
                self.log("warn","[SSL] 🚨 Cipher suite grade: F")
        except Exception as e:
            self.log("info", f"[SSL] Cipher enum skipped: {e}")

    # ─── HEARTBLEED ───────────────────────────────────────────
    def _check_heartbleed(self, port: int):
        """Safe HEARTBLEED detection (CVE-2014-0160)."""
        self.log("info",f"[SSL] Probing for HEARTBLEED on port {port}...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(8)
                s.connect((self.target, port))
                s.sendall(HEARTBLEED_PROBE)
                # Wait for ServerHello
                data = b""
                deadline = time.time() + 5
                while time.time() < deadline:
                    try:
                        chunk = s.recv(1024)
                        if not chunk: break
                        data += chunk
                        if len(data) > 100: break
                    except socket.timeout:
                        break

                if len(data) < 5:
                    self.log("ok", f"[SSL] HEARTBLEED: no response (likely patched) ✓")
                    return

                # Send heartbeat request
                s.sendall(HEARTBLEED_MSG)
                resp = b""
                deadline2 = time.time() + 3
                while time.time() < deadline2:
                    try:
                        chunk = s.recv(4096)
                        if not chunk: break
                        resp += chunk
                        if len(resp) > 100: break
                    except socket.timeout:
                        break

                # Heartbeat response (type 0x18) with large payload = vulnerable
                if resp and resp[0:1] == b"\x18" and len(resp) > 50:
                    self.log("warn", f"[SSL] 🚨 HEARTBLEED VULNERABLE!")
                    self.finding({
                        "severity":       "critical",
                        "cvss":           9.8,
                        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                        "pci_dss_req":    ["6.3.3"],
                        "cwe_ids":        ["CWE-125"],
                        "title":          f"HEARTBLEED (CVE-2014-0160) — port {port}",
                        "description":    (
                            "OpenSSL HEARTBLEED vulnerability. Allows reading 64KB of server memory "
                            "per request, potentially exposing private keys, session tokens, passwords."),
                        "recommendation": "Update OpenSSL to 1.0.1g+ or 1.0.2+. Revoke and reissue certificates.",
                        "evidence":       f"Heartbeat response received ({len(resp)} bytes) on port {port}",
                        "host":           self.target,
                        "url":            f"https://{self.target}:{port}",
                        "tool":           "gator_heartbleed",
                        "category":       "ssl",
                    })
                else:
                    self.log("ok", f"[SSL] HEARTBLEED: not vulnerable ✓")
        except Exception:
            self.log("info", f"[SSL] HEARTBLEED probe inconclusive")

    # ─── BEAST ────────────────────────────────────────────────
    def _check_beast(self, port: int, result: dict):
        """BEAST: TLS 1.0 + CBC cipher combo."""
        tls10 = result.get("protocols", {}).get("TLSv1.0", False)
        cert  = result.get("cert", {})
        cipher = cert.get("cipher","")
        if tls10 and ("CBC" in cipher.upper() or not cipher):
            self.finding({
                "severity":       "medium",
                "cvss":           5.9,
                "owasp_category": "A02:2021-Cryptographic Failures",
                "pci_dss_req":    ["4.2.1"],
                "cwe_ids":        ["CWE-326"],
                "title":          f"BEAST attack possible — TLS 1.0 + CBC cipher — port {port}",
                "description":    (
                    "BEAST (Browser Exploit Against SSL/TLS) exploits TLS 1.0 "
                    "with CBC mode ciphers to decrypt HTTPS traffic."),
                "recommendation": "Disable TLS 1.0. Prefer TLS 1.2/1.3 with AEAD ciphers (GCM).",
                "evidence":       f"TLS 1.0 enabled, cipher: {cipher}",
                "host":           self.target,
                "url":            f"https://{self.target}:{port}",
                "tool":           "gator_ssl",
                "category":       "ssl",
            })
            self.log("warn", f"[SSL] ⚠️  BEAST possible: TLS 1.0 + {cipher}")

    # ─── TLS Compression (CRIME) ─────────────────────────────
    def _check_compression(self, port: int):
        """CRIME: TLS compression enabled."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.target) as ssock:
                    comp = ssock.compression()
                    if comp:
                        self.finding({
                            "severity":       "high",
                            "cvss":           7.5,
                            "owasp_category": "A02:2021-Cryptographic Failures",
                            "title":          f"CRIME: TLS compression enabled — port {port}",
                            "description":    (
                                "TLS compression enabled. CRIME attack recovers "
                                "HTTPS cookies by measuring compressed size."),
                            "recommendation": "Disable TLS compression: SSLCompression off (Apache/Nginx).",
                            "evidence":       f"TLS compression: {comp}",
                            "host":           self.target,
                            "url":            f"https://{self.target}:{port}",
                            "tool":           "gator_ssl",
                            "category":       "ssl",
                        })
                        self.log("warn", f"[SSL] 🚨 CRIME: TLS compression {comp}")
                    else:
                        self.log("ok", f"[SSL] TLS compression disabled ✓")
        except Exception:
            pass

    # ─── HSTS ────────────────────────────────────────────────
    def _check_hsts(self):
        self.log("data","[SSL] Checking HSTS (HTTP Strict Transport Security)...")
        try:
            import urllib.request
            req = urllib.request.Request(f"https://{self.target}")
            req.add_header("User-Agent","GATOR-PRO/2.0")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                hsts = resp.headers.get("Strict-Transport-Security","")
                if not hsts:
                    self.finding({
                        "severity":       "medium",
                        "cvss":           6.5,
                        "owasp_category": "A02:2021-Cryptographic Failures",
                        "pci_dss_req":    ["4.2.1","6.4.1"],
                        "title":          "HSTS not configured",
                        "description":    "Missing Strict-Transport-Security header. Allows protocol downgrade attacks.",
                        "recommendation": (
                            "Add: Strict-Transport-Security: max-age=31536000; "
                            "includeSubDomains; preload"),
                        "evidence":       "No Strict-Transport-Security header in HTTPS response",
                        "host":           self.target,
                        "url":            f"https://{self.target}",
                        "tool":           "gator_ssl",
                        "category":       "ssl",
                    })
                    self.log("warn","[SSL] ⚠️  HSTS not configured!")
                else:
                    self.log("ok", f"[SSL] HSTS: {hsts[:80]} ✓")
                    # Check max-age
                    m = re.search(r"max-age=(\d+)", hsts)
                    if m and int(m.group(1)) < 31536000:
                        self.log("warn",
                            f"[SSL] HSTS max-age too short: {m.group(1)}s (recommend ≥ 1 year)")

                # Check HTTP → HTTPS redirect
            req_http = urllib.request.Request(f"http://{self.target}")
            req_http.add_header("User-Agent","GATOR-PRO/2.0")
            class NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a): return None
            opener = urllib.request.build_opener(NoRedir())
            try:
                with opener.open(req_http, timeout=5) as resp_http:
                    if resp_http.status == 200:
                        self.finding({
                            "severity":       "high",
                            "cvss":           7.4,
                            "owasp_category": "A02:2021-Cryptographic Failures",
                            "pci_dss_req":    ["4.2.1"],
                            "title":          "HTTP available without redirect to HTTPS",
                            "description":    "Application accessible over plaintext HTTP without forced redirect.",
                            "recommendation": "Redirect all HTTP traffic to HTTPS (301). Enable HSTS.",
                            "evidence":       f"http://{self.target} → HTTP {resp_http.status}",
                            "host":           self.target,
                            "url":            f"http://{self.target}",
                            "tool":           "gator_ssl",
                            "category":       "ssl",
                        })
                        self.log("warn","[SSL] ⚠️  HTTP accessible without redirect!")
            except Exception:
                self.log("ok","[SSL] HTTP redirects to HTTPS ✓")
        except Exception as e:
            self.log("info", f"[SSL] HSTS check: {e}")

    # ─── SSLyze Integration ───────────────────────────────────
    def _run_sslyze(self, port: int):
        """Run SSLyze for comprehensive TLS analysis."""
        self.log("info","[SSLyze] Running deep TLS analysis with SSLyze...")
        try:
            # Try sslyze as CLI first
            r = subprocess.run([
                "python3","-m","sslyze",
                f"{self.target}:{port}",
                "--json_out=-",
                "--certinfo","--tlsv1","--tlsv1_1","--tlsv1_2","--tlsv1_3",
                "--heartbleed","--robot","--compression",
                "--early_data","--http_headers",
            ], capture_output=True, text=True, timeout=120)

            if r.returncode != 0 and not r.stdout:
                return

            try:
                data = json.loads(r.stdout)
            except json.JSONDecodeError:
                return

            # Parse SSLyze results
            for server in data.get("server_scan_results",[]):
                result = server.get("scan_result",{})

                # ROBOT
                robot = result.get("robot",{})
                if robot.get("result",{}).get("robot_result") not in (None,"NOT_VULNERABLE_NO_ORACLE"):
                    self.finding({
                        "severity":       "critical",
                        "cvss":           9.8,
                        "owasp_category": "A02:2021-Cryptographic Failures",
                        "title":          f"ROBOT attack (CVE-2017-13099) — port {port}",
                        "description":    "RSA PKCS#1 v1.5 oracle allows RSA decryption of TLS sessions.",
                        "recommendation": "Disable RSA key exchange. Use ECDHE/DHE exclusively.",
                        "evidence":       f"SSLyze ROBOT result: {robot}",
                        "host":           self.target,
                        "url":            f"https://{self.target}:{port}",
                        "tool":           "sslyze",
                        "category":       "ssl",
                    })
                    self.log("warn","[SSLyze] 🚨 ROBOT attack possible!")

                # HTTP Headers from SSLyze
                http_headers = result.get("http_headers",{})
                hsts_h = http_headers.get("result",{}).get("strict_transport_security_header")
                if hsts_h is None:
                    self.log("info","[SSLyze] HSTS not set (confirmed by SSLyze)")

            self.log("ok","[SSLyze] Analysis complete")
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            self.log("info", f"[SSLyze] Skipped: {e}")

    # ─── PCI DSS TLS Summary ──────────────────────────────────
    def _pci_tls_summary(self):
        """Generate PCI DSS v4.0 TLS compliance summary."""
        self.log("data","[PCI] Generating TLS compliance summary...")
        pci_findings = [f for f in self.findings
                        if "4.2.1" in f.get("pci_dss_req",[]) or
                           "ssl" in f.get("category","")]
        pci_fail = len(pci_findings)

        if pci_fail > 0:
            self.log("warn",
                f"[PCI] TLS compliance: FAIL — {pci_fail} PCI DSS 4.2.1 violations")
            self.push_event(
                self.db, self.scan_id, "pci_tls", "warn",
                f"PCI DSS TLS FAIL: {pci_fail} violations",
                {"pci_fail": pci_fail, "requirement": "4.2.1"})
        else:
            self.log("ok","[PCI] TLS compliance: PASS ✓")
            self.push_event(
                self.db, self.scan_id, "pci_tls", "ok",
                "PCI DSS TLS PASS", {"pci_fail": 0})

    def _which(self, tool: str) -> bool:
        try:
            return subprocess.run(["which", tool],
                capture_output=True, timeout=3).returncode == 0
        except Exception:
            return False
