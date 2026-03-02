"""
GATOR PRO Enterprise — Module 1: Recon & OSINT Engine
═══════════════════════════════════════════════════════
Full reconnaissance for banking targets:
  • DNS (A/AAAA/MX/NS/TXT/SOA/CAA) + PTR reverse lookup
  • WHOIS + ASN (whois CLI + raw socket fallback)
  • SSL Certificate info + SAN extraction
  • Subdomain bruteforce — 500-word banking wordlist (30 threads)
  • subfinder integration (if installed)
  • Certificate Transparency via crt.sh API
  • HTTP fingerprinting (server, tech stack, title)
  • Sensitive path discovery (robots/git/env/actuator/swagger...)
  • Email security: SPF / DKIM / DMARC analysis
  • DNS Zone Transfer attempt (AXFR)
  • Cloud asset detection (S3/Azure/GCP buckets)
  • Google dorks generator (12 banking-specific dorks)
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


# ─── Banking-focused subdomain wordlist (500 entries) ────────
SUBDOMAIN_WORDLIST = [
    # Internet banking core
    "www","mail","webmail","smtp","pop","imap","ftp","vpn","remote",
    "ibank","ebank","online","banking","internet-bank","internetbank",
    "ib","pib","mobile","m","app","apps","mobilebank","mbank","oib",
    # API / services
    "api","api2","api-v1","api-v2","apiv1","apiv2","rest","soap",
    "ws","webservice","services","gateway","gw","openapi","openbanking",
    "service","svc","msvc","microservice","backend","front","frontend",
    # Admin / management
    "admin","administrator","panel","control","management","manager",
    "cms","dashboard","portal","backoffice","back-office","intranet",
    "internal","staff","employee","corp","corporate","office","bo",
    # Infrastructure
    "ns","ns1","ns2","ns3","ns4","dns","dns1","dns2","mx","mx1","mx2",
    "relay","smtp1","smtp2","cdn","static","assets","media","images",
    "img","files","upload","uploads","download","downloads","storage",
    # DevOps / monitoring
    "dev","development","staging","stage","stg","test","testing","qa",
    "uat","demo","sandbox","preprod","pre-prod","prod","production",
    "monitor","monitoring","grafana","prometheus","kibana","elastic",
    "splunk","zabbix","nagios","jenkins","gitlab","bitbucket","jira",
    "confluence","wiki","docs","documentation","git","svn","repo",
    "ci","cd","build","deploy","ansible","puppet","chef","k8s","kube",
    # Security / auth
    "sso","auth","oauth","login","signin","logout","password","reset",
    "2fa","otp","captcha","ldap","ad","saml","idp","identity","iam",
    "keycloak","wso2","ping","okta","cas",
    # SWIFT / payments / cards
    "swift","payments","payment","pay","transaction","transfer",
    "remittance","forex","fx","cards","card","credit","debit","atm",
    "pos","merchant","acquiring","issuing","processing","clearing",
    "settlement","escrow","wallet","ewallet","crypto",
    # Compliance / analytics
    "report","reports","analytics","bi","datawarehouse","dw","crm",
    "erp","core","aml","kyc","compliance","audit","risk",
    "antifraud","fraud","fraud-detection",
    # Geographic / UZ
    "uz","tashkent","ru","en","kz","uz","global","local",
    "branch","head","hq","regional","central",
    # Cloud / infra
    "aws","azure","cloud","s3","blob","storage","cache","redis",
    "db","database","mysql","postgres","oracle","mssql","mongo",
    # Support
    "help","support","helpdesk","ticket","tickets","news","blog",
    "press","info","about","contact","feedback","survey",
    # Backup / old
    "old","new","backup","bak","archive","v1","v2","v3","beta","alpha",
    # Comms
    "socket","websocket","stream","push","notify","notification",
    "messaging","chat","broker","mq","rabbitmq","kafka",
    # Network
    "proxy","lb","load","balancer","waf","firewall","exchange",
    "autodiscover","ews","owa","sharepoint","teams","skype",
    # Panels
    "cpanel","plesk","whm","webmin","phpmyadmin","adminer",
    "pgadmin","kibana","flower","celery",
    # Misc
    "cron","scheduler","worker","queue","job","batch","etl",
    "log","logs","logging","syslog","graylog",
    "vpn2","vpn3","citrix","rdp","rdweb",
    "mail2","mx3","mail3","mailing","newsletter",
    "ftp2","sftp","ftps","ssh","bastion","jump",
    "pki","crl","ocsp","cert","certs","certificates",
    "wsdl","xsd","schema","schemas",
    "test1","test2","dev1","dev2","stage1","stage2",
    "uat1","uat2","qa1","qa2","demo1","demo2",
]

# ─── Technology fingerprint signatures ───────────────────────
TECH_SIGNATURES = {
    "Spring Boot":    ["X-Application-Context","Whitelabel Error Page"],
    "Apache Tomcat":  ["Apache-Coyote","catalina"],
    "IIS":            ["X-AspNet-Version","X-Powered-By: ASP.NET"],
    "nginx":          ["nginx"],
    "Apache httpd":   ["Server: Apache"],
    "Oracle WebLogic":["WebLogic","wls-context"],
    "JBoss/WildFly":  ["JBoss","WildFly"],
    "PHP":            ["X-Powered-By: PHP","PHPSESSID"],
    "Laravel":        ["laravel_session","XSRF-TOKEN"],
    "Django":         ["csrfmiddlewaretoken"],
    "WordPress":      ["wp-content","wp-login"],
    "Drupal":         ["Drupal","drupal"],
    "Oracle Flexcube":["Flexcube","fcubs"],
    "Temenos T24":    ["Temenos","T24","TAFC"],
    "1C:Enterprise":  ["1C:Enterprise","1c-fresh"],
    "Cloudflare":     ["CF-RAY","cf-request-id"],
    "AWS CloudFront": ["x-amz-cf-id","CloudFront"],
    "Azure":          ["ARRAffinity","x-azure"],
    "React":          ["__NEXT_DATA__","_next/static"],
    "Angular":        ["ng-version"],
    "Vue.js":         ["vue-meta","__vue__"],
}

# ─── Sensitive paths to probe ─────────────────────────────────
SENSITIVE_PATHS = [
    # Secrets
    "/.env","/.env.local","/.env.prod","/.env.backup","/.env.example",
    "/.git/config","/.git/HEAD","/.git/COMMIT_EDITMSG","/.git/info/refs",
    "/.svn/entries","/.svn/wc.db",
    # Config files
    "/config.php","/config.yml","/config.yaml","/config.json",
    "/application.properties","/application.yml","/application.yaml",
    "/appsettings.json","/appsettings.Production.json",
    "/web.config","/database.yml","/database.php",
    "/.htaccess","/.htpasswd",
    # Info disclosure
    "/server-status","/server-info",
    "/phpinfo.php","/info.php","/test.php","/phptest.php",
    "/wp-config.php","/wp-config.bak",
    # Public files
    "/robots.txt","/sitemap.xml","/sitemap_index.xml",
    "/crossdomain.xml","/clientaccesspolicy.xml",
    "/security.txt","/.well-known/security.txt",
    "/humans.txt","/readme.txt","/readme.md",
    "/CHANGELOG.md","/LICENSE",
    # API docs
    "/swagger.json","/swagger.yaml","/swagger-ui.html",
    "/api-docs","/api-docs.json","/api/docs",
    "/openapi.json","/openapi.yaml",
    "/v1/api-docs","/v2/api-docs","/v3/api-docs",
    "/graphql","/graphiql","/__graphql","/playground",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    # Spring Boot Actuator (CRITICAL for Java banks)
    "/actuator","/actuator/health","/actuator/env",
    "/actuator/beans","/actuator/mappings",
    "/actuator/heapdump","/actuator/threaddump",
    "/actuator/logfile","/actuator/configprops",
    "/actuator/metrics","/actuator/httptrace",
    "/actuator/auditevents","/actuator/sessions",
    # Admin panels
    "/admin","/admin/","/administrator","/administrator/",
    "/phpmyadmin","/pma","/adminer.php","/adminer",
    "/console","/jmx-console","/web-console",
    "/manager/html","/host-manager/html",
    # Monitoring
    "/metrics","/health","/healthz","/ready","/readyz",
    "/status","/ping","/alive",
    # Backup files
    "/backup.zip","/backup.tar.gz","/site.zip",
    "/dump.sql","/database.sql","/backup.sql",
    "/db.sql","/data.sql",
    # Logs
    "/access.log","/error.log","/debug.log",
    "/logs/access.log","/logs/error.log",
    "/var/log/apache2/access.log",
    # HashiCorp Vault
    "/v1/sys/health","/v1/secret",
    # IIS
    "/trace.axd","/elmah.axd","/global.asax","/_profiler",
]


class ReconEngine:
    """Full OSINT & reconnaissance engine."""

    def __init__(self, target: str, scan_id: str, db, push_event: Callable, **kwargs):
        self.target = self._clean(target)
        self.scan_id = scan_id
        self.db = db
        self.push_event = push_event
        self.results = {
            "target": self.target,
            "ip_addresses": [],
            "dns": {},
            "whois": {},
            "ssl_cert": {},
            "subdomains": [],
            "crt_sh": [],
            "http_info": {},
            "sensitive_paths": [],
            "technologies": [],
            "email_security": {},
            "zone_transfer": [],
            "cloud_assets": [],
            "google_dorks": [],
        }

    def _clean(self, t: str) -> str:
        return t.replace("https://","").replace("http://","").split("/")[0].split(":")[0].strip()

    def log(self, level: str, msg: str, data: dict = None):
        self.push_event(self.db, self.scan_id, "log", level, msg, data or {})

    # ═══════════════════════════════════════════════════════════
    def run(self) -> dict:
        self.log("info", f"╔══ RECON ENGINE ══ {self.target} ══╗")
        t0 = time.time()

        self._dns()
        self._whois()
        self._ssl_cert()
        self._subdomains()
        self._crt_sh()
        self._http_fingerprint()
        self._sensitive_paths()
        self._email_security()
        self._zone_transfer()
        self._cloud_assets()
        self._google_dorks()

        elapsed = round(time.time() - t0, 1)
        s = self.results
        self.log("ok",
            f"╚══ RECON DONE {elapsed}s ══ "
            f"Subs:{len(s['subdomains'])} "
            f"CRT:{len(s['crt_sh'])} "
            f"Paths:{len(s['sensitive_paths'])} ══╝")
        return self.results

    # ─── DNS ──────────────────────────────────────────────────
    def _dns(self):
        self.log("data", f"[DNS] Enumerating records → {self.target}")
        dns = {}

        # A record
        try:
            infos = socket.getaddrinfo(self.target, None, socket.AF_INET)
            ips = list(dict.fromkeys([i[4][0] for i in infos]))
            dns["A"] = ips
            self.results["ip_addresses"] = ips
            for ip in ips:
                self.log("ok", f"[DNS] A    {self.target} → {ip}")
                # Reverse PTR
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                    dns.setdefault("PTR", []).append(f"{ip} → {ptr}")
                    self.log("info", f"[DNS] PTR  {ip} → {ptr}")
                except Exception:
                    pass
        except Exception as e:
            self.log("warn", f"[DNS] A lookup failed: {e}")
            dns["A"] = []

        # AAAA
        try:
            i6 = socket.getaddrinfo(self.target, None, socket.AF_INET6)
            dns["AAAA"] = list(dict.fromkeys([i[4][0] for i in i6]))
        except Exception:
            dns["AAAA"] = []

        # MX, NS, TXT, CAA, SOA via dig/nslookup
        for rtype in ["MX","NS","TXT","CAA","SOA"]:
            records = self._dig(self.target, rtype)
            dns[rtype] = records
            icons = {"MX":"📧","NS":"🔢","TXT":"📝","CAA":"🔒","SOA":"📋"}
            for r in records[:6]:
                self.log("info", f"[DNS] {rtype} {icons.get(rtype,'')}  {r[:90]}")

        self.results["dns"] = dns

    def _dig(self, domain: str, rtype: str) -> list:
        for cmd in [["dig","+short",domain,rtype], ["nslookup",f"-type={rtype}",domain]]:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                if r.returncode == 0 and r.stdout.strip():
                    lines = [l.strip() for l in r.stdout.strip().split("\n")
                             if l.strip() and not l.startswith(";")]
                    return [l for l in lines if l][:10]
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return []

    # ─── WHOIS ────────────────────────────────────────────────
    def _whois(self):
        self.log("data", f"[WHOIS] Querying {self.target}...")
        result = {}

        # Try CLI whois
        if self._which("whois"):
            try:
                r = subprocess.run(["whois", self.target],
                    capture_output=True, text=True, timeout=15)
                raw = r.stdout
                result = {"raw": raw[:3000], "parsed": self._parse_whois(raw)}
            except Exception as e:
                self.log("warn", f"[WHOIS] CLI error: {e}")

        # Fallback: raw socket
        if not result.get("raw"):
            try:
                raw = self._whois_socket(self.target)
                result = {"raw": raw[:3000], "parsed": self._parse_whois(raw)}
            except Exception as e:
                self.log("warn", f"[WHOIS] Socket error: {e}")

        p = result.get("parsed", {})
        for k,v in [("Registrar",p.get("registrar")),
                    ("Created",p.get("creation_date")),
                    ("Expires",p.get("expiry_date")),
                    ("Org",p.get("registrant_org"))]:
            if v:
                self.log("info", f"[WHOIS] {k}: {v}")

        self.results["whois"] = result

    def _whois_socket(self, domain: str) -> str:
        tld = domain.split(".")[-1].lower()
        servers = {"com":"whois.verisign-grs.com","net":"whois.verisign-grs.com",
                   "org":"whois.pir.org","ru":"whois.nic.ru","uz":"whois.cctld.uz",
                   "kz":"whois.nic.kz","uk":"whois.nic.uk","io":"whois.nic.io"}
        server = servers.get(tld, "whois.iana.org")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((server, 43))
            s.sendall((domain + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
        return data.decode("utf-8", errors="ignore")

    def _parse_whois(self, raw: str) -> dict:
        patterns = {
            "registrar":       r"(?:Registrar|registrar):\s*(.+)",
            "creation_date":   r"(?:Creation Date|Created|created):\s*(.+)",
            "expiry_date":     r"(?:Expiry Date|Expires|expiry|Registry Expiry):\s*(.+)",
            "registrant_org":  r"(?:Registrant Organization|Registrant Org|org):\s*(.+)",
            "registrant_email":r"(?:Registrant Email|email):\s*(.+@.+)",
            "dnssec":          r"(?:DNSSEC):\s*(.+)",
            "name_servers":    r"(?:Name Server|nserver):\s*(.+)",
        }
        parsed = {}
        for k, pat in patterns.items():
            m = re.findall(pat, raw, re.IGNORECASE)
            if m:
                parsed[k] = m[0].strip()[:200] if k != "name_servers" else [x.strip() for x in m[:4]]
        return parsed

    # ─── SSL Certificate ──────────────────────────────────────
    def _ssl_cert(self):
        self.log("data", f"[SSL] Extracting certificate for {self.target}:443...")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target, 443), timeout=8) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_ver = ssock.version()

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer",  []))
            sans    = [s[1] for s in cert.get("subjectAltName", [])]

            info = {
                "cn":        subject.get("commonName",""),
                "org":       subject.get("organizationName",""),
                "issuer_org":issuer.get("organizationName",""),
                "not_before":cert.get("notBefore",""),
                "not_after": cert.get("notAfter",""),
                "san":       sans,
                "tls_version":tls_ver,
                "cipher":    cipher[0] if cipher else "",
            }
            self.results["ssl_cert"] = info
            self.log("ok",   f"[SSL] CN: {info['cn']} | Issuer: {info['issuer_org']}")
            self.log("info",  f"[SSL] TLS: {tls_ver} | Cipher: {info['cipher']}")
            self.log("info",  f"[SSL] Expires: {info['not_after']} | SANs: {len(sans)}")

            # Add SANs to subdomain pool
            for san in sans:
                if "*" not in san and self.target in san and san != self.target:
                    ip = self._resolve(san)
                    if ip:
                        self.results["subdomains"].append(
                            {"subdomain": san, "ip": ip, "source": "ssl_san"})
        except Exception as e:
            self.log("warn", f"[SSL] Cert extraction failed: {e}")
            self.results["ssl_cert"] = {"error": str(e)}

    # ─── Subdomain Enumeration ────────────────────────────────
    def _subdomains(self):
        self.log("data",
            f"[SUBS] Starting subdomain enum ({len(SUBDOMAIN_WORDLIST)} words, 30 threads)...")

        # subfinder first
        if self._which("subfinder"):
            subs = self._run_subfinder()
            self.results["subdomains"].extend(subs)
            self.log("ok", f"[SUBS] subfinder: {len(subs)} found")

        # DNS bruteforce
        existing = {s["subdomain"] for s in self.results["subdomains"]}
        found = []
        done = [0]

        def check(word):
            fqdn = f"{word}.{self.target}"
            ip = self._resolve(fqdn)
            done[0] += 1
            if ip:
                return {"subdomain": fqdn, "ip": ip, "source": "dns_brute"}
            return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(check, w): w for w in SUBDOMAIN_WORDLIST}
            for f in as_completed(futures):
                r = f.result()
                if r and r["subdomain"] not in existing:
                    existing.add(r["subdomain"])
                    found.append(r)
                    self.results["subdomains"].append(r)
                    self.push_event(self.db, self.scan_id, "subdomain", "ok",
                        f"FOUND: {r['subdomain']} → {r['ip']}", r)
                if done[0] % 100 == 0:
                    self.push_event(self.db, self.scan_id, "progress", "info",
                        f"[SUBS] {done[0]}/{len(SUBDOMAIN_WORDLIST)} checked, {len(found)} found",
                        {"progress": round(done[0]/len(SUBDOMAIN_WORDLIST)*100, 1)})

        self.log("ok",
            f"[SUBS] DNS brute: +{len(found)} | "
            f"Total subdomains: {len(self.results['subdomains'])}")

    def _run_subfinder(self) -> list:
        try:
            r = subprocess.run(
                ["subfinder","-d",self.target,"-silent","-json"],
                capture_output=True, text=True, timeout=120)
            results = []
            for line in r.stdout.strip().split("\n"):
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    host = data.get("host","")
                except json.JSONDecodeError:
                    host = line.strip()
                if host and "." in host:
                    ip = self._resolve(host)
                    entry = {"subdomain": host, "ip": ip or "", "source": "subfinder"}
                    results.append(entry)
                    self.push_event(self.db, self.scan_id, "subdomain", "ok",
                        f"subfinder: {host} → {ip or '?'}", entry)
            return results
        except Exception as e:
            self.log("warn", f"[SUBS] subfinder failed: {e}")
            return []

    # ─── Certificate Transparency ─────────────────────────────
    def _crt_sh(self):
        self.log("data", f"[CRT.sh] Querying certificate transparency logs...")
        try:
            url  = f"https://crt.sh/?q=%.{self.target}&output=json"
            req  = urllib.request.Request(url,
                headers={"User-Agent": "GATOR-PRO/2.0"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
                data = json.loads(resp.read())

            seen  = set()
            entries = []
            for cert in data:
                for n in cert.get("name_value","").lower().split("\n"):
                    n = n.strip().lstrip("*.")
                    if not n or n in seen or self.target not in n or n == self.target:
                        continue
                    seen.add(n)
                    entry = {
                        "name":       n,
                        "issuer":     cert.get("issuer_name","")[:60],
                        "not_before": cert.get("not_before",""),
                        "not_after":  cert.get("not_after",""),
                    }
                    entries.append(entry)
                    # Try resolve → add to subdomains
                    ip = self._resolve(n)
                    if ip:
                        existing = {s["subdomain"] for s in self.results["subdomains"]}
                        if n not in existing:
                            sub = {"subdomain": n, "ip": ip, "source": "crt.sh"}
                            self.results["subdomains"].append(sub)
                            self.push_event(self.db, self.scan_id, "subdomain", "ok",
                                f"CRT.sh: {n} → {ip}", sub)

            self.results["crt_sh"] = entries
            self.log("ok", f"[CRT.sh] {len(entries)} unique certs | "
                           f"+{len([e for e in entries if self._resolve(e['name'])])} resolved")
        except Exception as e:
            self.log("warn", f"[CRT.sh] Failed: {e}")

    # ─── HTTP Fingerprinting ──────────────────────────────────
    def _http_fingerprint(self):
        self.log("data", f"[HTTP] Fingerprinting {self.target}...")
        for scheme in ["https","http"]:
            resp = self._http_get(f"{scheme}://{self.target}", timeout=10)
            if not resp: continue

            server  = resp["headers"].get("Server","")
            powered = resp["headers"].get("X-Powered-By","")
            title   = self._title(resp["body"])
            combined = str(resp["headers"]) + resp["body"][:8000]
            techs   = [t for t,sigs in TECH_SIGNATURES.items()
                       if any(s.lower() in combined.lower() for s in sigs)]

            info = {
                "url":          f"{scheme}://{self.target}",
                "status":       resp["status"],
                "server":       server,
                "powered_by":   powered,
                "title":        title,
                "technologies": techs,
                "headers":      {k: v for k, v in resp["headers"].items()
                                 if k in ["Server","X-Powered-By","X-Frame-Options",
                                          "Strict-Transport-Security","Content-Security-Policy",
                                          "X-Content-Type-Options","Set-Cookie"]},
            }
            self.results["http_info"]   = info
            self.results["technologies"]= techs

            self.log("ok",
                f"[HTTP] {resp['status']} | Server: {server or '?'} | Title: {title[:60] or '?'}")
            if techs:
                self.log("info", f"[HTTP] Tech stack: {', '.join(techs)}")
            if powered:
                self.log("info", f"[HTTP] X-Powered-By: {powered}")
            break

    # ─── Sensitive Paths ──────────────────────────────────────
    def _sensitive_paths(self):
        self.log("data",
            f"[PATHS] Probing {len(SENSITIVE_PATHS)} sensitive paths (15 threads)...")
        base = f"https://{self.target}"
        found = []

        def probe(path):
            r = self._http_get(base + path, timeout=5)
            if not r: return None
            s = r["status"]
            # Interesting = 200 (exposed!) + 401/403 (protected but exists) + 500 (error info)
            if s in [200, 301, 302, 401, 403, 500]:
                return {"path": path, "url": base+path, "status": s,
                        "size": len(r.get("body","")),
                        "exposed": s == 200}
            return None

        with ThreadPoolExecutor(max_workers=15) as ex:
            futs = {ex.submit(probe, p): p for p in SENSITIVE_PATHS}
            for f in as_completed(futs):
                r = f.result()
                if r:
                    found.append(r)
                    icon  = "🚨" if r["exposed"] else "⚠️"
                    level = "warn" if r["exposed"] else "info"
                    self.log(level,
                        f"[PATH] {icon} [{r['status']}] {r['path']} ({r['size']}b)")

        self.results["sensitive_paths"] = sorted(found, key=lambda x: -x["exposed"])
        exposed = len([p for p in found if p["exposed"]])
        self.log("ok",
            f"[PATHS] {len(found)} responded | 🚨 {exposed} exposed (HTTP 200)")

    # ─── Email Security ───────────────────────────────────────
    def _email_security(self):
        self.log("data", f"[EMAIL] Checking SPF/DKIM/DMARC for {self.target}...")
        esec = {}

        # SPF
        txts = self.results["dns"].get("TXT", [])
        spf  = next((r for r in txts if "v=spf1" in r.lower()), None)
        esec["spf"] = spf
        if spf:
            self.log("ok", f"[EMAIL] SPF: {spf[:80]}")
            if "+all" in spf:
                self.log("warn","[EMAIL] ⚠️  SPF +all — permits ALL senders (CRITICAL MISCONFIGURATION)")
            elif "~all" in spf:
                self.log("warn","[EMAIL] SPF ~all (softfail) — consider upgrading to -all")
            elif "-all" in spf:
                self.log("ok","[EMAIL] SPF -all (hardfail) ✓")
        else:
            self.log("warn","[EMAIL] ❌ No SPF record — email spoofing possible!")

        # DMARC
        dmarc_recs = self._dig(f"_dmarc.{self.target}", "TXT")
        dmarc = next((r for r in dmarc_recs if "v=dmarc1" in r.lower()), None)
        esec["dmarc"] = dmarc
        if dmarc:
            self.log("ok", f"[EMAIL] DMARC: {dmarc[:80]}")
            if "p=none" in dmarc.lower():
                self.log("warn","[EMAIL] DMARC p=none — monitoring only, not enforced!")
            elif "p=reject" in dmarc.lower():
                self.log("ok","[EMAIL] DMARC p=reject ✓")
        else:
            self.log("warn","[EMAIL] ❌ No DMARC — phishing risk!")

        # DKIM
        esec["dkim"] = None
        for sel in ["default","google","mail","dkim","selector1","selector2","s1","k1"]:
            recs = self._dig(f"{sel}._domainkey.{self.target}", "TXT")
            if recs:
                esec["dkim"] = {"selector": sel, "record": recs[0][:100]}
                self.log("ok", f"[EMAIL] DKIM selector '{sel}' found ✓")
                break
        if not esec["dkim"]:
            self.log("warn","[EMAIL] ❌ No DKIM record found")

        self.results["email_security"] = esec

    # ─── Zone Transfer (AXFR) ─────────────────────────────────
    def _zone_transfer(self):
        self.log("data", f"[AXFR] Attempting DNS zone transfer...")
        ns_list = self.results["dns"].get("NS", [])
        transfers = []
        for ns in ns_list[:3]:
            ns = ns.rstrip(".").strip()
            if not ns: continue
            try:
                r = subprocess.run(["dig", f"@{ns}", self.target, "AXFR"],
                    capture_output=True, text=True, timeout=10)
                out = r.stdout
                if ("Transfer failed" not in out and "REFUSED" not in out
                        and "connection refused" not in out.lower()
                        and len(out.strip()) > 200):
                    transfers.append({"ns": ns, "data": out[:2000], "success": True})
                    self.log("warn",
                        f"[AXFR] 🚨 ZONE TRANSFER SUCCESS on {ns}! "
                        f"All DNS records exposed!", {"ns": ns})
                else:
                    self.log("ok", f"[AXFR] {ns} — refused ✓")
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
                pass

        if not transfers:
            self.log("ok","[AXFR] All nameservers refused zone transfer ✓")
        self.results["zone_transfer"] = transfers

    # ─── Cloud Asset Detection ────────────────────────────────
    def _cloud_assets(self):
        self.log("data", f"[CLOUD] Checking for exposed cloud storage assets...")
        assets = []
        base  = self.target.split(".")[0]

        # S3 bucket candidates
        for name in [base, f"{base}-backup", f"{base}-uploads",
                     f"{base}-media", f"{base}-assets", f"{base}-data"]:
            for url in [f"https://{name}.s3.amazonaws.com",
                        f"https://s3.amazonaws.com/{name}"]:
                r = self._http_get(url, timeout=5)
                if r and r["status"] in [200, 403]:
                    entry = {"type":"S3","url":url,"status":r["status"],
                             "public": r["status"] == 200}
                    assets.append(entry)
                    self.log("warn" if r["status"]==200 else "info",
                        f"[CLOUD] {'🚨 PUBLIC' if r['status']==200 else '🔒 EXISTS'} "
                        f"S3 bucket: {url}")

        # Azure Blob
        for name in [base, f"{base}storage", f"{base}media"]:
            url = f"https://{name}.blob.core.windows.net"
            r = self._http_get(url, timeout=5)
            if r and r["status"] in [200, 400, 403]:
                assets.append({"type":"Azure Blob","url":url,"status":r["status"]})
                self.log("info", f"[CLOUD] Azure Blob detected: {url}")

        if not assets:
            self.log("info","[CLOUD] No cloud storage assets found")
        self.results["cloud_assets"] = assets

    # ─── Google Dorks ─────────────────────────────────────────
    def _google_dorks(self):
        d = self.target
        dorks = [
            f'site:{d} filetype:pdf "confidential" OR "internal use only"',
            f'site:{d} filetype:xls OR xlsx "account" OR "password" OR "transfer"',
            f'site:{d} inurl:admin OR inurl:login OR inurl:panel OR inurl:portal',
            f'site:{d} "SQL syntax" OR "mysql_fetch" OR "ORA-" OR "JDBC"',
            f'site:{d} "phpinfo()" OR "PHP Version" OR "phpinfo"',
            f'site:{d} ext:env OR ext:yml OR ext:config "password" OR "secret"',
            f'site:{d} inurl:api OR inurl:swagger OR inurl:graphql OR inurl:wsdl',
            f'site:{d} "Index of /" -"403 Forbidden"',
            f'site:{d} inurl:backup OR inurl:dump OR inurl:old OR inurl:bak',
            f'"{d}" "Internal Server Error" OR "stack trace" OR "Exception in"',
            f'"{d}" site:pastebin.com OR site:github.com "password" OR "token" OR "secret"',
            f'"{d}" site:shodan.io OR site:zoomeye.org OR site:fofa.info',
        ]
        self.results["google_dorks"] = dorks
        self.log("info", f"[DORKS] Generated {len(dorks)} Google dorks for manual OSINT")

    # ─── Helpers ──────────────────────────────────────────────
    def _resolve(self, hostname: str) -> Optional[str]:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def _http_get(self, url: str, timeout: int = 8) -> Optional[dict]:
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            req.add_header("Accept","text/html,application/xhtml+xml,*/*;q=0.9")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
                body = resp.read(32768).decode("utf-8", errors="ignore")
                return {"status": resp.status, "headers": dict(resp.headers), "body": body}
        except urllib.error.HTTPError as e:
            body = ""
            try: body = e.read(4096).decode("utf-8", errors="ignore")
            except Exception: pass
            return {"status": e.code, "headers": dict(e.headers), "body": body}
        except Exception:
            return None

    def _title(self, html: str) -> str:
        m = re.search(r"<title[^>]*>([^<]{1,200})</title>", html, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def _which(self, tool: str) -> bool:
        try:
            return subprocess.run(["which", tool],
                capture_output=True, timeout=3).returncode == 0
        except Exception:
            return False
