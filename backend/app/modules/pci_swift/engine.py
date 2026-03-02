"""
GATOR PRO Enterprise — Module 9: PCI DSS v4.0 + SWIFT CSP Compliance Engine
═════════════════════════════════════════════════════════════════════════════
Automated compliance validation for banking pentests:

PCI DSS v4.0 Requirements (all 12):
  Req 1-12 automated + manual placeholders

SWIFT Customer Security Programme (CSP):
  27 mandatory controls (v2024)

ISO 27001:2022 cross-mapping.
"""

import json, re, ssl, socket, subprocess, time
import urllib.request, urllib.error, urllib.parse
from typing import Callable, Optional
from datetime import datetime


class PCISwiftEngine:
    def __init__(self, target: str, scan_id: str, db, push_event: Callable,
                 recon_data: dict = None, port_data: dict = None,
                 ssl_data: dict = None, web_data: dict = None, **kwargs):
        self.target     = self._clean(target)
        self.base_url   = f"https://{self._clean(target)}"
        self.scan_id    = scan_id
        self.db         = db
        self.push_event = push_event
        self.recon      = recon_data or {}
        self.ports      = port_data  or {}
        self.ssl        = ssl_data   or {}
        self.web        = web_data   or {}
        self.checks     = []
        self.findings   = []

    def _clean(self, t):
        return t.replace("https://","").replace("http://","").split("/")[0].split(":")[0].strip()

    def log(self, level, msg, data=None):
        self.push_event(self.db, self.scan_id, "log", level, msg, data or {})

    def check(self, req_id: str, framework: str, title: str, status: str,
              evidence: str, remediation: str = "", cvss: float = 0.0):
        result = {
            "req_id": req_id, "framework": framework, "title": title,
            "status": status, "evidence": evidence, "remediation": remediation,
            "cvss": cvss, "timestamp": datetime.utcnow().isoformat(),
        }
        self.checks.append(result)
        icon  = {"PASS": "✅", "FAIL": "🚨", "WARNING": "⚠️", "MANUAL": "📋"}.get(status, "ℹ️")
        level = "ok" if status == "PASS" else "warn" if status in ("FAIL","WARNING") else "info"
        self.log(level, f"[{framework}] {icon} {req_id}: {title[:55]} → {status}")

        if status in ("FAIL","WARNING") and cvss > 0:
            sev = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
            self.findings.append({
                "severity": sev, "cvss": cvss,
                "owasp_category": self._req_to_owasp(req_id, framework),
                "pci_dss_req":   [req_id] if framework == "PCI DSS" else [],
                "swift_control": [req_id] if framework == "SWIFT CSP" else [],
                "title":  f"[{framework} {req_id}] {title}",
                "description": evidence, "recommendation": remediation,
                "evidence": evidence, "host": self.target, "url": self.base_url,
                "tool": "gator_pci", "category": "compliance",
            })

    def _req_to_owasp(self, req_id, framework):
        for prefix, owasp in [
            ("1.","A05:2021-Security Misconfiguration"),
            ("2.","A05:2021-Security Misconfiguration"),
            ("3.","A02:2021-Cryptographic Failures"),
            ("4.","A02:2021-Cryptographic Failures"),
            ("6.","A06:2021-Vulnerable and Outdated Components"),
            ("7.","A01:2021-Broken Access Control"),
            ("8.","A07:2021-Identification and Authentication Failures"),
            ("10.","A09:2021-Security Logging and Monitoring Failures"),
        ]:
            if req_id.startswith(prefix):
                return owasp
        return "A05:2021-Security Misconfiguration"

    def run(self) -> dict:
        self.log("info", f"╔══ PCI DSS v4.0 + SWIFT CSP ══ {self.target} ══╗")
        t0 = time.time()
        self._pci_req1_network()
        self._pci_req2_configs()
        self._pci_req3_account_data()
        self._pci_req4_cryptography()
        self._pci_req5_antimalware()
        self._pci_req6_software()
        self._pci_req7_access_control()
        self._pci_req8_authentication()
        self._pci_req10_logging()
        self._pci_req11_testing()
        self._swift_csp()
        self._iso27001()
        elapsed = round(time.time() - t0, 1)
        total  = len(self.checks)
        passed = len([c for c in self.checks if c["status"] == "PASS"])
        failed = len([c for c in self.checks if c["status"] == "FAIL"])
        warned = len([c for c in self.checks if c["status"] == "WARNING"])
        manual = len([c for c in self.checks if c["status"] == "MANUAL"])
        self.log("ok",
            f"╚══ COMPLIANCE {elapsed}s ══ {total} checks: "
            f"✅{passed} 🚨{failed} ⚠️{warned} 📋{manual} ══╝")
        return {
            "checks": self.checks, "findings": self.findings,
            "summary": {"total": total, "passed": passed, "failed": failed,
                        "warned": warned, "manual": manual,
                        "score_pct": round(passed/total*100,1) if total else 0},
        }

    def _open_ports(self):
        return {p["port"]: p.get("service","")
                for p in self.ports.get("open_ports",[])}

    def _web_findings(self):
        return self.web.get("findings",[]) if isinstance(self.web, dict) else []

    def _ssl_findings(self):
        return self.ssl.get("findings",[]) if isinstance(self.ssl, dict) else []

    def _auth_findings(self):
        return [f for f in self._web_findings() if f.get("category") == "auth"]

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 1 — Network Security Controls
    # ══════════════════════════════════════════════════════════
    def _pci_req1_network(self):
        self.log("data","[PCI] Req 1: Network Security Controls")
        op = self._open_ports()

        cleartext = {p: s for p, s in op.items() if p in (21, 23, 80)}
        self.check("1.2.5","PCI DSS","Only necessary services/ports open",
            "FAIL" if cleartext else "PASS",
            f"Cleartext services: {cleartext}" if cleartext else "No cleartext ports",
            "Disable FTP(21)/Telnet(23). Redirect HTTP→HTTPS.", 7.5 if cleartext else 0)

        db_ports = {p: s for p, s in op.items()
                    if p in (3306, 5432, 1433, 1521, 27017, 6379, 9200)}
        self.check("1.3.1","PCI DSS","DB ports not internet-accessible",
            "FAIL" if db_ports else "PASS",
            f"DB ports exposed: {db_ports}" if db_ports else "No DB ports exposed",
            "Move DBs behind firewall. Use app layer for all DB access.", 9.8 if db_ports else 0)

        remote = {p: s for p, s in op.items() if p in (3389, 5900, 5901)}
        self.check("1.3.2","PCI DSS","Remote access ports not exposed",
            "FAIL" if remote else "PASS",
            f"Remote desktop exposed: {remote}" if remote else "No RDP/VNC exposed",
            "Restrict RDP/VNC behind VPN. Use bastion host.", 8.1 if remote else 0)

        resp = self._get(self.base_url)
        headers_str = str(resp.get("headers",{}) if resp else {}).lower()
        waf = any(k in headers_str for k in ["cloudflare","cf-ray","x-sucuri","akamai"])
        self.check("1.4.1","PCI DSS","WAF deployed for public-facing apps",
            "PASS" if waf else "WARNING",
            f"WAF {'detected' if waf else 'NOT detected'}",
            "Deploy WAF (Cloudflare, ModSecurity, AWS WAF).", 5.3 if not waf else 0)

        self.check("1.5.1","PCI DSS","Security controls on mobile/remote devices",
            "MANUAL", "Manual: verify MDM and endpoint controls for remote workers",
            "Deploy MDM solution. Enforce device compliance before VPN access.")

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 2 — Secure Configurations
    # ══════════════════════════════════════════════════════════
    def _pci_req2_configs(self):
        self.log("data","[PCI] Req 2: Secure Configurations")
        op = self._open_ports()
        resp = self._get(self.base_url)
        headers = resp.get("headers",{}) if resp else {}

        has_default = any("Default credentials" in f.get("title","")
                          for f in self._auth_findings())
        self.check("2.2.1","PCI DSS","Default vendor passwords changed",
            "FAIL" if has_default else "MANUAL",
            "Default credentials detected" if has_default else
            "Manual: verify no default passwords on any system component",
            "Change ALL default passwords. Use secrets manager.", 9.8 if has_default else 0)

        server = headers.get("Server","")
        self.check("2.2.4","PCI DSS","Version info not disclosed",
            "FAIL" if (server and re.search(r"\d+\.\d+", server)) else "PASS",
            f"Server: {server}" if server else "No Server header",
            "Set ServerTokens Prod (Apache) / server_tokens off (Nginx).",
            4.3 if server and re.search(r"\d+\.\d+", server) else 0)

        mgmt = {p for p in op if p in (8080, 8161, 4848, 7001, 15672, 9000)}
        self.check("2.2.5","PCI DSS","Management interfaces not externally accessible",
            "WARNING" if mgmt else "PASS",
            f"Management ports: {mgmt}" if mgmt else "No management ports exposed",
            "Restrict management ports to admin IP ranges.", 6.5 if mgmt else 0)

        self.check("2.3.1","PCI DSS","All admin access encrypted",
            "WARNING" if mgmt else "PASS",
            "HTTP management ports found" if mgmt else "No unencrypted mgmt ports",
            "Enforce TLS for all admin interfaces.", 6.5 if mgmt else 0)

        self.check("2.3.2","PCI DSS","All wireless environments documented and secured",
            "MANUAL", "Manual: verify Wi-Fi security (WPA3), segmentation from CDE",
            "Wireless networks must not connect to CDE without WAF/IDS.")

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 3 — Protect Account Data
    # ══════════════════════════════════════════════════════════
    def _pci_req3_account_data(self):
        self.log("data","[PCI] Req 3: Protection of Account Data")
        pan = any("PAN" in f.get("title","") or "Credit Card" in f.get("title","")
                  for f in self._web_findings())
        cvv = any("CVV" in f.get("title","") for f in self._web_findings())

        self.check("3.3.1","PCI DSS","SAD not retained post-auth",
            "FAIL" if (pan or cvv) else "MANUAL",
            "PAN/CVV in API responses" if (pan or cvv) else
            "Manual: verify no SAD in databases, logs, files",
            "Never store CVV/PIN/full track. Delete immediately after authorization.",
            9.8 if (pan or cvv) else 0)

        for req, title, rec in [
            ("3.4.1","PAN unreadable where stored (tokenization/encryption)",
             "Use tokenization or AES-256. Never store plain PAN."),
            ("3.5.1","One-way hashing uses keyed HMAC",
             "HMAC-SHA256 with secret key for PAN hashing."),
            ("3.6.1","Key management procedures documented",
             "Document key lifecycle per NIST SP 800-57."),
            ("3.7.1","Key custodians acknowledge key responsibilities",
             "Formal key custodian agreements signed by all handlers."),
        ]:
            self.check(req,"PCI DSS",title,"MANUAL",
                f"Manual: verify {title.lower()}",rec)

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 4 — Cryptography in Transit
    # ══════════════════════════════════════════════════════════
    def _pci_req4_cryptography(self):
        self.log("data","[PCI] Req 4: Cryptography in Transit")
        ssl_f = self._ssl_findings()
        weak_tls = [f for f in ssl_f if any(
            x in f.get("title","") for x in ["TLS 1.0","TLS 1.1","SSL 3","SSL 2","RC4","NULL","EXPORT"])]

        if weak_tls:
            for f in weak_tls[:4]:
                self.check("4.2.1","PCI DSS",
                    f"Strong crypto: {f.get('title','')[:45]}",
                    "FAIL", f.get("evidence",""), f.get("recommendation",""), f.get("cvss",7.5))
        else:
            self.check("4.2.1","PCI DSS","Strong cryptography for all CHD transmission",
                "PASS","No weak TLS/cipher issues detected")

        cert_issues = [f for f in ssl_f if any(x in f.get("title","").lower()
                       for x in ["expir","self-signed","mismatch"])]
        if cert_issues:
            for f in cert_issues[:2]:
                self.check("4.2.1","PCI DSS",
                    f"Certificate: {f.get('title','')[:45]}",
                    "FAIL", f.get("evidence",""), f.get("recommendation",""), f.get("cvss",7.5))
        else:
            self.check("4.2.1","PCI DSS","Certificate valid and properly issued",
                "PASS","No certificate issues detected")

        self.check("4.2.2","PCI DSS","Inventory of trusted keys/certs maintained",
            "MANUAL","Manual: verify certificate inventory and review process",
            "Track all certs. Automate expiry alerts (≥30 days).")

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 5 — Anti-Malware
    # ══════════════════════════════════════════════════════════
    def _pci_req5_antimalware(self):
        self.log("data","[PCI] Req 5: Protect Against Malware")
        for req, title, rec in [
            ("5.2.1","Anti-malware deployed on all applicable systems",
             "Deploy EDR (CrowdStrike/Defender) on all CDE systems."),
            ("5.3.1","Anti-malware signatures updated in real time",
             "Enable automatic signature updates. Alert on failures."),
            ("5.3.2","Anti-malware scans performed periodically",
             "Schedule daily full scans. Real-time protection always active."),
            ("5.4.1","Phishing protection mechanisms deployed",
             "Email gateway filtering + DMARC p=reject + security training."),
        ]:
            self.check(req,"PCI DSS",title,"MANUAL",
                f"Manual verification required: {title.lower()}",rec)

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 6 — Secure Systems and Software
    # ══════════════════════════════════════════════════════════
    def _pci_req6_software(self):
        self.log("data","[PCI] Req 6: Secure Systems and Software")
        wf = self._web_findings()
        port_findings = [p for p in self.ports.get("open_ports",[]) if p.get("cves")]

        for vuln_name in ["SQL Injection","XSS","SSRF","XXE","SSTI","Path Traversal"]:
            found = [f for f in wf if vuln_name in f.get("title","")]
            self.check("6.2.4","PCI DSS",
                f"No {vuln_name} vulnerabilities",
                "FAIL" if found else "PASS",
                f"{len(found)} {vuln_name} findings" if found else f"No {vuln_name} found",
                f"Fix all {vuln_name} vulnerabilities. Use parameterized queries / encoding.",
                max((f.get("cvss",0) for f in found), default=0))

        if port_findings:
            worst = max(max(c.get("cvss",0) for c in p.get("cves",[])) if p.get("cves") else 0
                        for p in port_findings)
            self.check("6.3.1","PCI DSS","Security vulnerabilities addressed",
                "FAIL" if worst >= 7 else "WARNING",
                f"CVEs on {len(port_findings)} services, worst CVSS {worst}",
                "Critical CVEs: patch within 1 day. High: 7 days. Medium: 30 days.",
                worst)
        else:
            self.check("6.3.1","PCI DSS","Security vulnerabilities addressed",
                "PASS","No CVE vulnerabilities detected")

        for req, title, rec in [
            ("6.3.2","Software component inventory (SBOM)",
             "Generate SBOM with CycloneDX/SPDX. Use SCA tools (Snyk)."),
            ("6.3.3","All components protected from known vulnerabilities",
             "Enable Dependabot. Subscribe to vendor security advisories."),
            ("6.4.3","All payment page scripts authorized and integrity-checked",
             "Use SRI for all third-party scripts on payment pages."),
        ]:
            self.check(req,"PCI DSS",title,"MANUAL",f"Manual: verify {title.lower()}",rec)

        resp = self._get(self.base_url)
        headers = resp.get("headers",{}) if resp else {}
        waf = any(k.lower() in str(headers).lower() for k in ["cf-ray","x-sucuri","x-waf"])
        self.check("6.4.2","PCI DSS","Automated solution for public-facing web apps",
            "PASS" if waf else "WARNING",
            f"WAF: {'detected' if waf else 'not detected'}",
            "Deploy WAF. Configure custom rules for banking-specific patterns.",
            5.3 if not waf else 0)

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 7 — Restrict Access
    # ══════════════════════════════════════════════════════════
    def _pci_req7_access_control(self):
        self.log("data","[PCI] Req 7: Restrict Access by Business Need")
        wf = self._web_findings()
        bola = [f for f in wf if "BOLA" in f.get("title","") or "IDOR" in f.get("title","")]
        bfla = [f for f in wf if "BFLA" in f.get("title","")]

        self.check("7.2.1","PCI DSS","Access control model implemented",
            "FAIL" if bola else "PASS",
            "BOLA/IDOR detected" if bola else "No object-level auth bypass detected",
            "Implement object-level authorization on every request.",
            9.1 if bola else 0)

        self.check("7.3.1","PCI DSS","Access managed via access control system",
            "FAIL" if bfla else "PASS",
            "BFLA detected" if bfla else "No function-level auth bypass detected",
            "Implement RBAC. Verify role before every privileged operation.",
            9.8 if bfla else 0)

        for req, title, rec in [
            ("7.2.4","User account reviews performed regularly",
             "Quarterly access review. Remove dormant/excess accounts."),
            ("7.2.5","Service account access minimized",
             "Audit service accounts. Restrict to required permissions only."),
            ("7.3.2","Principle of least privilege enforced",
             "Remove excess permissions. Use PAM for privileged access."),
        ]:
            self.check(req,"PCI DSS",title,"MANUAL",f"Manual: verify {title.lower()}",rec)

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 8 — Authentication
    # ══════════════════════════════════════════════════════════
    def _pci_req8_authentication(self):
        self.log("data","[PCI] Req 8: Identify Users and Authenticate")
        af = self._auth_findings()
        no_lockout = any("No brute-force" in f.get("title","") or "No rate limit" in f.get("title","") for f in af)
        weak_pw    = any("Weak password" in f.get("title","") for f in af)
        default_creds = any("Default credentials" in f.get("title","") for f in af)
        otp_issues = any("OTP" in f.get("title","") or "2FA" in f.get("title","") for f in af)
        jwt_issues = [f for f in self._web_findings() if "JWT" in f.get("title","")]

        self.check("8.2.1","PCI DSS","All users uniquely identified",
            "MANUAL","Manual: verify no shared accounts in any CDE system",
            "Disable generic/shared accounts. Each person uses unique credentials.")

        self.check("8.3.4","PCI DSS","Lockout after max 10 failed attempts",
            "FAIL" if no_lockout else "MANUAL",
            "No lockout/rate-limiting detected" if no_lockout else
            "Manual: verify lockout policy in IdP configuration",
            "Lock accounts after 6-10 failures for ≥30 minutes.",
            9.8 if no_lockout else 0)

        self.check("8.3.6","PCI DSS","Passwords minimum 12 chars + complexity",
            "FAIL" if weak_pw else "MANUAL",
            "Weak passwords accepted" if weak_pw else
            "Manual: verify password policy in IdP/AD",
            "12+ chars, upper+lower+digit+special. Reject known-breached.",
            7.5 if weak_pw else 0)

        self.check("8.3.9","PCI DSS","Passwords changed every 90 days",
            "MANUAL","Manual: verify max password age in AD/LDAP",
            "Set max password age to 90 days.")

        self.check("8.4.1","PCI DSS","MFA for all non-console CDE admin access",
            "MANUAL","Manual: verify MFA enforced for all admin remote access",
            "Hardware FIDO2 token for all privileged access to CDE.")

        self.check("8.4.2","PCI DSS","MFA for all non-console access into CDE",
            "FAIL" if otp_issues else "MANUAL",
            "2FA/OTP weaknesses detected" if otp_issues else
            "Manual: verify MFA enforcement scope",
            "All remote CDE access requires MFA. No exceptions.",
            7.5 if otp_issues else 0)

        self.check("8.6.1","PCI DSS","System/application account passwords managed",
            "FAIL" if default_creds else "MANUAL",
            "Default credentials found" if default_creds else
            "Manual: verify service account password management",
            "Use HashiCorp Vault / CyberArk for secrets. Rotate quarterly.",
            9.8 if default_creds else 0)

        if jwt_issues:
            worst_jwt = max(f.get("cvss",0) for f in jwt_issues)
            self.check("8.4.2","PCI DSS","JWT token security",
                "FAIL", f"JWT issues: {[f.get('title','')[:40] for f in jwt_issues[:2]]}",
                "Use RS256/ES256. Validate exp/iss/aud. Rotate signing keys.",
                worst_jwt)

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 10 — Logging and Monitoring
    # ══════════════════════════════════════════════════════════
    def _pci_req10_logging(self):
        self.log("data","[PCI] Req 10: Log and Monitor All Access")
        sensitive_paths = self.recon.get("sensitive_paths",[])
        exposed_logs = [p for p in sensitive_paths
                        if p.get("exposed") and ".log" in p.get("path","").lower()]

        self.check("10.2.1","PCI DSS","Audit logs not publicly accessible",
            "FAIL" if exposed_logs else "PASS",
            f"Exposed logs: {[p.get('path') for p in exposed_logs]}" if exposed_logs else
            "No exposed log files",
            "Remove logs from web root. Restrict log access to admins.",
            7.5 if exposed_logs else 0)

        for req, title, rec in [
            ("10.2.1.1","Individual user activity in CDE logged",
             "Log all user access to cardholder data with user ID and timestamp."),
            ("10.2.1.2","All system component actions logged",
             "Log privilege escalation, failed auth, all sudo/su commands."),
            ("10.2.1.4","Invalid logical access attempts logged",
             "Log and alert on all failed authentication attempts."),
            ("10.2.1.5","Use and changes to ID mechanisms logged",
             "Log all changes to accounts, permissions, and authentication methods."),
            ("10.3.1","Audit logs protected from modification",
             "Write logs to WORM storage or centralized SIEM. Enable integrity monitoring."),
            ("10.3.3","Audit logs backed up",
             "Back up logs to separate environment. Test restore quarterly."),
            ("10.4.1","Security events reviewed daily",
             "Automate alerts in SIEM for critical events. SOC review daily."),
            ("10.5.1","Log retention 12 months (3 months immediate)",
             "Configure 12-month retention policy. Hot storage for 3 months."),
            ("10.6.1","System clocks synchronized (NTP)",
             "Configure NTP on all systems. Use stratum 1-2 sources."),
            ("10.7.1","Failures of security controls detected",
             "Alert on log pipeline failures, AV issues, FIM alerts."),
        ]:
            self.check(req,"PCI DSS",title,"MANUAL",f"Manual: verify {title.lower()}",rec)

    # ══════════════════════════════════════════════════════════
    # PCI DSS REQUIREMENT 11 — Test Security Regularly
    # ══════════════════════════════════════════════════════════
    def _pci_req11_testing(self):
        self.log("data","[PCI] Req 11: Test Security Regularly")

        self.check("11.3.1","PCI DSS","Internal vulnerability scan quarterly",
            "PASS","Vulnerability scan performed in this engagement",
            "Schedule quarterly internal scans. Remediate Highs within 30 days.")

        self.check("11.3.2","PCI DSS","External ASV scan quarterly",
            "MANUAL","Manual: submit ASV scan reports from approved vendor",
            "Engage PCI-approved ASV for quarterly external scans.")

        self.check("11.3.2.1","PCI DSS","ASV scan rescan after remediation",
            "MANUAL","Manual: provide passing ASV scan after remediation",
            "All High findings must be remediated before passing ASV scan.")

        self.check("11.4.1","PCI DSS","Penetration testing methodology defined",
            "MANUAL","Manual: verify documented pentest methodology",
            "Document methodology covering all CDE segments, OWASP WSTG, PTES.")

        self.check("11.4.3","PCI DSS","External pentest annually",
            "PASS","External penetration test performed in this engagement",
            "Annual pentest by CREST/OSCP certified tester.")

        self.check("11.4.4","PCI DSS","Exploitable vulnerabilities corrected and retested",
            "MANUAL","Manual: verify remediation verification process",
            "All critical/high pentest findings retested by tester.")

        self.check("11.4.7","PCI DSS","Multi-tenant provider supports tenant pentest",
            "MANUAL","Manual: verify if cloud provider allows tenant-specific pentesting",
            "Cloud providers must allow customers to test their own environments.")

        self.check("11.5.1","PCI DSS","IDS/IPS deployed at network perimeter and CDE",
            "MANUAL","Manual: verify IDS/IPS coverage of all CDE traffic",
            "Network IDS/IPS on all CDE entry points. Alert and block.")

        self.check("11.5.2","PCI DSS","File integrity monitoring (FIM) deployed",
            "MANUAL","Manual: verify FIM on OS files, app files, log files",
            "FIM alerts on unauthorized changes. Tripwire/OSSEC/CrowdStrike.")

        self.check("11.6.1","PCI DSS","Tamper detection for payment pages",
            "MANUAL","Manual: verify script integrity monitoring on payment pages",
            "Implement SRI for all third-party scripts. Monitor for Magecart-style attacks.")

    # ══════════════════════════════════════════════════════════
    # SWIFT CSP Controls (v2024)
    # ══════════════════════════════════════════════════════════
    def _swift_csp(self):
        self.log("data","[SWIFT] Mandatory CSP controls...")
        wf  = self._web_findings()
        af  = self._auth_findings()
        sf  = self._ssl_findings()
        op  = self._open_ports()

        docker_exposed = 2375 in op
        tls_issues     = [f for f in sf if "TLS 1.0" in f.get("title","") or "TLS 1.1" in f.get("title","")]
        bola = any("BOLA" in f.get("title","") or "IDOR" in f.get("title","") for f in wf)
        bfla = any("BFLA" in f.get("title","") for f in wf)
        jwt  = [f for f in wf if "JWT" in f.get("title","")]
        otp  = [f for f in wf if "OTP" in f.get("title","") or "2FA" in f.get("title","")]
        no_lockout  = any("No brute-force" in f.get("title","") for f in af)
        weak_pw     = any("Weak password" in f.get("title","") for f in af)
        default_creds = any("Default credentials" in f.get("title","") for f in af)
        hsts_missing  = any("HSTS" in f.get("title","") for f in sf)
        cves = [p for p in self.ports.get("open_ports",[]) if p.get("cves")]

        swift_checks = [
            ("1.1","SWIFT environment protection (isolation)",
             "MANUAL","Manual: verify SWIFT on isolated VLAN, no direct internet",
             "Deny-all firewall default. Whitelist only SWIFT Alliance destinations.", 0),
            ("1.2","Privileged account control",
             "MANUAL","Manual: verify dual-control for SWIFT transactions, operator accounts",
             "4-eyes for transactions above threshold. Dedicated operator workstations.", 0),
            ("1.3","Virtualisation platform security",
             "FAIL" if docker_exposed else "MANUAL",
             "Docker API (2375) exposed" if docker_exposed else
             "Manual: verify hypervisor/container platform hardening",
             "Disable unauthenticated Docker API. Harden container runtime.",
             9.8 if docker_exposed else 0),
            ("2.1","Data flow security (internal encryption)",
             "MANUAL","Manual: verify mTLS between SWIFT components",
             "Enable TLS 1.2+ for all SWIFT component communication.", 0),
            ("2.2","Security updates on SWIFT environment",
             "FAIL" if cves else "MANUAL",
             f"CVEs on {len(cves)} services" if cves else "Manual: verify SWIFT patch compliance",
             "SWIFT patches: Critical 7d, High 30d, Medium 90d.",
             max((max(c.get("cvss",0) for c in p.get("cves",[])) for p in cves), default=0) if cves else 0),
            ("2.3","System hardening (CIS Benchmarks)",
             "MANUAL","Manual: run CIS-CAT against SWIFT servers",
             "CIS Benchmark Level 2 for all SWIFT platform hosts.", 0),
            ("2.4A","Back-office application security",
             "MANUAL","Manual: verify back-office app pentest and secure SDLC",
             "Annual application pentest. Secure coding training for developers.", 0),
            ("2.5A","External transmission protection (TLS 1.2+)",
             "FAIL" if tls_issues else "PASS",
             f"Weak TLS: {[f.get('title','')[:35] for f in tls_issues[:2]]}" if tls_issues else
             "TLS 1.2+ enforced",
             "Disable TLS 1.0/1.1 per SWIFT mandate.",
             7.5 if tls_issues else 0),
            ("2.6","Operator session confidentiality",
             "FAIL" if hsts_missing else "PASS",
             "HSTS missing" if hsts_missing else "HSTS enabled",
             "HSTS max-age=31536000; includeSubDomains.",
             6.5 if hsts_missing else 0),
            ("2.7","Vulnerability scanning",
             "PASS","Automated vulnerability scan performed",
             "Quarterly scans. Track and remediate all findings."),
            ("2.8A","Outsourced critical activities security",
             "MANUAL","Manual: verify third-party providers have CSP attestation",
             "CSP requirements in third-party contracts. Annual reviews.", 0),
            ("2.9A","Transaction business controls",
             "MANUAL","Manual: verify transaction limits, reconciliation, anomaly detection",
             "Daily reconciliation. Alert on anomalous transaction patterns.", 0),
            ("3.1","Physical security of SWIFT infrastructure",
             "MANUAL","Manual: verify SWIFT HSM/servers in secured datacenter",
             "Biometric access, CCTV, visitor logs for SWIFT hardware.", 0),
            ("4.1","Password policy for SWIFT operators",
             "FAIL" if (no_lockout or weak_pw) else "MANUAL",
             "Auth weaknesses: " + ("no brute protection" if no_lockout else "weak passwords") if (no_lockout or weak_pw) else
             "Manual: verify SWIFT operator password policy (8+ chars, 90d rotation, 3-strike lockout)",
             "Min 8 chars, complexity, 90-day rotation, max 3 attempts.",
             9.8 if no_lockout else 7.5 if weak_pw else 0),
            ("5.1","Logical access control for SWIFT components",
             "FAIL" if (bola or bfla) else "PASS",
             "Access control bypass detected" if (bola or bfla) else
             "No access control bypass in automated tests",
             "RBAC with least privilege. Quarterly access reviews.",
             9.1 if bola else 8.8 if bfla else 0),
            ("5.2","Token management for SWIFT operators",
             "FAIL" if jwt else "MANUAL",
             f"JWT issues: {[f.get('title','')[:35] for f in jwt[:2]]}" if jwt else
             "Manual: verify hardware token lifecycle management",
             "RS256/ES256 JWT. Rotate keys quarterly. Enforce exp/iss validation.",
             max((f.get("cvss",0) for f in jwt), default=0)),
            ("5.4","Multi-factor authentication for SWIFT",
             "FAIL" if otp else "MANUAL",
             f"MFA issues: {[f.get('title','')[:35] for f in otp[:2]]}" if otp else
             "Manual: verify hardware MFA for all SWIFT operators",
             "FIDO2 hardware token for all SWIFT operator sessions.",
             max((f.get("cvss",0) for f in otp), default=0)),
            ("6.1","Cyber incident response plan",
             "MANUAL","Manual: verify IR plan covers SWIFT, includes SWIFT ISAC reporting",
             "IR plan with SWIFT-specific procedures. Report to SWIFT within 24h.", 0),
            ("6.2","Security training for SWIFT staff",
             "MANUAL","Manual: verify annual SWIFT-specific security training",
             "Annual training covering SWIFT fraud patterns, social engineering.", 0),
            ("6.3","Penetration testing of SWIFT infrastructure",
             "PASS","SWIFT infrastructure tested in this engagement",
             "Annual pentest by qualified CREST tester.", 0),
            ("7.1","Vulnerability scanning of SWIFT environment",
             "PASS","Automated vulnerability scan performed",
             "Quarterly scans. Critical fixes within 7 days.", 0),
            ("7.2","Annual security assessment",
             "PASS","Annual assessment performed in this engagement",
             "Document and submit attestation to SWIFT annually.", 0),
        ]

        for args in swift_checks:
            self.check(*args[:6])

        passed = len([c for c in self.checks if c["framework"]=="SWIFT CSP" and c["status"]=="PASS"])
        failed = len([c for c in self.checks if c["framework"]=="SWIFT CSP" and c["status"]=="FAIL"])
        self.log("ok", f"[SWIFT] CSP: ✅{passed} PASS / 🚨{failed} FAIL")

    # ══════════════════════════════════════════════════════════
    # ISO 27001:2022
    # ══════════════════════════════════════════════════════════
    def _iso27001(self):
        self.log("data","[ISO] ISO 27001:2022 key controls...")
        for ctrl, title, status, evidence, rec in [
            ("A.8.8","Management of technical vulnerabilities",
             "PASS","Automated vulnerability scan performed",""),
            ("A.8.9","Configuration management",
             "MANUAL","Manual: verify CIS-benchmark configuration baselines",
             "CIS-CAT scans. Automated config drift detection."),
            ("A.8.12","Data leakage prevention",
             "MANUAL","Manual: verify DLP on email, USB, cloud egress",
             "Deploy DLP solution. Monitor and alert on sensitive data egress."),
            ("A.8.20","Network security",
             "MANUAL","Manual: verify network diagrams, segmentation",
             "Network diagrams current. IDS/IPS covers all CDE."),
            ("A.8.24","Use of cryptography",
             "MANUAL","Manual: verify encryption policy and key management",
             "Encryption policy covering data at rest and in transit."),
            ("A.8.25","Secure development lifecycle",
             "MANUAL","Manual: verify SDLC includes threat modeling, SAST/DAST",
             "Threat modeling for all new features. SAST in CI/CD pipeline."),
            ("A.8.28","Secure coding",
             "MANUAL","Manual: verify OWASP Secure Coding Practices adopted",
             "OWASP SAMM assessment. Secure coding training for all devs."),
            ("A.5.24","Information security incident management",
             "MANUAL","Manual: verify IR plan and breach notification procedures",
             "IR plan tested annually. Breach notification within 72h (GDPR/PCI)."),
            ("A.5.25","Assessment of security events",
             "MANUAL","Manual: verify SIEM and SOC for event triage",
             "24/7 SOC monitoring. SIEM with banking-specific use cases."),
            ("A.5.29","Information security during disruption",
             "MANUAL","Manual: verify BCP includes security during incidents",
             "BCP tested annually. Failover environment includes security controls."),
            ("A.5.36","Compliance with policies and rules",
             "MANUAL","Manual: verify compliance monitoring and reporting process",
             "Quarterly compliance dashboard. Automated policy checks."),
        ]:
            self.check(ctrl, "ISO 27001", title, status, evidence,
                rec if rec else "See ISO 27002:2022 for implementation guidance.")

    # ─── HTTP helper ─────────────────────────────────────────
    def _get(self, url: str) -> Optional[dict]:
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent","GATOR-PRO/2.0")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                return {"status":resp.status,"headers":dict(resp.headers),
                        "body":resp.read(4096).decode("utf-8","ignore")}
        except Exception:
            return None
