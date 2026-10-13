"""Unified AgentGuard AI dashboard and security analysis API.

Provides deterministic, explainable security analysis across five modes:
1. URL & Link Scanner (static lexical analysis)
2. Message & Phishing Scanner (SMS, email, and chat heuristics)
3. AI Prompt Injection Scanner (jailbreaks and instruction overrides)
4. AI Agent Action Security (simulated tool chains & policy enforcement)
5. General Pasted Content Scanner (secrets and destructive script detection)

Includes SQLite persistence, credential redaction, and standard-library HTTP serving.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import db
from security_engine import (
    analyze_action,
    scan_message,
    scan_pasted_content,
    scan_prompt_injection,
    scan_url,
)

ROOT = Path(__file__).resolve().parent
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/static/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
MAX_REQUEST_BYTES = 8_192
AUDIT_LIMIT = 100
AUDIT_EVENTS: list[dict] = []
AUDIT_LOCK = threading.Lock()
AUDIT_METRICS = {
    "scanned": 0,
    "allowed": 0,
    "review": 0,
    "blocked": 0,
    "high_risk": 0,
}

VALID_MODES = ("agent", "url", "message", "prompt", "content")

TOOL_POLICIES = {
    "read_notes": "allowed",
    "summarize_report": "allowed",
    "agent_plan": "allowed",
    "read_env": "restricted",
    "read_sensitive_data": "restricted",
    "send_external_data": "blocked",
    "delete_database": "blocked",
    "admin_access": "blocked",
    "execute_command": "blocked",
}

CATEGORY_WEIGHTS = {
    "Prompt Injection": 35,
    "Secret/Data Exfiltration": 30,
    "Privilege Escalation": 30,
    "Destructive Action": 40,
    "Suspicious Tool Chain": 35,
    "Sensitive Data Access": 25,
    "Unsafe External Destination": 35,
    "Unauthorized Tool Use": 30,
    "Dangerous Commands": 40,
}

# Auto-initialize database on import
try:
    db.init_db()
except Exception as _e:
    sys.stderr.write(f"Notice: database init deferred: {_e}\n")


def _contains(patterns: tuple[str, ...], text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _redact_sensitive_values(request: str) -> str:
    """Redact passwords, bearer tokens, and credentials from request text."""
    return db.redact_sensitive_content(request)


def simulate_agent(request: str) -> dict:
    """Create a proposed tool plan from text without executing any tool."""
    text = request.lower().replace("_", " ")
    tools: list[str] = []

    destructive = _contains(
        (
            r"\b(delete|remove|wipe|destroy|drop|format)\b.{0,50}\b"
            r"(database|backups?|files?|production)\b",
            r"\b(production database|all backups)\b",
        ),
        text,
    )
    privilege = _contains(
        (r"\b(admin|administrator|root|privilege|privileges)\b",),
        text,
    )
    secret_access = _contains(
        (
            r"\b(api keys?|secrets?|passwords?|private keys?|environment variables|"
            r"env(?:ironment)? variables?)\b",
            r"\b\.env\b",
        ),
        text,
    )
    outbound = _contains(
        (
            r"\b(send|email|upload|transfer|share|post|exfiltrate)\b",
            r"\bexternal (server|service|destination)\b",
        ),
        text,
    )
    command_request = _contains(
        (r"\b(run|execute|launch)\b.{0,30}\b(command|shell|powershell|script)\b",),
        text,
    )
    sensitive_access = _contains(
        (
            r"\b(ssn|social security|aadhaar|credit card|bank account|"
            r"sensitive data|personal data|phone number)\b",
        ),
        text,
    )

    if sensitive_access:
        tools.append("read_sensitive_data")
    if secret_access:
        tools.append("read_env")
    if outbound:
        tools.append("send_external_data")
    if destructive:
        tools.append("delete_database")
    if privilege:
        tools.append("admin_access")
    if command_request:
        tools.append("execute_command")

    if not tools and _contains((r"\b(notes?|summarize|summary|report)\b",), text):
        tools.extend(("read_notes", "summarize_report"))
    if not tools:
        tools.append("agent_plan")

    action = " → ".join(tools)
    if len(tools) == 1:
        action = f"Proposed {tools[0].replace('_', ' ')} (simulated)"
    elif len(tools) > 1:
        action = f"Proposed tool chain: {action} (simulated)"
    else:
        action = f"Proposed {tools[0]} (simulated)"

    return {
        "tools": tools,
        "action": action,
        "signals": {
            "destructive": destructive,
            "privilege": privilege,
            "secret_access": secret_access,
            "outbound": outbound,
            "sensitive_access": sensitive_access,
        },
    }


def analyze_request(request: str, mode: str = "agent") -> dict:
    """Analyze a request across 5 security modes with deterministic policy scoring."""
    mode = (mode or "agent").lower()
    indicators: list[str] = []

    if mode == "url":
        res = scan_url(request)
        threats = res["threats"]
        risk_score = res["risk_score"]
        decision = res["decision"]
        reason = res["reason"]
        recommended_action = res["recommended_action"]
        indicators = res.get("indicators", [])
        tool = "url_inspector"
        action = "Static lexical inspection of URL (simulated)"
        policies = [
            {
                "tool": "url_parser",
                "status": "allowed" if decision == "ALLOW" else ("restricted" if decision == "REVIEW" else "blocked"),
            }
        ]

    elif mode == "message":
        res = scan_message(request)
        threats = res["threats"]
        risk_score = res["risk_score"]
        decision = res["decision"]
        reason = res["reason"]
        recommended_action = res["recommended_action"]
        indicators = res.get("indicators", [])
        tool = "message_phishing_filter"
        action = "Social engineering and phishing heuristic analysis (simulated)"
        policies = [
            {
                "tool": "message_filter",
                "status": "allowed" if decision == "ALLOW" else ("restricted" if decision == "REVIEW" else "blocked"),
            }
        ]

    elif mode == "prompt":
        res = scan_prompt_injection(request)
        threats = res["threats"]
        risk_score = res["risk_score"]
        decision = res["decision"]
        reason = res["reason"]
        recommended_action = res["recommended_action"]
        indicators = res.get("indicators", [])
        tool = "prompt_injection_guard"
        action = "Prompt injection and jailbreak analysis (simulated)"
        policies = [
            {
                "tool": "prompt_filter",
                "status": "allowed" if decision == "ALLOW" else ("restricted" if decision == "REVIEW" else "blocked"),
            }
        ]

    elif mode == "content":
        res = scan_pasted_content(request)
        threats = res["threats"]
        risk_score = res["risk_score"]
        decision = res["decision"]
        reason = res["reason"]
        recommended_action = res["recommended_action"]
        indicators = res.get("indicators", [])
        tool = "content_security_scanner"
        action = "Content secrets and destructive script scanner (simulated)"
        policies = [
            {
                "tool": "content_analyzer",
                "status": "allowed" if decision == "ALLOW" else ("restricted" if decision == "REVIEW" else "blocked"),
            }
        ]

    else:
        # Default: Mode 4 - AI Agent Action Security (Existing Engine & Policy Workflow)
        mode = "agent"
        plan = simulate_agent(request)
        base = analyze_action(" ".join(plan["tools"]), request, " ".join(plan["tools"]))
        original_threats = base["threats"]
        threats = []
        for threat in original_threats:
            if threat == "Destructive Actions":
                threat = "Destructive Action"
            elif threat == "Sensitive-data exposure":
                threat = "Sensitive Data Access"
            elif threat == "Suspicious Tool Chains":
                threat = "Suspicious Tool Chain"
            elif threat == "Unauthorized Tool Usage":
                threat = "Unauthorized Tool Use"
            if threat not in threats:
                threats.append(threat)

        signals = plan["signals"]
        if signals["destructive"] and "Destructive Action" not in threats:
            threats.append("Destructive Action")
        if signals["privilege"] and "Privilege Escalation" not in threats:
            threats.append("Privilege Escalation")
        if signals["secret_access"] and "Secret/Data Exfiltration" not in threats:
            threats.append("Secret/Data Exfiltration")
        if signals["sensitive_access"] and "Sensitive Data Access" not in threats:
            threats.append("Sensitive Data Access")
        if signals["outbound"] and "send_external_data" in plan["tools"]:
            if "Unsafe External Destination" not in threats:
                threats.append("Unsafe External Destination")
        if (
            signals["secret_access"]
            and signals["outbound"]
            and "Suspicious Tool Chain" not in threats
        ):
            threats.append("Suspicious Tool Chain")

        risk_score = base["risk_score"]
        category_aliases = {
            "Prompt Injection": "Prompt Injection",
            "Secret/Data Exfiltration": "Secret/Data Exfiltration",
            "Privilege Escalation": "Privilege Escalation",
            "Destructive Action": "Destructive Actions",
            "Suspicious Tool Chain": "Suspicious Tool Chains",
            "Sensitive Data Access": "Sensitive-data exposure",
            "Unauthorized Tool Use": "Unauthorized Tool Usage",
        }
        for threat in threats:
            if threat not in category_aliases or category_aliases[threat] not in original_threats:
                risk_score += CATEGORY_WEIGHTS.get(threat, 20)

        policies = [
            {"tool": tool, "status": TOOL_POLICIES.get(tool, "restricted")}
            for tool in plan["tools"]
        ]
        blocked_tools = [policy["tool"] for policy in policies if policy["status"] == "blocked"]
        restricted_tools = [
            policy["tool"] for policy in policies if policy["status"] == "restricted"
        ]

        if blocked_tools and "Unauthorized Tool Use" not in threats:
            threats.append("Unauthorized Tool Use")
            risk_score += CATEGORY_WEIGHTS["Unauthorized Tool Use"]

        if blocked_tools:
            risk_score = max(risk_score, 90)
        elif restricted_tools:
            risk_score = max(risk_score, 40)
        if "Prompt Injection" in threats:
            risk_score = max(risk_score, 70)
        risk_score = min(risk_score, 100)

        if blocked_tools or risk_score >= 70:
            decision = "BLOCK"
        elif restricted_tools or risk_score >= 30:
            decision = "REVIEW"
        else:
            decision = "ALLOW"

        if decision == "BLOCK":
            recommended_action = "Block the simulated tool call and require an approved, safer alternative."
        elif decision == "REVIEW":
            recommended_action = "Pause execution and request human approval before any tool is used."
        else:
            recommended_action = "Allow the low-risk simulated plan; no real tool is connected."

        if threats:
            reason = (
                f"{decision.title()} because the request triggered "
                f"{', '.join(threats)}. Tool policy: "
                + "; ".join(
                    "{} is {}".format(item["tool"], item["status"]) for item in policies
                )
                + "."
            )
        else:
            reason = "No configured attack or policy signals were detected in this request."

        tool = " → ".join(plan["tools"])
        action = plan["action"]

    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    redacted_input = _redact_sensitive_values(request)

    event = {
        "timestamp": timestamp,
        "mode": mode,
        "request": redacted_input,
        "tool": tool,
        "decision": decision,
        "risk_score": risk_score,
        "threats": threats,
        "reason": reason,
        "action": action,
        "recommended_action": recommended_action,
    }

    # Save to persistent SQLite storage
    try:
        db.save_scan_event(event)
    except Exception as exc:
        sys.stderr.write(f"Database error writing scan event: {exc}\n")

    # Update in-memory audit log and counters for instant access
    with AUDIT_LOCK:
        AUDIT_EVENTS.append(event)
        del AUDIT_EVENTS[:-AUDIT_LIMIT]
        AUDIT_METRICS["scanned"] += 1
        metric_key = {"ALLOW": "allowed", "REVIEW": "review", "BLOCK": "blocked"}[decision]
        AUDIT_METRICS[metric_key] += 1
        AUDIT_METRICS["high_risk"] += risk_score >= 70
        scan_number = AUDIT_METRICS["scanned"]

    return {
        **event,
        "scan_number": scan_number,
        "action": action,
        "recommended_action": recommended_action,
        "policies": policies,
        "indicators": indicators,
        "simulated_only": True,
    }


def _metrics() -> dict:
    """Return metrics, preferring SQLite values if available."""
    try:
        db_metrics = db.get_metrics()
        if db_metrics["scanned"] > 0:
            return db_metrics
    except Exception:
        pass
    with AUDIT_LOCK:
        return dict(AUDIT_METRICS)


def _audit_events() -> list[dict]:
    """Return recent scan audit events, preferring SQLite values if available."""
    try:
        events = db.get_recent_scans(limit=AUDIT_LIMIT)
        if events:
            return events
    except Exception:
        pass
    with AUDIT_LOCK:
        return list(reversed(AUDIT_EVENTS))


class AgentGuardHandler(BaseHTTPRequestHandler):
    server_version = "AgentGuardDemo/2.0"

    def log_message(self, format: str, *args: object) -> None:
        sys.stdout.write(f"{self.log_date_time_string()} {format % args}\n")

    def _send_json(self, payload: dict | list, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._send_json({"status": "ready", "mode": "simulated", "database": "sqlite_ready"})
            return
        if path == "/api/metrics":
            self._send_json(_metrics())
            return
        if path == "/api/audit":
            self._send_json({"events": _audit_events()})
            return
        asset = STATIC_FILES.get(path)
        if asset is None:
            self._send_json({"error": "Not found"}, 404)
            return
        filename, content_type = asset
        body = (ROOT / "static" / filename).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path

        if path == "/api/audit/clear":
            try:
                db.clear_history()
            except Exception as e:
                sys.stderr.write(f"Database clear history error: {e}\n")
            with AUDIT_LOCK:
                AUDIT_EVENTS.clear()
            self._send_json({"status": "cleared"})
            return

        if path != "/api/scan":
            self._send_json({"error": "Not found"}, 404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json({"error": "Invalid Content-Length"}, 400)
            return

        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._send_json(
                {"error": f"Request body must be between 1 and {MAX_REQUEST_BYTES} bytes"},
                413 if length > MAX_REQUEST_BYTES else 400,
            )
            return

        if "application/json" not in self.headers.get("Content-Type", "").lower():
            self._send_json({"error": "Content-Type must be application/json"}, 415)
            return

        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"error": "Request body must contain valid JSON"}, 400)
            return

        if not isinstance(payload, dict) or not isinstance(payload.get("request"), str):
            self._send_json({"error": "JSON body must include a string 'request' field"}, 400)
            return

        request = payload["request"].strip()
        if not request:
            self._send_json({"error": "Enter a request to scan"}, 400)
            return

        if len(request) > 3_000:
            self._send_json({"error": "Request must be 3,000 characters or fewer"}, 413)
            return

        mode = payload.get("mode", "agent")
        if not isinstance(mode, str) or mode.lower() not in VALID_MODES:
            self._send_json(
                {
                    "error": f"Invalid mode '{mode}'. Choose from: {', '.join(VALID_MODES)}",
                },
                400,
            )
            return

        self._send_json(analyze_request(request, mode=mode.lower()))


def main() -> None:
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", "8000"))
    db.init_db()
    httpd = ThreadingHTTPServer((host, port), AgentGuardHandler)
    print(f"AgentGuard AI is ready at http://{host}:{port}")
    print("Multi-mode simulation active: URL, Message, Prompt, Agent Action, Pasted Content.")
    print("Persistent scan history: SQLite (data/agentguard.db).")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AgentGuard AI.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
