"""VibeShield: Zero-Trust Runtime Security Engine for AI Agents.
Deterministic Python inspection rules mapped to OWASP LLM Top 10 and Agentic Security (ASI).
Pipeline stages: Observe -> Evaluate against Policy -> Remediate -> Self-Heal.
"""
import re
import os
import socket
import ipaddress
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
WORKSPACE = os.path.join(DATA_DIR, "workspace")

# OWASP Policy Catalog
POLICY_CATALOG = [
    {
        "id": "VS-001",
        "owasp": "LLM01",
        "name": "Prompt Injection Detection",
        "owasp_full": "OWASP LLM01: Prompt Injection",
        "phase": "Post-execution (Tool Output)",
        "action": "Sanitize (strip offending lines)",
        "severity": "high",
        "penalty": 20,
        "description": "Scans tool outputs (files, web pages, search results) for instruction-override patterns and neutralizes them by removing offending lines."
    },
    {
        "id": "VS-002",
        "owasp": "ASI05",
        "name": "Excessive Agency & Scope Enforcement",
        "owasp_full": "OWASP ASI05: Excessive Agency",
        "phase": "Pre-execution (Tool Call)",
        "action": "Block",
        "severity": "critical",
        "penalty": 30,
        "description": "Enforces workspace sandboxing by resolving real file paths against declared workspace boundaries, preventing directory traversal."
    },
    {
        "id": "VS-003",
        "owasp": "LLM04",
        "name": "Persistent Memory Poisoning Prevention",
        "owasp_full": "OWASP LLM04: Data and Model Poisoning",
        "phase": "Pre-execution (Memory Write)",
        "action": "Quarantine",
        "severity": "high",
        "penalty": 15,
        "description": "Inspects memory write operations for behavioral override prompts and quarantines malicious instructions to maintain system alignment."
    },
    {
        "id": "VS-004",
        "owasp": "LLM02",
        "name": "Sensitive Information & Credential Disclosure",
        "owasp_full": "OWASP LLM02: Sensitive Information Disclosure",
        "phase": "Post-execution (Tool Output)",
        "action": "Redact",
        "severity": "high",
        "penalty": 15,
        "description": "Detects API keys, private tokens, and passwords in tool responses and redacts them with structured masks before passing to the agent."
    },
    {
        "id": "VS-005",
        "owasp": "LLM06",
        "name": "Server-Side Request Forgery (SSRF) Prevention",
        "owasp_full": "OWASP LLM06: Excessive Agency / SSRF",
        "phase": "Pre-execution (Network Request)",
        "action": "Block",
        "severity": "critical",
        "penalty": 25,
        "description": "Blocks non-HTTP schemes, loopback interfaces, private RFC 1918 subnets, and cloud metadata link-local endpoints across all network operations and redirects."
    }
]

POLICY_MAP = {p["id"]: p for p in POLICY_CATALOG}

# Deterministic Pattern Definitions
INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts|directives)",
    r"disregard\s+(?:all\s+|any\s+)?.{0,40}(?:rules|instructions|guidelines|directives)",
    r"agent\s+instruction\s*:",
    r"<\s*system\s*>",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"do\s+not\s+(?:tell|inform|alert)\s+the\s+user",
    r"you\s+are\s+now\s+(?:a|an|dan)\b",
    r"system\s*:\s*override",
    r"new\s+instructions\s*:",
    r"override\s+system\s+prompt"
]

PERSONA_PATTERNS = [
    r"from\s+now\s+on,?\s+you\s+(?:are|will|must)",
    r"ignore\s+(?:all\s+)?(?:safety|security)\s+(?:rules|checks|guidelines)",
    r"you\s+are\s+(?:now\s+)?dan\b",
    r"always\s+obey\s+(?:any|every|all)",
    r"disable\s+(?:the\s+)?(?:shield|filter|guardrails|security)",
    r"system\s+prompt\s+override"
]

SECRET_PATTERNS = [
    (r"(sk-[A-Za-z0-9_-]{20,})", "OpenAI / Standard API Key"),
    (r"(AKIA[0-9A-Z]{16})", "AWS Access Key ID"),
    (r"(?i)(?:api[_-]?key|secret[_-]?key|bearer|auth[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*_\-+=]{12,})['\"]?", "Generic API Token / Secret"),
    (r"(?i)password\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?", "Plaintext Password")
]

@dataclass
class Evidence:
    bad_content: str = ""
    line_numbers: List[int] = field(default_factory=list)
    offending_lines: List[str] = field(default_factory=list)
    requested_path: str = ""
    resolved_path: str = ""
    target_workspace: str = ""
    memory_payload: str = ""
    masked_secret: str = ""
    secret_type: str = ""
    rejected_url: str = ""
    url_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bad_content": self.bad_content,
            "line_numbers": self.line_numbers,
            "offending_lines": self.offending_lines,
            "requested_path": self.requested_path,
            "resolved_path": self.resolved_path,
            "target_workspace": self.target_workspace,
            "memory_payload": self.memory_payload,
            "masked_secret": self.masked_secret,
            "secret_type": self.secret_type,
            "rejected_url": self.rejected_url,
            "url_reason": self.url_reason
        }

@dataclass
class Verdict:
    rule_id: str = ""
    rule_name: str = ""
    owasp: str = ""
    owasp_full: str = ""
    severity: str = ""
    desc: str = ""
    remediation: str = ""
    penalty: int = 0
    action: str = "allow"      # allow | block | sanitize | quarantine | redact
    clean: str = ""            # sanitized text
    evidence: Evidence = field(default_factory=Evidence)

def mask_secret(secret: str) -> str:
    """Mask secret retaining first 4 characters plus total length, e.g. 'sk-A*** [length 35]'."""
    s = secret.strip()
    if len(s) <= 4:
        return f"{s[:1]}*** [length {len(s)}]"
    return f"{s[:4]}*** [length {len(s)}]"

def blocked_url(url: str) -> str:
    """Zero-Trust SSRF inspection.
    Returns rejection reason string if URL is prohibited, or empty string if allowed.
    """
    if not url or not isinstance(url, str):
        return "Empty or invalid URL provided."
    try:
        parsed = urlparse(url.strip())
    except Exception as e:
        return f"Malformed URL structure: {e}"

    if parsed.scheme.lower() not in ("http", "https"):
        return f"Scheme '{parsed.scheme}' is prohibited. Only HTTP and HTTPS are permitted (RFC 3986)."

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return "URL is missing a valid hostname."

    # Controlled local sandbox test page exception
    if hostname in ("localhost", "127.0.0.1"):
        if parsed.path.startswith("/sandbox/pages/"):
            return ""  # Allowed for local simulation lab only
        return f"Loopback address '{hostname}' blocked. Access to internal services is forbidden."

    # Check for direct numeric IP representations
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if ip_obj.is_loopback:
            return f"Loopback address {hostname} is blocked."
        if ip_obj.is_link_local:
            return f"Link-local / Cloud metadata address {hostname} is blocked."
        if ip_obj.is_private:
            return f"Private RFC 1918 address {hostname} is blocked."
        if ip_obj.is_reserved or ip_obj.is_multicast or not ip_obj.is_global:
            return f"Non-public address {hostname} is blocked."
    except ValueError:
        pass  # Hostname is a domain name, proceed to DNS resolution check

    # Resolve domain to all bound IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = {item[4][0] for item in addr_info}
    except socket.gaierror as e:
        # If hostname cannot be resolved, block it defensively
        return f"Hostname DNS resolution failed: {e}"
    except Exception as e:
        return f"DNS lookup error: {e}"

    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback:
                return f"Resolved host '{hostname}' points to loopback address {ip_str}."
            if ip_obj.is_link_local:
                return f"Resolved host '{hostname}' points to link-local / cloud metadata {ip_str}."
            if ip_obj.is_private:
                return f"Resolved host '{hostname}' points to private internal subnet {ip_str} (RFC 1918)."
            if not ip_obj.is_global:
                return f"Resolved host '{hostname}' points to non-global address {ip_str}."
        except ValueError:
            return f"Invalid IP returned for host: {ip_str}"

    return ""

def check_tool_call(tool: str, args: Dict[str, Any], workspace_dir: Optional[str] = None) -> Verdict:
    """Pre-execution Policy Gate (Observe -> Evaluate). Deny-by-default outside scope."""
    ws = workspace_dir or WORKSPACE
    real_ws = os.path.realpath(os.path.abspath(ws))

    # VS-002: Excessive Agency / Path Traversal
    if tool in ("delete_file", "read_file", "write_file", "list_files"):
        req_path = str(args.get("path", "."))
        target_path = os.path.realpath(os.path.abspath(os.path.join(real_ws, req_path)))
        if target_path != real_ws and not target_path.startswith(real_ws + os.sep):
            ev = Evidence(
                bad_content=f"Tool: {tool}(path={req_path!r})",
                requested_path=req_path,
                resolved_path=target_path,
                target_workspace=real_ws
            )
            p = POLICY_MAP["VS-002"]
            return Verdict(
                rule_id=p["id"],
                rule_name=p["name"],
                owasp=p["owasp"],
                owasp_full=p["owasp_full"],
                severity=p["severity"],
                desc=f"Target path {req_path!r} resolves to {target_path!r}, outside authorized workspace boundary.",
                remediation="Execution blocked before filesystem access. Session trust penalized.",
                penalty=p["penalty"],
                action="block",
                evidence=ev
            )

    # VS-003: Memory Poisoning
    if tool == "write_memory":
        content = str(args.get("content", ""))
        for pat in PERSONA_PATTERNS + INJECTION_PATTERNS:
            m = re.search(pat, content, re.IGNORECASE)
            if m:
                ev = Evidence(
                    bad_content=content,
                    memory_payload=content
                )
                p = POLICY_MAP["VS-003"]
                return Verdict(
                    rule_id=p["id"],
                    rule_name=p["name"],
                    owasp=p["owasp"],
                    owasp_full=p["owasp_full"],
                    severity=p["severity"],
                    desc=f"Memory write matches adversarial directive pattern: {m.group(0)!r}.",
                    remediation="Memory entry quarantined in isolated store. Active memory remains untainted.",
                    penalty=p["penalty"],
                    action="quarantine",
                    evidence=ev
                )

    # VS-005: SSRF on network fetch
    if tool == "browse":
        target_url = str(args.get("url", ""))
        reason = blocked_url(target_url)
        if reason:
            ev = Evidence(
                bad_content=target_url,
                rejected_url=target_url,
                url_reason=reason
            )
            p = POLICY_MAP["VS-005"]
            return Verdict(
                rule_id=p["id"],
                rule_name=p["name"],
                owasp=p["owasp"],
                owasp_full=p["owasp_full"],
                severity=p["severity"],
                desc=f"Prohibited destination {target_url!r}: {reason}",
                remediation="Network request aborted before socket connection. Only public HTTP/HTTPS permitted.",
                penalty=p["penalty"],
                action="block",
                evidence=ev
            )

    return Verdict()

def check_tool_result(tool: str, text: str) -> Verdict:
    """Post-execution Policy Gate (Inspect Tool Output -> Remediate).
    Sanitizes prompt injection and redacts exposed credentials.
    """
    if not text or not isinstance(text, str):
        return Verdict()

    # VS-001: Prompt Injection Scan (line by line)
    lines = text.splitlines()
    flagged_indices = []
    flagged_lines = []

    for idx, line in enumerate(lines, start=1):
        for pat in INJECTION_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                flagged_indices.append(idx)
                flagged_lines.append(f"[Line {idx}] {line.strip()}")
                break

    if flagged_lines:
        clean_lines = [line for idx, line in enumerate(lines, start=1) if idx not in flagged_indices]
        clean_text = "\n".join(clean_lines).strip()
        ev = Evidence(
            bad_content="\n".join(flagged_lines),
            line_numbers=flagged_indices,
            offending_lines=flagged_lines
        )
        p = POLICY_MAP["VS-001"]
        return Verdict(
            rule_id=p["id"],
            rule_name=p["name"],
            owasp=p["owasp"],
            owasp_full=p["owasp_full"],
            severity=p["severity"],
            desc=f"Tool output contains {len(flagged_lines)} instruction-override directive(s).",
            remediation="Offending line(s) stripped from tool response before agent processing.",
            penalty=p["penalty"],
            action="sanitize",
            clean=clean_text,
            evidence=ev
        )

    # VS-004: Credential Exposure Scan
    detected_secrets = []
    cleaned_text = text
    for pat, sec_type in SECRET_PATTERNS:
        matches = list(re.finditer(pat, text))
        for m in matches:
            # Capture whole secret or first capture group
            raw_secret = m.group(1) if m.groups() else m.group(0)
            masked = mask_secret(raw_secret)
            detected_secrets.append((sec_type, masked, raw_secret))
            # Redact the actual secret in cleaned output
            cleaned_text = cleaned_text.replace(raw_secret, f"[REDACTED_SECRET: {masked}]")

    if detected_secrets:
        primary = detected_secrets[0]
        ev = Evidence(
            bad_content="\n".join(f"{st}: {ms}" for st, ms, _ in detected_secrets),
            masked_secret=primary[1],
            secret_type=primary[0]
        )
        p = POLICY_MAP["VS-004"]
        return Verdict(
            rule_id=p["id"],
            rule_name=p["name"],
            owasp=p["owasp"],
            owasp_full=p["owasp_full"],
            severity=p["severity"],
            desc=f"Detected sensitive credential ({primary[0]}: {primary[1]}) in tool response.",
            remediation="Secrets redacted from tool response buffer prior to model consumption.",
            penalty=p["penalty"],
            action="redact",
            clean=cleaned_text,
            evidence=ev
        )

    return Verdict()
