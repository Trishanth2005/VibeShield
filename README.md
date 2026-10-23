# VibeShield: Zero-Trust Runtime Security & Self-Healing for AI Agents

VibeShield is an autonomous runtime security engine and state integrity monitor built for AI agents. Paired with **MRU**, a tool-using AI assistant, VibeShield observes every action the agent intends to take and inspects every piece of untrusted data returned by external tools, files, and web links.

It executes a deterministic 4-stage pipeline on every step:
**Observe &rarr; Evaluate against Policy &rarr; Remediate &rarr; Self-Heal**.

---

## Architecture Overview

The system consists of two tightly integrated components sharing a unified local Python backend and SQLite audit ledger:

1. **MRU Agent (`http://localhost:8000/`)**
   - Natural language assistant equipped with system tools: `list_files`, `read_file`, `write_file`, `delete_file`, `browse`, `search_web`, `write_memory`, `get_time`, `get_events`, and `generate_report`.
   - File attachment and drag-and-drop parsing for `.txt`, `.md`, `.csv`, `.json`, code, `.docx` (standard library XML parser), and `.pdf` (via optional `pypdf`), with strict 5 MB validation.
   - Live web search powered by DuckDuckGo HTML without external API keys.
   - Dynamic local AI brain using **Ollama** (auto-detecting `llama3.2:3b` or any installed local model). If Ollama is offline, the agent gracefully falls back to deterministic Basic mode without crashing.
   - **Action Transparency**: Each assistant response displays a structured Result Card detailing the tool used, target, VibeShield decision (`allowed`, `sanitized`, `redacted`, `blocked`, `quarantined`), policy reason, and timestamp.
   - **Session Activity Drawer**: Slide-over panel tracking all actions executed in the current session.
   - **Audit Report Generator**: Type `"generate a security report"` to produce an executive audit summary with direct **HTML** and **TXT** download buttons.

2. **VibeShield Runtime Enforcement (`http://localhost:8000/shield`)**
   - Professional security operations dashboard with live KPI counters, SVG trust score timeline chart, OWASP coverage hit breakdown, and threat feed.
   - **Admin Authentication**: Protected behind `/admin/login` (Username: `admin`, Password: `Admin123`) with HttpOnly session cookies.
   - Deep incident evidence inspector detailing exact offending lines, resolved traversal paths, masked secrets, and rejected SSRF targets.
   - Cryptographic self-healing monitor tracking file integrity against SHA-256 checkpoints.
   - Threat simulation lab featuring one-click attack scenarios and custom prompt execution.

---

## OWASP Policy Mapping (Deterministic Rules)

All security rules are deterministic pure Python (no AI-on-AI hallucination risks):

| Rule ID | OWASP Category | Target Phase | Enforcement Action | Description |
| :--- | :--- | :--- | :--- | :--- |
| **VS-001** | **LLM01: Prompt Injection** | Post-execution (Tool Output) | Sanitize (strip offending lines) | Scans tool outputs (files, web pages, search results) for instruction-override directives and removes offending lines. |
| **VS-002** | **ASI05: Excessive Agency** | Pre-execution (Tool Call) | Block | Resolves canonical file paths (`os.path.realpath`) against declared workspace bounds to prevent directory traversal (`../`). |
| **VS-003** | **LLM04: Memory Poisoning** | Pre-execution (Memory Write) | Quarantine | Detects adversarial persona modification directives ("from now on you are DAN") and routes them to an isolated quarantine store. |
| **VS-004** | **LLM02: Credential Exposure** | Post-execution (Tool Output) | Redact | Identifies API keys, private tokens (`sk-...`, `AKIA...`), and passwords, masking them before reaching the model. |
| **VS-005** | **LLM06: SSRF Prevention** | Pre-execution (Network Fetch) | Block | Prohibits non-HTTP schemes, loopback interfaces, private RFC 1918 subnets, and cloud metadata (169.254.169.254). Re-checks on every HTTP redirect. |

---

## Real Self-Healing Subsystem

Self-healing in VibeShield is real and auditable:
- **Verified Checkpoint**: Automatically captures a mirror of protected directories (`workspace` and `private`) along with an immutable SHA-256 manifest.
- **Integrity Monitor**: Continuously calculates file hashes and labels every file as `verified`, `modified`, or `missing`.
- **Enforcement Modes**:
  - **Enforce Mode**: Policy violations are actively blocked before execution, keeping state untouched.
  - **Audit Only Mode**: Violations are logged without blocking. If an unauthorized tool deletes or corrupts a file:
    - When **Self-Healing is ON**: VibeShield immediately detects state divergence, restores the file from the verified checkpoint, rolls back tainted memory, and records an outcome of `recovered`.
    - When **Self-Healing is OFF**: Damage remains in place on disk (`compromised`), turning the integrity monitor red until manually restored via the "Restore from Checkpoint" button or session reset.
- Checkpoints automatically refresh after clean runs and verified user uploads.

---

## Quick Start (Zero Dependencies)

The core project runs on the Python 3.9+ standard library. No pip installations are strictly necessary.

### 1. Start the Server
```bash
python server.py
```
Open your browser to:
- **MRU Agent Console**: [http://localhost:8000/](http://localhost:8000/)
- **Admin Login**: [http://localhost:8000/admin/login](http://localhost:8000/admin/login) *(Credentials: `admin` / `Admin123`)*
- **VibeShield Dashboard**: [http://localhost:8000/shield](http://localhost:8000/shield)
- **Privacy Policy**: [http://localhost:8000/privacy](http://localhost:8000/privacy)
- **Terms and Conditions**: [http://localhost:8000/terms](http://localhost:8000/terms)

### 2. Run Automated Test Suite
```bash
python test_vibeshield.py
```
Verifies all 5 OWASP policies, SSRF defenses, self-healing restoration, upload sanitization, action tracking, report generation, and fallback routing. All tests run locally and pass in under 5 seconds.

### 3. Optional: Connect Local LLM (Free)
To enable generative reasoning, install [Ollama](https://ollama.com) and pull a model:
```bash
ollama pull llama3.2:3b
```
MRU auto-detects Ollama on startup. If Ollama is not installed or offline, MRU automatically operates in **Basic mode** and shows extracted tool content without crashing.

---

## Project Structure

```
d:/VibeShield/
├── server.py              # Multi-threaded HTTP API & static server with admin auth (std library)
├── agent.py               # MRU agent, planner, action tracker & Ollama bridge
├── shield.py              # Pure-Python deterministic policy engine (VS-001 - VS-005)
├── healing.py             # SHA-256 checkpoint manager & self-healing recovery
├── tools.py               # Agent tools, security report generator, DOCX extractor, DDG search
├── db.py                  # SQLite persistence: audit events, incidents, trust, memory
├── test_vibeshield.py     # Automated test suite (18 unit tests covering all policies and healing)
├── requirements.txt       # Optional dependencies (e.g. pypdf)
├── .gitignore             # Ignores databases, caches, and checkpoints
├── README.md              # Documentation and presentation guide
├── static/
│   ├── index.html         # VibeShield Security Console UI (Light & Premium theme)
│   ├── login.html         # Admin Login Page
│   ├── mru.html           # MRU Agent Chat UI with Action Result Cards & Activity Drawer
│   ├── privacy.html       # Local privacy policy page
│   ├── terms.html         # Academic demonstration terms
│   └── favicon.svg        # SVG shield icon
├── sandbox/pages/         # Sandboxed test web pages (news.html, clean.html, secrets.html)
└── demo_files/            # Sample reports (poisoned_report.txt, config_with_secrets.txt)
```
