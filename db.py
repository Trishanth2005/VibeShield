"""Database persistence for VibeShield and MRU Agent.
Stores security audit logs, incident evidence, trust metrics, memory and recovery events in SQLite.
"""
import sqlite3
import time
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "vibeshield.db")

def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init(custom_db=None):
    global DB_PATH
    if custom_db:
        DB_PATH = custom_db
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            stage TEXT NOT NULL,
            src TEXT,
            msg TEXT NOT NULL,
            owasp TEXT,
            severity TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            owasp TEXT NOT NULL,
            owasp_full TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            decision TEXT NOT NULL,
            outcome TEXT NOT NULL,
            trust_before INTEGER NOT NULL,
            trust_after INTEGER NOT NULL,
            penalty INTEGER NOT NULL,
            evidence_json TEXT NOT NULL,
            remediation TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS session (
            id INTEGER PRIMARY KEY CHECK(id=1),
            trust INTEGER NOT NULL DEFAULT 100,
            actions INTEGER NOT NULL DEFAULT 0,
            threats INTEGER NOT NULL DEFAULT 0,
            remediated INTEGER NOT NULL DEFAULT 0,
            recovered INTEGER NOT NULL DEFAULT 0,
            enforcement_mode TEXT NOT NULL DEFAULT 'enforce',
            self_healing INTEGER NOT NULL DEFAULT 1,
            last_checkpoint REAL
        );

        CREATE TABLE IF NOT EXISTS memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            content TEXT NOT NULL,
            quarantined INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS recovery_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            trigger_threat TEXT NOT NULL,
            items_restored TEXT NOT NULL,
            outcome TEXT NOT NULL DEFAULT 'recovered'
        );

        INSERT OR IGNORE INTO session (id, trust, actions, threats, remediated, recovered, enforcement_mode, self_healing, last_checkpoint)
        VALUES (1, 100, 0, 0, 0, 0, 'enforce', 1, 0.0);
        """)

def log_event(stage, src, msg, owasp=None, severity=None):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO events (ts, stage, src, msg, owasp, severity) VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), stage, src, msg, owasp, severity)
        )

def record_incident(rule_id, rule_name, owasp, owasp_full, severity, source,
                    decision, outcome, trust_before, trust_after, penalty,
                    evidence_dict, remediation):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO incidents (
                ts, rule_id, rule_name, owasp, owasp_full, severity, source,
                decision, outcome, trust_before, trust_after, penalty,
                evidence_json, remediation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            time.time(), rule_id, rule_name, owasp, owasp_full, severity, source,
            decision, outcome, trust_before, trust_after, penalty,
            json.dumps(evidence_dict), remediation
        ))

def get_state():
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM session WHERE id=1").fetchone()
        if not row:
            return {
                "trust": 100, "actions": 0, "threats": 0, "remediated": 0,
                "recovered": 0, "enforcement_mode": "enforce", "self_healing": True,
                "last_checkpoint": 0.0, "memory": [], "quarantine": []
            }
        state = dict(row)
        state["self_healing"] = bool(state.get("self_healing", 1))
        mem_rows = conn.execute("SELECT content FROM memory WHERE quarantined=0 ORDER BY id").fetchall()
        quar_rows = conn.execute("SELECT content FROM memory WHERE quarantined=1 ORDER BY id").fetchall()
        state["memory"] = [r["content"] for r in mem_rows]
        state["quarantine"] = [r["content"] for r in quar_rows]
        return state

def update_session(trust_delta=0, actions_delta=0, threats_delta=0,
                   remediated_delta=0, recovered_delta=0,
                   enforcement_mode=None, self_healing=None, last_checkpoint=None):
    with get_conn() as conn:
        curr = dict(conn.execute("SELECT * FROM session WHERE id=1").fetchone())
        new_trust = max(0, min(100, curr["trust"] + trust_delta))
        new_actions = curr["actions"] + actions_delta
        new_threats = curr["threats"] + threats_delta
        new_remediated = curr["remediated"] + remediated_delta
        new_recovered = curr["recovered"] + recovered_delta
        new_mode = enforcement_mode if enforcement_mode is not None else curr["enforcement_mode"]
        new_heal = (1 if self_healing else 0) if self_healing is not None else curr["self_healing"]
        new_cp = last_checkpoint if last_checkpoint is not None else curr["last_checkpoint"]

        conn.execute("""
            UPDATE session SET
                trust=?, actions=?, threats=?, remediated=?, recovered=?,
                enforcement_mode=?, self_healing=?, last_checkpoint=?
            WHERE id=1
        """, (new_trust, new_actions, new_threats, new_remediated, new_recovered,
              new_mode, new_heal, new_cp))
        return {
            "trust": new_trust, "actions": new_actions, "threats": new_threats,
            "remediated": new_remediated, "recovered": new_recovered,
            "enforcement_mode": new_mode, "self_healing": bool(new_heal),
            "last_checkpoint": new_cp
        }

def set_enforcement_mode(mode):
    if mode in ("enforce", "audit"):
        update_session(enforcement_mode=mode)

def set_self_healing(enabled):
    update_session(self_healing=bool(enabled))

def remember(content):
    with get_conn() as conn:
        conn.execute("INSERT INTO memory (ts, content, quarantined) VALUES (?, ?, 0)",
                     (time.time(), content))

def quarantine_memory(content):
    with get_conn() as conn:
        conn.execute("INSERT INTO memory (ts, content, quarantined) VALUES (?, ?, 1)",
                     (time.time(), content))

def rollback_memory(count=1):
    with get_conn() as conn:
        rows = conn.execute("SELECT id FROM memory ORDER BY id DESC LIMIT ?", (count,)).fetchall()
        for r in rows:
            conn.execute("DELETE FROM memory WHERE id=?", (r["id"],))

def get_incidents(limit=100):
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        res = []
        for r in rows:
            item = dict(r)
            try:
                item["evidence"] = json.loads(item["evidence_json"])
            except Exception:
                item["evidence"] = {}
            res.append(item)
        return res

def get_audit_events(limit=200, stage=None, severity=None):
    with get_conn() as conn:
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        if stage:
            query += " AND stage=?"
            params.append(stage)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in conn.execute(query, params).fetchall()]

def get_policy_stats():
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT rule_id, COUNT(*) as hit_count, MAX(ts) as last_hit
            FROM incidents
            GROUP BY rule_id
        """).fetchall()
        return {r["rule_id"]: {"hits": r["hit_count"], "last_hit": r["last_hit"]} for r in rows}

def get_trust_timeline(limit=30):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT ts, trust_after as trust, rule_id, outcome
            FROM incidents
            ORDER BY id ASC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

def record_recovery(trigger_threat, items_restored, outcome="recovered"):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO recovery_history (ts, trigger_threat, items_restored, outcome)
            VALUES (?, ?, ?, ?)
        """, (time.time(), trigger_threat, items_restored, outcome))

def get_recovery_history(limit=50):
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM recovery_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

def reset():
    with get_conn() as conn:
        conn.executescript("""
            DELETE FROM events;
            DELETE FROM incidents;
            DELETE FROM memory;
            DELETE FROM recovery_history;
            UPDATE session SET
                trust=100, actions=0, threats=0, remediated=0, recovered=0,
                enforcement_mode='enforce', self_healing=1, last_checkpoint=0.0
            WHERE id=1;
        """)
