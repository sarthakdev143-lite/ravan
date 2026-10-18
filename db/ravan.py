#!/usr/bin/env python3
"""
db/ravan.py — SQLite findings database. Merged from opencode-pentester.

Replaces the JSONL ledger with a queryable, cross-session SQLite store.
Imports existing JSONL on first run. The JSONL ledger is kept for subagents
that write via ledger_append.py — this DB syncs from it.

Usage:
    python3 db/ravan.py init                            # create DB
    python3 db/ravan.py import-jsonl                    # sync from JSONL
    python3 db/ravan.py findings [--target X] [--sev high]
    python3 db/ravan.py chains suggest [--target X]     # auto-correlate
    python3 db/ravan.py chains add --findings A,B,C --desc "attack chain"
    python3 db/ravan.py session log --agent X --tool Y --command Z --target T --phase P --exit N
    python3 db/ravan.py session show [--tail N] [--target X]
    python3 db/ravan.py export [--target X]             # markdown summary

Exit codes: 0 = success, 1 = error
"""

import argparse
import datetime
import json
import os
import sqlite3
import sys

LEDGER_PATH = os.path.join(".opencode", "security", "findings.jsonl")
DB_PATH = os.path.join(".opencode", "security", "ravan.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id              TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    started_at      TEXT,
    state           TEXT DEFAULT 'active',
    scope           TEXT,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT,
    engagement_id   TEXT,
    target          TEXT,
    check_name      TEXT,
    title           TEXT,
    severity        TEXT,
    status          TEXT DEFAULT 'open',
    cvss            TEXT,
    kev             INTEGER DEFAULT 0,
    epss            REAL,
    confidence      TEXT,
    verdict         TEXT,
    evidence_ref    TEXT,
    evidence        TEXT,   -- JSON array
    analysis        TEXT,
    impact          TEXT,
    remediation     TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    PRIMARY KEY (id, engagement_id)
);

CREATE TABLE IF NOT EXISTS verification_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT,
    engagement_id   TEXT,
    verdict         TEXT,
    verified_at     TEXT,
    evidence_ref    TEXT,
    requests_used   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   TEXT,
    description     TEXT,
    finding_ids     TEXT,   -- JSON array of finding IDs
    severity        TEXT,
    created_at      TEXT
);

CREATE TABLE IF NOT EXISTS leads (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT,
    target          TEXT,
    type            TEXT,
    value           TEXT,
    source          TEXT,
    why             TEXT,
    status          TEXT DEFAULT 'open',
    outcome         TEXT,
    close_reason    TEXT,
    discovered_at   TEXT,
    closed_at       TEXT
);

CREATE TABLE IF NOT EXISTS session_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   TEXT,
    agent           TEXT,
    tool            TEXT,
    command         TEXT,
    target          TEXT,
    phase           TEXT,
    exit_code       INTEGER,
    duration_ms     INTEGER,
    output_file     TEXT,
    summary         TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_session_log_target ON session_log(target);
"""


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def cmd_init(args) -> int:
    conn = _conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"[+] Database initialized: {DB_PATH}")
    return 0


def cmd_import_jsonl(args) -> int:
    if not os.path.exists(LEDGER_PATH):
        print(f"[!] No ledger at {LEDGER_PATH}", file=sys.stderr)
        return 1

    conn = _conn()
    conn.executescript(SCHEMA)

    imported = 0
    skipped = 0
    with open(LEDGER_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue

            schema = obj.get("schema", "")
            if schema == "ravan-findings-v1":
                continue  # header line

            if schema == "ravan-verification-v1":
                fid = obj.get("finding_id")
                if fid:
                    conn.execute(
                        "INSERT OR IGNORE INTO verification_records "
                        "(finding_id, verdict, verified_at, evidence_ref, requests_used) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (fid, obj.get("verdict"), obj.get("verified_at"),
                         obj.get("evidence_ref"), obj.get("requests_used", 0))
                    )
                    imported += 1
                continue

            fid = obj.get("id")
            if not fid:
                skipped += 1
                continue

            target = obj.get("target", "")
            existing = conn.execute(
                "SELECT id FROM findings WHERE id = ?", (str(fid),)
            ).fetchone()

            if existing:
                skipped += 1
                continue

            conn.execute(
                "INSERT OR IGNORE INTO findings "
                "(id, target, check_name, title, severity, status, cvss, kev, epss, "
                " confidence, verdict, evidence_ref, analysis, impact, remediation, "
                " first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(fid), target, obj.get("check"), obj.get("title"),
                    obj.get("severity"), obj.get("status", "open"),
                    str(obj.get("cvss") or ""), 1 if obj.get("kev") else 0,
                    obj.get("epss"), obj.get("confidence"), obj.get("verdict"),
                    obj.get("evidence_ref"),
                    obj.get("analysis"), obj.get("impact"), obj.get("remediation"),
                    obj.get("first_seen"), obj.get("last_seen"),
                )
            )
            imported += 1

    conn.commit()
    conn.close()
    print(f"[+] Imported {imported} records from {LEDGER_PATH} ({skipped} skipped)")
    return 0


def cmd_findings(args) -> int:
    conn = _conn()
    conn.executescript(SCHEMA)
    sql = "SELECT * FROM findings WHERE 1=1"
    params: list = []
    if args.target:
        sql += " AND target LIKE ?"
        params.append(f"%{args.target}%")
    if args.severity:
        sql += " AND severity = ?"
        params.append(args.severity.lower())
    if args.status:
        sql += " AND status = ?"
        params.append(args.status)
    sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    if args.json:
        print(json.dumps([dict(r) for r in rows], indent=2))
    else:
        print(f"{'ID':<20} {'Sev':<10} {'Status':<18} {'Verdict':<12} Title")
        print("-" * 90)
        for r in rows:
            print(f"{str(r['id']):<20} {str(r['severity']):<10} {str(r['status']):<18} "
                  f"{str(r['verdict'] or ''):<12} {str(r['title'])[:60]}")
        print(f"\n{len(rows)} findings")
    return 0


def cmd_chains_suggest(args) -> int:
    conn = _conn()
    conn.executescript(SCHEMA)
    sql = "SELECT id, title, severity, check_name FROM findings WHERE 1=1"
    params = []
    if args.target:
        sql += " AND target LIKE ?"
        params.append(f"%{args.target}%")
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    findings = [dict(r) for r in rows]
    chains = []

    # Simple chain detection: look for common patterns
    recon_ids = [f["id"] for f in findings if any(
        k in str(f.get("title") or "").lower()
        for k in ("subdomain", "dns", "ct log", "email", "header", "tls", "cert")
    )]
    access_ids = [f["id"] for f in findings if any(
        k in str(f.get("title") or "").lower()
        for k in ("access", "cors", "jwt", "auth", "session", "csrf")
    )]
    exfil_ids = [f["id"] for f in findings if any(
        k in str(f.get("title") or "").lower()
        for k in ("ssrf", "redirect", "injection", "xss", "rce")
    )]

    if recon_ids and access_ids:
        chains.append({
            "description": "Recon -> Access control bypass",
            "finding_ids": recon_ids[:2] + access_ids[:2],
            "severity": "high",
        })
    if access_ids and exfil_ids:
        chains.append({
            "description": "Access bypass -> Exfiltration/Impact",
            "finding_ids": access_ids[:2] + exfil_ids[:2],
            "severity": "critical",
        })
    if recon_ids and exfil_ids:
        chains.append({
            "description": "Recon -> Direct exploitation",
            "finding_ids": recon_ids[:1] + exfil_ids[:2],
            "severity": "high",
        })

    print(f"Suggested attack chains ({len(chains)} found):")
    for c in chains:
        print(f"  [{c['severity'].upper()}] {c['description']}")
        print(f"    Findings: {', '.join(str(x) for x in c['finding_ids'])}")
        print(f"    Add: python3 db/ravan.py chains add --findings {','.join(str(x) for x in c['finding_ids'])} --desc \"{c['description']}\"")
    return 0


def cmd_chains_add(args) -> int:
    conn = _conn()
    conn.executescript(SCHEMA)
    fids = [f.strip() for f in args.findings.split(",") if f.strip()]
    conn.execute(
        "INSERT INTO attack_chains (description, finding_ids, severity, created_at) "
        "VALUES (?, ?, ?, ?)",
        (args.desc, json.dumps(fids), args.severity or "high",
         datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    )
    conn.commit()
    conn.close()
    print(f"[+] Attack chain added: {args.desc} ({len(fids)} findings)")
    return 0


def cmd_session_log(args) -> int:
    conn = _conn()
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO session_log (engagement_id, agent, tool, command, target, phase, exit_code, duration_ms, summary) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (args.engagement or "default", args.agent, args.tool, args.command or "",
         args.target or "", args.phase or "", args.exit_code, args.duration_ms or 0, args.summary or "")
    )
    conn.commit()
    conn.close()
    print(f"[+] Session log: {args.agent}/{args.tool} -> exit {args.exit_code}")
    return 0


def cmd_session_show(args) -> int:
    conn = _conn()
    conn.executescript(SCHEMA)
    sql = "SELECT * FROM session_log WHERE 1=1"
    params = []
    if args.target:
        sql += " AND target LIKE ?"
        params.append(f"%{args.target}%")
    if args.agent:
        sql += " AND agent = ?"
        params.append(args.agent)
    sql += " ORDER BY id DESC"
    if args.tail:
        sql += f" LIMIT {args.tail}"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    if args.json:
        print(json.dumps([dict(r) for r in rows], indent=2))
    else:
        print(f"{'#':<5} {'Time':<22} {'Agent':<18} {'Tool':<18} {'Exit':<6} Summary")
        print("-" * 90)
        for r in reversed(rows):
            ts = str(r["created_at"] or "")[:19]
            print(f"{r['id']:<5} {ts:<22} {str(r['agent'] or ''):<18} {str(r['tool'] or ''):<18} "
                  f"{str(r['exit_code'] or ''):<6} {str(r['summary'] or '')[:50]}")
    return 0


def cmd_export(args) -> int:
    conn = _conn()
    conn.executescript(SCHEMA)
    sql = "SELECT * FROM findings WHERE 1=1"
    params = []
    if args.target:
        sql += " AND target LIKE ?"
        params.append(f"%{args.target}%")
    sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    findings = conn.execute(sql, params).fetchall()
    chains = conn.execute("SELECT * FROM attack_chains").fetchall()
    conn.close()

    lines = ["# Ravan Findings Export", f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}", ""]
    counts: dict[str, int] = {}
    for f in findings:
        sev = f["severity"] or "info"
        counts[sev] = counts.get(sev, 0) + 1
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            lines.append(f"- {sev.upper()}: {counts[sev]}")
    lines.append("")
    for f in findings:
        lines.append(f"## {f['id']} - {f['title']}")
        lines.append(f"**Severity:** {f['severity']} | **Verdict:** {f['verdict']} | **Status:** {f['status']}")
        if f["analysis"]:
            lines.append(f"\n{f['analysis']}")
        lines.append("")
    if chains:
        lines.append("## Attack Chains")
        for c in chains:
            lines.append(f"- [{c['severity']}] {c['description']} ({c['finding_ids']})")

    print("\n".join(lines))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Ravan SQLite findings database")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="Initialize the database")

    sub.add_parser("import-jsonl", help="Import from findings.jsonl")

    f_p = sub.add_parser("findings", help="Query findings")
    f_p.add_argument("--target")
    f_p.add_argument("--severity")
    f_p.add_argument("--status")
    f_p.add_argument("--json", action="store_true")

    chains_p = sub.add_parser("chains", help="Attack chain operations")
    chains_sub = chains_p.add_subparsers(dest="chains_cmd", required=True)
    cs_p = chains_sub.add_parser("suggest")
    cs_p.add_argument("--target")
    ca_p = chains_sub.add_parser("add")
    ca_p.add_argument("--findings", required=True, help="Comma-separated finding IDs")
    ca_p.add_argument("--desc", required=True)
    ca_p.add_argument("--severity", default="high")

    session_p = sub.add_parser("session", help="Session log operations")
    session_sub = session_p.add_subparsers(dest="session_cmd", required=True)
    sl_p = session_sub.add_parser("log")
    sl_p.add_argument("--agent", required=True)
    sl_p.add_argument("--tool", required=True)
    sl_p.add_argument("--command")
    sl_p.add_argument("--target")
    sl_p.add_argument("--phase")
    sl_p.add_argument("--exit-code", dest="exit_code", type=int, default=0)
    sl_p.add_argument("--duration-ms", dest="duration_ms", type=int)
    sl_p.add_argument("--summary")
    sl_p.add_argument("--engagement")
    ss_p = session_sub.add_parser("show")
    ss_p.add_argument("--target")
    ss_p.add_argument("--agent")
    ss_p.add_argument("--tail", type=int, default=20)
    ss_p.add_argument("--json", action="store_true")

    ex_p = sub.add_parser("export", help="Export findings as markdown")
    ex_p.add_argument("--target")

    args = p.parse_args()
    dispatch = {
        "init": cmd_init,
        "import-jsonl": cmd_import_jsonl,
        "findings": cmd_findings,
        "export": cmd_export,
    }
    if args.cmd in dispatch:
        return dispatch[args.cmd](args)
    if args.cmd == "chains":
        if args.chains_cmd == "suggest":
            return cmd_chains_suggest(args)
        return cmd_chains_add(args)
    if args.cmd == "session":
        if args.session_cmd == "log":
            return cmd_session_log(args)
        return cmd_session_show(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
