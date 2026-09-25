"""
scratch/view_database.py
------------------------
Utility script to inspect the SentinelTrace SQLite database:
Lists all tables, column schemas, and row counts, and provides sample data.
"""

import os
import sqlite3
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "backend", "sentinel_trace.db")

def inspect_database():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database file not found at: {DB_PATH}")
        sys.exit(1)

    print("=" * 70)
    print("           SENTINELTRACE V5 - DATABASE INSPECTOR")
    print("=" * 70)
    print(f"File Path : {DB_PATH}")
    print(f"File Size : {os.path.getsize(DB_PATH):,} bytes")
    print("-" * 70)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
    tables = [r[0] for r in cur.fetchall()]

    print(f"Total Tables: {len(tables)}\n")
    print(f"{'#':<3} | {'Table Name':<42} | {'Rows':<8} | {'Columns':<8}")
    print("-" * 70)

    total_rows = 0
    for idx, table in enumerate(tables, 1):
        try:
            cur.execute(f"SELECT count(*) FROM [{table}]")
            row_count = cur.fetchone()[0]
            total_rows += row_count
        except Exception:
            row_count = "N/A"

        try:
            cur.execute(f"PRAGMA table_info([{table}])")
            cols = cur.fetchall()
            col_count = len(cols)
        except Exception:
            col_count = "N/A"

        print(f"{idx:<3} | {table:<42} | {str(row_count):<8} | {str(col_count):<8}")

    print("-" * 70)
    print(f"Total Records across all tables: {total_rows:,}\n")

    # Show highlight sample counts
    highlights = [
        "users",
        "ingested_events",
        "normalized_events",
        "detection_rules",
        "detection_executions",
        "risk_correlations",
        "remediation_candidates",
        "security_incidents",
        "security_investigation_cases",
        "threat_indicators",
        "threat_actors",
        "compliance_frameworks",
        "security_analytics_snapshots",
        "governance_ledger_entries",
    ]

    print("=" * 70)
    print("  KEY SECURITY INTELLIGENCE ENTITIES:")
    print("=" * 70)
    for h in highlights:
        if h in tables:
            cur.execute(f"SELECT count(*) FROM [{h}]")
            cnt = cur.fetchone()[0]
            print(f"  * {h:<35} : {cnt} records")

    conn.close()
    print("=" * 70)

if __name__ == "__main__":
    inspect_database()
