import sqlite3
from datetime import datetime, UTC

DB_NAME = "assets.db"


def init_asset_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        asset_id TEXT PRIMARY KEY,
        asset_type TEXT,
        account_id TEXT,
        region TEXT,
        hostname TEXT,
        ip_address TEXT,
        risk_score INTEGER,
        last_scan TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_asset(asset):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT OR REPLACE INTO assets (
        asset_id,
        asset_type,
        account_id,
        region,
        hostname,
        ip_address,
        risk_score,
        last_scan
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        asset.get("asset_id"),
        asset.get("asset_type"),
        asset.get("account_id"),
        asset.get("region"),
        asset.get("hostname"),
        asset.get("ip_address"),
        asset.get("risk_score", 0),
        asset.get("last_scan", str(datetime.now(UTC)))
    ))

    conn.commit()
    conn.close()


def get_assets():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM assets")

    rows = cursor.fetchall()

    conn.close()

    return rows
