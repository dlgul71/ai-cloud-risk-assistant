import sqlite3

DB_NAME = "assets.db"

def init_asset_db():
    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
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
