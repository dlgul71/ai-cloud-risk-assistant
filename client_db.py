import sqlite3

DB_NAME = "clients.db"

def init_client_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_name TEXT,
        aws_account_id TEXT,
        role_arn TEXT,
        environment TEXT
    )
    """)

    conn.commit()
    conn.close()


def add_client(client_name, aws_account_id, role_arn, environment):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO clients
    (client_name, aws_account_id, role_arn, environment)
    VALUES (?, ?, ?, ?)
    """, (
        client_name,
        aws_account_id,
        role_arn,
        environment
    ))

    conn.commit()
    conn.close()


def get_clients():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM clients")

    results = cursor.fetchall()

    conn.close()

    return results
