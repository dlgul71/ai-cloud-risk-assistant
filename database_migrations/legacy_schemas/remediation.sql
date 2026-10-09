CREATE TABLE remediation_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 created_at TEXT, category TEXT, priority TEXT, finding TEXT,
 recommendation TEXT, owner TEXT, status TEXT, risk_score INTEGER,
 aws_account_id TEXT, client_name TEXT, occurrence_count INTEGER DEFAULT 1,
 last_seen_at TEXT, client_key TEXT
);

CREATE INDEX idx_remediation_client_key
            ON remediation_items(client_key);

CREATE INDEX idx_remediation_client_status
            ON remediation_items(
                client_key,
                status,
                risk_score DESC
            );

CREATE INDEX idx_remediation_client_finding
            ON remediation_items(
                client_key,
                aws_account_id,
                category,
                finding,
                status
            );

CREATE TRIGGER remediation_require_client_key_insert
            BEFORE INSERT ON remediation_items
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END;

CREATE TRIGGER remediation_require_client_key_update
            BEFORE UPDATE OF client_key
            ON remediation_items
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END;
