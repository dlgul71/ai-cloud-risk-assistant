CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL
                    COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL
                    DEFAULT 1,
                is_global_admin INTEGER NOT NULL
                    DEFAULT 0,
                failed_login_attempts INTEGER
                    NOT NULL DEFAULT 0,
                locked_until TEXT,
                password_changed_at TEXT NOT NULL,
                last_login_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (TRIM(username) <> ''),
                CHECK (
                    role IN (
                        'Administrator',
                        'Analyst',
                        'Viewer'
                    )
                ),
                CHECK (
                    is_active IN (0, 1)
                ),
                CHECK (
                    is_global_admin IN (0, 1)
                ),
                CHECK (
                    failed_login_attempts >= 0
                )
            );

CREATE TABLE IF NOT EXISTS
            user_client_access (
                user_id TEXT NOT NULL,
                client_key TEXT NOT NULL,
                granted_at TEXT NOT NULL,
                granted_by TEXT,
                PRIMARY KEY (
                    user_id,
                    client_key
                ),
                FOREIGN KEY (user_id)
                    REFERENCES users(user_id)
                    ON DELETE CASCADE,
                CHECK (
                    TRIM(client_key) <> ''
                )
            );

CREATE TABLE IF NOT EXISTS
            authentication_audit_events (
                event_id INTEGER
                    PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                username TEXT,
                client_key TEXT,
                event_type TEXT NOT NULL,
                success INTEGER NOT NULL,
                occurred_at TEXT NOT NULL,
                details_json TEXT,
                FOREIGN KEY (user_id)
                    REFERENCES users(user_id)
                    ON DELETE SET NULL,
                CHECK (
                    TRIM(event_type) <> ''
                ),
                CHECK (
                    success IN (0, 1)
                )
            );

CREATE INDEX IF NOT EXISTS
            idx_users_active_role
            ON users(
                is_active,
                role
            );

CREATE INDEX IF NOT EXISTS
            idx_user_client_access_client
            ON user_client_access(
                client_key,
                user_id
            );

CREATE INDEX IF NOT EXISTS
            idx_auth_events_occurred
            ON authentication_audit_events(
                occurred_at DESC
            );

CREATE INDEX IF NOT EXISTS
            idx_auth_events_user
            ON authentication_audit_events(
                user_id,
                occurred_at DESC
            );
