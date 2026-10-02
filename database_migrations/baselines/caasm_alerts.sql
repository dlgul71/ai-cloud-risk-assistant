CREATE TABLE IF NOT EXISTS caasm_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            last_notified_at TEXT,
            alert_type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            priority TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            asset_id TEXT,
            hostname TEXT,
            asset_type TEXT,
            source TEXT,
            owner TEXT,
            risk_drivers TEXT,
            status TEXT NOT NULL DEFAULT 'OPEN',
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            notification_count INTEGER NOT NULL DEFAULT 0,
            acknowledged_at TEXT,
            acknowledged_by TEXT,
            resolved_at TEXT,
            resolved_by TEXT,
            resolution_note TEXT
        );

CREATE INDEX IF NOT EXISTS
        idx_caasm_alerts_status_priority
        ON caasm_alerts(status, priority, risk_score);

CREATE INDEX IF NOT EXISTS
        idx_caasm_alerts_last_notified
        ON caasm_alerts(last_notified_at);
