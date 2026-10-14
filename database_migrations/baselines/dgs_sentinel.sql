CREATE TABLE IF NOT EXISTS scan_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT,
            cve_id TEXT,
            priority TEXT,
            risk_score INTEGER,
            kev_exploited BOOLEAN,
            known_ransomware TEXT,
            required_action TEXT
        );
