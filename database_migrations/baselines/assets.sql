CREATE TABLE IF NOT EXISTS assets (
            client_key TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            asset_type TEXT,
            account_id TEXT,
            region TEXT,
            hostname TEXT,
            ip_address TEXT,
            public_ip TEXT,
            state TEXT,
            risk_score INTEGER,
            last_scan TEXT,
            PRIMARY KEY (client_key, asset_id)
        );

CREATE INDEX IF NOT EXISTS
            idx_assets_client_key
            ON assets(client_key);

CREATE INDEX IF NOT EXISTS
            idx_assets_account_id
            ON assets(account_id);

CREATE INDEX IF NOT EXISTS
            idx_assets_client_risk
            ON assets(client_key, risk_score DESC);
