CREATE TABLE IF NOT EXISTS ai_assets (
                client_key TEXT NOT NULL,
                ai_asset_id TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                name TEXT NOT NULL,
                provider TEXT,
                environment TEXT,
                description TEXT,
                risk_score INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (
                    client_key,
                    ai_asset_id
                )
            );

CREATE TABLE IF NOT EXISTS ai_asset_relationships (
                client_key TEXT NOT NULL,
                source_asset_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                target_asset_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (
                    client_key,
                    source_asset_id,
                    relationship_type,
                    target_asset_id
                )
            );

CREATE INDEX IF NOT EXISTS
            idx_ai_assets_client_key
            ON ai_assets(client_key);

CREATE INDEX IF NOT EXISTS
            idx_ai_assets_type
            ON ai_assets(asset_type);

CREATE INDEX IF NOT EXISTS
            idx_ai_assets_client_risk
            ON ai_assets(
                client_key,
                risk_score DESC
            );

CREATE INDEX IF NOT EXISTS
            idx_ai_relationships_client
            ON ai_asset_relationships(client_key);
