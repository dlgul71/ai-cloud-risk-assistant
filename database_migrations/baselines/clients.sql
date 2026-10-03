CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT,
                aws_account_id TEXT,
                role_arn TEXT,
                environment TEXT,
                cloud_provider TEXT DEFAULT 'AWS',
                azure_subscription_id TEXT,
                azure_tenant_id TEXT,
                azure_client_id TEXT,
                client_key TEXT
            );

CREATE UNIQUE INDEX IF NOT EXISTS
            idx_clients_client_key
            ON clients(client_key);

CREATE TRIGGER IF NOT EXISTS
            clients_require_client_key_insert
            BEFORE INSERT ON clients
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END;

CREATE TRIGGER IF NOT EXISTS
            clients_require_client_key_update
            BEFORE UPDATE OF client_key ON clients
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END;
