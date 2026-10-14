CREATE TABLE IF NOT EXISTS health_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_key TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                source TEXT NOT NULL,
                overall_status TEXT NOT NULL,
                pass_count INTEGER NOT NULL DEFAULT 0,
                warning_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                check_count INTEGER NOT NULL DEFAULT 0
            );

CREATE TABLE IF NOT EXISTS
            health_check_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                component TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                FOREIGN KEY (run_id)
                    REFERENCES health_runs(id)
                    ON DELETE CASCADE
            );

CREATE INDEX IF NOT EXISTS
            idx_health_runs_client_checked_at
            ON health_runs(
                client_key,
                checked_at DESC
            );

CREATE INDEX IF NOT EXISTS
            idx_health_runs_client_status
            ON health_runs(
                client_key,
                overall_status,
                checked_at DESC
            );

CREATE INDEX IF NOT EXISTS
            idx_health_results_component
            ON health_check_results(
                component,
                checked_at DESC
            );

CREATE INDEX IF NOT EXISTS
            idx_health_results_run_id
            ON health_check_results(run_id);

CREATE TRIGGER IF NOT EXISTS
            health_runs_require_client_key_insert
            BEFORE INSERT ON health_runs
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END;

CREATE TRIGGER IF NOT EXISTS
            health_runs_require_client_key_update
            BEFORE UPDATE OF client_key
            ON health_runs
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END;
