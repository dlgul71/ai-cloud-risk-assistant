CREATE TABLE health_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checked_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                source TEXT NOT NULL,
                overall_status TEXT NOT NULL,
                pass_count INTEGER NOT NULL DEFAULT 0,
                warning_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                check_count INTEGER NOT NULL DEFAULT 0
            );

CREATE TABLE health_check_results (
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

CREATE INDEX idx_health_runs_checked_at ON health_runs(checked_at DESC);

CREATE INDEX idx_health_runs_status ON health_runs(overall_status, checked_at DESC);

CREATE INDEX idx_health_results_component
            ON health_check_results(
                component,
                checked_at DESC
            );

CREATE INDEX idx_health_results_run_id
            ON health_check_results(run_id);
