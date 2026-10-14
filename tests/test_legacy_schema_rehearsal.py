import hashlib
import sqlite3
from pathlib import Path

import pytest

from database_migrations.baseline import recognize_baseline
from database_migrations.legacy_rehearsal import DOMAINS, LEGACY_DIRECTORY, rehearse_legacy_upgrade


def source_set(root):
    root.mkdir()
    for name in DOMAINS:
        with sqlite3.connect(root / name) as connection:
            connection.executescript((LEGACY_DIRECTORY / (Path(name).stem + ".sql")).read_text())
    with sqlite3.connect(root / "remediation.db") as connection:
        connection.execute("INSERT INTO remediation_items(id,finding,risk_score,client_key) VALUES (7,?,30,?)", ("Original finding", "__legacy_unassigned__"))
        connection.execute("UPDATE sqlite_sequence SET seq=90 WHERE name='remediation_items'")
    with sqlite3.connect(root / "operational_monitoring.db") as connection:
        connection.execute("INSERT INTO health_runs VALUES (4,'time','time','manual','PASS',1,0,0,1)")
        connection.execute("INSERT INTO health_check_results VALUES (8,4,'time','sqlite','PASS','original detail')")
    with sqlite3.connect(root / "remediation_actions.db") as connection:
        connection.execute("INSERT INTO remediation_actions(id,execution_mode,cloud_provider,evidence_hash,evidence_authentication_type,evidence_key_id) VALUES (5,'Live',NULL,?,'HMAC-SHA256',?)", ("a" * 64, "b" * 16))
        connection.execute("INSERT INTO remediation_audit(id,action_id,event_detail) VALUES (10,5,'original audit')")
    return root


def hashes(root):
    return {n: hashlib.sha256((root / n).read_bytes()).hexdigest() for n in DOMAINS}


def test_preserves_records_evidence_sequence_and_source(tmp_path):
    source = source_set(tmp_path / "source")
    before = hashes(source)
    output = tmp_path / "rehearsal"
    result = rehearse_legacy_upgrade(source, output, confirm_stopped=True)
    assert result["status"] == "REHEARSAL_CREATED"
    assert result["adoption_eligible"] is False
    assert hashes(source) == before
    for name in DOMAINS:
        assert recognize_baseline(name, output / name)["status"] == "RECOGNIZED"
        assert (output / name).stat().st_mode & 0o777 == 0o600
        with sqlite3.connect(source / name) as original, sqlite3.connect(output / name) as target:
            for (table,) in original.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
                columns = [r[1] for r in original.execute(f'PRAGMA table_info("{table}")')]
                projection = ",".join(f'"{c}"' for c in columns)
                assert original.execute(f'SELECT {projection} FROM "{table}" ORDER BY id').fetchall() == target.execute(f'SELECT {projection} FROM "{table}" ORDER BY id').fetchall()
            assert original.execute("SELECT * FROM sqlite_sequence ORDER BY name").fetchall() == target.execute("SELECT * FROM sqlite_sequence ORDER BY name").fetchall()
    with sqlite3.connect(output / "operational_monitoring.db") as target:
        assert target.execute("SELECT client_key FROM health_runs").fetchone()[0] == "__legacy_unassigned__"
    with sqlite3.connect(output / "remediation_actions.db") as target:
        assert target.execute("SELECT cloud_provider,evidence_hash FROM remediation_actions").fetchone() == (None, "a" * 64)
        target.execute("INSERT INTO remediation_actions(execution_mode) VALUES ('Simulation')")
        assert target.execute("SELECT cloud_provider FROM remediation_actions WHERE id=6").fetchone()[0] == "AWS"
    assert (output / "rehearsal.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("change", ["column", "trigger", "missing", "registry", "symlink", "foreign_key"])
def test_refuses_unknown_or_invalid_sources_before_output(tmp_path, change):
    source = source_set(tmp_path / "source")
    path = source / "remediation.db"
    if change == "missing":
        path.unlink()
    elif change == "symlink":
        path.rename(tmp_path / "linked.db")
        path.symlink_to(tmp_path / "linked.db")
    else:
        if change == "foreign_key":
            path = source / "operational_monitoring.db"
        with sqlite3.connect(path) as connection:
            sql = {"column": "ALTER TABLE remediation_items ADD COLUMN unexpected TEXT",
                   "trigger": "DROP TRIGGER remediation_require_client_key_insert",
                   "registry": "CREATE TABLE schema_migrations(version INTEGER)",
                   "foreign_key": "UPDATE health_check_results SET run_id=999"}[change]
            connection.execute(sql)
    output = tmp_path / "out"
    assert rehearse_legacy_upgrade(source, output, confirm_stopped=True)["status"] == "REFUSED"
    assert not output.exists()


def test_existing_output_and_unconfirmed_sources_are_refused(tmp_path):
    source = source_set(tmp_path / "source")
    output = tmp_path / "out"
    assert rehearse_legacy_upgrade(source, output)["status"] == "REFUSED"
    assert not output.exists()
    output.mkdir()
    (output / "keep").write_text("keep")
    assert rehearse_legacy_upgrade(source, output, confirm_stopped=True)["status"] == "REFUSED"
    assert (output / "keep").read_text() == "keep"
    assert rehearse_legacy_upgrade(source, source / "child", confirm_stopped=True)["status"] == "REFUSED"


def test_bad_legacy_ownership_fails_without_editing_source(tmp_path):
    source = source_set(tmp_path / "source")
    with sqlite3.connect(source / "remediation.db") as connection:
        connection.execute("DELETE FROM remediation_items")
        # Existing older data can predate the present insert guard.
        connection.execute("DROP TRIGGER remediation_require_client_key_insert")
        connection.execute("INSERT INTO remediation_items(client_key) VALUES(NULL)")
        template = sqlite3.connect(":memory:")
        template.executescript((LEGACY_DIRECTORY / "remediation.sql").read_text())
        sql = template.execute("SELECT sql FROM sqlite_master WHERE name='remediation_require_client_key_insert'").fetchone()[0]
        connection.execute(sql)
        template.close()
    before = hashes(source)
    result = rehearse_legacy_upgrade(source, tmp_path / "out", confirm_stopped=True)
    assert result["status"] == "ERROR"
    assert result["databases"] == []
    assert hashes(source) == before
    assert not (tmp_path / "out" / "rehearsal.json").exists()


def test_row_limit_refuses_before_output(tmp_path, monkeypatch):
    import database_migrations.legacy_rehearsal as module
    source = source_set(tmp_path / "source")
    monkeypatch.setattr(module, "MAX_ROWS", 0)
    assert rehearse_legacy_upgrade(source, tmp_path / "out", confirm_stopped=True)["status"] == "REFUSED"
    assert not (tmp_path / "out").exists()
