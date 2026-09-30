"""Scan findings persistence and configured-storage regressions."""
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

import pytest

import db


@pytest.fixture
def configured_storage(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    work_dir = tmp_path / "app"
    data_dir.mkdir()
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)
    monkeypatch.setenv("DGS_DATA_DIR", str(data_dir))
    monkeypatch.setattr(db, "DB_NAME", None)
    return data_dir, work_dir


def sample_finding(label="sample"):
    return {
        "cve_id": label, "priority": "HIGH", "risk_score": 75,
        "kev_exploited": True, "known_ransomware": "Unknown",
        "required_action": "Review and remediate.",
    }


def test_configured_scan_storage_round_trip(configured_storage):
    data_dir, work_dir = configured_storage
    db.init_db()
    db.save_findings([sample_finding("first"), sample_finding("second")])
    rows = db.get_all_findings()
    assert [row[1] for row in rows] == ["second", "first"]
    assert rows[0][2:] == ("HIGH", 75, 1, "Unknown", "Review and remediate.")
    assert datetime.fromisoformat(rows[0][0]).utcoffset().total_seconds() == 0
    assert (data_dir / "dgs_sentinel.db").is_file()
    assert not (work_dir / "dgs_sentinel.db").exists()


def test_existing_schema_and_records_are_preserved(configured_storage):
    data_dir, _ = configured_storage
    target = data_dir / "dgs_sentinel.db"
    with closing(sqlite3.connect(target)) as connection, connection:
        connection.execute("""
            CREATE TABLE scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT, cve_id TEXT, priority TEXT,
                risk_score INTEGER, kev_exploited BOOLEAN,
                known_ransomware TEXT, required_action TEXT
            )
        """)
        connection.execute(
            "INSERT INTO scan_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (7, "2026-09-01T12:00:00", "legacy-record", "LOW", 20, 0,
             "Unknown", "Review."),
        )
    db.init_db()
    db.init_db()
    assert db.get_all_findings()[0][1] == "legacy-record"
    db.save_findings([sample_finding("new-record")])
    assert [row[1] for row in db.get_all_findings()] == [
        "new-record", "legacy-record"
    ]
    with closing(sqlite3.connect(target)) as connection, connection:
        assert connection.execute(
            "SELECT id FROM scan_findings ORDER BY id"
        ).fetchall() == [(7,), (8,)]


def test_explicit_override_takes_precedence(configured_storage, monkeypatch):
    data_dir, work_dir = configured_storage
    override = work_dir / "isolated.db"
    monkeypatch.setattr(db, "DB_NAME", override)
    db.init_db()
    db.save_findings([sample_finding()])
    assert len(db.get_all_findings()) == 1
    assert override.is_file()
    assert not (data_dir / "dgs_sentinel.db").exists()


def test_unconfigured_storage_preserves_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DGS_DATA_DIR", raising=False)
    monkeypatch.setattr(db, "DB_NAME", None)
    db.init_db()
    db.save_findings([sample_finding()])
    assert db.get_all_findings()[0][1] == "sample"
    assert (tmp_path / "dgs_sentinel.db").is_file()


def test_environment_change_does_not_copy_or_delete_legacy_file(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DGS_DATA_DIR", raising=False)
    monkeypatch.setattr(db, "DB_NAME", None)
    db.init_db()
    db.save_findings([sample_finding("legacy")])
    legacy = Path("dgs_sentinel.db").read_bytes()
    target_dir = tmp_path / "new-data"
    target_dir.mkdir()
    monkeypatch.setenv("DGS_DATA_DIR", str(target_dir))
    db.init_db()
    assert db.get_all_findings() == []
    assert Path("dgs_sentinel.db").read_bytes() == legacy
    monkeypatch.delenv("DGS_DATA_DIR")
    assert db.get_all_findings()[0][1] == "legacy"


def test_unavailable_directory_does_not_fall_back(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DGS_DATA_DIR", str(tmp_path / "missing"))
    monkeypatch.setattr(db, "DB_NAME", None)
    with pytest.raises(sqlite3.OperationalError):
        db.init_db()
    assert not (tmp_path / "dgs_sentinel.db").exists()


def test_empty_findings_preserve_saved_records(configured_storage):
    db.init_db()
    db.save_findings([sample_finding()])
    db.save_findings([])
    assert len(db.get_all_findings()) == 1
