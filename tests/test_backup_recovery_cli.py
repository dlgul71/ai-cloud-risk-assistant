from pathlib import Path

from scripts import backup_recovery_cli


def test_create_command_reports_success(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        backup_recovery_cli,
        "create_backup",
        lambda database_files, backup_root: {
            "status": "PASS",
            "backup_id": "20260728T210000Z",
            "backup_directory": "backups/20260728T210000Z",
            "database_count": 3,
            "missing_databases": [],
        },
    )

    result = backup_recovery_cli.main(
        [
            "create",
            "--backup-root",
            "backups",
        ]
    )

    output = capsys.readouterr().out

    assert result == 0
    assert "Backup completed" in output
    assert "20260728T210000Z" in output


def test_create_command_returns_warning_exit_code(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        backup_recovery_cli,
        "create_backup",
        lambda database_files, backup_root: {
            "status": "WARN",
            "backup_id": "20260728T210000Z",
            "backup_directory": "backups/20260728T210000Z",
            "database_count": 2,
            "missing_databases": ["remediation.db"],
        },
    )

    result = backup_recovery_cli.main(["create"])

    assert result == 2
    assert "remediation.db" in capsys.readouterr().out


def test_verify_command_reports_success(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        backup_recovery_cli,
        "verify_backup",
        lambda backup_directory: {
            "status": "PASS",
            "backup_id": "20260728T210000Z",
            "verified_count": 3,
            "failed_count": 0,
            "checks": [],
        },
    )

    result = backup_recovery_cli.main(
        [
            "verify",
            "backups/20260728T210000Z",
        ]
    )

    assert result == 0
    assert "Backup verification passed" in (
        capsys.readouterr().out
    )


def test_verify_command_returns_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        backup_recovery_cli,
        "verify_backup",
        lambda backup_directory: {
            "status": "FAIL",
            "backup_id": "20260728T210000Z",
            "verified_count": 2,
            "failed_count": 1,
            "checks": [
                {
                    "database": "assets.db",
                    "status": "FAIL",
                    "detail": "Checksum mismatch",
                }
            ],
        },
    )

    result = backup_recovery_cli.main(
        [
            "verify",
            "backups/20260728T210000Z",
        ]
    )

    assert result == 1


def test_restore_command_reports_success(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        backup_recovery_cli,
        "restore_backup",
        lambda backup_directory, restore_root: {
            "status": "PASS",
            "backup_id": "20260728T210000Z",
            "restore_root": str(restore_root),
            "restored_count": 3,
            "restored_files": [
                str(Path(restore_root) / "assets.db"),
                str(Path(restore_root) / "clients.db"),
                str(Path(restore_root) / "remediation.db"),
            ],
        },
    )

    result = backup_recovery_cli.main(
        [
            "restore",
            "backups/20260728T210000Z",
            "--restore-root",
            "restored_backups/test",
        ]
    )

    assert result == 0
    assert "Restore completed" in capsys.readouterr().out


def test_restore_command_handles_verification_failure(
    monkeypatch,
    capsys,
):
    def failing_restore(
        backup_directory,
        restore_root,
    ):
        raise backup_recovery_cli.BackupVerificationError(
            "Backup verification failed"
        )

    monkeypatch.setattr(
        backup_recovery_cli,
        "restore_backup",
        failing_restore,
    )

    result = backup_recovery_cli.main(
        [
            "restore",
            "backups/invalid",
        ]
    )

    assert result == 1
    assert "Backup verification failed" in (
        capsys.readouterr().err
    )
