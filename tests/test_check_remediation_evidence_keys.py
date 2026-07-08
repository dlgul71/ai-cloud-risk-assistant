from scripts import check_remediation_evidence_keys


def test_validate_key_rotation_reports_verified_records(
    monkeypatch,
):
    monkeypatch.setattr(
        check_remediation_evidence_keys.remediation_execution,
        "_get_evidence_verification_keys",
        lambda: ("current-key", "previous-key"),
    )
    monkeypatch.setattr(
        check_remediation_evidence_keys.remediation_execution,
        "_get_evidence_key_id",
        lambda key: f"id-{key}",
    )
    monkeypatch.setattr(
        check_remediation_evidence_keys.remediation_execution,
        "get_execution_actions",
        lambda: [
            (1,) + (None,) * 18 + ("hash-one",),
            (2,) + (None,) * 18 + ("hash-two",),
            (3,) + (None,) * 19,
        ],
    )
    monkeypatch.setattr(
        check_remediation_evidence_keys.remediation_execution,
        "verify_execution_evidence",
        lambda action_id, actor: {
            "action_id": action_id,
            "status": "VERIFIED",
        },
    )

    report = check_remediation_evidence_keys.validate_key_rotation()

    assert report == {
        "current_key_id": "id-current-key",
        "previous_key_ids": ("id-previous-key",),
        "signed_record_count": 2,
        "status_counts": {"VERIFIED": 2},
        "successful": True,
    }


def test_validate_key_rotation_reports_failed_records(
    monkeypatch,
):
    monkeypatch.setattr(
        check_remediation_evidence_keys.remediation_execution,
        "_get_evidence_verification_keys",
        lambda: ("current-key",),
    )
    monkeypatch.setattr(
        check_remediation_evidence_keys.remediation_execution,
        "_get_evidence_key_id",
        lambda key: "current-key-id",
    )
    monkeypatch.setattr(
        check_remediation_evidence_keys.remediation_execution,
        "get_execution_actions",
        lambda: [
            (1,) + (None,) * 18 + ("hash-one",),
            (2,) + (None,) * 18 + ("hash-two",),
        ],
    )

    statuses = {
        1: "VERIFIED",
        2: "KEY_MISMATCH",
    }

    monkeypatch.setattr(
        check_remediation_evidence_keys.remediation_execution,
        "verify_execution_evidence",
        lambda action_id, actor: {
            "action_id": action_id,
            "status": statuses[action_id],
        },
    )

    report = check_remediation_evidence_keys.validate_key_rotation()

    assert report["status_counts"] == {
        "VERIFIED": 1,
        "KEY_MISMATCH": 1,
    }
    assert report["successful"] is False


def test_main_returns_configuration_error(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        check_remediation_evidence_keys,
        "validate_key_rotation",
        lambda: (_ for _ in ()).throw(
            RuntimeError("missing key")
        ),
    )

    assert check_remediation_evidence_keys.main() == 2
    assert "Configuration error: missing key" in capsys.readouterr().out
