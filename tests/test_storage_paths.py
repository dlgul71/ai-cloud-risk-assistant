from pathlib import Path

import storage_paths


def test_data_directory_defaults_to_current_directory(
    monkeypatch,
):
    monkeypatch.delenv(
        "DGS_DATA_DIR",
        raising=False,
    )

    assert storage_paths.get_data_directory() == Path(".")


def test_data_directory_reads_environment_value(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    assert (
        storage_paths.get_data_directory()
        == tmp_path
    )


def test_database_path_uses_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    assert storage_paths.database_path(
        "assets.db"
    ) == tmp_path / "assets.db"


def test_runtime_directory_creates_directory(
    monkeypatch,
    tmp_path,
):
    data_directory = tmp_path / "runtime"

    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(data_directory),
    )

    result = storage_paths.runtime_directory(
        "scan_snapshots"
    )

    assert result == (
        data_directory / "scan_snapshots"
    )
    assert result.exists()
    assert result.is_dir()


def test_database_path_rejects_nested_or_unsafe_name():
    for unsafe_name in (
        "../assets.db",
        "/tmp/assets.db",
        "nested/assets.db",
    ):
        try:
            storage_paths.database_path(
                unsafe_name
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"Unsafe name accepted: {unsafe_name}"
            )
