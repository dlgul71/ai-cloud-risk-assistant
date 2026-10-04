"""Convert three exactly reviewed legacy shapes into new rehearsal files only."""

from contextlib import ExitStack, closing
import json
import os
from pathlib import Path
import sqlite3

from database_migrations import _readonly_connection
from database_migrations.baseline import BASELINE_DIRECTORY, _reviewed_candidate, schema_fingerprint

DOMAINS = ("remediation.db", "operational_monitoring.db", "remediation_actions.db")
LEGACY_DIRECTORY = Path(__file__).parent / "legacy_schemas"
MAX_ROWS = 100_000
MAX_FIELD_SIZE = 1_000_000
MAX_DOMAIN_BYTES = 50_000_000


def _shape(sql):
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(sql)
        return schema_fingerprint(connection)


def _columns(connection, table):
    return [row[0] for row in connection.execute("SELECT name FROM pragma_table_info(?) ORDER BY cid", (table,))]


def rehearse_legacy_upgrade(source_directory, output_directory, *, confirm_stopped=False):
    """Never overwrite inputs or adopt versions; preserve legacy ownership and evidence.

    The newly added health tenant key is explicitly legacy-unassigned. This is
    not a recovered owner, a system designation, or a certified migration.
    """
    source = Path(source_directory).expanduser().resolve()
    output = Path(output_directory).expanduser().absolute()
    result = {"status": "REFUSED", "adoption_eligible": False, "databases": [],
              "detail": "Rehearsal did not run."}
    if not confirm_stopped or not source.is_dir():
        result["detail"] = "A stopped/coherent source directory is required."
        return result
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        result["detail"] = "Output must be a new directory under an existing parent."
        return result
    resolved_output = output.resolve()
    if resolved_output == source or source in resolved_output.parents or resolved_output in source.parents:
        result["detail"] = "Source and output directories must be separate."
        return result
    created = False
    try:
        with ExitStack() as stack:
            inputs = {}
            rows = {}
            definitions = {}
            sequences = {}
            for name in DOMAINS:
                path = source / name
                if path.is_symlink() or not path.is_file():
                    raise ValueError("Missing or linked source.")
                connection = stack.enter_context(_readonly_connection(path))
                inputs[name] = connection
                candidate = _reviewed_candidate(name)
                sql = (BASELINE_DIRECTORY / candidate["definition"]).read_text()
                definitions[name] = sql
                legacy_sql = (LEGACY_DIRECTORY / candidate["definition"]).read_text()
                if schema_fingerprint(connection) != _shape(legacy_sql):
                    raise ValueError("Unreviewed source shape.")
                if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise ValueError("Source integrity failed.")
                if connection.execute("PRAGMA foreign_key_check").fetchall():
                    raise ValueError("Source foreign keys failed.")
                tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
                rows[name] = {}
                domain_bytes = 0
                for table in tables:
                    columns = _columns(connection, table)
                    count = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]  # nosec B608
                    if count > MAX_ROWS:
                        raise ValueError("Row limit exceeded.")
                    for column in columns:
                        oversized = connection.execute(f'SELECT 1 FROM "{table}" WHERE typeof("{column}") IN (\'text\',\'blob\') AND length("{column}") > ? LIMIT 1', (MAX_FIELD_SIZE,)).fetchone()  # nosec B608
                        if oversized:
                            raise ValueError("Field limit exceeded.")
                        domain_bytes += connection.execute(f'SELECT COALESCE(SUM(length(CAST("{column}" AS BLOB))),0) FROM "{table}"').fetchone()[0]  # nosec B608
                        if domain_bytes > MAX_DOMAIN_BYTES:
                            raise ValueError("Domain byte limit exceeded.")
                    values = connection.execute(f'SELECT * FROM "{table}" ORDER BY id').fetchall()  # nosec B608
                    rows[name][table] = (columns, values)
                sequences[name] = connection.execute("SELECT name, seq FROM sqlite_sequence ORDER BY name").fetchall()
            # Refuse unknown schemas before creating any output.
            output.mkdir(mode=0o700, exist_ok=False)
            created = True
            for name in DOMAINS:
                destination = output / name
                descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
                with closing(sqlite3.connect(destination)) as target:
                    target.execute("PRAGMA foreign_keys=ON")
                    target.executescript(definitions[name])
                    target.execute("BEGIN")
                    counts = {}
                    # health_runs must precede its children with FK enforcement.
                    tables = sorted(rows[name], key=lambda t: (t != "health_runs", t))
                    for table in tables:
                        columns, values = rows[name][table]
                        inserted_columns = list(columns)
                        inserted_values = values
                        if name == "operational_monitoring.db" and table == "health_runs":
                            inserted_columns.append("client_key")
                            inserted_values = [(*row, "__legacy_unassigned__") for row in values]
                        names = ",".join(f'"{column}"' for column in inserted_columns)
                        placeholders = ",".join("?" for _ in inserted_columns)
                        target.executemany(f'INSERT INTO "{table}" ({names}) VALUES ({placeholders})', inserted_values)  # nosec B608
                        projection = ",".join(f'"{column}"' for column in columns)
                        if target.execute(f'SELECT {projection} FROM "{table}" ORDER BY id').fetchall() != values:  # nosec B608
                            raise ValueError("Original values were not preserved.")
                        counts[table] = len(values)
                    target.execute("DELETE FROM sqlite_sequence")
                    target.executemany("INSERT INTO sqlite_sequence(name,seq) VALUES (?,?)", sequences[name])
                    if target.execute("PRAGMA foreign_key_check").fetchall():
                        raise ValueError("Output foreign keys failed.")
                    if target.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                        raise ValueError("Output integrity failed.")
                    if schema_fingerprint(target) != _reviewed_candidate(name)["schema_sha256"]:
                        raise ValueError("Output schema mismatch.")
                    target.commit()
                result["databases"].append({"database": name, "row_counts": counts,
                                             "original_values_preserved": True})
            result.update(status="REHEARSAL_CREATED", detail="Three new schema copies created; ownership and evidence review remain required.",
                          output_directory=str(output), health_ownership="__legacy_unassigned__",
                          limitations=["Only three reviewed legacy stores are in scope.",
                                       "No migration registry was adopted and no source file was changed.",
                                       "Original null provider values and signature metadata are preserved.",
                                       "Rehearsal does not establish tenant ownership or verify signatures."])
            report = output / "rehearsal.json"
            descriptor = os.open(report, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                json.dump(result, handle, indent=2, sort_keys=True)
                handle.write("\n")
        return result
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError):
        result.update(status="ERROR" if created else "REFUSED", databases=[],
                      detail="Rehearsal failed; source unchanged. Any output is incomplete and must not be deployed.")
        return result
