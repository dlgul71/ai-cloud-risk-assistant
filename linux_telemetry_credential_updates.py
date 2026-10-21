"""Atomic replacement of protected receiver credentials."""

import json
import os
import stat
import tempfile
from pathlib import Path

from linux_telemetry_credentials import load_credential_hashes


def replace_credential_hashes_atomically(path, mapping):
    target = Path(path)
    directory = target.parent

    info = os.stat(directory, follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
    ):
        raise PermissionError("Credential directory is unsafe")

    # Existing file must already satisfy security requirements.
    load_credential_hashes(target)

    payload = json.dumps(
        mapping, sort_keys=True, allow_nan=False
    ).encode("utf-8")

    fd, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.",
        dir=directory,
    )

    try:
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())

        # Validate the complete replacement before publishing it.
        load_credential_hashes(temporary)

        # Recheck the original before replacement.
        load_credential_hashes(target)

        os.replace(temporary, target)

        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
