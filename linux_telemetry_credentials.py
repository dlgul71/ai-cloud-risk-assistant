"""Protected credential configuration for the Linux receiver."""

import json
import os
import re
import stat


def load_credential_hashes(path):
    """Load token hashes without exposing plaintext credentials."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)

    with os.fdopen(os.open(path, flags), "rb") as source:
        info = os.fstat(source.fileno())

        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise PermissionError("Credential file must be private")

        data = source.read(65537)

    if len(data) > 65536:
        raise ValueError("Credential configuration too large")

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate credential hash")
            result[key] = value
        return result

    mapping = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=reject_duplicates,
    )

    if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 128:
        raise ValueError("Invalid credential configuration")

    for token_hash, client_key in mapping.items():
        if not re.fullmatch(r"[0-9a-f]{64}", token_hash):
            raise ValueError("Invalid credential hash")

        if (
            not isinstance(client_key, str)
            or not client_key.strip()
            or client_key != client_key.strip()
            or len(client_key) > 128
        ):
            raise ValueError("Invalid assigned client key")

    return mapping
