"""Run production deployment smoke tests against DGS Sentinel AI.

Usage:
    python -m scripts.production_smoke_test \
        --base-url http://127.0.0.1:8502
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request


def check_endpoint(
    url: str,
    expected_body: str | None = None,
    timeout: float = 5.0,
) -> tuple[bool, str]:
    parsed_url = urllib.parse.urlsplit(url)

    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.hostname
    ):
        return False, "Only HTTP and HTTPS URLs are permitted"

    try:
        with urllib.request.urlopen(  # nosec B310
            url,
            timeout=timeout,
        ) as response:
            status_code = response.status
            body = response.read().decode(
                "utf-8",
                errors="replace",
            ).strip()

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ) as error:
        return False, f"{type(error).__name__}: {error}"

    if status_code != 200:
        return False, f"Unexpected HTTP status {status_code}"

    if expected_body is not None and body != expected_body:
        return False, (
            f"Unexpected response body: {body!r}"
        )

    return True, f"HTTP {status_code}"


def run_smoke_tests(
    base_url: str,
    timeout: float = 5.0,
) -> list[dict[str, str]]:
    normalized_url = base_url.rstrip("/")

    checks = (
        (
            "Application root",
            normalized_url + "/",
            None,
        ),
        (
            "Streamlit health endpoint",
            normalized_url + "/_stcore/health",
            "ok",
        ),
    )

    results = []

    for name, url, expected_body in checks:
        passed, detail = check_endpoint(
            url=url,
            expected_body=expected_body,
            timeout=timeout,
        )

        results.append(
            {
                "check": name,
                "status": "PASS" if passed else "FAIL",
                "detail": detail,
                "url": url,
            }
        )

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a running DGS Sentinel AI deployment."
        )
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8501",
        help="Base URL of the running deployment.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds.",
    )

    arguments = parser.parse_args(argv)

    results = run_smoke_tests(
        base_url=arguments.base_url,
        timeout=arguments.timeout,
    )

    for result in results:
        print(
            f"{result['status']}: {result['check']} "
            f"({result['detail']})"
        )

    if all(
        result["status"] == "PASS"
        for result in results
    ):
        print("Production deployment smoke test passed.")
        return 0

    print("Production deployment smoke test failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
