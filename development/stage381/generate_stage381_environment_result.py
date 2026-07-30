#!/usr/bin/env python3
"""
Stage381 environment result generator.

Runs the preserved Stage380 deterministic verifier and converts its output
into a platform-neutral Stage381 environment result.

Exit codes:
  0 = environment result generated and Stage380 verifier succeeded
  1 = Stage380 verifier failed closed
  2 = execution or configuration error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any


STAGE = 381

STAGE380_VERIFIER = Path(
    "development/stage380/verify_stage380_independent_package.py"
)

STAGE380_RESULT = Path(
    "development/stage380/"
    "stage380_independent_verification_result.json"
)

OUTPUT_DIRECTORY = Path(
    "development/stage381/environment-results"
)

ALLOWED_PLATFORMS = {
    "ubuntu",
    "windows",
    "macos",
}


def canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(key)): canonicalize(
                current_value
            )
            for key, current_value in sorted(
                value.items(),
                key=lambda item: str(item[0]),
            )
        }

    if isinstance(value, list):
        return [canonicalize(item) for item in value]

    if isinstance(value, str):
        return unicodedata.normalize(
            "NFC",
            value.replace("\\", "/"),
        )

    return value


def canonical_json_bytes(value: Any) -> bytes:
    normalized = canonicalize(value)

    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--platform",
        required=True,
        choices=sorted(ALLOWED_PLATFORMS),
    )

    return parser.parse_args()


def write_result(platform_name: str, result: dict[str, Any]) -> Path:
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    output_path = OUTPUT_DIRECTORY / (
        f"stage381_{platform_name}_environment_result.json"
    )

    output_path.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    return output_path


def main() -> int:
    arguments = parse_arguments()
    platform_name = arguments.platform

    try:
        if not STAGE380_VERIFIER.is_file():
            raise FileNotFoundError(
                f"Stage380 verifier is missing: {STAGE380_VERIFIER}"
            )

        completed_process = subprocess.run(
            [
                sys.executable,
                str(STAGE380_VERIFIER),
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

        if not STAGE380_RESULT.is_file():
            raise FileNotFoundError(
                f"Stage380 result is missing: {STAGE380_RESULT}"
            )

        stage380_result = load_json(STAGE380_RESULT)

        comparison_payload = {
            "decision": stage380_result.get("decision"),
            "verification_status": stage380_result.get(
                "verification_status"
            ),
            "package_integrity_verified": stage380_result.get(
                "package_integrity_verified"
            ),
            "critical_failure_count": stage380_result.get(
                "critical_failure_count"
            ),
            "result_sha256": stage380_result.get("result_sha256"),
            "process_exit_code": completed_process.returncode,
        }

        canonical_result_sha256 = sha256_bytes(
            canonical_json_bytes(comparison_payload)
        )

        result_without_hash = {
            "stage": STAGE,
            "source_stage": 380,
            "generator": "Stage381 Environment Result Generator",
            "development_only": True,
            "platform": platform_name,
            "verification_mode": (
                "cross_platform_deterministic_offline"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "stage380_verifier_path": str(
                STAGE380_VERIFIER
            ).replace("\\", "/"),
            "stage380_result_path": str(
                STAGE380_RESULT
            ).replace("\\", "/"),
            "comparison_payload": comparison_payload,
            "canonical_result_sha256": canonical_result_sha256,
            "stage380_process_succeeded": (
                completed_process.returncode == 0
            ),
            "stdout_sha256": sha256_bytes(
                completed_process.stdout.replace(
                    "\r\n",
                    "\n",
                ).encode("utf-8")
            ),
            "stderr_sha256": sha256_bytes(
                completed_process.stderr.replace(
                    "\r\n",
                    "\n",
                ).encode("utf-8")
            ),
        }

        environment_result_sha256 = sha256_bytes(
            canonical_json_bytes(result_without_hash)
        )

        result = dict(result_without_hash)
        result["environment_result_sha256"] = (
            environment_result_sha256
        )

        output_path = write_result(platform_name, result)

        print(f"platform={platform_name}")
        print(
            "process_exit_code="
            f"{completed_process.returncode}"
        )
        print(
            "canonical_result_sha256="
            f"{canonical_result_sha256}"
        )
        print(f"result_path={output_path}")

        if completed_process.returncode == 0:
            return 0

        if completed_process.returncode == 1:
            return 1

        return 2

    except (
        FileNotFoundError,
        PermissionError,
        json.JSONDecodeError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        error_result_without_hash = {
            "stage": STAGE,
            "source_stage": 380,
            "generator": "Stage381 Environment Result Generator",
            "development_only": True,
            "platform": platform_name,
            "verification_mode": (
                "cross_platform_deterministic_offline"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "verification_status": "execution_error",
            "decision": "fail_closed",
            "errors": [
                f"{type(exc).__name__}: {exc}"
            ],
        }

        error_result = dict(error_result_without_hash)
        error_result["environment_result_sha256"] = sha256_bytes(
            canonical_json_bytes(error_result_without_hash)
        )

        output_path = write_result(
            platform_name,
            error_result,
        )

        print("decision=fail_closed", file=sys.stderr)
        print(
            f"error={type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        print(f"result_path={output_path}", file=sys.stderr)

        return 2


if __name__ == "__main__":
    sys.exit(main())
