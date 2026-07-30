#!/usr/bin/env python3
"""
Stage381
Cross-Platform Deterministic Reverification Comparator

Compares independently generated Ubuntu, Windows, and macOS environment
results. The comparison fails closed unless all required platforms produce
the same Stage380 verification decision, status, integrity state, exit code,
result hash, and canonical result hash.

Exit codes:
  0 = all required platform results match
  1 = comparison completed but failed closed
  2 = execution or configuration error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any


STAGE = 381

REQUIRED_PLATFORMS = (
    "ubuntu",
    "windows",
    "macos",
)

REQUIRED_COMPARISON_FIELDS = (
    "decision",
    "verification_status",
    "package_integrity_verified",
    "critical_failure_count",
    "result_sha256",
    "process_exit_code",
)

DEFAULT_INPUT_DIRECTORY = Path(
    "development/stage381/environment-results"
)

DEFAULT_OUTPUT_PATH = Path(
    "development/stage381/"
    "stage381_cross_platform_verification_result.json"
)


def canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        normalized_items = sorted(
            value.items(),
            key=lambda item: unicodedata.normalize(
                "NFC",
                str(item[0]),
            ),
        )

        return {
            unicodedata.normalize("NFC", str(key)): canonicalize(
                current_value
            )
            for key, current_value in normalized_items
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
    return json.dumps(
        canonicalize(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file_handle:
        for chunk in iter(
            lambda: file_handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def add_check(
    checks: list[dict[str, Any]],
    *,
    name: str,
    passed: bool,
    expected: Any,
    actual: Any,
    critical: bool = True,
) -> None:
    checks.append(
        {
            "name": name,
            "passed": bool(passed),
            "critical": bool(critical),
            "expected": expected,
            "actual": actual,
        }
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input-directory",
        type=Path,
        default=DEFAULT_INPUT_DIRECTORY,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
    )

    return parser.parse_args()


def expected_environment_path(
    input_directory: Path,
    platform_name: str,
) -> Path:
    return input_directory / (
        f"stage381_{platform_name}_environment_result.json"
    )


def validate_environment_result(
    *,
    platform_name: str,
    path: Path,
    result: Any,
    checks: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        add_check(
            checks,
            name=f"{platform_name}_result_is_object",
            passed=False,
            expected="object",
            actual=type(result).__name__,
        )
        return None

    required_top_level_fields = {
        "stage": STAGE,
        "source_stage": 380,
        "development_only": True,
        "platform": platform_name,
        "verification_mode": (
            "cross_platform_deterministic_offline"
        ),
        "network_access_required": False,
        "fail_closed": True,
    }

    for field_name, expected_value in (
        required_top_level_fields.items()
    ):
        actual_value = result.get(field_name)

        add_check(
            checks,
            name=f"{platform_name}_{field_name}",
            passed=actual_value == expected_value,
            expected=expected_value,
            actual=actual_value,
        )

    comparison_payload = result.get("comparison_payload")

    add_check(
        checks,
        name=f"{platform_name}_comparison_payload_is_object",
        passed=isinstance(comparison_payload, dict),
        expected="object",
        actual=type(comparison_payload).__name__,
    )

    if not isinstance(comparison_payload, dict):
        return None

    for field_name in REQUIRED_COMPARISON_FIELDS:
        add_check(
            checks,
            name=(
                f"{platform_name}_comparison_field_present:"
                f"{field_name}"
            ),
            passed=field_name in comparison_payload,
            expected=True,
            actual=field_name in comparison_payload,
        )

    expected_canonical_hash = sha256_bytes(
        canonical_json_bytes(comparison_payload)
    )
    actual_canonical_hash = result.get(
        "canonical_result_sha256"
    )

    add_check(
        checks,
        name=f"{platform_name}_canonical_result_sha256_valid",
        passed=actual_canonical_hash == expected_canonical_hash,
        expected=expected_canonical_hash,
        actual=actual_canonical_hash,
    )

    environment_result_without_hash = dict(result)
    recorded_environment_hash = (
        environment_result_without_hash.pop(
            "environment_result_sha256",
            None,
        )
    )

    expected_environment_hash = sha256_bytes(
        canonical_json_bytes(environment_result_without_hash)
    )

    add_check(
        checks,
        name=(
            f"{platform_name}_environment_result_sha256_valid"
        ),
        passed=(
            recorded_environment_hash
            == expected_environment_hash
        ),
        expected=expected_environment_hash,
        actual=recorded_environment_hash,
    )

    add_check(
        checks,
        name=f"{platform_name}_source_file_sha256_available",
        passed=path.is_file(),
        expected=True,
        actual=path.is_file(),
    )

    return {
        "platform": platform_name,
        "path": path.as_posix(),
        "file_sha256": sha256_file(path),
        "canonical_result_sha256": actual_canonical_hash,
        "comparison_payload": {
            field_name: comparison_payload.get(field_name)
            for field_name in REQUIRED_COMPARISON_FIELDS
        },
        "environment_result_sha256": (
            recorded_environment_hash
        ),
    }


def write_result(
    output_path: Path,
    result: dict[str, Any],
) -> None:
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
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


def main() -> int:
    arguments = parse_arguments()
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        platform_summaries: dict[str, dict[str, Any]] = {}

        for platform_name in REQUIRED_PLATFORMS:
            result_path = expected_environment_path(
                arguments.input_directory,
                platform_name,
            )

            exists = result_path.is_file()

            add_check(
                checks,
                name=f"{platform_name}_result_file_present",
                passed=exists,
                expected=True,
                actual=exists,
            )

            if not exists:
                continue

            environment_result = load_json(result_path)

            platform_summary = validate_environment_result(
                platform_name=platform_name,
                path=result_path,
                result=environment_result,
                checks=checks,
            )

            if platform_summary is not None:
                platform_summaries[platform_name] = (
                    platform_summary
                )

        all_platforms_present = (
            set(platform_summaries)
            == set(REQUIRED_PLATFORMS)
        )

        add_check(
            checks,
            name="all_required_platform_results_available",
            passed=all_platforms_present,
            expected=list(REQUIRED_PLATFORMS),
            actual=sorted(platform_summaries),
        )

        reference_platform = REQUIRED_PLATFORMS[0]
        reference_summary = platform_summaries.get(
            reference_platform
        )

        comparison_field_matches: dict[str, bool] = {}

        for field_name in REQUIRED_COMPARISON_FIELDS:
            observed_values = {
                platform_name: (
                    platform_summaries[platform_name][
                        "comparison_payload"
                    ].get(field_name)
                )
                for platform_name in REQUIRED_PLATFORMS
                if platform_name in platform_summaries
            }

            field_matches = (
                all_platforms_present
                and len(
                    {
                        json.dumps(
                            value,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        for value in observed_values.values()
                    }
                )
                == 1
            )

            comparison_field_matches[field_name] = (
                field_matches
            )

            expected_value = (
                reference_summary["comparison_payload"].get(
                    field_name
                )
                if reference_summary is not None
                else "same value on all platforms"
            )

            add_check(
                checks,
                name=f"cross_platform_match:{field_name}",
                passed=field_matches,
                expected=expected_value,
                actual=observed_values,
            )

        observed_canonical_hashes = {
            platform_name: platform_summaries[
                platform_name
            ].get("canonical_result_sha256")
            for platform_name in REQUIRED_PLATFORMS
            if platform_name in platform_summaries
        }

        canonical_hashes_match = (
            all_platforms_present
            and len(set(observed_canonical_hashes.values())) == 1
        )

        add_check(
            checks,
            name="cross_platform_canonical_result_sha256_match",
            passed=canonical_hashes_match,
            expected="identical SHA-256 on all required platforms",
            actual=observed_canonical_hashes,
        )

        critical_failures = sorted(
            check["name"]
            for check in checks
            if check["critical"] and not check["passed"]
        )

        cross_platform_reverification_verified = (
            len(critical_failures) == 0
        )

        if cross_platform_reverification_verified:
            decision = (
                "cross_platform_reverification_verified_"
                "upstream_pending"
            )
            verification_status = "verified_development_only"
        else:
            decision = "fail_closed"
            verification_status = "invalid"

        common_canonical_result_sha256 = (
            next(iter(observed_canonical_hashes.values()))
            if canonical_hashes_match
            else None
        )

        result_without_hash: dict[str, Any] = {
            "stage": STAGE,
            "source_stage": 380,
            "verifier": (
                "Stage381 Cross-Platform Deterministic "
                "Reverification Comparator"
            ),
            "execution_mode": "development",
            "development_only": True,
            "verification_mode": (
                "cross_platform_deterministic_offline"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "required_platforms": list(
                REQUIRED_PLATFORMS
            ),
            "platform_result_count": len(
                platform_summaries
            ),
            "all_required_platforms_present": (
                all_platforms_present
            ),
            "same_input_same_output_verified": (
                cross_platform_reverification_verified
            ),
            "same_decision_verified": (
                comparison_field_matches.get(
                    "decision",
                    False,
                )
            ),
            "same_exit_code_verified": (
                comparison_field_matches.get(
                    "process_exit_code",
                    False,
                )
            ),
            "same_stage380_result_sha256_verified": (
                comparison_field_matches.get(
                    "result_sha256",
                    False,
                )
            ),
            "same_canonical_result_sha256_verified": (
                canonical_hashes_match
            ),
            "cross_platform_reverification_verified": (
                cross_platform_reverification_verified
            ),
            "verification_status": verification_status,
            "decision": decision,
            "common_canonical_result_sha256": (
                common_canonical_result_sha256
            ),
            "platform_results": {
                platform_name: platform_summaries[
                    platform_name
                ]
                for platform_name in sorted(
                    platform_summaries
                )
            },
            "check_count": len(checks),
            "critical_failure_count": len(
                critical_failures
            ),
            "critical_failures": critical_failures,
            "checks": sorted(
                checks,
                key=lambda item: item["name"],
            ),
            "errors": errors,
            "deterministic_statement": (
                "No runtime timestamp, hostname, username, "
                "absolute path, temporary path, random value, "
                "or network-derived value is included."
            ),
            "upstream_statement": (
                "Stage381 verifies cross-platform "
                "reproducibility only and does not upgrade "
                "Stage377, Stage378, Stage379, or Stage380 "
                "formal acceptance."
            ),
        }

        result = dict(result_without_hash)
        result["result_sha256"] = sha256_bytes(
            canonical_json_bytes(result_without_hash)
        )

        write_result(arguments.output, result)

        print(f"decision={decision}")
        print(
            "cross_platform_reverification_verified="
            f"{str(cross_platform_reverification_verified).lower()}"
        )
        print(
            "critical_failure_count="
            f"{len(critical_failures)}"
        )
        print(
            "common_canonical_result_sha256="
            f"{common_canonical_result_sha256}"
        )
        print(f"result_path={arguments.output}")

        return (
            0
            if cross_platform_reverification_verified
            else 1
        )

    except (
        FileNotFoundError,
        PermissionError,
        json.JSONDecodeError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        error_result_without_hash: dict[str, Any] = {
            "stage": STAGE,
            "source_stage": 380,
            "verifier": (
                "Stage381 Cross-Platform Deterministic "
                "Reverification Comparator"
            ),
            "execution_mode": "development",
            "development_only": True,
            "verification_mode": (
                "cross_platform_deterministic_offline"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "verification_status": "execution_error",
            "decision": "fail_closed",
            "critical_failure_count": 1,
            "critical_failures": [
                "comparator_execution_error"
            ],
            "checks": sorted(
                checks,
                key=lambda item: item["name"],
            ),
            "errors": [
                f"{type(exc).__name__}: {exc}"
            ],
        }

        error_result = dict(error_result_without_hash)
        error_result["result_sha256"] = sha256_bytes(
            canonical_json_bytes(
                error_result_without_hash
            )
        )

        write_result(arguments.output, error_result)

        print("decision=fail_closed", file=sys.stderr)
        print(
            f"error={type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        print(
            f"result_path={arguments.output}",
            file=sys.stderr,
        )

        return 2


if __name__ == "__main__":
    sys.exit(main())
