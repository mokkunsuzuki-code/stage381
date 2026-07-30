#!/usr/bin/env python3
"""
Stage381
Deterministic Reverification & Reproducibility Gate

Cross-Platform Verification Package Verifier

This development-only verifier validates:

- the Stage381 package contract and its SHA-256 record;
- the Stage381 canonicalization profile;
- Ubuntu, Windows, and macOS environment results;
- the Stage381 cross-platform comparison result;
- deterministic internal result hashes;
- binding to the Stage380 verification result;
- fail-closed behavior when any required evidence is absent or inconsistent.

This verifier performs no network communication.

Exit codes:
  0 = Stage381 package integrity verified
  1 = verification completed but failed closed
  2 = execution or configuration error
"""

from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any


STAGE = 381
SOURCE_STAGE = 380

VERIFIER_NAME = (
    "Stage381 Cross-Platform Verification Package Verifier"
)

BASE_DIRECTORY = Path("development/stage381")

CONTRACT_PATH = BASE_DIRECTORY / (
    "stage381_cross_platform_verification_package_contract.json"
)

CONTRACT_SHA256_PATH = BASE_DIRECTORY / (
    "stage381_cross_platform_verification_package_contract.sha256"
)

CANONICALIZATION_PROFILE_PATH = BASE_DIRECTORY / (
    "stage381_canonicalization_profile.json"
)

COMPARISON_RESULT_PATH = BASE_DIRECTORY / (
    "stage381_cross_platform_verification_result.json"
)

STAGE380_RESULT_PATH = Path(
    "development/stage380/"
    "stage380_independent_verification_result.json"
)

ENVIRONMENT_RESULTS_DIRECTORY = (
    BASE_DIRECTORY / "environment-results"
)

OUTPUT_PATH = BASE_DIRECTORY / (
    "stage381_cross_platform_verification_package_result.json"
)

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


def normalize_string(value: str) -> str:
    return unicodedata.normalize(
        "NFC",
        value.replace("\\", "/"),
    )


def canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        normalized_items = sorted(
            value.items(),
            key=lambda item: normalize_string(str(item[0])),
        )

        return {
            normalize_string(str(key)): canonicalize(current_value)
            for key, current_value in normalized_items
        }

    if isinstance(value, list):
        return [canonicalize(item) for item in value]

    if isinstance(value, str):
        return normalize_string(value)

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


def parse_sha256_record(path: Path) -> tuple[str, str]:
    line = path.read_text(
        encoding="utf-8"
    ).strip()

    parts = line.split(maxsplit=1)

    if len(parts) != 2:
        raise ValueError(
            f"invalid SHA-256 record format: {path}"
        )

    expected_hash = parts[0].strip().lower()
    recorded_path = parts[1].strip()

    if recorded_path.startswith("*"):
        recorded_path = recorded_path[1:]

    if len(expected_hash) != 64:
        raise ValueError(
            f"SHA-256 must contain 64 characters: {path}"
        )

    try:
        int(expected_hash, 16)
    except ValueError as exc:
        raise ValueError(
            f"SHA-256 is not hexadecimal: {path}"
        ) from exc

    return expected_hash, recorded_path


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


def verify_embedded_hash(
    *,
    document: dict[str, Any],
    hash_field: str,
) -> tuple[bool, str | None, str]:
    document_without_hash = dict(document)
    recorded_hash = document_without_hash.pop(
        hash_field,
        None,
    )

    expected_hash = sha256_bytes(
        canonical_json_bytes(document_without_hash)
    )

    return (
        recorded_hash == expected_hash,
        recorded_hash,
        expected_hash,
    )


def environment_result_path(
    platform_name: str,
) -> Path:
    return ENVIRONMENT_RESULTS_DIRECTORY / (
        f"stage381_{platform_name}_environment_result.json"
    )


def main() -> int:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        required_files = {
            "contract": CONTRACT_PATH,
            "contract_sha256": CONTRACT_SHA256_PATH,
            "canonicalization_profile": (
                CANONICALIZATION_PROFILE_PATH
            ),
            "comparison_result": COMPARISON_RESULT_PATH,
            "stage380_result": STAGE380_RESULT_PATH,
        }

        for file_name, file_path in required_files.items():
            exists = file_path.is_file()

            add_check(
                checks,
                name=f"{file_name}_file_present",
                passed=exists,
                expected=True,
                actual=exists,
            )

        missing_required_files = [
            str(path)
            for path in required_files.values()
            if not path.is_file()
        ]

        if missing_required_files:
            raise FileNotFoundError(
                "missing required files: "
                + ", ".join(missing_required_files)
            )

        contract = load_json(CONTRACT_PATH)

        add_check(
            checks,
            name="contract_is_object",
            passed=isinstance(contract, dict),
            expected="object",
            actual=type(contract).__name__,
        )

        if not isinstance(contract, dict):
            raise TypeError(
                "Stage381 contract must be a JSON object"
            )

        expected_contract_hash, recorded_contract_path = (
            parse_sha256_record(CONTRACT_SHA256_PATH)
        )

        actual_contract_hash = sha256_file(
            CONTRACT_PATH
        )

        add_check(
            checks,
            name="contract_sha256_valid",
            passed=(
                actual_contract_hash
                == expected_contract_hash
            ),
            expected=expected_contract_hash,
            actual=actual_contract_hash,
        )

        add_check(
            checks,
            name="contract_sha256_record_path_valid",
            passed=(
                recorded_contract_path
                == CONTRACT_PATH.as_posix()
            ),
            expected=CONTRACT_PATH.as_posix(),
            actual=recorded_contract_path,
        )

        contract_requirements = {
            "stage": STAGE,
            "source_stage": SOURCE_STAGE,
            "development_only": True,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "verification_mode": (
                "cross_platform_deterministic_offline"
            ),
            "package_locked": True,
            "scope_reduction_allowed": False,
            "fail_closed": True,
        }

        for field_name, expected_value in (
            contract_requirements.items()
        ):
            actual_value = contract.get(
                field_name
            )

            add_check(
                checks,
                name=f"contract_{field_name}",
                passed=actual_value == expected_value,
                expected=expected_value,
                actual=actual_value,
            )

        required_platforms = contract.get(
            "required_platforms"
        )

        add_check(
            checks,
            name="contract_required_platforms_valid",
            passed=required_platforms == list(
                REQUIRED_PLATFORMS
            ),
            expected=list(REQUIRED_PLATFORMS),
            actual=required_platforms,
        )

        reproducibility_requirements = contract.get(
            "reproducibility_requirements",
            {},
        )

        if not isinstance(
            reproducibility_requirements,
            dict,
        ):
            reproducibility_requirements = {}

        for requirement_name in (
            "same_input_same_output",
            "same_decision",
            "same_process_exit_code",
            "same_source_result_sha256",
            "same_canonical_result_sha256",
            "offline_only",
        ):
            actual_value = (
                reproducibility_requirements.get(
                    requirement_name
                )
            )

            add_check(
                checks,
                name=(
                    "contract_reproducibility_"
                    f"{requirement_name}"
                ),
                passed=actual_value is True,
                expected=True,
                actual=actual_value,
            )

        canonicalization_profile = load_json(
            CANONICALIZATION_PROFILE_PATH
        )

        add_check(
            checks,
            name="canonicalization_profile_is_object",
            passed=isinstance(
                canonicalization_profile,
                dict,
            ),
            expected="object",
            actual=type(
                canonicalization_profile
            ).__name__,
        )

        if not isinstance(
            canonicalization_profile,
            dict,
        ):
            raise TypeError(
                "canonicalization profile must be an object"
            )

        canonicalization_requirements = {
            "stage": (
                canonicalization_profile.get("stage"),
                STAGE,
            ),
            "source_stage": (
                canonicalization_profile.get("source_stage"),
                SOURCE_STAGE,
            ),
            "development_only": (
                canonicalization_profile.get("development_only"),
                True,
            ),
            "encoding": (
                canonicalization_profile.get(
                    "canonical_json",
                    {},
                ).get("encoding"),
                "UTF-8",
            ),
            "object_keys": (
                canonicalization_profile.get(
                    "canonical_json",
                    {},
                ).get("object_keys"),
                "lexicographically_sorted",
            ),
            "line_endings": (
                canonicalization_profile.get(
                    "text_normalization",
                    {},
                ).get("line_endings"),
                "LF",
            ),
            "unicode_normalization": (
                canonicalization_profile.get(
                    "text_normalization",
                    {},
                ).get("unicode_normalization"),
                "NFC",
            ),
            "path_separator": (
                canonicalization_profile.get(
                    "path_normalization",
                    {},
                ).get("separator"),
                "/",
            ),
            "file_order": (
                canonicalization_profile.get(
                    "file_processing",
                    {},
                ).get("file_order"),
                "lexicographically_sorted_relative_paths",
            ),
            "hash_algorithm": (
                canonicalization_profile.get(
                    "file_processing",
                    {},
                ).get("hash_algorithm"),
                "sha256",
            ),
            "fail_closed": (
                canonicalization_profile.get("fail_closed"),
                True,
            ),
        }

        for field_name, values in (
            canonicalization_requirements.items()
        ):
            actual_value, expected_value = values

            add_check(
                checks,
                name=(
                    "canonicalization_profile_"
                    f"{field_name}"
                ),
                passed=actual_value == expected_value,
                expected=expected_value,
                actual=actual_value,
            )

        required_profile_platforms = (
            canonicalization_profile.get(
                "required_platforms"
            )
        )

        add_check(
            checks,
            name=(
                "canonicalization_profile_"
                "required_platforms"
            ),
            passed=(
                required_profile_platforms
                == list(REQUIRED_PLATFORMS)
            ),
            expected=list(REQUIRED_PLATFORMS),
            actual=required_profile_platforms,
        )

        required_profile_comparison_fields = (
            canonicalization_profile.get(
                "required_comparison_fields"
            )
        )

        expected_profile_comparison_fields = [
            *REQUIRED_COMPARISON_FIELDS,
            "canonical_result_sha256",
        ]

        add_check(
            checks,
            name=(
                "canonicalization_profile_"
                "required_comparison_fields"
            ),
            passed=(
                required_profile_comparison_fields
                == expected_profile_comparison_fields
            ),
            expected=expected_profile_comparison_fields,
            actual=required_profile_comparison_fields,
        )

        comparison_result = load_json(
            COMPARISON_RESULT_PATH
        )

        add_check(
            checks,
            name="comparison_result_is_object",
            passed=isinstance(
                comparison_result,
                dict,
            ),
            expected="object",
            actual=type(
                comparison_result
            ).__name__,
        )

        if not isinstance(
            comparison_result,
            dict,
        ):
            raise TypeError(
                "comparison result must be an object"
            )

        (
            comparison_hash_valid,
            recorded_comparison_hash,
            expected_comparison_hash,
        ) = verify_embedded_hash(
            document=comparison_result,
            hash_field="result_sha256",
        )

        add_check(
            checks,
            name="comparison_result_embedded_hash_valid",
            passed=comparison_hash_valid,
            expected=expected_comparison_hash,
            actual=recorded_comparison_hash,
        )

        comparison_requirements = {
            "stage": STAGE,
            "source_stage": SOURCE_STAGE,
            "development_only": True,
            "verification_mode": (
                "cross_platform_deterministic_offline"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "all_required_platforms_present": True,
            "same_input_same_output_verified": True,
            "same_decision_verified": True,
            "same_exit_code_verified": True,
            "same_stage380_result_sha256_verified": True,
            "same_canonical_result_sha256_verified": True,
            "cross_platform_reverification_verified": True,
            "critical_failure_count": 0,
        }

        for field_name, expected_value in (
            comparison_requirements.items()
        ):
            actual_value = comparison_result.get(
                field_name
            )

            add_check(
                checks,
                name=(
                    "comparison_result_"
                    f"{field_name}"
                ),
                passed=actual_value == expected_value,
                expected=expected_value,
                actual=actual_value,
            )

        platform_results: dict[
            str,
            dict[str, Any]
        ] = {}

        for platform_name in REQUIRED_PLATFORMS:
            result_path = environment_result_path(
                platform_name
            )

            exists = result_path.is_file()

            add_check(
                checks,
                name=(
                    f"{platform_name}_environment_"
                    "result_present"
                ),
                passed=exists,
                expected=True,
                actual=exists,
            )

            if not exists:
                continue

            environment_result = load_json(
                result_path
            )

            add_check(
                checks,
                name=(
                    f"{platform_name}_environment_"
                    "result_is_object"
                ),
                passed=isinstance(
                    environment_result,
                    dict,
                ),
                expected="object",
                actual=type(
                    environment_result
                ).__name__,
            )

            if not isinstance(
                environment_result,
                dict,
            ):
                continue

            environment_requirements = {
                "stage": STAGE,
                "source_stage": SOURCE_STAGE,
                "development_only": True,
                "platform": platform_name,
                "verification_mode": (
                    "cross_platform_deterministic_offline"
                ),
                "network_access_required": False,
                "fail_closed": True,
            }

            for field_name, expected_value in (
                environment_requirements.items()
            ):
                actual_value = (
                    environment_result.get(
                        field_name
                    )
                )

                add_check(
                    checks,
                    name=(
                        f"{platform_name}_"
                        f"{field_name}"
                    ),
                    passed=(
                        actual_value
                        == expected_value
                    ),
                    expected=expected_value,
                    actual=actual_value,
                )

            comparison_payload = (
                environment_result.get(
                    "comparison_payload"
                )
            )

            add_check(
                checks,
                name=(
                    f"{platform_name}_comparison_"
                    "payload_is_object"
                ),
                passed=isinstance(
                    comparison_payload,
                    dict,
                ),
                expected="object",
                actual=type(
                    comparison_payload
                ).__name__,
            )

            if not isinstance(
                comparison_payload,
                dict,
            ):
                continue

            for field_name in (
                REQUIRED_COMPARISON_FIELDS
            ):
                add_check(
                    checks,
                    name=(
                        f"{platform_name}_comparison_"
                        f"field_present:{field_name}"
                    ),
                    passed=(
                        field_name
                        in comparison_payload
                    ),
                    expected=True,
                    actual=(
                        field_name
                        in comparison_payload
                    ),
                )

            expected_canonical_hash = (
                sha256_bytes(
                    canonical_json_bytes(
                        comparison_payload
                    )
                )
            )

            recorded_canonical_hash = (
                environment_result.get(
                    "canonical_result_sha256"
                )
            )

            add_check(
                checks,
                name=(
                    f"{platform_name}_canonical_"
                    "result_sha256_valid"
                ),
                passed=(
                    recorded_canonical_hash
                    == expected_canonical_hash
                ),
                expected=expected_canonical_hash,
                actual=recorded_canonical_hash,
            )

            (
                environment_hash_valid,
                recorded_environment_hash,
                expected_environment_hash,
            ) = verify_embedded_hash(
                document=environment_result,
                hash_field=(
                    "environment_result_sha256"
                ),
            )

            add_check(
                checks,
                name=(
                    f"{platform_name}_environment_"
                    "result_sha256_valid"
                ),
                passed=environment_hash_valid,
                expected=expected_environment_hash,
                actual=recorded_environment_hash,
            )

            platform_results[platform_name] = {
                "path": result_path.as_posix(),
                "file_sha256": sha256_file(
                    result_path
                ),
                "canonical_result_sha256": (
                    recorded_canonical_hash
                ),
                "environment_result_sha256": (
                    recorded_environment_hash
                ),
                "comparison_payload": {
                    field_name: (
                        comparison_payload.get(
                            field_name
                        )
                    )
                    for field_name in (
                        REQUIRED_COMPARISON_FIELDS
                    )
                },
            }

        all_platforms_present = (
            set(platform_results)
            == set(REQUIRED_PLATFORMS)
        )

        add_check(
            checks,
            name="all_required_platform_results_present",
            passed=all_platforms_present,
            expected=list(REQUIRED_PLATFORMS),
            actual=sorted(platform_results),
        )

        for field_name in REQUIRED_COMPARISON_FIELDS:
            observed_values = {
                platform_name: (
                    platform_results[
                        platform_name
                    ]["comparison_payload"].get(
                        field_name
                    )
                )
                for platform_name in (
                    REQUIRED_PLATFORMS
                )
                if platform_name
                in platform_results
            }

            unique_values = {
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for value in (
                    observed_values.values()
                )
            }

            values_match = (
                all_platforms_present
                and len(unique_values) == 1
            )

            add_check(
                checks,
                name=(
                    "environment_results_match:"
                    f"{field_name}"
                ),
                passed=values_match,
                expected=(
                    "identical value on ubuntu, "
                    "windows, and macos"
                ),
                actual=observed_values,
            )

        observed_canonical_hashes = {
            platform_name: (
                platform_results[
                    platform_name
                ]["canonical_result_sha256"]
            )
            for platform_name in REQUIRED_PLATFORMS
            if platform_name in platform_results
        }

        canonical_hashes_match = (
            all_platforms_present
            and len(
                set(
                    observed_canonical_hashes.values()
                )
            )
            == 1
        )

        add_check(
            checks,
            name=(
                "environment_results_canonical_"
                "sha256_match"
            ),
            passed=canonical_hashes_match,
            expected=(
                "identical canonical SHA-256 on "
                "ubuntu, windows, and macos"
            ),
            actual=observed_canonical_hashes,
        )

        common_canonical_hash = (
            next(
                iter(
                    observed_canonical_hashes.values()
                )
            )
            if canonical_hashes_match
            else None
        )

        add_check(
            checks,
            name=(
                "comparison_result_common_"
                "canonical_hash_matches"
            ),
            passed=(
                comparison_result.get(
                    "common_canonical_result_sha256"
                )
                == common_canonical_hash
            ),
            expected=common_canonical_hash,
            actual=comparison_result.get(
                "common_canonical_result_sha256"
            ),
        )

        stage380_result = load_json(
            STAGE380_RESULT_PATH
        )

        add_check(
            checks,
            name="stage380_result_is_object",
            passed=isinstance(
                stage380_result,
                dict,
            ),
            expected="object",
            actual=type(
                stage380_result
            ).__name__,
        )

        if not isinstance(
            stage380_result,
            dict,
        ):
            raise TypeError(
                "Stage380 result must be an object"
            )

        (
            stage380_hash_valid,
            recorded_stage380_hash,
            expected_stage380_hash,
        ) = verify_embedded_hash(
            document=stage380_result,
            hash_field="result_sha256",
        )

        add_check(
            checks,
            name="stage380_result_embedded_hash_valid",
            passed=stage380_hash_valid,
            expected=expected_stage380_hash,
            actual=recorded_stage380_hash,
        )

        observed_stage380_hashes = {
            platform_name: (
                platform_results[
                    platform_name
                ]["comparison_payload"].get(
                    "result_sha256"
                )
            )
            for platform_name in REQUIRED_PLATFORMS
            if platform_name in platform_results
        }

        stage380_binding_valid = (
            all_platforms_present
            and all(
                value == recorded_stage380_hash
                for value in (
                    observed_stage380_hashes.values()
                )
            )
        )

        add_check(
            checks,
            name=(
                "environment_results_bound_to_"
                "stage380_result"
            ),
            passed=stage380_binding_valid,
            expected=recorded_stage380_hash,
            actual=observed_stage380_hashes,
        )

        stage380_package_integrity_verified = (
            stage380_result.get(
                "package_integrity_verified"
            )
            is True
        )

        add_check(
            checks,
            name=(
                "stage380_package_integrity_"
                "verified"
            ),
            passed=(
                stage380_package_integrity_verified
            ),
            expected=True,
            actual=stage380_result.get(
                "package_integrity_verified"
            ),
        )

        upstream_formal_acceptance = (
            stage380_result.get(
                "formal_acceptance"
            )
            is True
            and stage380_result.get(
                "pipeline_completed"
            )
            is True
        )

        critical_failures = sorted(
            check["name"]
            for check in checks
            if (
                check["critical"]
                and not check["passed"]
            )
        )

        package_integrity_verified = (
            len(critical_failures) == 0
        )

        if not package_integrity_verified:
            decision = "fail_closed"
            verification_status = "invalid"

        elif upstream_formal_acceptance:
            decision = (
                "cross_platform_verification_"
                "package_ready"
            )
            verification_status = "verified"

        else:
            decision = (
                "cross_platform_reverification_"
                "verified_upstream_pending"
            )
            verification_status = (
                "verified_development_only"
            )

        formal_acceptance = (
            package_integrity_verified
            and upstream_formal_acceptance
        )

        result_without_hash: dict[str, Any] = {
            "stage": STAGE,
            "source_stage": SOURCE_STAGE,
            "verifier": VERIFIER_NAME,
            "execution_mode": "development",
            "development_only": True,
            "verification_mode": (
                "cross_platform_deterministic_offline"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "package_integrity_verified": (
                package_integrity_verified
            ),
            "cross_platform_reverification_verified": (
                package_integrity_verified
            ),
            "formal_independent_verification": (
                formal_acceptance
            ),
            "formal_acceptance": formal_acceptance,
            "pipeline_completed": formal_acceptance,
            "public_release_allowed": False,
            "verification_status": verification_status,
            "decision": decision,
            "upstream_state": {
                "stage380_result_path": (
                    STAGE380_RESULT_PATH.as_posix()
                ),
                "stage380_result_sha256": (
                    recorded_stage380_hash
                ),
                "stage380_package_integrity_verified": (
                    stage380_package_integrity_verified
                ),
                "stage380_formal_acceptance": (
                    stage380_result.get(
                        "formal_acceptance"
                    )
                ),
                "stage380_pipeline_completed": (
                    stage380_result.get(
                        "pipeline_completed"
                    )
                ),
                "upstream_formal_acceptance": (
                    upstream_formal_acceptance
                ),
            },
            "contract": {
                "path": CONTRACT_PATH.as_posix(),
                "sha256": actual_contract_hash,
                "sha256_record_path": (
                    CONTRACT_SHA256_PATH.as_posix()
                ),
            },
            "canonicalization_profile": {
                "path": (
                    CANONICALIZATION_PROFILE_PATH
                    .as_posix()
                ),
                "sha256": sha256_file(
                    CANONICALIZATION_PROFILE_PATH
                ),
            },
            "comparison_result": {
                "path": (
                    COMPARISON_RESULT_PATH
                    .as_posix()
                ),
                "file_sha256": sha256_file(
                    COMPARISON_RESULT_PATH
                ),
                "result_sha256": (
                    recorded_comparison_hash
                ),
                "common_canonical_result_sha256": (
                    comparison_result.get(
                        "common_canonical_result_sha256"
                    )
                ),
            },
            "required_platforms": list(
                REQUIRED_PLATFORMS
            ),
            "platform_result_count": len(
                platform_results
            ),
            "platform_results": {
                platform_name: (
                    platform_results[
                        platform_name
                    ]
                )
                for platform_name in sorted(
                    platform_results
                )
            },
            "same_input_same_output_verified": (
                package_integrity_verified
            ),
            "same_decision_verified": (
                package_integrity_verified
            ),
            "same_exit_code_verified": (
                package_integrity_verified
            ),
            "same_stage380_result_sha256_verified": (
                stage380_binding_valid
            ),
            "same_canonical_result_sha256_verified": (
                canonical_hashes_match
            ),
            "common_canonical_result_sha256": (
                common_canonical_hash
            ),
            "check_count": len(checks),
            "critical_failure_count": len(
                critical_failures
            ),
            "critical_failures": (
                critical_failures
            ),
            "checks": sorted(
                checks,
                key=lambda item: item["name"],
            ),
            "errors": errors,
            "deterministic_statement": (
                "The result contains no runtime timestamp, "
                "hostname, username, absolute path, "
                "temporary path, random value, or "
                "network-derived value."
            ),
            "scope_statement": (
                "Stage381 verifies deterministic "
                "cross-platform reproducibility. It does "
                "not independently upgrade unresolved "
                "Stage377, Stage378, Stage379, or Stage380 "
                "formal acceptance."
            ),
        }

        result = dict(result_without_hash)
        result["result_sha256"] = sha256_bytes(
            canonical_json_bytes(
                result_without_hash
            )
        )

        OUTPUT_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        OUTPUT_PATH.write_text(
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

        print(f"decision={decision}")
        print(
            "package_integrity_verified="
            f"{str(package_integrity_verified).lower()}"
        )
        print(
            "cross_platform_reverification_verified="
            f"{str(package_integrity_verified).lower()}"
        )
        print(
            "formal_independent_verification="
            f"{str(formal_acceptance).lower()}"
        )
        print(
            "critical_failure_count="
            f"{len(critical_failures)}"
        )
        print(
            "common_canonical_result_sha256="
            f"{common_canonical_hash}"
        )
        print(
            "result_sha256="
            f"{result['result_sha256']}"
        )
        print(f"result_path={OUTPUT_PATH}")

        return (
            0
            if package_integrity_verified
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
            "source_stage": SOURCE_STAGE,
            "verifier": VERIFIER_NAME,
            "execution_mode": "development",
            "development_only": True,
            "verification_mode": (
                "cross_platform_deterministic_offline"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "package_integrity_verified": False,
            "cross_platform_reverification_verified": False,
            "formal_independent_verification": False,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "verification_status": "execution_error",
            "decision": "fail_closed",
            "critical_failure_count": 1,
            "critical_failures": [
                "verifier_execution_error"
            ],
            "checks": sorted(
                checks,
                key=lambda item: item["name"],
            ),
            "errors": [
                f"{type(exc).__name__}: {exc}"
            ],
        }

        error_result = dict(
            error_result_without_hash
        )

        error_result["result_sha256"] = (
            sha256_bytes(
                canonical_json_bytes(
                    error_result_without_hash
                )
            )
        )

        OUTPUT_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        OUTPUT_PATH.write_text(
            json.dumps(
                error_result,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        print(
            "decision=fail_closed",
            file=sys.stderr,
        )
        print(
            f"error={type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        print(
            f"result_path={OUTPUT_PATH}",
            file=sys.stderr,
        )

        return 2


if __name__ == "__main__":
    sys.exit(main())
