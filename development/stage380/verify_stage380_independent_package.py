#!/usr/bin/env python3
"""
Stage380
Independent Verification Package Contract
& Deterministic Offline Core Verifier

Development-only verifier.

This program:
- performs no network communication;
- verifies the Stage380 contract and its SHA-256 record;
- verifies all required input files;
- verifies the Stage379 development snapshot artifact hashes;
- evaluates upstream Stage377/Stage378/Stage379 acceptance state;
- fails closed on integrity or policy violations;
- produces deterministic JSON output.

Exit codes:
  0 = package integrity verified
  1 = verification failed closed
  2 = verifier execution/configuration error
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


STAGE = 380
VERIFIER_NAME = "Deterministic Offline Core Verifier"
CONTRACT_PATH = Path(
    "development/stage380/"
    "stage380_independent_verification_package_contract.json"
)
CONTRACT_SHA256_PATH = Path(
    "development/stage380/"
    "stage380_independent_verification_package_contract.sha256"
)
OUTPUT_PATH = Path(
    "development/stage380/"
    "stage380_independent_verification_result.json"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def result_sha256(result_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(result_without_hash)
    ).hexdigest()


def recursive_find(data: Any, key: str) -> list[Any]:
    values: list[Any] = []

    if isinstance(data, dict):
        for current_key, current_value in data.items():
            if current_key == key:
                values.append(current_value)

            values.extend(recursive_find(current_value, key))

    elif isinstance(data, list):
        for item in data:
            values.extend(recursive_find(item, key))

    return values


def first_value(data: Any, key: str, default: Any = None) -> Any:
    values = recursive_find(data, key)

    if not values:
        return default

    return values[0]


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


def parse_sha256_record(path: Path) -> tuple[str, str]:
    line = path.read_text(encoding="utf-8").strip()

    parts = line.split(maxsplit=1)

    if len(parts) != 2:
        raise ValueError("invalid SHA-256 record format")

    expected_hash = parts[0].strip().lower()
    recorded_path = parts[1].strip()

    if recorded_path.startswith("*"):
        recorded_path = recorded_path[1:]

    if len(expected_hash) != 64:
        raise ValueError("SHA-256 value must contain 64 hexadecimal characters")

    try:
        int(expected_hash, 16)
    except ValueError as exc:
        raise ValueError("SHA-256 value is not hexadecimal") from exc

    return expected_hash, recorded_path


def verify_snapshot_artifacts(
    snapshot_manifest: dict[str, Any],
    checks: list[dict[str, Any]],
) -> tuple[int, int]:
    artifacts = snapshot_manifest.get("artifacts", [])

    if not isinstance(artifacts, list):
        add_check(
            checks,
            name="stage379_snapshot_artifacts_is_list",
            passed=False,
            expected="list",
            actual=type(artifacts).__name__,
        )
        return 0, 0

    valid_count = 0
    invalid_count = 0
    seen_paths: set[str] = set()

    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            add_check(
                checks,
                name=f"snapshot_artifact_{index}_is_object",
                passed=False,
                expected="object",
                actual=type(artifact).__name__,
            )
            invalid_count += 1
            continue

        artifact_path_value = (
            artifact.get("path")
            or artifact.get("artifact_path")
            or artifact.get("file")
        )
        expected_hash = (
            artifact.get("sha256")
            or artifact.get("artifact_sha256")
            or artifact.get("hash")
        )
        expected_size = (
            artifact.get("size_bytes")
            if "size_bytes" in artifact
            else artifact.get("size")
        )

        if not isinstance(artifact_path_value, str) or not artifact_path_value:
            add_check(
                checks,
                name=f"snapshot_artifact_{index}_path_present",
                passed=False,
                expected="non-empty string",
                actual=artifact_path_value,
            )
            invalid_count += 1
            continue

        artifact_path = Path(artifact_path_value)

        duplicate = artifact_path_value in seen_paths
        seen_paths.add(artifact_path_value)

        exists = artifact_path.is_file()

        actual_hash = sha256_file(artifact_path) if exists else None
        actual_size = artifact_path.stat().st_size if exists else None

        hash_valid = (
            isinstance(expected_hash, str)
            and len(expected_hash) == 64
            and actual_hash == expected_hash.lower()
        )

        size_required = expected_size is not None
        size_valid = (
            not size_required
            or (
                isinstance(expected_size, int)
                and actual_size == expected_size
            )
        )

        artifact_valid = (
            exists
            and not duplicate
            and hash_valid
            and size_valid
        )

        add_check(
            checks,
            name=f"snapshot_artifact_{index}_valid",
            passed=artifact_valid,
            expected={
                "exists": True,
                "duplicate": False,
                "sha256": expected_hash,
                "size_bytes": expected_size,
            },
            actual={
                "path": artifact_path_value,
                "exists": exists,
                "duplicate": duplicate,
                "sha256": actual_hash,
                "size_bytes": actual_size,
            },
        )

        if artifact_valid:
            valid_count += 1
        else:
            invalid_count += 1

    return valid_count, invalid_count


def main() -> int:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        add_check(
            checks,
            name="contract_file_present",
            passed=CONTRACT_PATH.is_file(),
            expected=True,
            actual=CONTRACT_PATH.is_file(),
        )

        add_check(
            checks,
            name="contract_sha256_record_present",
            passed=CONTRACT_SHA256_PATH.is_file(),
            expected=True,
            actual=CONTRACT_SHA256_PATH.is_file(),
        )

        if not CONTRACT_PATH.is_file() or not CONTRACT_SHA256_PATH.is_file():
            raise FileNotFoundError(
                "Stage380 contract or SHA-256 record is missing"
            )

        contract = load_json(CONTRACT_PATH)

        expected_contract_hash, recorded_contract_path = (
            parse_sha256_record(CONTRACT_SHA256_PATH)
        )
        actual_contract_hash = sha256_file(CONTRACT_PATH)

        add_check(
            checks,
            name="contract_sha256_valid",
            passed=actual_contract_hash == expected_contract_hash,
            expected=expected_contract_hash,
            actual=actual_contract_hash,
        )

        add_check(
            checks,
            name="contract_sha256_record_path_valid",
            passed=recorded_contract_path == str(CONTRACT_PATH),
            expected=str(CONTRACT_PATH),
            actual=recorded_contract_path,
        )

        contract_requirements = {
            "stage": STAGE,
            "development_only": True,
            "formal_independent_verification": False,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "source_stage": 379,
            "verification_mode": "deterministic_offline",
            "package_locked": True,
            "scope_reduction_allowed": False,
            "fail_closed": True,
        }

        for key, expected in contract_requirements.items():
            actual = contract.get(key)

            add_check(
                checks,
                name=f"contract_{key}",
                passed=actual == expected,
                expected=expected,
                actual=actual,
            )

        deterministic_output = contract.get("deterministic_output", {})

        if not isinstance(deterministic_output, dict):
            deterministic_output = {}

        for key in (
            "same_input_same_output",
            "same_hash_same_decision",
            "offline_only",
        ):
            actual = deterministic_output.get(key)

            add_check(
                checks,
                name=f"deterministic_output_{key}",
                passed=actual is True,
                expected=True,
                actual=actual,
            )

        required_inputs = contract.get("required_inputs", [])

        add_check(
            checks,
            name="required_inputs_is_nonempty_list",
            passed=(
                isinstance(required_inputs, list)
                and len(required_inputs) > 0
                and all(isinstance(item, str) for item in required_inputs)
            ),
            expected="non-empty list of paths",
            actual=required_inputs,
        )

        required_input_hashes: dict[str, str | None] = {}

        if isinstance(required_inputs, list):
            for input_path_value in required_inputs:
                if not isinstance(input_path_value, str):
                    continue

                input_path = Path(input_path_value)
                exists = input_path.is_file()
                input_hash = sha256_file(input_path) if exists else None

                required_input_hashes[input_path_value] = input_hash

                add_check(
                    checks,
                    name=f"required_input_present:{input_path_value}",
                    passed=exists,
                    expected=True,
                    actual=exists,
                )

        snapshot_manifest_path = Path(
            contract.get(
                "source_snapshot_manifest",
                "development/stage379/"
                "stage379_development_snapshot_manifest.json",
            )
        )

        add_check(
            checks,
            name="source_snapshot_manifest_present",
            passed=snapshot_manifest_path.is_file(),
            expected=True,
            actual=snapshot_manifest_path.is_file(),
        )

        snapshot_valid_artifacts = 0
        snapshot_invalid_artifacts = 0

        if snapshot_manifest_path.is_file():
            snapshot_manifest = load_json(snapshot_manifest_path)

            add_check(
                checks,
                name="stage379_snapshot_development_only",
                passed=(
                    first_value(
                        snapshot_manifest,
                        "development_only",
                        None,
                    )
                    is True
                ),
                expected=True,
                actual=first_value(
                    snapshot_manifest,
                    "development_only",
                    None,
                ),
            )

            snapshot_valid_artifacts, snapshot_invalid_artifacts = (
                verify_snapshot_artifacts(snapshot_manifest, checks)
            )
        else:
            snapshot_manifest = {}

        stage379_result_path = Path(
            "development/stage379/"
            "stage379_scoped_total_verification_result.json"
        )
        stage379_certificate_path = Path(
            "development/stage379/"
            "stage379_development_acceptance_certificate.json"
        )
        stage377_result_path = Path(
            "docs/timestamp-finalization/"
            "stage377_dual_timestamp_finalization_result.json"
        )
        stage378_result_path = Path(
            "docs/qkd/"
            "stage378_qkd_safety_metadata_binding_result.json"
        )

        stage379_result = (
            load_json(stage379_result_path)
            if stage379_result_path.is_file()
            else {}
        )
        stage379_certificate = (
            load_json(stage379_certificate_path)
            if stage379_certificate_path.is_file()
            else {}
        )
        stage377_result = (
            load_json(stage377_result_path)
            if stage377_result_path.is_file()
            else {}
        )
        stage378_result = (
            load_json(stage378_result_path)
            if stage378_result_path.is_file()
            else {}
        )

        stage377_verified_proof_count = first_value(
            stage377_result,
            "verified_proof_count",
            None,
        )
        stage377_effective_final_acceptance = first_value(
            stage377_result,
            "effective_final_acceptance",
            None,
        )
        stage378_qkd_metadata_bound = first_value(
            stage378_result,
            "qkd_metadata_bound",
            None,
        )
        stage379_formal_acceptance = first_value(
            stage379_result,
            "formal_acceptance",
            None,
        )
        stage379_pipeline_completed = first_value(
            stage379_result,
            "pipeline_completed",
            None,
        )
        stage379_critical_integrity_valid = first_value(
            stage379_result,
            "critical_integrity_valid",
            None,
        )

        certificate_type = first_value(
            stage379_certificate,
            "certificate_type",
            None,
        )

        add_check(
            checks,
            name="stage377_verified_proof_count_observed",
            passed=isinstance(stage377_verified_proof_count, int),
            expected="integer",
            actual=stage377_verified_proof_count,
            critical=False,
        )

        add_check(
            checks,
            name="stage377_effective_final_acceptance_observed",
            passed=isinstance(
                stage377_effective_final_acceptance,
                bool,
            ),
            expected="boolean",
            actual=stage377_effective_final_acceptance,
            critical=False,
        )

        add_check(
            checks,
            name="stage378_qkd_metadata_bound_observed",
            passed=isinstance(stage378_qkd_metadata_bound, bool),
            expected="boolean",
            actual=stage378_qkd_metadata_bound,
            critical=False,
        )

        add_check(
            checks,
            name="stage379_formal_acceptance_observed",
            passed=isinstance(stage379_formal_acceptance, bool),
            expected="boolean",
            actual=stage379_formal_acceptance,
            critical=False,
        )

        add_check(
            checks,
            name="stage379_pipeline_completed_observed",
            passed=isinstance(stage379_pipeline_completed, bool),
            expected="boolean",
            actual=stage379_pipeline_completed,
            critical=False,
        )

        add_check(
            checks,
            name="stage379_critical_integrity_valid",
            passed=stage379_critical_integrity_valid is True,
            expected=True,
            actual=stage379_critical_integrity_valid,
        )

        add_check(
            checks,
            name="stage379_certificate_is_development_non_acceptance",
            passed=(
                certificate_type
                == "development_non_acceptance_certificate"
            ),
            expected="development_non_acceptance_certificate",
            actual=certificate_type,
        )

        formal_acceptance_ready = (
            stage377_verified_proof_count == 2
            and stage377_effective_final_acceptance is True
            and stage378_qkd_metadata_bound is True
            and stage379_formal_acceptance is True
            and stage379_pipeline_completed is True
        )

        critical_failures = [
            check["name"]
            for check in checks
            if check["critical"] and not check["passed"]
        ]

        package_integrity_verified = len(critical_failures) == 0

        if not package_integrity_verified:
            decision = "fail_closed"
            verification_status = "invalid"
        elif formal_acceptance_ready:
            decision = "independent_verification_package_ready"
            verification_status = "verified"
        else:
            decision = "development_package_verified_upstream_pending"
            verification_status = "verified_development_only"

        result_without_hash: dict[str, Any] = {
            "stage": STAGE,
            "verifier": VERIFIER_NAME,
            "contract_name": contract.get("contract_name"),
            "contract_version": contract.get("contract_version"),
            "execution_mode": "development",
            "verification_mode": "deterministic_offline",
            "network_access_required": False,
            "fail_closed": True,
            "package_integrity_verified": package_integrity_verified,
            "formal_independent_verification": (
                package_integrity_verified and formal_acceptance_ready
            ),
            "formal_acceptance": (
                package_integrity_verified and formal_acceptance_ready
            ),
            "pipeline_completed": (
                package_integrity_verified and formal_acceptance_ready
            ),
            "public_release_allowed": False,
            "verification_status": verification_status,
            "decision": decision,
            "upstream_state": {
                "stage377_verified_proof_count": (
                    stage377_verified_proof_count
                ),
                "stage377_effective_final_acceptance": (
                    stage377_effective_final_acceptance
                ),
                "stage378_qkd_metadata_bound": (
                    stage378_qkd_metadata_bound
                ),
                "stage379_formal_acceptance": (
                    stage379_formal_acceptance
                ),
                "stage379_pipeline_completed": (
                    stage379_pipeline_completed
                ),
                "formal_acceptance_ready": formal_acceptance_ready,
            },
            "contract": {
                "path": str(CONTRACT_PATH),
                "sha256": actual_contract_hash,
                "sha256_record_path": str(CONTRACT_SHA256_PATH),
            },
            "source_snapshot": {
                "path": str(snapshot_manifest_path),
                "sha256": (
                    sha256_file(snapshot_manifest_path)
                    if snapshot_manifest_path.is_file()
                    else None
                ),
                "valid_artifact_count": snapshot_valid_artifacts,
                "invalid_artifact_count": snapshot_invalid_artifacts,
            },
            "required_input_sha256": dict(
                sorted(required_input_hashes.items())
            ),
            "check_count": len(checks),
            "critical_failure_count": len(critical_failures),
            "critical_failures": sorted(critical_failures),
            "checks": sorted(checks, key=lambda item: item["name"]),
            "errors": errors,
            "deterministic_statement": (
                "The result contains no runtime timestamp, random value, "
                "hostname, username, absolute path, or network-derived value."
            ),
        }

        result = dict(result_without_hash)
        result["result_sha256"] = result_sha256(result_without_hash)

        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT_PATH.write_text(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        print(f"decision={decision}")
        print(
            "package_integrity_verified="
            f"{str(package_integrity_verified).lower()}"
        )
        print(
            "formal_independent_verification="
            f"{str(result['formal_independent_verification']).lower()}"
        )
        print(f"critical_failure_count={len(critical_failures)}")
        print(f"result_sha256={result['result_sha256']}")
        print(f"result_path={OUTPUT_PATH}")

        return 0 if package_integrity_verified else 1

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
            "verifier": VERIFIER_NAME,
            "execution_mode": "development",
            "verification_mode": "deterministic_offline",
            "network_access_required": False,
            "fail_closed": True,
            "package_integrity_verified": False,
            "formal_independent_verification": False,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "verification_status": "execution_error",
            "decision": "fail_closed",
            "critical_failure_count": 1,
            "critical_failures": ["verifier_execution_error"],
            "checks": sorted(checks, key=lambda item: item["name"]),
            "errors": [f"{type(exc).__name__}: {exc}"],
        }

        error_result = dict(error_result_without_hash)
        error_result["result_sha256"] = result_sha256(
            error_result_without_hash
        )

        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT_PATH.write_text(
            json.dumps(
                error_result,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        print("decision=fail_closed", file=sys.stderr)
        print(
            f"error={type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        print(f"result_path={OUTPUT_PATH}", file=sys.stderr)

        return 2


if __name__ == "__main__":
    sys.exit(main())
