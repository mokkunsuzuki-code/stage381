import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Tuple


ROOT = Path(__file__).resolve().parents[2]

DEVELOPMENT_GATE_SCRIPT = Path(
    "scripts/stage379_development_gate.py"
)

STAGE379_ENGINE_SCRIPT = Path(
    "scripts/stage379_scoped_total_verification_gate.py"
)

POLICY_PATH = Path(
    "development/stage379/"
    "stage379_verification_scope_policy.json"
)

POLICY_HASH_PATH = Path(
    "development/stage379/"
    "stage379_verification_scope_policy.sha256"
)

STAGE377_PATH = Path(
    "docs/timestamp-finalization/"
    "stage377_dual_timestamp_finalization_result.json"
)

STAGE378_PATH = Path(
    "docs/qkd/"
    "stage378_qkd_safety_metadata_binding_result.json"
)

DEVELOPMENT_POLICY_PATH = Path(
    ".stage379-development-policy.json"
)

DEVELOPMENT_GATE_RESULT_PATH = Path(
    "development/"
    "stage379_development_gate_result.json"
)

STAGE379_RESULT_PATH = Path(
    "development/stage379/"
    "stage379_scoped_total_verification_result.json"
)

CERTIFICATE_PATH = Path(
    "development/stage379/"
    "stage379_development_acceptance_certificate.json"
)


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> Dict[str, Any]:
    parsed = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(parsed, dict):
        raise AssertionError(f"JSON root is not an object: {path}")

    return parsed


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(data) + b"\n")


def verify_self_hash(
    path: Path,
    hash_field: str,
) -> bool:
    data = read_json(path)
    declared = data.get(hash_field)

    copied = dict(data)
    copied.pop(hash_field, None)

    recomputed = sha256_bytes(canonical_json(copied))

    return declared == recomputed


def copy_required_workspace(destination: Path) -> None:
    required_files = [
        DEVELOPMENT_GATE_SCRIPT,
        STAGE379_ENGINE_SCRIPT,
        POLICY_PATH,
        POLICY_HASH_PATH,
        STAGE377_PATH,
        STAGE378_PATH,
        DEVELOPMENT_POLICY_PATH,
    ]

    for relative_path in required_files:
        source = ROOT / relative_path

        if not source.is_file():
            raise AssertionError(
                f"Required source file missing: {source}"
            )

        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def run_script(
    workspace: Path,
    script: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, script.as_posix()],
        cwd=workspace,
        text=True,
        capture_output=True,
        check=False,
    )


def prepare_workspace() -> Tuple[
    tempfile.TemporaryDirectory[str],
    Path,
]:
    temporary_directory = tempfile.TemporaryDirectory(
        prefix="stage379-fail-closed-"
    )

    workspace = Path(temporary_directory.name)
    copy_required_workspace(workspace)

    return temporary_directory, workspace


def run_normal_development_case() -> None:
    temporary_directory, workspace = prepare_workspace()

    try:
        development_gate = run_script(
            workspace,
            DEVELOPMENT_GATE_SCRIPT,
        )

        assert development_gate.returncode == 0, (
            development_gate.stdout
            + development_gate.stderr
        )

        development_result = read_json(
            workspace / DEVELOPMENT_GATE_RESULT_PATH
        )

        assert (
            development_result.get("decision")
            == "development_only_upstream_pending"
        )

        assert (
            development_result
            .get("checks", {})
            .get("development_execution_allowed")
            is True
        )

        assert (
            development_result
            .get("checks", {})
            .get(
                "formal_promotion_requirements_satisfied"
            )
            is False
        )

        assert verify_self_hash(
            workspace / DEVELOPMENT_GATE_RESULT_PATH,
            "result_sha256",
        )

        stage379_run = run_script(
            workspace,
            STAGE379_ENGINE_SCRIPT,
        )

        assert stage379_run.returncode == 0, (
            stage379_run.stdout
            + stage379_run.stderr
        )

        result = read_json(
            workspace / STAGE379_RESULT_PATH
        )

        certificate = read_json(
            workspace / CERTIFICATE_PATH
        )

        assert (
            result.get("decision")
            == "development_verification_pending_upstream"
        )

        assert (
            result
            .get("checks", {})
            .get("critical_integrity_valid")
            is True
        )

        assert (
            result
            .get("checks", {})
            .get(
                "formal_acceptance_requirements_satisfied"
            )
            is False
        )

        assert result.get("formal_acceptance") is False
        assert result.get("certificate_issued") is False
        assert result.get("pipeline_completed") is False
        assert result.get("public_release_allowed") is False

        assert (
            certificate.get("certificate_type")
            == "development_non_acceptance_certificate"
        )

        assert certificate.get("formal_certificate") is False
        assert certificate.get("formal_acceptance") is False
        assert certificate.get("pipeline_completed") is False

        assert (
            certificate.get("stage379_result_sha256")
            == result.get("result_sha256")
        )

        assert verify_self_hash(
            workspace / STAGE379_RESULT_PATH,
            "result_sha256",
        )

        assert verify_self_hash(
            workspace / CERTIFICATE_PATH,
            "certificate_sha256",
        )
    finally:
        temporary_directory.cleanup()


def run_stage377_tamper_case() -> None:
    temporary_directory, workspace = prepare_workspace()

    try:
        path = workspace / STAGE377_PATH
        data = read_json(path)

        data["verified_proof_count"] = 2
        write_json(path, data)

        development_gate = run_script(
            workspace,
            DEVELOPMENT_GATE_SCRIPT,
        )

        assert development_gate.returncode != 0

        result = read_json(
            workspace / DEVELOPMENT_GATE_RESULT_PATH
        )

        assert result.get("decision") == "block"
        assert (
            "stage377_result_hash_invalid"
            in result.get("reasons", [])
        )
    finally:
        temporary_directory.cleanup()


def run_stage378_tamper_case() -> None:
    temporary_directory, workspace = prepare_workspace()

    try:
        path = workspace / STAGE378_PATH
        data = read_json(path)

        data["qkd_metadata_bound"] = True
        write_json(path, data)

        development_gate = run_script(
            workspace,
            DEVELOPMENT_GATE_SCRIPT,
        )

        assert development_gate.returncode != 0

        result = read_json(
            workspace / DEVELOPMENT_GATE_RESULT_PATH
        )

        assert result.get("decision") == "block"
        assert (
            "stage378_result_hash_invalid"
            in result.get("reasons", [])
        )
    finally:
        temporary_directory.cleanup()


def run_policy_tamper_case() -> None:
    temporary_directory, workspace = prepare_workspace()

    try:
        development_gate = run_script(
            workspace,
            DEVELOPMENT_GATE_SCRIPT,
        )

        assert development_gate.returncode == 0

        path = workspace / POLICY_PATH
        policy = read_json(path)

        policy["scope_reduction_allowed"] = True
        write_json(path, policy)

        stage379_run = run_script(
            workspace,
            STAGE379_ENGINE_SCRIPT,
        )

        assert stage379_run.returncode != 0

        result = read_json(
            workspace / STAGE379_RESULT_PATH
        )

        assert result.get("decision") == "block"
        assert (
            "verification_scope_policy_hash_invalid"
            in result.get("reasons", [])
        )
    finally:
        temporary_directory.cleanup()


def run_git_metadata_case() -> None:
    temporary_directory, workspace = prepare_workspace()

    try:
        (workspace / ".git").mkdir()

        development_gate = run_script(
            workspace,
            DEVELOPMENT_GATE_SCRIPT,
        )

        assert development_gate.returncode != 0

        result = read_json(
            workspace / DEVELOPMENT_GATE_RESULT_PATH
        )

        assert result.get("decision") == "block"
        assert (
            "git_metadata_present_in_development_workspace"
            in result.get("reasons", [])
        )
    finally:
        temporary_directory.cleanup()


def main() -> int:
    tests = [
        (
            "normal_development_non_acceptance",
            run_normal_development_case,
        ),
        (
            "stage377_tamper_detection",
            run_stage377_tamper_case,
        ),
        (
            "stage378_tamper_detection",
            run_stage378_tamper_case,
        ),
        (
            "scope_policy_tamper_detection",
            run_policy_tamper_case,
        ),
        (
            "git_metadata_rejection",
            run_git_metadata_case,
        ),
    ]

    failures = []

    for name, test_function in tests:
        try:
            test_function()
        except Exception as error:
            failures.append((name, str(error)))
            print(f"FAIL: {name}")
            print(f"  {error}")
        else:
            print(f"PASS: {name}")

    print("")
    print(f"tests_total: {len(tests)}")
    print(f"tests_passed: {len(tests) - len(failures)}")
    print(f"tests_failed: {len(failures)}")
    print(
        "fail_closed_regression_valid: "
        f"{len(failures) == 0}"
    )

    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
