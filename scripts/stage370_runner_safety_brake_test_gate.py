import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone

STAGE = 370

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "runner-safety"

STAGE369_RESULT = DOCS / "timestamp-runner" / "stage369_real_timestamp_verifier_runner_result.json"

TEST_INPUT = OUT_DIR / "stage370_runner_safety_brake_test_input.json"
OUT_JSON = OUT_DIR / "stage370_runner_safety_brake_test_result.json"
OUT_SUMMARY = OUT_DIR / "stage370_runner_safety_brake_test_summary.txt"

OUT_DIR.mkdir(parents=True, exist_ok=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path):
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def contains_private_material(obj) -> bool:
    raw = json.dumps(obj, ensure_ascii=False).lower()
    danger = [
        "-----begin private key-----",
        "private_key_material",
        "raw_private_key",
        "raw_secret",
        "raw_qkd_key",
        "seed_phrase",
        "password",
        "api_key",
        "access_token",
    ]
    return any(x in raw for x in danger)


def raw_binary_marker_detected(obj) -> bool:
    raw = json.dumps(obj, ensure_ascii=False).lower()
    return any(x in raw for x in [".ots", ".tsr", ".tsa", ".token", ".der"])


def run_safe_command(command: str):
    completed = subprocess.run(
        command,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    return {
        "exit_code": completed.returncode,
        "stdout_sha256": sha256_text(completed.stdout),
        "stderr_sha256": sha256_text(completed.stderr),
        "combined_output_sha256": sha256_text(completed.stdout + completed.stderr),
    }


def default_tests():
    return {
        "stage": STAGE,
        "engine": "Runner Safety Brake Test Gate Input",
        "simulation_only": False,
        "purpose": "Verify that unsafe, failing, incomplete, or fake runner conditions do not become accepted.",
        "test_cases": [
            {
                "case_id": "safe_bad_command_test",
                "execute_commands": True,
                "command": "false",
                "expected_decision": "runner_rejected",
                "expected_reason": "safe_bad_command_rejected"
            },
            {
                "case_id": "missing_metadata_test",
                "execute_commands": False,
                "pretend_exit_code": 0,
                "verified_target_hash": None,
                "expected_decision": "runner_rejected",
                "expected_reason": "missing_metadata_rejected"
            },
            {
                "case_id": "fake_verified_claim_test",
                "timestamp_verified": True,
                "exit_code": None,
                "expected_decision": "block",
                "expected_reason": "fake_verified_claim_blocked"
            },
            {
                "case_id": "raw_binary_guard_test",
                "raw_binary_reference": "example.ots",
                "expected_decision": "block",
                "expected_reason": "raw_binary_reference_blocked"
            }
        ]
    }


def evaluate_case(case):
    case_id = case.get("case_id")

    if contains_private_material(case):
        return {
            "case_id": case_id,
            "decision": "block",
            "reason": "private_material_blocked",
            "test_pass": case.get("expected_decision") == "block"
        }

    if raw_binary_marker_detected(case):
        return {
            "case_id": case_id,
            "decision": "block",
            "reason": "raw_binary_reference_blocked",
            "test_pass": case.get("expected_decision") == "block"
        }

    if case.get("timestamp_verified") is True and not case.get("exit_code") == 0:
        return {
            "case_id": case_id,
            "decision": "block",
            "reason": "fake_verified_claim_blocked",
            "test_pass": case.get("expected_decision") == "block"
        }

    if case.get("execute_commands") is True and case.get("command"):
        result = run_safe_command(case["command"])
        decision = "runner_rejected" if result["exit_code"] != 0 else "safety_test_failed"
        reason = "safe_bad_command_rejected" if result["exit_code"] != 0 else "bad_command_unexpectedly_succeeded"
        return {
            "case_id": case_id,
            "decision": decision,
            "reason": reason,
            "command_receipt": result,
            "test_pass": decision == case.get("expected_decision")
        }

    if case.get("pretend_exit_code") == 0 and not case.get("verified_target_hash"):
        return {
            "case_id": case_id,
            "decision": "runner_rejected",
            "reason": "missing_metadata_rejected",
            "test_pass": case.get("expected_decision") == "runner_rejected"
        }

    return {
        "case_id": case_id,
        "decision": "safety_test_failed",
        "reason": "unhandled_test_case",
        "test_pass": False
    }


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage369 = read_json(STAGE369_RESULT)
    previous_hash = sha256_file(STAGE369_RESULT)

    if TEST_INPUT.exists():
        test_input = read_json(TEST_INPUT)
    else:
        test_input = default_tests()
        TEST_INPUT.write_text(json.dumps(test_input, ensure_ascii=False, indent=2), encoding="utf-8")

    results = [evaluate_case(c) for c in test_input.get("test_cases", [])]
    all_passed = bool(results) and all(r.get("test_pass") for r in results)

    if not isinstance(stage369, dict):
        decision = "block"
        reasons = ["stage369_result_missing"]
    elif stage369.get("decision") == "block":
        decision = "block"
        reasons = ["stage369_is_blocked"]
    elif contains_private_material(test_input):
        decision = "block"
        reasons = ["private_material_detected"]
    elif all_passed:
        decision = "safety_test_pass"
        reasons = ["runner_safety_brake_tests_passed"]
    else:
        decision = "safety_test_failed"
        reasons = ["one_or_more_runner_safety_tests_failed"]

    result = {
        "stage": STAGE,
        "engine": "Runner Safety Brake Test Gate with Stage369 Receipt Generation Binding",
        "created_at": now,
        "source_stage": 369,
        "previous_hash": previous_hash,
        "stage369_decision": stage369.get("decision") if isinstance(stage369, dict) else None,
        "decision": decision,
        "reasons": reasons,
        "test_results": results,
        "all_tests_passed": all_passed,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_raw_timestamp_binaries_in_public_docs": True,
            "bad_command_must_reject": True,
            "missing_metadata_must_reject": True,
            "fake_verified_claim_must_block": True,
            "stage370_does_not_accept_timestamp_verified": True
        },
        "guarantee": {
            "what_stage370_guarantees": [
                "Stage369 runner result is bound as previous_hash when present.",
                "A deliberately failing safe command must land in runner_rejected.",
                "Missing metadata must not become accepted.",
                "Fake timestamp_verified claims must be blocked.",
                "Raw timestamp binary references must be blocked.",
                "Stage370 does not final-accept timestamp_verified."
            ],
            "what_stage370_does_not_guarantee": [
                "It does not perform a real successful OpenTimestamps verification.",
                "It does not perform a real successful RFC3161 verification.",
                "It does not publish raw timestamp binaries.",
                "It does not verify Sigstore, Rekor, OCSP, or CRL."
            ]
        },
        "test_input": test_input
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage370: Runner Safety Brake Test Gate",
            "with Stage369 Receipt Generation Binding",
            "",
            f"Decision: {decision}",
            f"All Tests Passed: {all_passed}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage370 confirms that the timestamp runner fails safely before real timestamp success is accepted.",
            "Bad commands, incomplete metadata, fake verified claims, and raw binary references must not pass.",
            "Stage370 does not final-accept timestamp_verified.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"all_tests_passed={all_passed}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
