import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone

STAGE = 371

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "timestamp-first-receipt"

STAGE370_RESULT = DOCS / "runner-safety" / "stage370_runner_safety_brake_test_result.json"
STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"

INPUT_JSON = OUT_DIR / "stage371_real_timestamp_first_receipt_input.json"
OUT_JSON = OUT_DIR / "stage371_real_timestamp_first_receipt_result.json"
OUT_SUMMARY = OUT_DIR / "stage371_real_timestamp_first_receipt_summary.txt"

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


def run_command(command: str):
    try:
        completed = subprocess.run(
            command,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        return {
            "exit_code": completed.returncode,
            "stdout_sha256": sha256_text(completed.stdout),
            "stderr_sha256": sha256_text(completed.stderr),
            "combined_output_sha256": sha256_text(completed.stdout + completed.stderr),
        }
    except Exception as e:
        return {
            "exit_code": 999,
            "stdout_sha256": sha256_text(""),
            "stderr_sha256": sha256_text(str(e)),
            "combined_output_sha256": sha256_text(str(e)),
            "error": str(e),
        }


def default_input(stage360_target_hash):
    return {
        "stage": STAGE,
        "engine": "Real Timestamp First Successful Receipt Input",
        "target_source_stage": 360,
        "target_hash": stage360_target_hash,
        "receipt_mode": "metadata_only_no_raw_timestamp_binaries",
        "execute_commands": False,
        "opentimestamps_first_receipt": {
            "enabled": True,
            "command": None,
            "stamped_file_sha256": None,
            "ots_file_sha256": None,
            "verified_target_hash": None,
            "ots_verified": False
        },
        "rfc3161_first_receipt": {
            "enabled": True,
            "command": None,
            "original_file_sha256": None,
            "timestamp_token_sha256": None,
            "message_imprint_sha256": None,
            "tsa_certificate_fingerprint": None,
            "verified_target_hash": None,
            "rfc3161_verified": False
        },
        "timestamp_verified": False,
        "note": "Default input. Stage371 can generate first_receipt_generated only when real verifier command output exists, exit_code=0, and verified_target_hash matches Stage360."
    }


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage370 = read_json(STAGE370_RESULT)
    stage360 = read_json(STAGE360_RESULT)

    previous_hash = sha256_file(STAGE370_RESULT)

    stage360_target_hash = None
    if isinstance(stage360, dict):
        stage360_target_hash = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("stage359_result_sha256")
            or stage360.get("result_sha256")
        )

    if INPUT_JSON.exists():
        input_data = read_json(INPUT_JSON)
    else:
        input_data = default_input(stage360_target_hash)
        INPUT_JSON.write_text(json.dumps(input_data, ensure_ascii=False, indent=2), encoding="utf-8")

    ots = input_data.get("opentimestamps_first_receipt", {})
    rfc3161 = input_data.get("rfc3161_first_receipt", {})

    target_hash = input_data.get("target_hash")
    target_hash_matches_stage360 = bool(stage360_target_hash and target_hash and target_hash == stage360_target_hash)

    execute = input_data.get("execute_commands") is True

    ots_command_result = None
    rfc3161_command_result = None

    if execute and ots.get("enabled") and ots.get("command"):
        ots_command_result = run_command(ots.get("command"))

    if execute and rfc3161.get("enabled") and rfc3161.get("command"):
        rfc3161_command_result = run_command(rfc3161.get("command"))

    ots_first_receipt_ready = bool(
        ots_command_result
        and ots_command_result.get("exit_code") == 0
        and ots.get("stamped_file_sha256")
        and ots.get("ots_file_sha256")
        and ots.get("verified_target_hash") == stage360_target_hash
        and ots.get("ots_verified") is True
    )

    rfc3161_first_receipt_ready = bool(
        rfc3161_command_result
        and rfc3161_command_result.get("exit_code") == 0
        and rfc3161.get("original_file_sha256")
        and rfc3161.get("timestamp_token_sha256")
        and rfc3161.get("message_imprint_sha256")
        and rfc3161.get("tsa_certificate_fingerprint")
        and rfc3161.get("verified_target_hash") == stage360_target_hash
        and rfc3161.get("rfc3161_verified") is True
    )

    checks = {
        "stage370_result_present": stage370 is not None,
        "stage370_previous_hash_bound": previous_hash is not None,
        "stage370_safety_test_pass": isinstance(stage370, dict) and stage370.get("decision") == "safety_test_pass",
        "stage370_all_tests_passed": isinstance(stage370, dict) and stage370.get("all_tests_passed") is True,
        "stage360_result_present": stage360 is not None,
        "stage360_target_hash_present": stage360_target_hash is not None,
        "input_present": input_data is not None,
        "target_hash_present": target_hash is not None,
        "target_hash_matches_stage360": target_hash_matches_stage360,
        "execute_commands": execute,
        "ots_command_supplied": bool(ots.get("command")),
        "rfc3161_command_supplied": bool(rfc3161.get("command")),
        "ots_first_receipt_ready": ots_first_receipt_ready,
        "rfc3161_first_receipt_ready": rfc3161_first_receipt_ready,
        "timestamp_verified_claim": input_data.get("timestamp_verified") is True,
        "private_material_detected": contains_private_material(input_data),
        "raw_binary_marker_detected": raw_binary_marker_detected(input_data)
    }

    decision = "first_receipt_pending"
    receipt_status = "not_generated"
    reasons = []

    if not checks["stage370_result_present"]:
        decision = "block"
        reasons.append("stage370_result_missing")

    elif not checks["stage370_safety_test_pass"] or not checks["stage370_all_tests_passed"]:
        decision = "block"
        reasons.append("stage370_safety_brake_not_passed")

    elif not checks["stage360_result_present"]:
        decision = "block"
        reasons.append("stage360_result_missing")

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["raw_binary_marker_detected"]:
        decision = "block"
        reasons.append("raw_timestamp_binary_marker_detected_in_public_input")

    elif checks["timestamp_verified_claim"] and not ots_first_receipt_ready and not rfc3161_first_receipt_ready:
        decision = "block"
        reasons.append("fake_timestamp_verified_claim_detected")

    elif not checks["target_hash_present"]:
        decision = "first_receipt_pending"
        reasons.append("target_hash_missing")

    elif not checks["target_hash_matches_stage360"]:
        decision = "first_receipt_rejected"
        reasons.append("target_hash_mismatch")

    elif not execute:
        decision = "first_receipt_pending"
        reasons.append("execute_commands_false")

    elif not checks["ots_command_supplied"] and not checks["rfc3161_command_supplied"]:
        decision = "first_receipt_pending"
        reasons.append("real_verifier_command_missing")

    elif ots_command_result and ots_command_result.get("exit_code") != 0:
        decision = "first_receipt_rejected"
        receipt_status = "command_failed"
        reasons.append("opentimestamps_command_failed")

    elif rfc3161_command_result and rfc3161_command_result.get("exit_code") != 0:
        decision = "first_receipt_rejected"
        receipt_status = "command_failed"
        reasons.append("rfc3161_command_failed")

    elif ots_first_receipt_ready:
        decision = "first_receipt_generated"
        receipt_status = "opentimestamps_first_receipt_generated"
        reasons.append("opentimestamps_first_successful_receipt_generated")

    elif rfc3161_first_receipt_ready:
        decision = "first_receipt_generated"
        receipt_status = "rfc3161_first_receipt_generated"
        reasons.append("rfc3161_first_successful_receipt_generated")

    else:
        decision = "first_receipt_rejected"
        receipt_status = "receipt_metadata_incomplete"
        reasons.append("command_output_present_but_receipt_metadata_incomplete")

    result = {
        "stage": STAGE,
        "engine": "Real Timestamp First Successful Receipt Gate with Stage370 Safety Brake Binding",
        "created_at": now,
        "source_stage": 370,
        "previous_hash": previous_hash,
        "stage370_decision": stage370.get("decision") if isinstance(stage370, dict) else None,
        "stage370_all_tests_passed": stage370.get("all_tests_passed") if isinstance(stage370, dict) else None,
        "stage360_target_hash": stage360_target_hash,
        "decision": decision,
        "receipt_status": receipt_status,
        "reasons": reasons,
        "checks": checks,
        "input": input_data,
        "command_receipts": {
            "opentimestamps": ots_command_result,
            "rfc3161": rfc3161_command_result
        },
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_raw_timestamp_binaries_in_public_docs": True,
            "metadata_receipt_only": True,
            "stage371_does_not_final_accept_timestamp_verified": True,
            "stage370_safety_brake_required": True
        },
        "guarantee": {
            "what_stage371_guarantees": [
                "Stage370 safety brake result is bound as previous_hash when present.",
                "Stage370 safety_test_pass is required before first receipt generation.",
                "first_receipt_generated requires exit_code=0 and matching verified_target_hash.",
                "OpenTimestamps and RFC3161 successful receipts are represented as metadata only.",
                "Stage371 does not final-accept timestamp_verified.",
                "Raw timestamp binaries and secret leakage are blocked."
            ],
            "what_stage371_does_not_guarantee": [
                "It does not publish raw .ots or RFC3161 token binaries.",
                "It does not final-accept timestamp_verified.",
                "It does not verify Sigstore, Rekor, OCSP, or CRL."
            ]
        }
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage371: Real Timestamp First Successful Receipt Gate",
            "with Stage370 Safety Brake Binding",
            "",
            f"Decision: {decision}",
            f"Receipt Status: {receipt_status}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage371 can generate the first real successful timestamp receipt only after Stage370 safety brake tests pass.",
            "It requires exit_code=0, matching verified_target_hash, and metadata-only receipt evidence.",
            "Stage371 does not final-accept timestamp_verified; final acceptance belongs to the next gate.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"receipt_status={receipt_status}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
