import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone

STAGE = 369

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "timestamp-runner"

STAGE368_RESULT = DOCS / "timestamp-receipt" / "stage368_production_timestamp_verification_receipt_result.json"
STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"

RUNNER_INPUT = OUT_DIR / "stage369_real_timestamp_verifier_runner_input.json"
OUT_JSON = OUT_DIR / "stage369_real_timestamp_verifier_runner_result.json"
OUT_SUMMARY = OUT_DIR / "stage369_real_timestamp_verifier_runner_summary.txt"

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
    dangerous = [
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "raw_private_key",
        "private_key_material",
        "raw_secret",
        "raw_qkd_key",
        "seed_phrase",
        "password",
        "api_key",
        "access_token",
    ]
    return any(x in raw for x in dangerous)


def raw_binary_path_detected(obj) -> bool:
    raw = json.dumps(obj, ensure_ascii=False).lower()
    blocked_ext = [".ots", ".tsr", ".tsa", ".token", ".der"]
    return any(ext in raw for ext in blocked_ext)


def run_command(command):
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


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage368 = read_json(STAGE368_RESULT)
    stage360 = read_json(STAGE360_RESULT)

    previous_hash = sha256_file(STAGE368_RESULT)

    stage360_target_hash = None
    if isinstance(stage360, dict):
        stage360_target_hash = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("stage359_result_sha256")
            or stage360.get("result_sha256")
        )

    if RUNNER_INPUT.exists():
        runner_input = read_json(RUNNER_INPUT)
    else:
        runner_input = {
            "stage": 369,
            "engine": "Real Timestamp Verifier Runner Input",
            "target_source_stage": 360,
            "target_hash": stage360_target_hash,
            "runner_mode": "metadata_only_no_raw_timestamp_binaries",
            "execute_commands": False,
            "opentimestamps_runner": {
                "enabled": True,
                "command": None,
                "stamped_file_sha256": None,
                "ots_file_sha256": None,
                "verified_target_hash": None
            },
            "rfc3161_runner": {
                "enabled": True,
                "command": None,
                "original_file_sha256": None,
                "timestamp_token_sha256": None,
                "message_imprint_sha256": None,
                "tsa_certificate_fingerprint": None,
                "verified_target_hash": None
            },
            "note": "Default runner input. Commands are not executed unless execute_commands is true and safe command metadata is supplied."
        }
        RUNNER_INPUT.write_text(
            json.dumps(runner_input, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    ots = runner_input.get("opentimestamps_runner", {})
    rfc3161 = runner_input.get("rfc3161_runner", {})

    target_hash = runner_input.get("target_hash")
    target_hash_matches_stage360 = bool(stage360_target_hash and target_hash and target_hash == stage360_target_hash)

    private_material = contains_private_material(runner_input)
    raw_binary_path = raw_binary_path_detected(runner_input)

    execute = runner_input.get("execute_commands") is True

    ots_command_result = None
    rfc3161_command_result = None

    if execute and ots.get("enabled") and ots.get("command"):
        ots_command_result = run_command(ots.get("command"))

    if execute and rfc3161.get("enabled") and rfc3161.get("command"):
        rfc3161_command_result = run_command(rfc3161.get("command"))

    ots_receipt_generated = bool(
        ots_command_result
        and ots_command_result.get("exit_code") == 0
        and ots.get("stamped_file_sha256")
        and ots.get("ots_file_sha256")
        and ots.get("verified_target_hash") == stage360_target_hash
    )

    rfc3161_receipt_generated = bool(
        rfc3161_command_result
        and rfc3161_command_result.get("exit_code") == 0
        and rfc3161.get("original_file_sha256")
        and rfc3161.get("timestamp_token_sha256")
        and rfc3161.get("message_imprint_sha256")
        and rfc3161.get("tsa_certificate_fingerprint")
        and rfc3161.get("verified_target_hash") == stage360_target_hash
    )

    checks = {
        "stage368_result_present": stage368 is not None,
        "stage368_previous_hash_bound": previous_hash is not None,
        "stage368_not_block": isinstance(stage368, dict) and stage368.get("decision") != "block",
        "stage360_result_present": stage360 is not None,
        "stage360_target_hash_present": stage360_target_hash is not None,
        "runner_input_present": runner_input is not None,
        "runner_target_hash_present": target_hash is not None,
        "target_hash_matches_stage360": target_hash_matches_stage360,
        "execute_commands": execute,
        "ots_command_supplied": bool(ots.get("command")),
        "rfc3161_command_supplied": bool(rfc3161.get("command")),
        "ots_receipt_generated": ots_receipt_generated,
        "rfc3161_receipt_generated": rfc3161_receipt_generated,
        "private_material_detected": private_material,
        "raw_binary_path_detected": raw_binary_path,
    }

    decision = "runner_pending"
    runner_status = "not_executed"
    reasons = []

    if not checks["stage368_result_present"]:
        decision = "block"
        reasons.append("stage368_result_missing")

    elif not checks["stage368_not_block"]:
        decision = "block"
        reasons.append("stage368_is_blocked")

    elif not checks["stage360_result_present"]:
        decision = "block"
        reasons.append("stage360_result_missing")

    elif private_material:
        decision = "block"
        reasons.append("private_material_detected")

    elif raw_binary_path:
        decision = "block"
        reasons.append("raw_timestamp_binary_path_detected_in_public_runner_input")

    elif not checks["runner_target_hash_present"]:
        decision = "runner_pending"
        reasons.append("runner_target_hash_missing")

    elif not checks["target_hash_matches_stage360"]:
        decision = "runner_rejected"
        reasons.append("runner_target_hash_mismatch")

    elif not execute:
        decision = "runner_pending"
        reasons.append("execute_commands_false")

    elif not checks["ots_command_supplied"] and not checks["rfc3161_command_supplied"]:
        decision = "runner_pending"
        reasons.append("real_verifier_command_missing")

    elif ots_command_result and ots_command_result.get("exit_code") != 0:
        decision = "runner_rejected"
        runner_status = "command_failed"
        reasons.append("opentimestamps_command_failed")

    elif rfc3161_command_result and rfc3161_command_result.get("exit_code") != 0:
        decision = "runner_rejected"
        runner_status = "command_failed"
        reasons.append("rfc3161_command_failed")

    elif ots_receipt_generated:
        decision = "receipt_generated"
        runner_status = "opentimestamps_receipt_generated"
        reasons.append("opentimestamps_runner_receipt_generated")

    elif rfc3161_receipt_generated:
        decision = "receipt_generated"
        runner_status = "rfc3161_receipt_generated"
        reasons.append("rfc3161_runner_receipt_generated")

    else:
        decision = "runner_rejected"
        runner_status = "receipt_metadata_incomplete"
        reasons.append("command_output_present_but_receipt_metadata_incomplete")

    result = {
        "stage": STAGE,
        "engine": "Real Timestamp Verifier Runner with Production Receipt Generation",
        "created_at": now,
        "source_stage": 368,
        "previous_hash": previous_hash,
        "stage368_decision": stage368.get("decision") if isinstance(stage368, dict) else None,
        "stage360_target_hash": stage360_target_hash,
        "decision": decision,
        "runner_status": runner_status,
        "reasons": reasons,
        "checks": checks,
        "runner_input": runner_input,
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
            "stage369_does_not_final_accept_timestamp_verified": True
        },
        "guarantee": {
            "what_stage369_guarantees": [
                "Stage368 receipt result is bound as previous_hash when present.",
                "Real verifier commands are not executed unless explicitly enabled.",
                "Runner output is converted into SHA256 metadata receipts.",
                "receipt_generated requires exit_code=0 and matching verified_target_hash.",
                "Stage369 does not final-accept timestamp_verified.",
                "Raw timestamp binaries and secret leakage are blocked."
            ],
            "what_stage369_does_not_guarantee": [
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
            "Stage369: Real Timestamp Verifier Runner",
            "with Production Receipt Generation",
            "",
            f"Decision: {decision}",
            f"Runner Status: {runner_status}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage369 runs or prepares real timestamp verifier commands and converts their outputs into metadata receipts.",
            "It can generate a production receipt only with exit_code=0 and matching verified_target_hash.",
            "It does not final-accept timestamp_verified; acceptance belongs to the next gate.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"runner_status={runner_status}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
