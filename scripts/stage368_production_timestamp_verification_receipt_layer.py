import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

STAGE = 368

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "timestamp-receipt"

STAGE367_RESULT = DOCS / "timestamp-activation" / "stage367_production_timestamp_activation_result.json"
STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"

RECEIPT_INPUT = OUT_DIR / "stage368_production_timestamp_verification_receipt_input.json"
OUT_JSON = OUT_DIR / "stage368_production_timestamp_verification_receipt_result.json"
OUT_SUMMARY = OUT_DIR / "stage368_production_timestamp_verification_receipt_summary.txt"

OUT_DIR.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path):
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def fake_verified_claim(obj) -> bool:
    raw = json.dumps(obj, ensure_ascii=False).lower()

    verified_claims = [
        '"timestamp_verified": true',
        '"ots_verified": true',
        '"rfc3161_verified": true',
        '"production_verified": true',
        '"verified": true',
    ]

    proof_markers = [
        "exit_code",
        "stdout_sha256",
        "stderr_sha256",
        "cli_output_sha256",
        "verified_target_hash",
        "receipt_evidence_sha256",
        "ots_file_sha256",
        "timestamp_token_sha256",
        "message_imprint_sha256",
        "tsa_certificate_fingerprint",
    ]

    has_claim = any(x in raw for x in verified_claims)
    has_marker = any(x in raw for x in proof_markers)

    return has_claim and not has_marker


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage367 = read_json(STAGE367_RESULT)
    stage360 = read_json(STAGE360_RESULT)

    previous_hash = sha256_file(STAGE367_RESULT)

    stage360_target_hash = None
    if isinstance(stage360, dict):
        stage360_target_hash = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("stage359_result_sha256")
            or stage360.get("result_sha256")
        )

    if RECEIPT_INPUT.exists():
        receipt = read_json(RECEIPT_INPUT)
    else:
        receipt = {
            "stage": 368,
            "engine": "Production Timestamp Verification Receipt Input",
            "target_source_stage": 360,
            "target_hash": stage360_target_hash,
            "receipt_mode": "metadata_only_no_raw_timestamp_binaries",
            "opentimestamps_receipt": {
                "enabled": True,
                "command": "ots verify <stamped_file>",
                "exit_code": None,
                "stdout_sha256": None,
                "stderr_sha256": None,
                "ots_cli_output_sha256": None,
                "stamped_file_sha256": None,
                "ots_file_sha256": None,
                "verified_target_hash": None,
                "ots_verified": False
            },
            "rfc3161_receipt": {
                "enabled": True,
                "command": "openssl ts -verify ...",
                "exit_code": None,
                "stdout_sha256": None,
                "stderr_sha256": None,
                "rfc3161_verifier_output_sha256": None,
                "original_file_sha256": None,
                "timestamp_token_sha256": None,
                "message_imprint_sha256": None,
                "tsa_certificate_fingerprint": None,
                "verified_target_hash": None,
                "rfc3161_verified": False
            },
            "timestamp_verified": False,
            "note": "Default receipt input. No real OpenTimestamps or RFC3161 command receipt has been added yet."
        }
        RECEIPT_INPUT.write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    ots = receipt.get("opentimestamps_receipt", {})
    rfc3161 = receipt.get("rfc3161_receipt", {})

    receipt_target_hash = receipt.get("target_hash")

    target_hash_matches_stage360 = bool(
        stage360_target_hash
        and receipt_target_hash
        and stage360_target_hash == receipt_target_hash
    )

    ots_receipt_ready = bool(
        ots.get("exit_code") == 0
        and ots.get("stdout_sha256")
        and ots.get("ots_cli_output_sha256")
        and ots.get("stamped_file_sha256")
        and ots.get("ots_file_sha256")
        and ots.get("verified_target_hash") == stage360_target_hash
        and ots.get("ots_verified") is True
    )

    rfc3161_receipt_ready = bool(
        rfc3161.get("exit_code") == 0
        and rfc3161.get("stdout_sha256")
        and rfc3161.get("rfc3161_verifier_output_sha256")
        and rfc3161.get("original_file_sha256")
        and rfc3161.get("timestamp_token_sha256")
        and rfc3161.get("message_imprint_sha256")
        and rfc3161.get("tsa_certificate_fingerprint")
        and rfc3161.get("verified_target_hash") == stage360_target_hash
        and rfc3161.get("rfc3161_verified") is True
    )

    checks = {
        "stage367_result_present": stage367 is not None,
        "stage367_previous_hash_bound": previous_hash is not None,
        "stage367_not_block": isinstance(stage367, dict) and stage367.get("decision") != "block",
        "stage360_result_present": stage360 is not None,
        "stage360_target_hash_present": stage360_target_hash is not None,
        "receipt_input_present": receipt is not None,
        "receipt_target_hash_present": receipt_target_hash is not None,
        "target_hash_matches_stage360": target_hash_matches_stage360,
        "ots_receipt_ready": ots_receipt_ready,
        "rfc3161_receipt_ready": rfc3161_receipt_ready,
        "timestamp_verified_claim": receipt.get("timestamp_verified") is True,
        "private_material_detected": contains_private_material(receipt),
        "raw_binary_path_detected": raw_binary_path_detected(receipt),
        "fake_verified_claim_detected": fake_verified_claim(receipt)
    }

    decision = "verifier_pending"
    verification_status = "not_verified"
    reasons = []

    if not checks["stage367_result_present"]:
        decision = "block"
        reasons.append("stage367_result_missing")

    elif not checks["stage367_not_block"]:
        decision = "block"
        reasons.append("stage367_is_blocked")

    elif not checks["stage360_result_present"]:
        decision = "block"
        reasons.append("stage360_result_missing")

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["raw_binary_path_detected"]:
        decision = "block"
        reasons.append("raw_timestamp_binary_path_detected_in_public_receipt")

    elif checks["fake_verified_claim_detected"]:
        decision = "block"
        reasons.append("fake_verified_claim_detected")

    elif not checks["receipt_target_hash_present"]:
        decision = "verifier_pending"
        reasons.append("receipt_target_hash_missing")

    elif not checks["target_hash_matches_stage360"]:
        decision = "verifier_rejected"
        reasons.append("receipt_target_hash_mismatch")

    elif not checks["ots_receipt_ready"] and not checks["rfc3161_receipt_ready"]:
        decision = "verifier_pending"
        reasons.append("production_timestamp_verification_receipt_missing")

    elif checks["ots_receipt_ready"]:
        decision = "timestamp_verified"
        verification_status = "verified_by_opentimestamps_receipt"
        reasons.append("opentimestamps_receipt_ready")

    elif checks["rfc3161_receipt_ready"]:
        decision = "timestamp_verified"
        verification_status = "verified_by_rfc3161_receipt"
        reasons.append("rfc3161_receipt_ready")

    else:
        decision = "verifier_rejected"
        reasons.append("receipt_rejected")

    result = {
        "stage": STAGE,
        "engine": "Production Timestamp Verification Receipt Layer for OpenTimestamps / RFC3161",
        "created_at": now,
        "source_stage": 367,
        "previous_hash": previous_hash,
        "stage367_decision": stage367.get("decision") if isinstance(stage367, dict) else None,
        "stage360_target_hash": stage360_target_hash,
        "decision": decision,
        "verification_status": verification_status,
        "reasons": reasons,
        "checks": checks,
        "receipt_input": receipt,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_raw_timestamp_binaries_in_public_docs": True,
            "metadata_receipt_only": True,
            "real_command_receipt_required_for_timestamp_verified": True,
            "no_false_timestamp_verified_claims": True
        },
        "guarantee": {
            "what_stage368_guarantees": [
                "Stage367 activation result is bound as previous_hash when present.",
                "Stage360 timestamp target hash is used as the receipt target.",
                "timestamp_verified requires command receipt metadata, exit_code=0, output SHA256, and matching verified_target_hash.",
                "OpenTimestamps and RFC3161 receipts are represented as metadata only.",
                "Raw timestamp binaries are blocked from public receipt metadata.",
                "Fake verified claims and secret leakage are blocked."
            ],
            "what_stage368_does_not_guarantee": [
                "It does not create a real .ots proof file.",
                "It does not create a real RFC3161 TimeStampToken.",
                "It does not publish raw timestamp binaries.",
                "It does not verify Sigstore, Rekor, OCSP, or CRL."
            ]
        }
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage368: Production Timestamp Verification Receipt Layer",
            "for OpenTimestamps / RFC3161",
            "",
            f"Decision: {decision}",
            f"Verification Status: {verification_status}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage368 records production timestamp verification command receipts as metadata.",
            "It can return timestamp_verified only with exit_code=0, output SHA256, and matching verified_target_hash.",
            "Without a real command receipt, the correct decision remains verifier_pending.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"verification_status={verification_status}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
