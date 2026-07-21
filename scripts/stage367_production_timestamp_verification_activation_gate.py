import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

STAGE = 367

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "timestamp-activation"

STAGE366_RESULT = DOCS / "timestamp-verifier" / "stage366_real_timestamp_verifier_adapter_result.json"
STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"

ACTIVATION_INPUT = OUT_DIR / "stage367_production_timestamp_activation_input.json"
OUT_JSON = OUT_DIR / "stage367_production_timestamp_activation_result.json"
OUT_SUMMARY = OUT_DIR / "stage367_production_timestamp_activation_summary.txt"

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
        "target_hash",
        "verified_target_hash",
        "ots_cli_output_sha256",
        "rfc3161_verifier_output_sha256",
        "activation_evidence_sha256",
        "stamped_file_sha256",
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

    stage366 = read_json(STAGE366_RESULT)
    stage360 = read_json(STAGE360_RESULT)

    previous_hash = sha256_file(STAGE366_RESULT)

    stage360_target_hash = None
    if isinstance(stage360, dict):
        stage360_target_hash = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("stage359_result_sha256")
            or stage360.get("result_sha256")
        )

    if ACTIVATION_INPUT.exists():
        activation = read_json(ACTIVATION_INPUT)
    else:
        activation = {
            "stage": 367,
            "engine": "Production Timestamp Verification Activation Input",
            "target_source_stage": 360,
            "target_hash": stage360_target_hash,
            "activation_mode": "metadata_only_until_real_verifier_output_is_added",
            "opentimestamps": {
                "enabled": True,
                "ots_file_path": None,
                "ots_file_sha256": None,
                "stamped_file_path": None,
                "stamped_file_sha256": None,
                "ots_cli_command": "ots verify <stamped_file>",
                "ots_cli_output_sha256": None,
                "verified_target_hash": None,
                "ots_verified": False
            },
            "rfc3161": {
                "enabled": True,
                "timestamp_token_path": None,
                "timestamp_token_sha256": None,
                "original_file_path": None,
                "original_file_sha256": None,
                "message_imprint_sha256": None,
                "tsa_certificate_fingerprint": None,
                "rfc3161_verify_command": "openssl ts -verify ...",
                "rfc3161_verifier_output_sha256": None,
                "verified_target_hash": None,
                "rfc3161_verified": False
            },
            "timestamp_verified": False,
            "note": "Default activation input. Real OpenTimestamps or RFC3161 verifier output has not been activated yet."
        }
        ACTIVATION_INPUT.write_text(
            json.dumps(activation, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    ots = activation.get("opentimestamps", {})
    rfc3161 = activation.get("rfc3161", {})

    activation_target_hash = activation.get("target_hash")

    ots_verified_target_hash = ots.get("verified_target_hash")
    rfc3161_verified_target_hash = rfc3161.get("verified_target_hash")

    target_hash_matches_stage360 = bool(
        stage360_target_hash
        and activation_target_hash
        and stage360_target_hash == activation_target_hash
    )

    ots_ready = bool(
        ots.get("ots_file_path")
        and ots.get("ots_file_sha256")
        and ots.get("stamped_file_path")
        and ots.get("stamped_file_sha256")
        and ots.get("ots_cli_output_sha256")
        and ots_verified_target_hash
        and ots_verified_target_hash == stage360_target_hash
        and ots.get("ots_verified") is True
    )

    rfc3161_ready = bool(
        rfc3161.get("timestamp_token_path")
        and rfc3161.get("timestamp_token_sha256")
        and rfc3161.get("original_file_path")
        and rfc3161.get("original_file_sha256")
        and rfc3161.get("message_imprint_sha256")
        and rfc3161.get("tsa_certificate_fingerprint")
        and rfc3161.get("rfc3161_verifier_output_sha256")
        and rfc3161_verified_target_hash
        and rfc3161_verified_target_hash == stage360_target_hash
        and rfc3161.get("rfc3161_verified") is True
    )

    checks = {
        "stage366_result_present": stage366 is not None,
        "stage366_previous_hash_bound": previous_hash is not None,
        "stage366_not_block": isinstance(stage366, dict) and stage366.get("decision") != "block",
        "stage360_result_present": stage360 is not None,
        "stage360_target_hash_present": stage360_target_hash is not None,
        "activation_input_present": activation is not None,
        "activation_target_hash_present": activation_target_hash is not None,
        "target_hash_matches_stage360": target_hash_matches_stage360,
        "ots_activation_ready": ots_ready,
        "rfc3161_activation_ready": rfc3161_ready,
        "timestamp_verified_claim": activation.get("timestamp_verified") is True,
        "private_material_detected": contains_private_material(activation),
        "fake_verified_claim_detected": fake_verified_claim(activation)
    }

    decision = "verifier_pending"
    verification_status = "not_verified"
    reasons = []

    if not checks["stage366_result_present"]:
        decision = "block"
        reasons.append("stage366_result_missing")

    elif not checks["stage366_not_block"]:
        decision = "block"
        reasons.append("stage366_is_blocked")

    elif not checks["stage360_result_present"]:
        decision = "block"
        reasons.append("stage360_result_missing")

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["fake_verified_claim_detected"]:
        decision = "block"
        reasons.append("fake_verified_claim_detected")

    elif not checks["activation_target_hash_present"]:
        decision = "verifier_pending"
        reasons.append("activation_target_hash_missing")

    elif not checks["target_hash_matches_stage360"]:
        decision = "verifier_rejected"
        reasons.append("activation_target_hash_mismatch")

    elif not checks["ots_activation_ready"] and not checks["rfc3161_activation_ready"]:
        decision = "verifier_pending"
        reasons.append("real_activation_verifier_output_missing")

    elif checks["ots_activation_ready"]:
        decision = "timestamp_verified"
        verification_status = "verified_by_opentimestamps_activation"
        reasons.append("opentimestamps_activation_evidence_ready")

    elif checks["rfc3161_activation_ready"]:
        decision = "timestamp_verified"
        verification_status = "verified_by_rfc3161_activation"
        reasons.append("rfc3161_activation_evidence_ready")

    else:
        decision = "verifier_rejected"
        reasons.append("activation_rejected")

    result = {
        "stage": STAGE,
        "engine": "Production Timestamp Verification Activation Gate for OpenTimestamps / RFC3161",
        "created_at": now,
        "source_stage": 366,
        "previous_hash": previous_hash,
        "stage366_decision": stage366.get("decision") if isinstance(stage366, dict) else None,
        "stage360_target_hash": stage360_target_hash,
        "decision": decision,
        "verification_status": verification_status,
        "reasons": reasons,
        "checks": checks,
        "activation_input": activation,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_raw_timestamp_binary_required_for_public_docs": True,
            "no_false_timestamp_verified_claims": True,
            "real_verifier_output_required_for_timestamp_verified": True
        },
        "guarantee": {
            "what_stage367_guarantees": [
                "Stage366 verifier adapter result is bound as previous_hash when present.",
                "Stage360 timestamp target hash is used as the activation target.",
                "Real OpenTimestamps or RFC3161 verifier output is required before timestamp_verified.",
                "A matching verified_target_hash is required before timestamp_verified.",
                "Fake verified claims and secret leakage are blocked.",
                "Raw timestamp binaries are not required for public documentation."
            ],
            "what_stage367_does_not_guarantee": [
                "It does not create a real .ots proof file.",
                "It does not create a real RFC3161 TimeStampToken.",
                "It does not verify Sigstore, Rekor, OCSP, or CRL.",
                "It does not publish private keys, raw secrets, or raw timestamp binaries by default."
            ]
        }
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage367: Production Timestamp Verification Activation Gate",
            "for OpenTimestamps / RFC3161",
            "",
            f"Decision: {decision}",
            f"Verification Status: {verification_status}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage367 activates production timestamp verification only when real verifier output exists.",
            "It can move verifier_pending to timestamp_verified only with matching target hash and verified output evidence.",
            "Without real verifier output, the correct decision remains verifier_pending.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"verification_status={verification_status}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
