import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

STAGE = 366

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "timestamp-verifier"

STAGE365_RESULT = DOCS / "timestamp-test" / "stage365_verified_timestamp_promotion_test_result.json"
STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"

ADAPTER_INPUT = OUT_DIR / "stage366_real_timestamp_verifier_adapter_input.json"
OUT_JSON = OUT_DIR / "stage366_real_timestamp_verifier_adapter_result.json"
OUT_SUMMARY = OUT_DIR / "stage366_real_timestamp_verifier_adapter_summary.txt"

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
        '"ots_verified": true',
        '"rfc3161_verified": true',
        '"timestamp_verified": true',
        '"verifier_success": true',
        '"verified": true',
    ]

    proof_markers = [
        "verified_target_hash",
        "verifier_output_sha256",
        "ots_cli_output_sha256",
        "rfc3161_verifier_output_sha256",
        "message_imprint_sha256",
        "tsa_certificate_fingerprint",
        "verification_command_sha256",
    ]

    has_claim = any(x in raw for x in verified_claims)
    has_marker = any(x in raw for x in proof_markers)

    return has_claim and not has_marker


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage365 = read_json(STAGE365_RESULT)
    stage360 = read_json(STAGE360_RESULT)

    previous_hash = sha256_file(STAGE365_RESULT)

    stage360_target_hash = None
    if isinstance(stage360, dict):
        stage360_target_hash = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("stage359_result_sha256")
            or stage360.get("result_sha256")
        )

    if ADAPTER_INPUT.exists():
        adapter_input = read_json(ADAPTER_INPUT)
    else:
        adapter_input = {
            "stage": 366,
            "engine": "Real OpenTimestamps / RFC3161 Verifier Adapter Input",
            "target_source_stage": 360,
            "target_hash": stage360_target_hash,
            "adapter_mode": "metadata_only_until_real_cli_output_exists",
            "opentimestamps": {
                "enabled": True,
                "ots_file_path": None,
                "stamped_file_path": None,
                "ots_cli_command": "ots verify <file>",
                "ots_cli_output_sha256": None,
                "ots_verified": False
            },
            "rfc3161": {
                "enabled": True,
                "timestamp_token_path": None,
                "original_file_path": None,
                "message_imprint_sha256": None,
                "tsa_certificate_fingerprint": None,
                "rfc3161_verifier_output_sha256": None,
                "rfc3161_verified": False
            },
            "timestamp_verified": False,
            "note": "Default adapter input. No real OpenTimestamps CLI or RFC3161 verifier output has been supplied yet."
        }
        ADAPTER_INPUT.write_text(
            json.dumps(adapter_input, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    ots = adapter_input.get("opentimestamps", {})
    rfc3161 = adapter_input.get("rfc3161", {})

    target_hash = adapter_input.get("target_hash")
    target_hash_matches = bool(stage360_target_hash and target_hash and stage360_target_hash == target_hash)

    ots_real_output_present = bool(
        ots.get("ots_file_path")
        and ots.get("stamped_file_path")
        and ots.get("ots_cli_output_sha256")
    )

    rfc3161_real_output_present = bool(
        rfc3161.get("timestamp_token_path")
        and rfc3161.get("original_file_path")
        and rfc3161.get("message_imprint_sha256")
        and rfc3161.get("tsa_certificate_fingerprint")
        and rfc3161.get("rfc3161_verifier_output_sha256")
    )

    checks = {
        "stage365_result_present": stage365 is not None,
        "stage365_previous_hash_bound": previous_hash is not None,
        "stage365_test_pass": isinstance(stage365, dict) and stage365.get("test_decision") == "test_pass",
        "stage365_simulation_only": isinstance(stage365, dict) and stage365.get("simulation_only") is True,
        "stage360_result_present": stage360 is not None,
        "stage360_target_hash_present": stage360_target_hash is not None,
        "adapter_input_present": adapter_input is not None,
        "adapter_target_hash_present": target_hash is not None,
        "target_hash_matches_stage360": target_hash_matches,
        "ots_real_output_present": ots_real_output_present,
        "ots_verified_claim": ots.get("ots_verified") is True,
        "rfc3161_real_output_present": rfc3161_real_output_present,
        "rfc3161_verified_claim": rfc3161.get("rfc3161_verified") is True,
        "timestamp_verified_claim": adapter_input.get("timestamp_verified") is True,
        "private_material_detected": contains_private_material(adapter_input),
        "fake_verified_claim_detected": fake_verified_claim(adapter_input),
    }

    decision = "verifier_pending"
    verification_status = "not_verified"
    reasons = []

    if not checks["stage365_result_present"]:
        decision = "block"
        reasons.append("stage365_result_missing")

    elif not checks["stage365_test_pass"]:
        decision = "block"
        reasons.append("stage365_test_not_passed")

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["fake_verified_claim_detected"]:
        decision = "block"
        reasons.append("fake_verified_claim_detected")

    elif not checks["stage360_result_present"]:
        decision = "block"
        reasons.append("stage360_result_missing")

    elif not checks["adapter_target_hash_present"]:
        decision = "verifier_pending"
        reasons.append("adapter_target_hash_missing")

    elif not checks["target_hash_matches_stage360"]:
        decision = "verifier_rejected"
        reasons.append("adapter_target_hash_mismatch")

    elif not checks["ots_real_output_present"] and not checks["rfc3161_real_output_present"]:
        decision = "verifier_pending"
        reasons.append("real_verifier_output_missing")

    elif checks["ots_real_output_present"] and checks["ots_verified_claim"]:
        decision = "timestamp_verified"
        verification_status = "verified_by_opentimestamps_adapter"
        reasons.append("opentimestamps_real_verifier_output_present")

    elif checks["rfc3161_real_output_present"] and checks["rfc3161_verified_claim"]:
        decision = "timestamp_verified"
        verification_status = "verified_by_rfc3161_adapter"
        reasons.append("rfc3161_real_verifier_output_present")

    else:
        decision = "verifier_rejected"
        reasons.append("verifier_output_present_but_not_verified")

    result = {
        "stage": STAGE,
        "engine": "Real OpenTimestamps / RFC3161 Verifier Adapter with Stage365 Promotion Test Binding",
        "created_at": now,
        "source_stage": 365,
        "previous_hash": previous_hash,
        "stage365_test_decision": stage365.get("test_decision") if isinstance(stage365, dict) else None,
        "stage365_simulation_only": stage365.get("simulation_only") if isinstance(stage365, dict) else None,
        "stage360_target_hash": stage360_target_hash,
        "decision": decision,
        "verification_status": verification_status,
        "reasons": reasons,
        "checks": checks,
        "adapter_input": adapter_input,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_false_timestamp_verified_claims": True,
            "real_cli_output_required_for_verified": True,
            "simulation_result_is_not_treated_as_production_verified": True
        },
        "guarantee": {
            "what_stage366_guarantees": [
                "Stage365 test result is bound as previous_hash when present.",
                "Stage365 simulation is not treated as production timestamp verification.",
                "Real OpenTimestamps or RFC3161 verifier output is required before timestamp_verified.",
                "Target hash must match the Stage360 timestamp target.",
                "Fake verified claims and secret leakage are blocked."
            ],
            "what_stage366_does_not_guarantee": [
                "It does not create a real .ots proof file.",
                "It does not create a real RFC3161 TimeStampToken.",
                "It does not verify Sigstore, Rekor, OCSP, or CRL.",
                "It does not publish private keys or raw secrets."
            ]
        }
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage366: Real OpenTimestamps / RFC3161 Verifier Adapter",
            "with Stage365 Promotion Test Binding",
            "",
            f"Decision: {decision}",
            f"Verification Status: {verification_status}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage366 connects the safe Stage365 promotion test result to a real timestamp verifier adapter.",
            "It does not treat simulation results as production timestamp verification.",
            "Without real OpenTimestamps or RFC3161 verifier output, the correct decision is verifier_pending.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"verification_status={verification_status}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
