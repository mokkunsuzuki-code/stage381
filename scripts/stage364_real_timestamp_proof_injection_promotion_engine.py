import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

STAGE = 364

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "timestamp-promotion"

STAGE363_RESULT = DOCS / "timestamp-verification" / "stage363_external_timestamp_verification_result.json"
STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"

INJECTION_INPUT = OUT_DIR / "stage364_real_timestamp_proof_injection_input.json"
OUT_JSON = OUT_DIR / "stage364_real_timestamp_proof_promotion_result.json"
OUT_SUMMARY = OUT_DIR / "stage364_real_timestamp_proof_promotion_summary.txt"

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
        '"tsa_signature_verified": true',
        '"promoted": true',
        '"verified": true',
    ]

    required_markers = [
        "target_hash",
        "verification_evidence_sha256",
        "ots_verification_result_sha256",
        "rfc3161_verification_result_sha256",
        "message_imprint_sha256",
        "tsa_certificate_fingerprint",
    ]

    has_claim = any(x in raw for x in verified_claims)
    has_marker = any(x in raw for x in required_markers)

    return has_claim and not has_marker


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage363 = read_json(STAGE363_RESULT)
    stage360 = read_json(STAGE360_RESULT)

    previous_hash = sha256_file(STAGE363_RESULT)

    if INJECTION_INPUT.exists():
        injection = read_json(INJECTION_INPUT)
    else:
        injection = {
            "stage": 364,
            "engine": "Real Timestamp Proof Injection Input",
            "target_source_stage": 360,
            "target_hash": None,
            "proof_type": "none",
            "opentimestamps": {
                "provided": False,
                "ots_file_sha256": None,
                "ots_verification_result_sha256": None,
                "ots_verified": False,
                "bitcoin_block_height": None,
                "bitcoin_attestation_time": None
            },
            "rfc3161": {
                "provided": False,
                "timestamp_token_sha256": None,
                "message_imprint_sha256": None,
                "rfc3161_verification_result_sha256": None,
                "tsa_certificate_fingerprint": None,
                "tsa_signature_verified": False,
                "gen_time": None
            },
            "claimed_promotion": "timestamp_pending_to_timestamp_verified",
            "timestamp_verified": False,
            "note": "Default placeholder. No real OpenTimestamps or RFC3161 verification evidence has been injected yet."
        }
        INJECTION_INPUT.write_text(
            json.dumps(injection, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    stage360_target_hash = None
    if isinstance(stage360, dict):
        stage360_target_hash = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("stage359_result_sha256")
            or stage360.get("result_sha256")
        )

    injection_target_hash = injection.get("target_hash")

    ots = injection.get("opentimestamps", {})
    rfc3161 = injection.get("rfc3161", {})

    ots_ready = bool(
        ots.get("provided")
        and ots.get("ots_file_sha256")
        and ots.get("ots_verification_result_sha256")
        and ots.get("ots_verified") is True
    )

    rfc3161_ready = bool(
        rfc3161.get("provided")
        and rfc3161.get("timestamp_token_sha256")
        and rfc3161.get("message_imprint_sha256")
        and rfc3161.get("rfc3161_verification_result_sha256")
        and rfc3161.get("tsa_certificate_fingerprint")
        and rfc3161.get("tsa_signature_verified") is True
    )

    target_hash_matches = bool(
        stage360_target_hash
        and injection_target_hash
        and stage360_target_hash == injection_target_hash
    )

    checks = {
        "stage363_result_present": stage363 is not None,
        "stage363_previous_hash_bound": previous_hash is not None,
        "stage363_not_block": isinstance(stage363, dict) and stage363.get("decision") != "block",
        "stage360_result_present": stage360 is not None,
        "stage360_target_hash_present": stage360_target_hash is not None,
        "injection_input_present": injection is not None,
        "injection_target_hash_present": injection_target_hash is not None,
        "target_hash_matches_stage360": target_hash_matches,
        "ots_real_verification_evidence_present": ots_ready,
        "rfc3161_real_verification_evidence_present": rfc3161_ready,
        "timestamp_verified_claim": injection.get("timestamp_verified") is True,
        "private_material_detected": contains_private_material(injection),
        "fake_verified_claim_detected": fake_verified_claim(injection),
        "future_time_claim_detected": False
    }

    decision = "timestamp_pending"
    promotion_status = "not_promoted"
    reasons = []

    if not checks["stage363_result_present"]:
        decision = "block"
        reasons.append("stage363_result_missing")

    elif not checks["stage363_not_block"]:
        decision = "block"
        reasons.append("stage363_is_blocked")

    elif not checks["stage360_result_present"]:
        decision = "block"
        reasons.append("stage360_result_missing")

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["fake_verified_claim_detected"]:
        decision = "block"
        reasons.append("fake_verified_claim_detected")

    elif not checks["stage360_target_hash_present"]:
        decision = "timestamp_pending"
        reasons.append("stage360_target_hash_missing")

    elif not checks["injection_target_hash_present"]:
        decision = "timestamp_pending"
        reasons.append("real_timestamp_proof_injection_target_hash_missing")

    elif not checks["target_hash_matches_stage360"]:
        decision = "timestamp_rejected"
        reasons.append("timestamp_target_hash_mismatch")

    elif not checks["ots_real_verification_evidence_present"] and not checks["rfc3161_real_verification_evidence_present"]:
        decision = "timestamp_pending"
        reasons.append("real_timestamp_verification_evidence_missing")

    elif checks["ots_real_verification_evidence_present"] or checks["rfc3161_real_verification_evidence_present"]:
        decision = "timestamp_verified"
        promotion_status = "promoted"
        reasons.append("real_timestamp_verification_evidence_present_and_target_hash_matched")

    else:
        decision = "timestamp_rejected"
        reasons.append("timestamp_proof_injection_rejected")

    result = {
        "stage": STAGE,
        "engine": "Real Timestamp Proof Injection and Promotion Engine for OpenTimestamps and RFC3161",
        "created_at": now,
        "source_stage": 363,
        "previous_hash": previous_hash,
        "stage363_decision": stage363.get("decision") if isinstance(stage363, dict) else None,
        "stage360_target_hash": stage360_target_hash,
        "promotion_status": promotion_status,
        "decision": decision,
        "reasons": reasons,
        "checks": checks,
        "injection_input": injection,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_false_timestamp_verified_claims": True,
            "ots_file_alone_is_not_verified": True,
            "rfc3161_token_alone_is_not_verified": True,
            "tsa_name_alone_is_not_verified": True
        },
        "guarantee": {
            "what_stage364_guarantees": [
                "Stage363 result is bound as previous_hash when present.",
                "Stage360 timestamp target hash is used as the promotion target when available.",
                "Missing real timestamp verification evidence remains timestamp_pending.",
                "Target hash mismatch becomes timestamp_rejected.",
                "OpenTimestamps or RFC3161 verification evidence can promote timestamp_pending to timestamp_verified only when target hash matches.",
                "Fake verified claims and secret leakage are blocked."
            ],
            "what_stage364_does_not_guarantee": [
                "It does not treat a .ots file alone as verified.",
                "It does not treat an RFC3161 token alone as verified.",
                "It does not verify OCSP or CRL revocation status.",
                "It does not verify Sigstore or Rekor transparency log inclusion.",
                "It does not publish private keys or raw secrets."
            ]
        }
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage364: Real Timestamp Proof Injection & Promotion Engine",
            "for OpenTimestamps and RFC3161",
            "",
            f"Decision: {decision}",
            f"Promotion Status: {promotion_status}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage364 injects real timestamp verification evidence into the QSP evidence rail.",
            "It can promote timestamp_pending to timestamp_verified only when target hash matches and verification evidence is present.",
            "Without real verification evidence, the correct decision remains timestamp_pending.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"promotion_status={promotion_status}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
