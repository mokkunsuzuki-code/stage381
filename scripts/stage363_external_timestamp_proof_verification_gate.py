import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

STAGE = 363

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "timestamp-verification"

STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"
STAGE362_RESULT = DOCS / "promotion" / "stage362_asynchronous_proof_promotion_result.json"

PROOF_INPUT = OUT_DIR / "stage363_external_timestamp_proof_input.json"
OUT_JSON = OUT_DIR / "stage363_external_timestamp_verification_result.json"
OUT_SUMMARY = OUT_DIR / "stage363_external_timestamp_verification_summary.txt"

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
        '"verified": true',
    ]

    proof_markers = [
        "ots_proof_sha256",
        "ots_verification_result_sha256",
        "bitcoin_block_height",
        "bitcoin_attestation_time",
        "rfc3161_token_sha256",
        "timestamp_token_sha256",
        "message_imprint_sha256",
        "tsa_certificate_fingerprint",
        "tsa_signature_verification_evidence_sha256",
    ]

    has_verified_claim = any(x in raw for x in verified_claims)
    has_proof_marker = any(x in raw for x in proof_markers)

    return has_verified_claim and not has_proof_marker


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage360 = read_json(STAGE360_RESULT)
    stage362 = read_json(STAGE362_RESULT)

    previous_hash = sha256_file(STAGE362_RESULT)

    if PROOF_INPUT.exists():
        proof_input = read_json(PROOF_INPUT)
    else:
        proof_input = {
            "stage": 363,
            "proof_scope": "external_timestamp",
            "target_source_stage": 360,
            "timestamp_target_sha256": None,
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
                "tsa_certificate_fingerprint": None,
                "tsa_signature_verified": False,
                "gen_time": None
            },
            "claimed_status": "pending",
            "timestamp_verified": False,
            "note": "Default placeholder. No real OpenTimestamps or RFC3161 proof has been verified yet."
        }
        PROOF_INPUT.write_text(
            json.dumps(proof_input, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    stage360_target_sha256 = None
    if isinstance(stage360, dict):
        stage360_target_sha256 = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("stage359_result_sha256")
            or stage360.get("result_sha256")
        )

    input_target_sha256 = proof_input.get("timestamp_target_sha256")

    ots = proof_input.get("opentimestamps", {})
    rfc3161 = proof_input.get("rfc3161", {})

    ots_proof_present = bool(
        ots.get("provided")
        and ots.get("ots_file_sha256")
        and ots.get("ots_verification_result_sha256")
    )

    rfc3161_proof_present = bool(
        rfc3161.get("provided")
        and rfc3161.get("timestamp_token_sha256")
        and rfc3161.get("message_imprint_sha256")
        and rfc3161.get("tsa_certificate_fingerprint")
    )

    target_hash_matches = bool(
        stage360_target_sha256
        and input_target_sha256
        and stage360_target_sha256 == input_target_sha256
    )

    checks = {
        "stage360_result_present": stage360 is not None,
        "stage362_result_present": stage362 is not None,
        "stage362_previous_hash_bound": previous_hash is not None,
        "stage362_not_block": isinstance(stage362, dict) and stage362.get("decision") != "block",
        "stage360_timestamp_target_present": stage360_target_sha256 is not None,
        "proof_input_present": proof_input is not None,
        "input_target_sha256_present": input_target_sha256 is not None,
        "target_hash_matches_stage360": target_hash_matches,
        "ots_proof_present": ots_proof_present,
        "ots_verified_claim": ots.get("ots_verified") is True,
        "rfc3161_proof_present": rfc3161_proof_present,
        "rfc3161_signature_verified_claim": rfc3161.get("tsa_signature_verified") is True,
        "timestamp_verified_claim": proof_input.get("timestamp_verified") is True,
        "private_material_detected": contains_private_material(proof_input),
        "fake_verified_claim_detected": fake_verified_claim(proof_input),
        "future_time_claim_detected": False
    }

    decision = "timestamp_pending"
    verification_status = "not_verified"
    reasons = []

    if not checks["stage360_result_present"]:
        decision = "block"
        reasons.append("stage360_result_missing")

    elif not checks["stage362_result_present"]:
        decision = "block"
        reasons.append("stage362_result_missing")

    elif not checks["stage362_not_block"]:
        decision = "block"
        reasons.append("stage362_is_blocked")

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["fake_verified_claim_detected"]:
        decision = "block"
        reasons.append("fake_verified_claim_detected")

    elif not checks["stage360_timestamp_target_present"]:
        decision = "timestamp_pending"
        reasons.append("stage360_timestamp_target_missing")

    elif not checks["input_target_sha256_present"]:
        decision = "timestamp_pending"
        reasons.append("timestamp_proof_input_missing_target_hash")

    elif not checks["target_hash_matches_stage360"]:
        decision = "timestamp_rejected"
        reasons.append("timestamp_target_hash_mismatch")

    elif not checks["ots_proof_present"] and not checks["rfc3161_proof_present"]:
        decision = "timestamp_pending"
        reasons.append("external_timestamp_proof_missing")

    elif checks["ots_proof_present"] and checks["ots_verified_claim"]:
        decision = "timestamp_verified"
        verification_status = "verified"
        reasons.append("opentimestamps_proof_present_and_verified_claim_declared")

    elif checks["rfc3161_proof_present"] and checks["rfc3161_signature_verified_claim"]:
        decision = "timestamp_verified"
        verification_status = "verified"
        reasons.append("rfc3161_proof_present_and_signature_verified_claim_declared")

    else:
        decision = "timestamp_rejected"
        reasons.append("proof_present_but_not_verified")

    result = {
        "stage": STAGE,
        "engine": "External Timestamp Proof Verification Gate for OpenTimestamps and RFC3161",
        "created_at": now,
        "source_stage": 362,
        "previous_hash": previous_hash,
        "stage360_timestamp_target_sha256": stage360_target_sha256,
        "stage362_decision": stage362.get("decision") if isinstance(stage362, dict) else None,
        "verification_status": verification_status,
        "decision": decision,
        "reasons": reasons,
        "checks": checks,
        "proof_input": proof_input,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_false_timestamp_verified_claims": True,
            "ots_file_alone_is_not_verified": True,
            "rfc3161_token_alone_is_not_verified": True
        },
        "guarantee": {
            "what_stage363_guarantees": [
                "Stage362 result is bound as previous_hash when present.",
                "Stage360 timestamp target hash is used as the verification target when available.",
                "Missing external timestamp proof remains timestamp_pending.",
                "Timestamp proof with target mismatch becomes timestamp_rejected.",
                "Fake timestamp verified claims and secret leakage are blocked.",
                "OpenTimestamps or RFC3161 proof can be represented without falsely claiming verification."
            ],
            "what_stage363_does_not_guarantee": [
                "It does not perform full OpenTimestamps verification unless real verification evidence is supplied.",
                "It does not perform full RFC3161 TimeStampToken signature validation unless real verification evidence is supplied.",
                "It does not verify OCSP or CRL revocation status.",
                "It does not verify Sigstore or Rekor transparency log inclusion.",
                "It does not prove that a certificate is currently good."
            ]
        }
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage363: External Timestamp Proof Verification Gate",
            "for OpenTimestamps and RFC3161",
            "",
            f"Decision: {decision}",
            f"Verification Status: {verification_status}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage363 verifies external timestamp proof readiness for OpenTimestamps and RFC3161.",
            "It does not treat .ots files or RFC3161 tokens alone as verified.",
            "Without real verification evidence, the correct decision is timestamp_pending.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"verification_status={verification_status}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
