import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

STAGE = 372

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "timestamp-final-acceptance"

STAGE371_RESULT = DOCS / "timestamp-first-receipt" / "stage371_real_timestamp_first_receipt_result.json"
STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"

OUT_JSON = OUT_DIR / "stage372_timestamp_verification_final_acceptance_result.json"
OUT_MANIFEST = OUT_DIR / "stage372_final_acceptance_manifest.json"
OUT_SUMMARY = OUT_DIR / "stage372_timestamp_verification_final_acceptance_summary.txt"

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
    """
    Detect actual secret-bearing fields or PEM private-key material.

    Safety declarations such as:
      no_private_keys
      no_raw_qkd_key_material

    must not be treated as secret material.
    """

    dangerous_exact_keys = {
        "private_key",
        "private_key_material",
        "raw_private_key",
        "raw_secret",
        "raw_qkd_key",
        "seed_phrase",
        "password",
        "api_key",
        "access_token",
        "secret_key",
        "client_secret",
    }

    private_key_markers = {
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "-----begin openssh private key-----",
        "-----begin encrypted private key-----",
    }

    def scan(value) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized_key = str(key).strip().lower()

                if normalized_key in dangerous_exact_keys:
                    if child not in (None, "", False, [], {}):
                        return True

                if scan(child):
                    return True

            return False

        if isinstance(value, list):
            return any(scan(item) for item in value)

        if isinstance(value, str):
            lowered = value.lower()
            return any(marker in lowered for marker in private_key_markers)

        return False

    return scan(obj)


def raw_timestamp_binary_file_detected() -> bool:
    forbidden_suffixes = {".ots", ".tsr", ".tsa", ".token", ".der"}

    for path in DOCS.rglob("*"):
        if path.is_file() and path.suffix.lower() in forbidden_suffixes:
            return True

    return False


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage371 = read_json(STAGE371_RESULT)
    stage360 = read_json(STAGE360_RESULT)

    previous_hash = sha256_file(STAGE371_RESULT)
    stage371_result_sha256 = None
    if isinstance(stage371, dict):
        stage371_result_sha256 = stage371.get("result_sha256")

    stage360_target_hash = None
    if isinstance(stage360, dict):
        stage360_target_hash = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("stage359_result_sha256")
            or stage360.get("result_sha256")
        )

    stage371_decision = stage371.get("decision") if isinstance(stage371, dict) else None
    stage371_receipt_status = stage371.get("receipt_status") if isinstance(stage371, dict) else None

    checks = {
        "stage371_result_present": stage371 is not None,
        "stage371_previous_hash_bound": previous_hash is not None,
        "stage371_result_sha256_present": stage371_result_sha256 is not None,
        "stage371_first_receipt_generated": stage371_decision == "first_receipt_generated",
        "stage371_not_block": stage371_decision != "block",
        "stage371_not_rejected": stage371_decision != "first_receipt_rejected",
        "stage360_result_present": stage360 is not None,
        "stage360_target_hash_present": stage360_target_hash is not None,
        "private_material_detected": contains_private_material(stage371) if stage371 else False,
        "raw_binary_marker_detected": raw_timestamp_binary_file_detected(),
    }

    decision = "final_acceptance_pending"
    timestamp_verified = False
    reasons = []

    if not checks["stage371_result_present"]:
        decision = "block"
        reasons.append("stage371_result_missing")

    elif not checks["stage371_not_block"]:
        decision = "block"
        reasons.append("stage371_is_blocked")

    elif not checks["stage371_not_rejected"]:
        decision = "final_acceptance_rejected"
        reasons.append("stage371_first_receipt_rejected")

    elif not checks["stage360_result_present"]:
        decision = "block"
        reasons.append("stage360_result_missing")

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append("private_material_detected")

    elif checks["raw_binary_marker_detected"]:
        decision = "block"
        reasons.append("raw_timestamp_binary_marker_detected")

    elif not checks["stage371_first_receipt_generated"]:
        decision = "final_acceptance_pending"
        reasons.append("stage371_first_receipt_not_generated")

    else:
        command_receipts = stage371.get("command_receipts", {})
        ots_receipt = command_receipts.get("opentimestamps")
        rfc3161_receipt = command_receipts.get("rfc3161")
        input_data = stage371.get("input", {})

        ots = input_data.get("opentimestamps_first_receipt", {})
        rfc3161 = input_data.get("rfc3161_first_receipt", {})

        ots_ok = bool(
            ots_receipt
            and ots_receipt.get("exit_code") == 0
            and ots.get("verified_target_hash") == stage360_target_hash
            and ots.get("ots_verified") is True
        )

        rfc3161_ok = bool(
            rfc3161_receipt
            and rfc3161_receipt.get("exit_code") == 0
            and rfc3161.get("verified_target_hash") == stage360_target_hash
            and rfc3161.get("rfc3161_verified") is True
        )

        if ots_ok or rfc3161_ok:
            decision = "timestamp_verified"
            timestamp_verified = True
            reasons.append("final_acceptance_conditions_met")
        else:
            decision = "final_acceptance_rejected"
            reasons.append("first_receipt_generated_but_receipt_integrity_incomplete")

    manifest = {
        "stage": STAGE,
        "manifest_type": "timestamp_verification_final_acceptance_manifest",
        "created_at": now,
        "source_stage": 371,
        "previous_hash": previous_hash,
        "stage371_result_sha256": stage371_result_sha256,
        "stage371_decision": stage371_decision,
        "stage371_receipt_status": stage371_receipt_status,
        "stage360_target_hash": stage360_target_hash,
        "timestamp_verified": timestamp_verified,
        "decision": decision,
        "reasons": reasons,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_raw_timestamp_binaries_in_public_docs": True,
            "metadata_only_final_acceptance": True
        }
    }

    manifest_canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)
    manifest["manifest_sha256"] = sha256_text(manifest_canonical)

    result = {
        "stage": STAGE,
        "engine": "Timestamp Verification Final Acceptance Gate with Stage371 First Receipt Binding",
        "created_at": now,
        "source_stage": 371,
        "previous_hash": previous_hash,
        "decision": decision,
        "timestamp_verified": timestamp_verified,
        "reasons": reasons,
        "checks": checks,
        "final_acceptance_manifest_sha256": manifest["manifest_sha256"],
        "final_acceptance_manifest": manifest,
        "guarantee": {
            "what_stage372_guarantees": [
                "Stage371 result is bound as previous_hash when present.",
                "timestamp_verified can be true only after Stage371 first_receipt_generated.",
                "If Stage371 is still pending, Stage372 remains final_acceptance_pending.",
                "Final acceptance is recorded as an immutable public metadata manifest.",
                "Raw timestamp binaries and secret leakage are blocked."
            ],
            "what_stage372_does_not_guarantee": [
                "It does not run OpenTimestamps or RFC3161 commands.",
                "It does not publish raw .ots, RFC3161 token, DER, TSA response, or secret material.",
                "It does not verify Sigstore, Rekor, OCSP, or CRL."
            ]
        }
    }

    result_canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(result_canonical)

    OUT_MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage372: Timestamp Verification Final Acceptance Gate",
            "with Stage371 First Receipt Binding",
            "",
            f"Decision: {decision}",
            f"Timestamp Verified: {timestamp_verified}",
            f"Previous Hash: {previous_hash}",
            f"Manifest SHA256: {manifest['manifest_sha256']}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage372 is the final acceptance gate for timestamp verification.",
            "Because Stage371 is currently pending unless a real first receipt exists, the correct default decision is final_acceptance_pending.",
            "timestamp_verified can become true only after Stage371 produces first_receipt_generated with complete metadata.",
        ]),
        encoding="utf-8"
    )

    print(f"decision={decision}")
    print(f"timestamp_verified={timestamp_verified}")
    print(f"previous_hash={previous_hash}")
    print(f"manifest_sha256={manifest['manifest_sha256']}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
