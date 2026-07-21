import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

STAGE = 365

ROOT = Path(".")
DOCS = ROOT / "docs"
OUT_DIR = DOCS / "timestamp-test"

STAGE364_RESULT = DOCS / "timestamp-promotion" / "stage364_real_timestamp_proof_promotion_result.json"
STAGE360_RESULT = DOCS / "timestamp-proof" / "stage360_external_timestamp_proof_result.json"

TEST_CASES = OUT_DIR / "stage365_timestamp_promotion_test_cases.json"
OUT_JSON = OUT_DIR / "stage365_verified_timestamp_promotion_test_result.json"
OUT_SUMMARY = OUT_DIR / "stage365_verified_timestamp_promotion_test_summary.txt"

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


def default_test_cases(stage360_target_hash):
    return {
        "stage": STAGE,
        "engine": "Verified Timestamp Promotion Test Harness with Fake-Verified Claim Guard",
        "simulation_only": True,
        "production_decision_must_remain": "timestamp_pending",
        "note": "These are safe simulation test cases. They do not claim real OpenTimestamps or RFC3161 verification.",
        "test_cases": [
            {
                "case_id": "valid_simulated_promotion",
                "purpose": "Confirm the promotion path can become ready when target hash matches and simulated verification metadata exists.",
                "simulation_only": True,
                "target_hash": stage360_target_hash,
                "simulated_ots_verification_result_sha256": sha256_text("simulated-ots-verification-result"),
                "simulated_rfc3161_verification_result_sha256": None,
                "timestamp_verified": False,
                "expected_test_decision": "promotion_path_ready"
            },
            {
                "case_id": "mismatch_rejection_test",
                "purpose": "Confirm mismatch is rejected.",
                "simulation_only": True,
                "target_hash": "0" * 64,
                "simulated_ots_verification_result_sha256": sha256_text("simulated-mismatch"),
                "simulated_rfc3161_verification_result_sha256": None,
                "timestamp_verified": False,
                "expected_test_decision": "timestamp_rejected_expected"
            },
            {
                "case_id": "fake_verified_block_test",
                "purpose": "Confirm fake verified claims are blocked.",
                "simulation_only": True,
                "target_hash": stage360_target_hash,
                "simulated_ots_verification_result_sha256": None,
                "simulated_rfc3161_verification_result_sha256": None,
                "timestamp_verified": True,
                "expected_test_decision": "fake_verified_block_expected"
            }
        ]
    }


def evaluate_case(case, stage360_target_hash):
    if contains_private_material(case):
        return {
            "case_id": case.get("case_id"),
            "test_decision": "block",
            "test_pass": False,
            "reason": "private_material_detected"
        }

    target_hash = case.get("target_hash")
    has_simulated_evidence = bool(
        case.get("simulated_ots_verification_result_sha256")
        or case.get("simulated_rfc3161_verification_result_sha256")
    )
    fake_verified = case.get("timestamp_verified") is True and not has_simulated_evidence

    if fake_verified:
        decision = "fake_verified_block_expected"
        reason = "fake_verified_claim_detected_in_test"
    elif not stage360_target_hash:
        decision = "test_failed"
        reason = "stage360_target_hash_missing"
    elif not target_hash:
        decision = "test_failed"
        reason = "test_target_hash_missing"
    elif target_hash != stage360_target_hash:
        decision = "timestamp_rejected_expected"
        reason = "target_hash_mismatch_expected"
    elif has_simulated_evidence:
        decision = "promotion_path_ready"
        reason = "simulated_evidence_present_and_target_hash_matched"
    else:
        decision = "test_failed"
        reason = "insufficient_test_evidence"

    expected = case.get("expected_test_decision")
    return {
        "case_id": case.get("case_id"),
        "test_decision": decision,
        "expected_test_decision": expected,
        "test_pass": decision == expected,
        "reason": reason,
        "simulation_only": case.get("simulation_only") is True
    }


def main():
    now = datetime.now(timezone.utc).isoformat()

    stage364 = read_json(STAGE364_RESULT)
    stage360 = read_json(STAGE360_RESULT)

    previous_hash = sha256_file(STAGE364_RESULT)

    stage360_target_hash = None
    if isinstance(stage360, dict):
        stage360_target_hash = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("stage359_result_sha256")
            or stage360.get("result_sha256")
        )

    if TEST_CASES.exists():
        test_cases_doc = read_json(TEST_CASES)
    else:
        test_cases_doc = default_test_cases(stage360_target_hash)
        TEST_CASES.write_text(
            json.dumps(test_cases_doc, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    cases = test_cases_doc.get("test_cases", [])
    evaluated = [evaluate_case(c, stage360_target_hash) for c in cases]

    all_tests_passed = bool(evaluated) and all(x.get("test_pass") for x in evaluated)
    private_material_detected = contains_private_material(test_cases_doc)

    production_decision = "timestamp_pending"
    simulated_promotion_result = "timestamp_verified"
    simulation_only = True

    if not isinstance(stage364, dict):
        overall_decision = "block"
        reasons = ["stage364_result_missing"]
    elif stage364.get("decision") == "block":
        overall_decision = "block"
        reasons = ["stage364_is_blocked"]
    elif private_material_detected:
        overall_decision = "block"
        reasons = ["private_material_detected"]
    elif all_tests_passed:
        overall_decision = "test_pass"
        reasons = ["all_timestamp_promotion_safety_tests_passed"]
    else:
        overall_decision = "test_failed"
        reasons = ["one_or_more_timestamp_promotion_tests_failed"]

    result = {
        "stage": STAGE,
        "engine": "Verified Timestamp Promotion Test Harness with Fake-Verified Claim Guard",
        "created_at": now,
        "source_stage": 364,
        "previous_hash": previous_hash,
        "stage364_decision": stage364.get("decision") if isinstance(stage364, dict) else None,
        "stage360_target_hash": stage360_target_hash,
        "production_decision": production_decision,
        "test_decision": overall_decision,
        "simulated_promotion_result": simulated_promotion_result,
        "simulation_only": simulation_only,
        "reasons": reasons,
        "test_results": evaluated,
        "all_tests_passed": all_tests_passed,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_raw_qkd_key_material": True,
            "no_real_timestamp_verified_claim": True,
            "simulation_result_is_not_production_result": True,
            "fake_verified_claim_guard_enabled": True
        },
        "guarantee": {
            "what_stage365_guarantees": [
                "Stage364 result is bound as previous_hash when present.",
                "The production decision remains timestamp_pending.",
                "The timestamp_verified path is tested only as simulation.",
                "Target hash mismatch is expected to be rejected.",
                "Fake verified claims are expected to be blocked.",
                "Simulation output is clearly separated from production verification."
            ],
            "what_stage365_does_not_guarantee": [
                "It does not perform real OpenTimestamps verification.",
                "It does not perform real RFC3161 TimeStampToken verification.",
                "It does not promote production evidence to timestamp_verified.",
                "It does not verify Sigstore, Rekor, OCSP, or CRL."
            ]
        },
        "test_cases": test_cases_doc
    }

    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    result["result_sha256"] = sha256_text(canonical)

    OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    OUT_SUMMARY.write_text(
        "\n".join([
            "Stage365: Verified Timestamp Promotion Test Harness",
            "with Fake-Verified Claim Guard",
            "",
            f"Production Decision: {production_decision}",
            f"Test Decision: {overall_decision}",
            f"Simulation Only: {simulation_only}",
            f"Previous Hash: {previous_hash}",
            f"Result SHA256: {result['result_sha256']}",
            "",
            "Meaning:",
            "Stage365 safely tests the timestamp promotion path.",
            "It does not convert production evidence to timestamp_verified.",
            "Fake verified claims and target hash mismatches are tested as expected failures.",
        ]),
        encoding="utf-8"
    )

    print(f"production_decision={production_decision}")
    print(f"test_decision={overall_decision}")
    print(f"simulation_only={simulation_only}")
    print(f"previous_hash={previous_hash}")
    print(f"result_sha256={result['result_sha256']}")


if __name__ == "__main__":
    main()
