import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


STAGE = 377

STAGE376_RESULT_PATH = Path(
    "docs/final-acceptance-v2/result/"
    "stage376_superseding_final_acceptance_result.json"
)

STAGE372_RESULT_PATH = Path(
    "docs/timestamp-final-acceptance/"
    "stage372_timestamp_verification_final_acceptance_result.json"
)

TARGET_PATH = Path(
    "docs/timestamp-evidence/"
    "stage376_stage360_timestamp_target.json"
)

POLICY_PATH = Path(
    "docs/timestamp-policy/"
    "stage377_dual_timestamp_finalization_policy.json"
)

RFC3161_RECEIPT_PATH = Path(
    "docs/timestamp-evidence/"
    "stage377_rfc3161_verification_receipt.json"
)

OTS_RECEIPT_PATH = Path(
    "docs/timestamp-evidence/"
    "stage377_opentimestamps_verification_receipt.json"
)

RESULT_PATH = Path(
    "docs/timestamp-finalization/"
    "stage377_dual_timestamp_finalization_result.json"
)

MANIFEST_PATH = Path(
    "docs/timestamp-finalization/"
    "stage377_superseding_final_acceptance_manifest.json"
)

SUMMARY_PATH = Path(
    "docs/timestamp-finalization/"
    "stage377_dual_timestamp_finalization_summary.txt"
)

ESTABLISHED_STAGE376_RESULT_SHA256 = (
    "32ff58a1f4d5837518226eee70b32833"
    "a8147617df3142ff2f641eca3f116138"
)

ESTABLISHED_STAGE372_RESULT_SHA256 = (
    "ef1847f09c7862d271d71e548f403f75"
    "c91b93b2ffc21dec6016f53e0db7c3aa"
)

ESTABLISHED_TIMESTAMP_TARGET_SHA256 = (
    "052c8f0283110e405443d56f2396c52"
    "a8486e7a70a489f831af107dad73ab1b5"
)


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    return data if isinstance(data, dict) else None


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    return sha256_bytes(path.read_bytes())


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


def recompute_self_hash(
    data: Optional[Dict[str, Any]],
    field: str,
) -> Optional[str]:
    if not isinstance(data, dict):
        return None

    copied = dict(data)
    copied.pop(field, None)
    return sha256_bytes(canonical_json(copied))


def nested(
    data: Optional[Dict[str, Any]],
    *keys: str,
) -> Any:
    current: Any = data

    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)

    return current


def public_private_material_detected() -> bool:
    markers = (
        b"-----BEGIN PRIVATE KEY-----",
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"-----BEGIN EC PRIVATE KEY-----",
        b"ACTIONS_ID_TOKEN_REQUEST_TOKEN=",
        b"GITHUB_TOKEN=",
    )

    for path in Path("docs").rglob("*"):
        if not path.is_file():
            continue

        try:
            raw = path.read_bytes()
        except OSError:
            return True

        if any(marker in raw for marker in markers):
            return True

    return False


def forbidden_public_file_detected() -> bool:
    forbidden_suffixes = {
        ".ots",
        ".tsq",
        ".tsr",
        ".tst",
        ".p7s",
        ".der",
        ".p12",
        ".pfx",
        ".seed",
        ".key",
        ".pk8",
    }

    return any(
        path.is_file()
        and path.suffix.lower() in forbidden_suffixes
        for path in Path("docs").rglob("*")
    )


def main() -> None:
    now = datetime.now(timezone.utc).isoformat()

    stage376 = read_json(STAGE376_RESULT_PATH)
    stage372 = read_json(STAGE372_RESULT_PATH)
    policy = read_json(POLICY_PATH)
    rfc3161 = read_json(RFC3161_RECEIPT_PATH)
    ots = read_json(OTS_RECEIPT_PATH)

    stage376_declared_hash = (
        stage376.get("result_sha256")
        if stage376
        else None
    )

    stage376_recomputed_hash = recompute_self_hash(
        stage376,
        "result_sha256",
    )

    stage372_declared_hash = (
        stage372.get("result_sha256")
        if stage372
        else None
    )

    target_file_sha256 = sha256_file(TARGET_PATH)

    rfc_status = (
        rfc3161.get("execution_status")
        if rfc3161
        else None
    )

    rfc_target_sha256 = nested(
        rfc3161,
        "timestamp_target",
        "sha256",
    )

    rfc_verified = all([
        rfc3161 is not None,
        rfc3161.get("stage") == STAGE,
        rfc3161.get("source_stage") == 376,
        rfc3161.get("previous_hash")
            == ESTABLISHED_STAGE376_RESULT_SHA256,
        rfc_status == "verified",
        rfc3161.get("rfc3161_verified") is True,
        rfc3161.get("verification_exit_code") == 0,
        rfc_target_sha256
            == ESTABLISHED_TIMESTAMP_TARGET_SHA256,
        nested(
            rfc3161,
            "timestamp_target",
            "stage360_target_sha256",
        ) == ESTABLISHED_TIMESTAMP_TARGET_SHA256,
        nested(
            rfc3161,
            "timestamp_target",
            "digest_matches_stage360",
        ) is True,
        is_sha256(
            nested(
                rfc3161,
                "timestamp_request",
                "request_sha256",
            )
        ),
        is_sha256(
            nested(
                rfc3161,
                "timestamp_response",
                "response_sha256",
            )
        ),
        bool(
            nested(
                rfc3161,
                "timestamp_response",
                "generation_time",
            )
        ),
        nested(
            rfc3161,
            "verification",
            "openssl_ts_verify",
        ) is True,
        nested(
            rfc3161,
            "verification",
            "target_message_imprint_match",
        ) is True,
        nested(
            rfc3161,
            "verification",
            "tsa_signature_valid",
        ) is True,
        nested(
            rfc3161,
            "verification",
            "certificate_chain_valid",
        ) is True,
        nested(
            rfc3161,
            "publication_boundary",
            "public_metadata_receipt_only",
        ) is True,
        nested(
            rfc3161,
            "publication_boundary",
            "raw_tsq_published",
        ) is False,
        nested(
            rfc3161,
            "publication_boundary",
            "raw_tsr_published",
        ) is False,
        nested(
            rfc3161,
            "publication_boundary",
            "raw_token_published",
        ) is False,
    ])

    ots_status = (
        ots.get("execution_status")
        if ots
        else None
    )

    ots_target_sha256 = nested(
        ots,
        "timestamp_target",
        "sha256",
    )

    ots_verified = all([
        ots is not None,
        ots.get("stage") == STAGE,
        ots.get("source_stage") == 376,
        ots.get("previous_hash")
            == ESTABLISHED_STAGE376_RESULT_SHA256,
        ots_status == "verified",
        ots.get("opentimestamps_verified") is True,
        ots.get("verification_exit_code") == 0,
        ots_target_sha256
            == ESTABLISHED_TIMESTAMP_TARGET_SHA256,
        nested(
            ots,
            "timestamp_target",
            "stage360_target_sha256",
        ) == ESTABLISHED_TIMESTAMP_TARGET_SHA256,
        nested(
            ots,
            "timestamp_target",
            "digest_matches_stage360",
        ) is True,
        is_sha256(
            nested(
                ots,
                "proof",
                "proof_sha256",
            )
        ),
        nested(
            ots,
            "verification",
            "target_hash_matches",
        ) is True,
        nested(
            ots,
            "verification",
            "confirmed_public_anchor",
        ) is True,
        bool(
            nested(
                ots,
                "verification",
                "confirmed_anchor_type",
            )
        ),
        bool(
            nested(
                ots,
                "verification",
                "confirmed_anchor_reference",
            )
        ),
        bool(
            nested(
                ots,
                "verification",
                "verified_time",
            )
        ),
        is_sha256(
            nested(
                ots,
                "verification",
                "verification_output_sha256",
            )
        ),
        nested(
            ots,
            "publication_boundary",
            "public_metadata_receipt_only",
        ) is True,
        nested(
            ots,
            "publication_boundary",
            "raw_ots_published",
        ) is False,
    ])

    verified_proof_count = sum([
        bool(rfc_verified),
        bool(ots_verified),
    ])

    required_proof_count = (
        policy.get("required_verified_proof_count")
        if policy
        else None
    )

    checks = {
        "stage376_result_present":
            stage376 is not None,
        "stage376_result_hash_valid":
            is_sha256(stage376_declared_hash),
        "stage376_result_hash_matches":
            stage376_declared_hash
            == stage376_recomputed_hash,
        "stage376_result_hash_established":
            stage376_declared_hash
            == ESTABLISHED_STAGE376_RESULT_SHA256,
        "stage376_source_decision_preserved":
            bool(
                stage376
                and stage376.get("decision")
                == "timestamp_execution_pending"
            ),
        "stage376_effective_acceptance_false":
            bool(
                stage376
                and stage376.get(
                    "effective_final_acceptance"
                ) is False
            ),
        "stage372_result_present":
            stage372 is not None,
        "stage372_result_hash_established":
            stage372_declared_hash
            == ESTABLISHED_STAGE372_RESULT_SHA256,
        "policy_present":
            policy is not None,
        "policy_stage_valid":
            bool(
                policy
                and policy.get("stage") == STAGE
            ),
        "policy_fail_closed":
            bool(
                policy
                and policy.get("fail_closed") is True
            ),
        "required_proof_count_valid":
            isinstance(required_proof_count, int)
            and required_proof_count == 2,
        "canonical_target_present":
            TARGET_PATH.is_file(),
        "canonical_target_hash_matches":
            target_file_sha256
            == ESTABLISHED_TIMESTAMP_TARGET_SHA256,
        "rfc3161_receipt_present":
            rfc3161 is not None,
        "opentimestamps_receipt_present":
            ots is not None,
        "both_receipts_same_target":
            rfc_target_sha256
            == ots_target_sha256
            == ESTABLISHED_TIMESTAMP_TARGET_SHA256,
        "rfc3161_verified":
            rfc_verified,
        "opentimestamps_verified":
            ots_verified,
        "verified_proof_count_satisfied":
            isinstance(required_proof_count, int)
            and verified_proof_count
            >= required_proof_count,
        "private_material_detected":
            public_private_material_detected(),
        "forbidden_public_file_detected":
            forbidden_public_file_detected(),
    }

    integrity_keys = [
        "stage376_result_present",
        "stage376_result_hash_valid",
        "stage376_result_hash_matches",
        "stage376_result_hash_established",
        "stage376_source_decision_preserved",
        "stage376_effective_acceptance_false",
        "stage372_result_present",
        "stage372_result_hash_established",
        "policy_present",
        "policy_stage_valid",
        "policy_fail_closed",
        "required_proof_count_valid",
        "canonical_target_present",
        "canonical_target_hash_matches",
        "rfc3161_receipt_present",
        "opentimestamps_receipt_present",
        "both_receipts_same_target",
    ]

    failed_integrity = [
        key
        for key in integrity_keys
        if not checks[key]
    ]

    reasons = []

    if failed_integrity:
        decision = "block"
        reasons.extend(
            f"integrity_check_failed:{key}"
            for key in failed_integrity
        )

    elif checks["private_material_detected"]:
        decision = "block"
        reasons.append(
            "private_material_detected_in_public_docs"
        )

    elif checks["forbidden_public_file_detected"]:
        decision = "block"
        reasons.append(
            "raw_timestamp_binary_detected_in_public_docs"
        )

    elif rfc_status not in (
        "not_executed",
        "pending",
        "verified",
    ):
        decision = "block"
        reasons.append(
            "unsupported_rfc3161_execution_status"
        )

    elif ots_status not in (
        "not_executed",
        "pending",
        "pending_confirmation",
        "verified",
    ):
        decision = "block"
        reasons.append(
            "unsupported_opentimestamps_execution_status"
        )

    elif checks["verified_proof_count_satisfied"]:
        decision = (
            "dual_timestamp_final_acceptance_verified"
        )
        reasons.append(
            "rfc3161_and_opentimestamps_verified"
        )

    elif rfc_verified:
        decision = (
            "rfc3161_verified_opentimestamps_pending"
        )
        reasons.append(
            "opentimestamps_public_anchor_not_final"
        )

    elif ots_verified:
        decision = (
            "opentimestamps_verified_rfc3161_pending"
        )
        reasons.append(
            "rfc3161_verification_not_final"
        )

    else:
        decision = "timestamp_finalization_pending"
        reasons.append(
            "production_dual_timestamp_receipts_not_verified"
        )

    effective_final_acceptance = (
        decision
        == "dual_timestamp_final_acceptance_verified"
    )

    manifest = {
        "stage": STAGE,
        "manifest_type":
            "dual_timestamp_finalization_and_"
            "superseding_final_acceptance_manifest",
        "created_at": now,
        "source_stage": 376,
        "previous_hash":
            stage376_declared_hash,
        "historic_stage372_result_sha256":
            stage372_declared_hash,
        "stage372_record_modified": False,
        "stage376_record_modified": False,
        "timestamp_target_sha256":
            ESTABLISHED_TIMESTAMP_TARGET_SHA256,
        "rfc3161_verified":
            rfc_verified,
        "opentimestamps_verified":
            ots_verified,
        "verified_proof_count":
            verified_proof_count,
        "required_verified_proof_count":
            required_proof_count,
        "timestamp_verified":
            effective_final_acceptance,
        "effective_final_acceptance":
            effective_final_acceptance,
        "maximum_timestamp_assurance":
            bool(rfc_verified and ots_verified),
        "supersedes_stage372_pending":
            effective_final_acceptance,
        "supersedes_stage376_pending":
            effective_final_acceptance,
        "decision":
            decision,
        "reasons":
            reasons,
    }

    manifest_sha256 = sha256_bytes(
        canonical_json(manifest)
    )

    manifest["manifest_sha256"] = (
        manifest_sha256
    )

    result = {
        "stage": STAGE,
        "engine":
            "Production Dual-Timestamp Finalization "
            "and Superseding Final Acceptance Gate",
        "created_at": now,
        "source_stage": 376,
        "previous_hash":
            stage376_declared_hash,
        "historic_stage372_result_sha256":
            stage372_declared_hash,
        "stage372_record_modified": False,
        "stage376_record_modified": False,
        "timestamp_target_sha256":
            ESTABLISHED_TIMESTAMP_TARGET_SHA256,
        "decision":
            decision,
        "effective_final_acceptance":
            effective_final_acceptance,
        "timestamp_verified":
            effective_final_acceptance,
        "supersedes_stage372_pending":
            effective_final_acceptance,
        "supersedes_stage376_pending":
            effective_final_acceptance,
        "rfc3161_verified":
            rfc_verified,
        "opentimestamps_verified":
            ots_verified,
        "maximum_timestamp_assurance":
            bool(rfc_verified and ots_verified),
        "verified_proof_count":
            verified_proof_count,
        "required_verified_proof_count":
            required_proof_count,
        "manifest_sha256":
            manifest_sha256,
        "reasons":
            reasons,
        "checks":
            checks,
        "safety_boundary": {
            "stage372_history_preserved": True,
            "stage376_history_preserved": True,
            "metadata_receipts_only": True,
            "no_raw_rfc3161_response_in_public_docs": True,
            "no_raw_opentimestamps_proof_in_public_docs": True,
            "no_private_keys_published": True,
            "no_oidc_token_published": True,
            "no_github_token_published": True,
            "no_raw_qkd_key_material": True,
            "no_free_form_commands": True,
            "fail_closed": True,
        },
        "guarantee": {
            "what_stage377_guarantees": [
                "The established Stage376 result remains hash-bound and unmodified.",
                "The historic Stage372 pending record remains unmodified.",
                "RFC3161 and OpenTimestamps must verify the same established Stage360 target.",
                "Effective final acceptance becomes true only after both production proofs independently verify.",
                "Raw timestamp proofs and private material remain outside public documentation."
            ],
            "what_stage377_does_not_guarantee": [
                "It does not rewrite Stage372 or Stage376 historical records.",
                "It does not claim RFC3161 verification before a valid production receipt is imported.",
                "It does not claim OpenTimestamps finality before a public anchor is confirmed.",
                "It does not publish raw RFC3161 or OpenTimestamps proof binaries."
            ]
        },
    }

    result_sha256 = sha256_bytes(
        canonical_json(result)
    )

    result["result_sha256"] = (
        result_sha256
    )

    RESULT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    RESULT_PATH.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    MANIFEST_PATH.write_text(
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    summary_lines = [
        "Stage377: Production Dual-Timestamp Finalization",
        "and Superseding Final Acceptance Gate",
        "",
        f"Decision: {decision}",
        f"Source Stage: 376",
        f"Stage376 Record Modified: False",
        f"Stage372 Record Modified: False",
        f"RFC3161 Verified: {rfc_verified}",
        f"OpenTimestamps Verified: {ots_verified}",
        (
            "Effective Final Acceptance: "
            f"{effective_final_acceptance}"
        ),
        (
            "Maximum Timestamp Assurance: "
            f"{bool(rfc_verified and ots_verified)}"
        ),
        f"Manifest SHA256: {manifest_sha256}",
        f"Result SHA256: {result_sha256}",
        "",
        "Reasons:",
    ]

    summary_lines.extend(
        f"- {reason}"
        for reason in reasons
    )

    summary_lines.extend([
        "",
        "Meaning:",
        (
            "Stage377 preserves Stage372 and Stage376 as "
            "historical records and issues a new effective "
            "final acceptance only after independently valid "
            "RFC3161 and OpenTimestamps production receipts "
            "verify the same canonical Stage360 target."
        ),
    ])

    SUMMARY_PATH.write_text(
        "\n".join(summary_lines) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(
        {
            "stage": STAGE,
            "decision": decision,
            "rfc3161_verified": rfc_verified,
            "opentimestamps_verified": ots_verified,
            "effective_final_acceptance":
                effective_final_acceptance,
            "manifest_sha256":
                manifest_sha256,
            "result_sha256":
                result_sha256,
        },
        ensure_ascii=False,
        indent=2,
    ))


if __name__ == "__main__":
    main()
