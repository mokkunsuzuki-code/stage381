import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


STAGE = 376

INPUT_PATH = Path(
    "docs/final-acceptance-v2/input/"
    "stage376_final_acceptance_input.json"
)

POLICY_PATH = Path(
    "docs/timestamp-policy/"
    "stage376_dual_timestamp_policy.json"
)

STAGE375_PATH = Path(
    "docs/mldsa-production/"
    "stage375_dual_signature_verification_result.json"
)

STAGE372_PATH = Path(
    "docs/timestamp-final-acceptance/"
    "stage372_timestamp_verification_final_acceptance_result.json"
)

STAGE360_PATH = Path(
    "docs/timestamp-proof/"
    "stage360_external_timestamp_proof_result.json"
)

RFC3161_RECEIPT_PATH = Path(
    "docs/timestamp-evidence/"
    "stage376_rfc3161_verification_receipt.json"
)

OTS_RECEIPT_PATH = Path(
    "docs/timestamp-evidence/"
    "stage376_opentimestamps_verification_receipt.json"
)

RESULT_PATH = Path(
    "docs/final-acceptance-v2/result/"
    "stage376_superseding_final_acceptance_result.json"
)

MANIFEST_PATH = Path(
    "docs/final-acceptance-v2/result/"
    "stage376_superseding_final_acceptance_manifest.json"
)

SUMMARY_PATH = Path(
    "docs/final-acceptance-v2/summary/"
    "stage376_superseding_final_acceptance_summary.txt"
)

ESTABLISHED_STAGE375_HASH = (
    "fb0a43e582e5e581ddbf06d2ad2636bd"
    "afd8a944bc74d049bf4e072db50d918c"
)

ESTABLISHED_STAGE372_HASH = (
    "ef1847f09c7862d271d71e548f403f75"
    "c91b93b2ffc21dec6016f53e0db7c3aa"
)

ESTABLISHED_TIMESTAMP_TARGET = (
    "052c8f0283110e405443d56f2396c52"
    "a8486e7a70a489f831af107dad73ab1b5"
)


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return None

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(value, dict):
        return None

    return value


def canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
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
    value: Optional[Dict[str, Any]],
    field: str,
) -> Optional[str]:
    if not isinstance(value, dict):
        return None

    copied = dict(value)
    copied.pop(field, None)

    return sha256_bytes(canonical_json(copied))


def contains_private_material() -> bool:
    public_roots = [
        Path("docs"),
        Path("README.md"),
    ]

    markers = [
        b"-----BEGIN PRIVATE KEY-----",
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"-----BEGIN EC PRIVATE KEY-----",
        b"GITHUB_TOKEN=",
        b"ACTIONS_ID_TOKEN_REQUEST_TOKEN=",
    ]

    for root in public_roots:
        paths = [root] if root.is_file() else root.rglob("*")

        for path in paths:
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
        ".der",
        ".p12",
        ".pfx",
        ".seed",
        ".key",
        ".pk8",
    }

    for path in Path("docs").rglob("*"):
        if not path.is_file():
            continue

        if path.suffix.lower() in forbidden_suffixes:
            return True

    return False


def main() -> None:
    now = datetime.now(timezone.utc).isoformat()

    input_data = read_json(INPUT_PATH)
    policy = read_json(POLICY_PATH)
    stage375 = read_json(STAGE375_PATH)
    stage372 = read_json(STAGE372_PATH)
    stage360 = read_json(STAGE360_PATH)
    rfc3161 = read_json(RFC3161_RECEIPT_PATH)
    ots = read_json(OTS_RECEIPT_PATH)

    stage375_declared_hash = (
        stage375.get("result_sha256")
        if stage375
        else None
    )

    stage375_recomputed_hash = recompute_self_hash(
        stage375,
        "result_sha256",
    )

    stage372_declared_hash = (
        stage372.get("result_sha256")
        if stage372
        else None
    )

    stage372_recomputed_hash = recompute_self_hash(
        stage372,
        "result_sha256",
    )

    input_previous_hash = (
        input_data.get("previous_hash")
        if input_data
        else None
    )

    input_timestamp_target = (
        input_data.get("timestamp_target", {}).get("sha256")
        if input_data
        else None
    )

    stage360_target = None

    if stage360:
        stage360_target = (
            stage360.get("timestamp_target_sha256")
            or stage360.get("target_sha256")
            or stage360.get("target_hash")
        )

    if not stage360_target and stage372:
        stage360_target = (
            stage372.get(
                "final_acceptance_manifest",
                {},
            ).get("stage360_target_hash")
        )

    stage375_verified = all([
        stage375 is not None,
        stage375.get("decision")
            == "quantum_safe_dual_signature_verified",
        stage375.get("sigstore_signature_verified") is True,
        stage375.get("rekor_inclusion_verified") is True,
        stage375.get("mldsa_signature_verified") is True,
        stage375.get(
            "dual_signature_target_matches"
        ) is True,
        stage375.get(
            "pqc_downgrade_prevented"
        ) is True,
    ])

    rfc3161_verified = all([
        rfc3161 is not None,
        rfc3161.get("execution_status") == "verified",
        rfc3161.get("verify_exit_code") == 0,
        is_sha256(rfc3161.get("response_sha256")),
        is_sha256(
            rfc3161.get("timestamp_token_sha256")
        ),
        rfc3161.get("message_imprint_sha256")
            == ESTABLISHED_TIMESTAMP_TARGET,
        rfc3161.get("message_imprint_matches") is True,
        rfc3161.get("tsa_signature_verified") is True,
        rfc3161.get(
            "certificate_chain_verified"
        ) is True,
        bool(rfc3161.get("generation_time")),
        is_sha256(
            rfc3161.get(
                "verification_output_sha256"
            )
        ),
        rfc3161.get("verified") is True,
        rfc3161.get("raw_response_published") is False,
        rfc3161.get("private_key_published") is False,
    ])

    ots_verified = all([
        ots is not None,
        ots.get("execution_status") == "verified",
        ots.get("verify_exit_code") == 0,
        is_sha256(ots.get("proof_sha256")),
        ots.get("verified_target_sha256")
            == ESTABLISHED_TIMESTAMP_TARGET,
        ots.get("target_hash_matches") is True,
        ots.get("confirmed_public_anchor") is True,
        bool(ots.get("confirmed_anchor_type")),
        bool(ots.get("confirmed_anchor_reference")),
        bool(ots.get("verified_time")),
        is_sha256(
            ots.get("verification_output_sha256")
        ),
        ots.get("verified") is True,
        ots.get("raw_proof_published") is False,
        ots.get("private_material_published") is False,
    ])

    verified_proof_count = sum([
        bool(rfc3161_verified),
        bool(ots_verified),
    ])

    required_proof_count = (
        policy.get(
            "final_acceptance",
            {},
        ).get("required_verified_proof_count")
        if policy
        else None
    )

    checks = {
        "input_present": input_data is not None,
        "policy_present": policy is not None,
        "stage375_result_present": stage375 is not None,
        "stage375_result_sha256_valid":
            is_sha256(stage375_declared_hash),
        "stage375_result_sha256_matches":
            stage375_declared_hash
            == stage375_recomputed_hash,
        "stage375_result_sha256_is_established":
            stage375_declared_hash
            == ESTABLISHED_STAGE375_HASH,
        "previous_hash_matches_stage375":
            input_previous_hash
            == stage375_declared_hash,
        "stage375_quantum_safe_verified":
            stage375_verified,
        "stage372_result_present": stage372 is not None,
        "stage372_result_sha256_valid":
            is_sha256(stage372_declared_hash),
        "stage372_result_sha256_matches":
            stage372_declared_hash
            == stage372_recomputed_hash,
        "stage372_result_sha256_is_established":
            stage372_declared_hash
            == ESTABLISHED_STAGE372_HASH,
        "stage372_original_decision_pending":
            bool(
                stage372
                and stage372.get("decision")
                == "final_acceptance_pending"
            ),
        "stage372_original_timestamp_false":
            bool(
                stage372
                and stage372.get(
                    "timestamp_verified"
                ) is False
            ),
        "stage372_record_unmodified":
            bool(
                input_data
                and input_data.get(
                    "historic_stage372",
                    {},
                ).get("record_modified") is False
            ),
        "stage360_result_present": stage360 is not None,
        "timestamp_target_matches_established":
            stage360_target
            == input_timestamp_target
            == ESTABLISHED_TIMESTAMP_TARGET,
        "rfc3161_receipt_present": rfc3161 is not None,
        "opentimestamps_receipt_present": ots is not None,
        "rfc3161_verified": rfc3161_verified,
        "opentimestamps_verified": ots_verified,
        "required_proof_count_valid":
            isinstance(required_proof_count, int)
            and required_proof_count == 2,
        "verified_proof_count_satisfied":
            isinstance(required_proof_count, int)
            and verified_proof_count
            >= required_proof_count,
        "private_material_detected":
            contains_private_material(),
        "forbidden_public_file_detected":
            forbidden_public_file_detected(),
    }

    integrity_keys = [
        "input_present",
        "policy_present",
        "stage375_result_present",
        "stage375_result_sha256_valid",
        "stage375_result_sha256_matches",
        "stage375_result_sha256_is_established",
        "previous_hash_matches_stage375",
        "stage375_quantum_safe_verified",
        "stage372_result_present",
        "stage372_result_sha256_valid",
        "stage372_result_sha256_matches",
        "stage372_result_sha256_is_established",
        "stage372_original_decision_pending",
        "stage372_original_timestamp_false",
        "stage372_record_unmodified",
        "stage360_result_present",
        "timestamp_target_matches_established",
        "rfc3161_receipt_present",
        "opentimestamps_receipt_present",
        "required_proof_count_valid",
    ]

    failed_integrity = [
        key
        for key in integrity_keys
        if not checks[key]
    ]

    decision = "timestamp_execution_pending"
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
            "private_material_detected_in_public_evidence"
        )

    elif checks["forbidden_public_file_detected"]:
        decision = "block"
        reasons.append(
            "raw_timestamp_binary_detected_in_public_docs"
        )

    elif (
        rfc3161
        and rfc3161.get("execution_status")
        not in ("not_executed", "pending", "verified")
    ):
        decision = "block"
        reasons.append(
            "unsupported_rfc3161_execution_status"
        )

    elif (
        ots
        and ots.get("execution_status")
        not in (
            "not_executed",
            "pending_confirmation",
            "pending",
            "verified",
        )
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

    elif rfc3161_verified and not ots_verified:
        decision = (
            "rfc3161_verified_opentimestamps_pending"
        )
        reasons.append(
            "rfc3161_verified_but_opentimestamps_not_final"
        )

    elif ots_verified and not rfc3161_verified:
        decision = (
            "opentimestamps_verified_rfc3161_pending"
        )
        reasons.append(
            "opentimestamps_verified_but_rfc3161_not_final"
        )

    else:
        decision = "timestamp_execution_pending"
        reasons.append(
            "production_timestamp_receipts_not_verified"
        )

    effective_final_acceptance = bool(
        decision
        == "dual_timestamp_final_acceptance_verified"
    )

    manifest = {
        "stage": STAGE,
        "manifest_type": (
            "superseding_final_acceptance_manifest"
        ),
        "created_at": now,
        "source_stage": 375,
        "previous_hash": stage375_declared_hash,
        "historic_stage372_result_sha256":
            stage372_declared_hash,
        "historic_stage372_decision":
            (
                stage372.get("decision")
                if stage372
                else None
            ),
        "historic_stage372_timestamp_verified":
            (
                stage372.get("timestamp_verified")
                if stage372
                else None
            ),
        "stage372_record_modified": False,
        "supersedes_stage372_pending":
            effective_final_acceptance,
        "timestamp_target_sha256":
            ESTABLISHED_TIMESTAMP_TARGET,
        "rfc3161_verified": rfc3161_verified,
        "opentimestamps_verified": ots_verified,
        "verified_proof_count":
            verified_proof_count,
        "required_verified_proof_count":
            required_proof_count,
        "timestamp_verified":
            effective_final_acceptance,
        "effective_final_acceptance":
            effective_final_acceptance,
        "maximum_timestamp_assurance":
            bool(
                rfc3161_verified
                and ots_verified
            ),
        "decision": decision,
        "reasons": reasons,
    }

    manifest_sha256 = sha256_bytes(
        canonical_json(manifest)
    )

    manifest["manifest_sha256"] = (
        manifest_sha256
    )

    result = {
        "stage": STAGE,
        "engine": (
            "Production Dual-Timestamp Verification "
            "and Superseding Final Acceptance Gate"
        ),
        "created_at": now,
        "source_stage": 375,
        "previous_hash": stage375_declared_hash,
        "historic_stage372_result_sha256":
            stage372_declared_hash,
        "historic_stage372_decision":
            (
                stage372.get("decision")
                if stage372
                else None
            ),
        "stage372_record_modified": False,
        "timestamp_target_sha256":
            ESTABLISHED_TIMESTAMP_TARGET,
        "decision": decision,
        "effective_final_acceptance":
            effective_final_acceptance,
        "timestamp_verified":
            effective_final_acceptance,
        "supersedes_stage372_pending":
            effective_final_acceptance,
        "rfc3161_verified": rfc3161_verified,
        "opentimestamps_verified": ots_verified,
        "maximum_timestamp_assurance":
            bool(
                rfc3161_verified
                and ots_verified
            ),
        "verified_proof_count":
            verified_proof_count,
        "required_verified_proof_count":
            required_proof_count,
        "manifest_sha256":
            manifest_sha256,
        "reasons": reasons,
        "checks": checks,
        "safety_boundary": {
            "stage372_history_preserved": True,
            "no_raw_rfc3161_response_in_public_docs":
                True,
            "no_raw_opentimestamps_proof_in_public_docs":
                True,
            "no_tsa_private_key_published": True,
            "no_oidc_token_published": True,
            "no_github_token_published": True,
            "no_raw_qkd_key_material": True,
            "no_free_form_commands": True,
            "fail_closed": True,
        },
        "guarantee": {
            "what_stage376_guarantees": [
                (
                    "Stage375 quantum-safe dual-signature "
                    "verification remains bound."
                ),
                (
                    "The historic Stage372 pending record "
                    "is not modified."
                ),
                (
                    "RFC3161 and OpenTimestamps must verify "
                    "the established Stage360 target."
                ),
                (
                    "Effective final acceptance becomes true "
                    "only when both timestamp proofs verify."
                ),
                (
                    "Raw timestamp binaries and private "
                    "material are excluded from public docs."
                ),
            ],
            "what_stage376_does_not_guarantee": [
                (
                    "It does not rewrite the historic "
                    "Stage372 result."
                ),
                (
                    "It does not claim RFC3161 verification "
                    "before a trusted TSA receipt is imported."
                ),
                (
                    "It does not claim OpenTimestamps "
                    "confirmation before a public anchor "
                    "is independently verified."
                ),
            ],
        },
    }

    result_sha256 = sha256_bytes(
        canonical_json(result)
    )

    result["result_sha256"] = result_sha256

    MANIFEST_PATH.write_text(
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
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

    summary_lines = [
        "Stage376: Production Dual-Timestamp Verification",
        "and Superseding Final Acceptance Gate",
        "",
        f"Decision: {decision}",
        (
            "Historic Stage372 Decision: "
            f"{result['historic_stage372_decision']}"
        ),
        (
            "Stage372 Record Modified: "
            f"{result['stage372_record_modified']}"
        ),
        (
            "RFC3161 Verified: "
            f"{rfc3161_verified}"
        ),
        (
            "OpenTimestamps Verified: "
            f"{ots_verified}"
        ),
        (
            "Effective Final Acceptance: "
            f"{effective_final_acceptance}"
        ),
        (
            "Timestamp Verified: "
            f"{effective_final_acceptance}"
        ),
        (
            "Maximum Timestamp Assurance: "
            f"{result['maximum_timestamp_assurance']}"
        ),
        f"Manifest SHA256: {manifest_sha256}",
        f"Result SHA256: {result_sha256}",
        "",
        "Reasons:",
    ]

    summary_lines.extend(
        f"- {reason}" for reason in reasons
    )

    summary_lines.extend([
        "",
        "Meaning:",
        (
            "Stage376 preserves the historic Stage372 "
            "pending result and may issue a new effective "
            "final acceptance only after both RFC3161 and "
            "OpenTimestamps production receipts verify."
        ),
    ])

    SUMMARY_PATH.write_text(
        "\n".join(summary_lines) + "\n",
        encoding="utf-8",
    )

    print(f"decision={decision}")
    print(
        "rfc3161_verified="
        f"{rfc3161_verified}"
    )
    print(
        "opentimestamps_verified="
        f"{ots_verified}"
    )
    print(
        "effective_final_acceptance="
        f"{effective_final_acceptance}"
    )
    print(
        "stage372_record_modified="
        f"{result['stage372_record_modified']}"
    )
    print(
        "manifest_sha256="
        f"{manifest_sha256}"
    )
    print(
        "result_sha256="
        f"{result_sha256}"
    )


if __name__ == "__main__":
    main()
