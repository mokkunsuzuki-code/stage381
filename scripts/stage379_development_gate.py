import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


STAGE = 379
SOURCE_STAGE = 378

POLICY_PATH = Path(".stage379-development-policy.json")

STAGE377_RESULT_PATH = Path(
    "docs/timestamp-finalization/"
    "stage377_dual_timestamp_finalization_result.json"
)

STAGE378_RESULT_PATH = Path(
    "docs/qkd/"
    "stage378_qkd_safety_metadata_binding_result.json"
)

RESULT_PATH = Path(
    "development/stage379_development_gate_result.json"
)

SUMMARY_PATH = Path(
    "development/stage379_development_gate_summary.txt"
)


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None

    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    return parsed if isinstance(parsed, dict) else None


def recompute_self_hash(
    data: Optional[Dict[str, Any]],
    hash_field: str,
) -> Optional[str]:
    if not isinstance(data, dict):
        return None

    copied = dict(data)
    copied.pop(hash_field, None)
    return sha256_bytes(canonical_json(copied))


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


def write_json_with_hash(
    path: Path,
    payload: Dict[str, Any],
    hash_field: str,
) -> Dict[str, Any]:
    output = dict(payload)
    output[hash_field] = sha256_bytes(canonical_json(output))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(output) + b"\n")

    return output


def main() -> int:
    created_at = datetime.now(timezone.utc).isoformat()

    policy = read_json(POLICY_PATH)
    stage377 = read_json(STAGE377_RESULT_PATH)
    stage378 = read_json(STAGE378_RESULT_PATH)

    policy_present = policy is not None
    stage377_present = stage377 is not None
    stage378_present = stage378 is not None

    policy_valid = all([
        policy_present,
        policy.get("stage") == STAGE if policy else False,
        policy.get("workspace_name") == "stage379-development"
            if policy else False,
        policy.get("execution_mode") == "development"
            if policy else False,
        policy.get("development_only") is True
            if policy else False,
        policy.get("production_eligible") is False
            if policy else False,
        policy.get("public_release_allowed") is False
            if policy else False,
        policy.get("git_repository_initialization_allowed") is False
            if policy else False,
        policy.get("github_push_allowed") is False
            if policy else False,
        policy.get("formal_stage379_acceptance") is False
            if policy else False,
    ])

    git_metadata_absent = not Path(".git").exists()

    stage377_declared_hash = (
        stage377.get("result_sha256")
        if stage377
        else None
    )

    stage377_recomputed_hash = recompute_self_hash(
        stage377,
        "result_sha256",
    )

    stage377_hash_valid = all([
        is_sha256(stage377_declared_hash),
        stage377_recomputed_hash is not None,
        stage377_declared_hash == stage377_recomputed_hash,
    ])

    stage377_verified_proof_count = (
        stage377.get("verified_proof_count")
        if stage377
        else None
    )

    stage377_effective_final_acceptance = (
        stage377.get("effective_final_acceptance") is True
        if stage377
        else False
    )

    stage377_formal_requirements_satisfied = all([
        stage377_present,
        stage377.get("stage") == 377,
        stage377_hash_valid,
        stage377.get("decision")
            == "dual_timestamp_final_acceptance_verified",
        stage377.get("rfc3161_verified") is True,
        stage377.get("opentimestamps_verified") is True,
        stage377.get("timestamp_verified") is True,
        stage377_verified_proof_count == 2,
        stage377_effective_final_acceptance,
    ])

    stage378_declared_hash = (
        stage378.get("result_sha256")
        if stage378
        else None
    )

    stage378_recomputed_hash = recompute_self_hash(
        stage378,
        "result_sha256",
    )

    stage378_hash_valid = all([
        is_sha256(stage378_declared_hash),
        stage378_recomputed_hash is not None,
        stage378_declared_hash == stage378_recomputed_hash,
    ])

    stage378_previous_hash_matches_stage377 = all([
        stage378_present,
        stage377_present,
        stage378.get("previous_hash")
            == stage377_declared_hash,
        stage378.get("stage377_result_sha256")
            == stage377_declared_hash,
    ])

    stage378_stage377_hash_valid = (
        stage378.get("stage377_hash_valid") is True
        if stage378
        else False
    )

    stage378_stage377_final_acceptance_verified = (
        stage378.get(
            "stage377_final_acceptance_verified"
        ) is True
        if stage378
        else False
    )

    forbidden_public_files = (
        stage378.get("forbidden_public_files")
        if stage378
        else None
    )

    private_content_candidates = (
        stage378.get("private_content_candidates")
        if stage378
        else None
    )

    stage378_public_boundary_valid = all([
        isinstance(forbidden_public_files, list),
        len(forbidden_public_files) == 0,
        isinstance(private_content_candidates, list),
        len(private_content_candidates) == 0,
        stage378.get(
            "raw_qkd_key_publication_detected"
        ) is False if stage378 else False,
        stage378.get(
            "private_material_content_detected"
        ) is False if stage378 else False,
    ])

    stage378_evidence_classification_completed = all([
        stage378_present,
        isinstance(
            stage378.get("evidence_classification"),
            str,
        ),
        bool(
            stage378.get("evidence_classification", "").strip()
        ),
        isinstance(stage378.get("evidence_level"), str),
        stage378.get("evidence_level") != "QKD-E0",
    ])

    formal_promotion_requirements_satisfied = all([
        policy_valid,
        git_metadata_absent,
        stage377_formal_requirements_satisfied,
        stage378_present,
        stage378.get("stage") == SOURCE_STAGE,
        stage378_hash_valid,
        stage378_previous_hash_matches_stage377,
        stage378_stage377_hash_valid,
        stage378_stage377_final_acceptance_verified,
        stage378_public_boundary_valid,
        stage378_evidence_classification_completed,
        stage378.get("qkd_metadata_bound") is True,
        stage378.get("decision") in {
            "qkd_operational_evidence_pending",
            "qkd_safety_metadata_bound",
        },
    ])

    development_execution_allowed = all([
        policy_valid,
        git_metadata_absent,
        stage377_present,
        stage377_hash_valid,
        stage378_present,
        stage378_hash_valid,
        stage378_previous_hash_matches_stage377,
        stage378_stage377_hash_valid,
        stage378_public_boundary_valid,
        stage378_evidence_classification_completed,
    ])

    reasons: List[str] = []

    if not policy_present:
        reasons.append("development_policy_missing")
    elif not policy_valid:
        reasons.append("development_policy_invalid")

    if not git_metadata_absent:
        reasons.append("git_metadata_present_in_development_workspace")

    if not stage377_present:
        reasons.append("stage377_result_missing")
    elif not stage377_hash_valid:
        reasons.append("stage377_result_hash_invalid")
    elif not stage377_formal_requirements_satisfied:
        reasons.append("stage377_formal_acceptance_pending")

    if not stage378_present:
        reasons.append("stage378_result_missing")
    elif stage378.get("stage") != SOURCE_STAGE:
        reasons.append("stage378_result_stage_invalid")
    elif not stage378_hash_valid:
        reasons.append("stage378_result_hash_invalid")

    if (
        stage377_present
        and stage378_present
        and not stage378_previous_hash_matches_stage377
    ):
        reasons.append("stage378_previous_hash_mismatch")

    if not stage378_stage377_hash_valid:
        reasons.append("stage378_stage377_hash_not_verified")

    if not stage378_stage377_final_acceptance_verified:
        reasons.append(
            "stage378_stage377_final_acceptance_pending"
        )

    if not stage378_public_boundary_valid:
        reasons.append("stage378_qkd_public_boundary_invalid")

    if not stage378_evidence_classification_completed:
        reasons.append(
            "stage378_evidence_classification_incomplete"
        )

    if not development_execution_allowed:
        decision = "block"
    elif formal_promotion_requirements_satisfied:
        decision = "formal_promotion_eligible"
    else:
        decision = "development_only_upstream_pending"

    result_payload: Dict[str, Any] = {
        "stage": STAGE,
        "source_stage": SOURCE_STAGE,
        "engine": "Stage379 Development-Only Fail-Closed Gate",
        "created_at": created_at,
        "workspace_name": "stage379-development",
        "execution_mode": "development",
        "development_only": True,
        "production_eligible": False,
        "public_release_allowed": False,
        "formal_stage379_acceptance": False,
        "policy_path": POLICY_PATH.as_posix(),
        "stage377_result_path":
            STAGE377_RESULT_PATH.as_posix(),
        "stage378_result_path":
            STAGE378_RESULT_PATH.as_posix(),
        "previous_hash": stage378_declared_hash,
        "stage377_result_sha256":
            stage377_declared_hash,
        "stage378_result_sha256":
            stage378_declared_hash,
        "checks": {
            "development_policy_present":
                policy_present,
            "development_policy_valid":
                policy_valid,
            "git_metadata_absent":
                git_metadata_absent,
            "stage377_result_present":
                stage377_present,
            "stage377_result_hash_valid":
                stage377_hash_valid,
            "stage377_formal_requirements_satisfied":
                stage377_formal_requirements_satisfied,
            "stage378_result_present":
                stage378_present,
            "stage378_result_hash_valid":
                stage378_hash_valid,
            "stage378_previous_hash_matches_stage377":
                stage378_previous_hash_matches_stage377,
            "stage378_stage377_hash_valid":
                stage378_stage377_hash_valid,
            "stage378_stage377_final_acceptance_verified":
                stage378_stage377_final_acceptance_verified,
            "stage378_qkd_public_boundary_valid":
                stage378_public_boundary_valid,
            "stage378_evidence_classification_completed":
                stage378_evidence_classification_completed,
            "development_execution_allowed":
                development_execution_allowed,
            "formal_promotion_requirements_satisfied":
                formal_promotion_requirements_satisfied,
        },
        "upstream_state": {
            "stage377_decision":
                stage377.get("decision")
                if stage377 else None,
            "stage377_verified_proof_count":
                stage377_verified_proof_count,
            "stage377_effective_final_acceptance":
                stage377_effective_final_acceptance,
            "stage378_decision":
                stage378.get("decision")
                if stage378 else None,
            "stage378_evidence_classification":
                stage378.get("evidence_classification")
                if stage378 else None,
            "stage378_evidence_level":
                stage378.get("evidence_level")
                if stage378 else None,
            "stage378_qkd_metadata_bound":
                stage378.get("qkd_metadata_bound")
                if stage378 else None,
        },
        "decision": decision,
        "reasons": reasons,
        "promotion_rule": (
            "Formal Stage379 creation and publication remain "
            "prohibited until every upstream requirement is "
            "verified from real evidence."
        ),
        "guarantee": (
            "This gate permits isolated development work only. "
            "It does not create, claim, or publish formal "
            "Stage379 acceptance and cannot convert pending "
            "upstream evidence into verified evidence."
        ),
    }

    result = write_json_with_hash(
        RESULT_PATH,
        result_payload,
        "result_sha256",
    )

    summary_lines = [
        "Stage379 Development-Only Fail-Closed Gate",
        "==========================================",
        f"created_at: {created_at}",
        f"decision: {decision}",
        "execution_mode: development",
        "development_only: true",
        "production_eligible: false",
        "public_release_allowed: false",
        "formal_stage379_acceptance: false",
        f"previous_hash: {stage378_declared_hash}",
        (
            "stage377_verified_proof_count: "
            f"{stage377_verified_proof_count}"
        ),
        (
            "stage377_effective_final_acceptance: "
            f"{stage377_effective_final_acceptance}"
        ),
        (
            "stage378_stage377_hash_valid: "
            f"{stage378_stage377_hash_valid}"
        ),
        (
            "stage378_stage377_final_acceptance_verified: "
            f"{stage378_stage377_final_acceptance_verified}"
        ),
        (
            "stage378_qkd_public_boundary_valid: "
            f"{stage378_public_boundary_valid}"
        ),
        (
            "stage378_evidence_classification_completed: "
            f"{stage378_evidence_classification_completed}"
        ),
        (
            "development_execution_allowed: "
            f"{development_execution_allowed}"
        ),
        (
            "formal_promotion_requirements_satisfied: "
            f"{formal_promotion_requirements_satisfied}"
        ),
        f"reasons: {', '.join(reasons) if reasons else 'none'}",
        f"result_sha256: {result['result_sha256']}",
        "",
        (
            "This is a local development result only. "
            "It is not formal Stage379 acceptance."
        ),
    ]

    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text(
        "\n".join(summary_lines) + "\n",
        encoding="utf-8",
    )

    print("Stage379 development gate execution completed.")
    print(f"decision={decision}")
    print(
        "development_execution_allowed="
        f"{development_execution_allowed}"
    )
    print(
        "formal_promotion_requirements_satisfied="
        f"{formal_promotion_requirements_satisfied}"
    )
    print(
        "stage377_verified_proof_count="
        f"{stage377_verified_proof_count}"
    )
    print(
        "stage377_effective_final_acceptance="
        f"{stage377_effective_final_acceptance}"
    )
    print(
        "stage378_stage377_hash_valid="
        f"{stage378_stage377_hash_valid}"
    )
    print(
        "stage378_stage377_final_acceptance_verified="
        f"{stage378_stage377_final_acceptance_verified}"
    )
    print(f"result_sha256={result['result_sha256']}")

    return 0 if development_execution_allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
