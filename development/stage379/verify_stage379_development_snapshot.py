import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List


MANIFEST_PATH = Path(
    "development/stage379/"
    "stage379_development_snapshot_manifest.json"
)


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


def main() -> int:
    reasons: List[str] = []

    if not MANIFEST_PATH.is_file():
        print("snapshot_verification_completed: False")
        print("decision=block")
        print("reasons=['snapshot_manifest_missing']")
        return 1

    try:
        manifest = json.loads(
            MANIFEST_PATH.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        print("snapshot_verification_completed: False")
        print("decision=block")
        print("reasons=['snapshot_manifest_invalid_json']")
        return 1

    if not isinstance(manifest, dict):
        print("snapshot_verification_completed: False")
        print("decision=block")
        print("reasons=['snapshot_manifest_root_invalid']")
        return 1

    declared_manifest_hash = manifest.get(
        "manifest_sha256"
    )

    manifest_without_hash = dict(manifest)
    manifest_without_hash.pop("manifest_sha256", None)

    recomputed_manifest_hash = hashlib.sha256(
        canonical_json(manifest_without_hash)
    ).hexdigest()

    manifest_hash_format_valid = is_sha256(
        declared_manifest_hash
    )

    manifest_self_hash_valid = all([
        manifest_hash_format_valid,
        declared_manifest_hash
            == recomputed_manifest_hash,
    ])

    if not manifest_hash_format_valid:
        reasons.append("manifest_hash_format_invalid")
    elif not manifest_self_hash_valid:
        reasons.append("manifest_self_hash_invalid")

    manifest_structure_valid = all([
        manifest.get("stage") == 379,
        manifest.get("manifest_type")
            == "development_snapshot_manifest",
        manifest.get("execution_mode")
            == "development",
        manifest.get("development_only") is True,
        manifest.get("formal_acceptance") is False,
        manifest.get("pipeline_completed") is False,
        manifest.get("public_release_allowed") is False,
        isinstance(manifest.get("artifacts"), list),
    ])

    if not manifest_structure_valid:
        reasons.append("manifest_structure_invalid")

    artifacts = manifest.get("artifacts", [])

    declared_artifact_count = manifest.get(
        "artifact_count"
    )

    artifact_count_valid = all([
        isinstance(declared_artifact_count, int),
        declared_artifact_count == len(artifacts),
    ])

    if not artifact_count_valid:
        reasons.append("artifact_count_mismatch")

    invalid_artifacts: List[Dict[str, Any]] = []
    duplicate_paths: List[str] = []
    seen_paths = set()

    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            invalid_artifacts.append({
                "index": index,
                "path": None,
                "reason": "artifact_record_invalid",
            })
            continue

        path_value = artifact.get("path")
        declared_hash = artifact.get("sha256")
        declared_size = artifact.get("size_bytes")

        if not isinstance(path_value, str) or not path_value:
            invalid_artifacts.append({
                "index": index,
                "path": path_value,
                "reason": "artifact_path_invalid",
            })
            continue

        if path_value in seen_paths:
            duplicate_paths.append(path_value)
        else:
            seen_paths.add(path_value)

        path = Path(path_value)

        if not path.is_file():
            invalid_artifacts.append({
                "index": index,
                "path": path_value,
                "reason": "artifact_missing",
            })
            continue

        actual_hash = sha256_file(path)
        actual_size = path.stat().st_size

        if not is_sha256(declared_hash):
            invalid_artifacts.append({
                "index": index,
                "path": path_value,
                "reason": "artifact_hash_format_invalid",
            })
            continue

        if declared_hash != actual_hash:
            invalid_artifacts.append({
                "index": index,
                "path": path_value,
                "reason": "artifact_hash_mismatch",
                "declared_hash": declared_hash,
                "actual_hash": actual_hash,
            })

        if not isinstance(declared_size, int):
            invalid_artifacts.append({
                "index": index,
                "path": path_value,
                "reason": "artifact_size_invalid",
            })
        elif declared_size != actual_size:
            invalid_artifacts.append({
                "index": index,
                "path": path_value,
                "reason": "artifact_size_mismatch",
                "declared_size": declared_size,
                "actual_size": actual_size,
            })

    if duplicate_paths:
        reasons.append("duplicate_artifact_paths_detected")

    if invalid_artifacts:
        reasons.append("artifact_verification_failed")

    valid_artifact_count = (
        len(artifacts)
        - len({
            item.get("index")
            for item in invalid_artifacts
        })
    )

    all_artifact_hashes_valid = (
        len(invalid_artifacts) == 0
    )

    safe_development_state = all([
        manifest.get("development_only") is True,
        manifest.get("formal_acceptance") is False,
        manifest.get("pipeline_completed") is False,
        manifest.get("public_release_allowed") is False,
    ])

    if not safe_development_state:
        reasons.append("unsafe_development_state")

    snapshot_valid = all([
        manifest_self_hash_valid,
        manifest_structure_valid,
        artifact_count_valid,
        all_artifact_hashes_valid,
        not duplicate_paths,
        safe_development_state,
    ])

    decision = (
        "development_snapshot_verified"
        if snapshot_valid
        else "block"
    )

    print("Stage379 development snapshot verification completed.")
    print(f"decision={decision}")
    print(
        "manifest_self_hash_valid="
        f"{manifest_self_hash_valid}"
    )
    print(
        "manifest_structure_valid="
        f"{manifest_structure_valid}"
    )
    print(
        "artifact_count_valid="
        f"{artifact_count_valid}"
    )
    print(
        "declared_artifact_count="
        f"{declared_artifact_count}"
    )
    print(
        "actual_artifact_count="
        f"{len(artifacts)}"
    )
    print(
        "valid_artifact_count="
        f"{valid_artifact_count}"
    )
    print(
        "invalid_artifact_count="
        f"{len(invalid_artifacts)}"
    )
    print(
        "duplicate_artifact_path_count="
        f"{len(duplicate_paths)}"
    )
    print(
        "all_artifact_hashes_valid="
        f"{all_artifact_hashes_valid}"
    )
    print(
        "safe_development_state="
        f"{safe_development_state}"
    )
    print(
        "snapshot_valid="
        f"{snapshot_valid}"
    )
    print(
        "manifest_sha256="
        f"{declared_manifest_hash}"
    )
    print(
        "reasons="
        f"{reasons}"
    )

    if duplicate_paths:
        print("duplicate_artifact_paths:")
        for path in sorted(set(duplicate_paths)):
            print(f"- {path}")

    if invalid_artifacts:
        print("invalid_artifacts:")
        for artifact in invalid_artifacts:
            print(
                json.dumps(
                    artifact,
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )

    return 0 if snapshot_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
