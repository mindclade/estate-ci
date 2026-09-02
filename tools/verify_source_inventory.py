#!/usr/bin/env python3
"""Verify the source-ready layout and the pinned organization policy artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


AUTHORITY_REVISION = "b4d28faa5fde98087f60262110a43f25f6da9eb8"
EXPECTED_GENERATED = {
    "generated/bazelrc.common",
    "generated/nix-bazel-policy.lock.json",
    "generated/nix-bazel-policy.nix",
    "generated/toolchain-manifest.defaults.json",
}
EXPECTED_SYSTEMS = ["aarch64-darwin", "aarch64-linux", "x86_64-linux"]


class VerificationError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{path} must contain a JSON object")
    return value


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_relative(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or value != path.as_posix():
        raise VerificationError(f"inventory path is not a safe canonical relative path: {value}")
    return path


def verify(root: Path) -> None:
    root = root.resolve()
    inventory = _load(root / "ci/source-inventory.json")
    if set(inventory) != {"schema_version", "authority", "generated_artifacts", "required_sources"}:
        raise VerificationError("source inventory has unexpected or missing fields")
    if inventory["schema_version"] != "estate.source-inventory/v1":
        raise VerificationError("source inventory schema version is unsupported")
    if inventory["authority"] != {
        "repository": "mindclade/.github",
        "implementation_revision": AUTHORITY_REVISION,
    }:
        raise VerificationError("source inventory authority is not the approved organization revision")

    artifacts = inventory["generated_artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != EXPECTED_GENERATED:
        raise VerificationError("generated artifact inventory must contain exactly the four canonical outputs")
    generated_dir = root / "generated"
    actual_generated = {
        path.relative_to(root).as_posix()
        for path in generated_dir.iterdir()
        if path.is_file()
    } if generated_dir.is_dir() else set()
    if actual_generated != EXPECTED_GENERATED:
        raise VerificationError("generated directory drift: missing or unexpected artifact")
    for name in sorted(EXPECTED_GENERATED):
        path = root / _safe_relative(name)
        actual = _digest(path)
        if artifacts[name] != actual:
            raise VerificationError(f"generated artifact digest drift: {name}: {actual}")

    required_sources = inventory["required_sources"]
    if not isinstance(required_sources, list) or required_sources != sorted(set(required_sources)):
        raise VerificationError("required_sources must be a unique sorted list")
    for name in required_sources:
        if not isinstance(name, str) or not (root / _safe_relative(name)).is_file():
            raise VerificationError(f"required source is missing: {name}")

    upstream_lock = _load(root / "generated/nix-bazel-policy.lock.json")
    authority = upstream_lock.get("authority")
    if authority != {"repository": "mindclade/.github", "revision": AUTHORITY_REVISION}:
        raise VerificationError("upstream policy lock authority is invalid")
    upstream_artifacts = upstream_lock.get("artifacts")
    if not isinstance(upstream_artifacts, dict):
        raise VerificationError("upstream policy lock has no artifact map")
    for name in sorted(EXPECTED_GENERATED - {"generated/nix-bazel-policy.lock.json"}):
        if upstream_artifacts.get(name) != artifacts[name]:
            raise VerificationError(f"local artifact does not match upstream lock: {name}")

    toolchain = _load(root / "generated/toolchain-manifest.defaults.json")
    if toolchain.get("authority", {}).get("revision") != AUTHORITY_REVISION:
        raise VerificationError("toolchain manifest is not pinned to the approved revision")
    if toolchain.get("supported_systems") != EXPECTED_SYSTEMS:
        raise VerificationError("toolchain manifest supported systems drifted")

    profile = _load(root / "ci/required-workflow-profile.json")
    if profile.get("authority", {}).get("implementation_revision") != AUTHORITY_REVISION:
        raise VerificationError("required workflow profile pin drifted")
    if profile.get("profile") != "buildkite-isolated" or profile.get("required_context") != "Pull request / required":
        raise VerificationError("required workflow profile contract is invalid")
    if profile.get("repository_local_duplicate_forbidden") is not True:
        raise VerificationError("repository-local required workflow must remain forbidden")

    workflow_dir = root / ".github/workflows"
    if workflow_dir.exists() and any(path.is_file() for path in workflow_dir.rglob("*")):
        raise VerificationError("repository-local GitHub Actions workflows are forbidden")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        verify(args.root)
    except VerificationError as error:
        print(f"source inventory verification failed: {error}")
        return 1
    print(f"source inventory verified at organization revision {AUTHORITY_REVISION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
