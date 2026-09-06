#!/usr/bin/env python3
"""Fail when committed CI configuration weakens supply-chain trust."""

from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION_SHA = re.compile(r"^\s*#?\s*-?\s*uses:\s+([^./\s][^@\s]*)@([^\s#]+)")
FULL_SHA = re.compile(r"[0-9a-f]{40}")


def fail(message: str, failures: list[str]) -> None:
    failures.append(message)


def check_actions(failures: list[str]) -> None:
    files = [*WORKFLOWS.iterdir(), *(ROOT / ".github" / "actions").rglob("*.yml")]
    for path in files:
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = ACTION_SHA.match(line)
            if match and not FULL_SHA.fullmatch(match.group(2)):
                fail(f"{path.relative_to(ROOT)}:{number}: action is not pinned to a full commit SHA", failures)


def check_workflows(failures: list[str]) -> None:
    for path in WORKFLOWS.glob("*.yml"):
        text = path.read_text()
        name = path.relative_to(ROOT)
        if "\npermissions:\n" not in text:
            fail(f"{name}: missing explicit top-level permissions", failures)
        if re.search(r"^ {2,4}[^ #\n][^:\n]*:\s+write\s*$", text, re.MULTILINE):
            fail(f"{name}: GITHUB_TOKEN write permission is not allowed", failures)
        if "pull_request_target:" in text:
            fail(f"{name}: pull_request_target is not allowed", failures)
        if re.search(r"run:[^\n]*(?:github\.event|github\.head_ref|inputs\.)", text):
            fail(f"{name}: untrusted expression is interpolated directly into a command", failures)

        lines = text.splitlines()
        for index, line in enumerate(lines):
            if re.match(r"^\s*-\s+uses:\s+actions/checkout@", line):
                block = "\n".join(lines[index + 1 : index + 6])
                if "persist-credentials: false" not in block:
                    fail(f"{name}:{index + 1}: checkout must disable persisted credentials", failures)


def check_tools(failures: list[str]) -> None:
    config = tomllib.loads((ROOT / ".mise.toml").read_text())
    for tool, version in config["tools"].items():
        if version == "latest" or not re.fullmatch(r"\d+\.\d+\.\d+", version):
            fail(f".mise.toml: {tool} must use an exact version", failures)

    for number, line in enumerate((ROOT / ".tool-versions").read_text().splitlines(), 1):
        if line and not re.fullmatch(r"\S+ \d+\.\d+\.\d+", line):
            fail(f".tool-versions:{number}: tool must use an exact version", failures)

    lock = tomllib.loads((ROOT / "mise.lock").read_text())
    for tool, entries in lock["tools"].items():
        for entry in entries:
            for platform, metadata in entry.get("platforms", {}).items():
                checksum = metadata.get("checksum", "")
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", checksum):
                    fail(f"mise.lock: {tool} {platform} lacks a SHA-256 checksum", failures)

    action = (ROOT / ".github" / "actions" / "mise" / "action.yml").read_text()
    if not re.search(r'version:\s*"\d+\.\d+\.\d+"', action):
        fail(".github/actions/mise/action.yml: mise binary version is not pinned", failures)
    if not re.search(r'sha256:\s*"[0-9a-f]{64}"', action):
        fail(".github/actions/mise/action.yml: mise binary checksum is not pinned", failures)
    if 'MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES: ""' not in action:
        fail(".github/actions/mise/action.yml: locked CI must exclude .tool-versions aliases", failures)


def check_release_binding(failures: list[str]) -> None:
    publish = (WORKFLOWS / "publish.yml").read_text()
    required = (
        "workflow_run:",
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.path == '.github/workflows/ci.yml'",
        "scripts/release_gate.py pr",
        "scripts/release_gate.py ci",
        "ref: ${{ needs.gate.outputs.release-sha }}",
        'environment: release',
    )
    for marker in required:
        if marker not in publish:
            fail(f".github/workflows/publish.yml: missing release binding marker {marker!r}", failures)

    gate = (ROOT / "scripts" / "release_gate.py").read_text()
    for marker in ("merge_commit_sha", "release/pending", "full_name", "event"):
        if marker not in gate:
            fail(f"scripts/release_gate.py: missing release validation marker {marker!r}", failures)

    ci = (WORKFLOWS / "ci.yml").read_text()
    if "HEXPM_READ_API_KEY" in ci or "secrets." in ci:
        fail(".github/workflows/ci.yml: pull-request CI must not receive secrets", failures)
    if "if: github.event_name == 'push'" not in ci:
        fail(".github/workflows/ci.yml: dependency cache save is not restricted to trusted push", failures)


def main() -> int:
    failures: list[str] = []
    check_actions(failures)
    check_workflows(failures)
    check_tools(failures)
    check_release_binding(failures)
    if failures:
        print("\n".join(f"ERROR: {failure}" for failure in failures), file=sys.stderr)
        return 1
    print("CI security policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
