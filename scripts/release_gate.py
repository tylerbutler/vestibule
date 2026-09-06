#!/usr/bin/env python3
"""Validate that a release SHA is the reviewed merge that passed trusted CI."""

import argparse
import json
import sys


def matching_release_pr(pulls: list[dict], sha: str, repository: str) -> bool:
    return any(
        pull.get("merged_at")
        and pull.get("merge_commit_sha") == sha
        and pull.get("base", {}).get("ref") == "main"
        and pull.get("base", {}).get("repo", {}).get("full_name") == repository
        and pull.get("head", {}).get("ref") == "release/pending"
        and pull.get("head", {}).get("repo", {}).get("full_name") == repository
        for pull in pulls
    )


def latest_ci_run_succeeded(payload: dict, sha: str, repository: str) -> bool:
    matching = [
        run
        for run in payload.get("workflow_runs", [])
        if run.get("head_sha") == sha
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("head_repository", {}).get("full_name") == repository
    ]
    if not matching:
        return False
    latest = max(matching, key=lambda run: (run.get("run_number", 0), run.get("run_attempt", 0)))
    return latest.get("status") == "completed" and latest.get("conclusion") == "success"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("check", choices=("pr", "ci"))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    payload = json.load(sys.stdin)
    if args.check == "pr":
        valid = matching_release_pr(payload, args.sha, args.repository)
    else:
        valid = latest_ci_run_succeeded(payload, args.sha, args.repository)
    print("true" if valid else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
