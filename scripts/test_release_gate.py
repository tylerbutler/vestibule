#!/usr/bin/env python3

import unittest

from release_gate import latest_ci_run_succeeded, matching_release_pr


REPOSITORY = "tylerbutler/vestibule"
SHA = "a" * 40


def release_pr(**changes):
    pull = {
        "merged_at": "2026-09-05T00:00:00Z",
        "merge_commit_sha": SHA,
        "base": {"ref": "main", "repo": {"full_name": REPOSITORY}},
        "head": {"ref": "release/pending", "repo": {"full_name": REPOSITORY}},
    }
    pull.update(changes)
    return pull


def ci_run(**changes):
    run = {
        "head_sha": SHA,
        "head_branch": "main",
        "event": "push",
        "path": ".github/workflows/ci.yml",
        "head_repository": {"full_name": REPOSITORY},
        "run_number": 10,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
    }
    run.update(changes)
    return run


class ReleaseGateTest(unittest.TestCase):
    def test_accepts_exact_release_merge(self):
        self.assertTrue(matching_release_pr([release_pr()], SHA, REPOSITORY))

    def test_rejects_earlier_associated_commit(self):
        self.assertFalse(
            matching_release_pr([release_pr(merge_commit_sha="b" * 40)], SHA, REPOSITORY)
        )

    def test_rejects_cross_repository_head(self):
        self.assertFalse(
            matching_release_pr(
                [release_pr(head={"ref": "release/pending", "repo": {"full_name": "fork/repo"}})],
                SHA,
                REPOSITORY,
            )
        )

    def test_accepts_latest_successful_push_run(self):
        payload = {"workflow_runs": [ci_run(run_number=11), ci_run(run_number=10)]}
        self.assertTrue(latest_ci_run_succeeded(payload, SHA, REPOSITORY))

    def test_rejects_latest_failed_rerun_without_counting_duplicates(self):
        payload = {
            "workflow_runs": [
                ci_run(run_number=11, run_attempt=2, conclusion="failure"),
                ci_run(run_number=11, run_attempt=1),
                ci_run(run_number=10),
            ]
        }
        self.assertFalse(latest_ci_run_succeeded(payload, SHA, REPOSITORY))

    def test_rejects_pull_request_ci(self):
        payload = {"workflow_runs": [ci_run(event="pull_request")]}
        self.assertFalse(latest_ci_run_succeeded(payload, SHA, REPOSITORY))

    def test_rejects_wrong_sha_or_repository_or_workflow(self):
        for change in (
            {"head_sha": "b" * 40},
            {"head_repository": {"full_name": "fork/repo"}},
            {"path": ".github/workflows/other.yml"},
        ):
            with self.subTest(change=change):
                self.assertFalse(
                    latest_ci_run_succeeded({"workflow_runs": [ci_run(**change)]}, SHA, REPOSITORY)
                )

    def test_rejects_latest_incomplete_attempt(self):
        payload = {"workflow_runs": [
            ci_run(run_attempt=2, status="in_progress", conclusion=None),
            ci_run(run_attempt=1),
        ]}
        self.assertFalse(latest_ci_run_succeeded(payload, SHA, REPOSITORY))

    def test_rejects_unmerged_or_wrong_base_release_pr(self):
        for change in (
            {"merged_at": None},
            {"base": {"ref": "feature", "repo": {"full_name": REPOSITORY}}},
            {"base": {"ref": "main", "repo": {"full_name": "fork/repo"}}},
            {"head": {"ref": "feature", "repo": {"full_name": REPOSITORY}}},
        ):
            with self.subTest(change=change):
                self.assertFalse(matching_release_pr([release_pr(**change)], SHA, REPOSITORY))


if __name__ == "__main__":
    unittest.main()
