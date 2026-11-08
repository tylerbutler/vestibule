#!/usr/bin/env python3

import unittest
from release_ready import incomplete_releases
from release_request import release_arguments


def package(name="vestibule", version="0.2.0", lifecycle="git_only", releasable=True):
    return {"name": name, "version": version, "lifecycle": lifecycle, "releasable": releasable}


def release(tag="vestibule-v0.2.0", draft=False, prerelease=False):
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease}


def missing(packages=None, tags=None, releases=None, exact_tag_format="{name}-v{version}"):
    return incomplete_releases(
        {"schema": "trellis.list/1", "packages": packages if packages is not None else [package()]},
        {"schema": "trellis.tag_plan/2", "tags": tags or []},
        releases if releases is not None else [release()],
        exact_tag_format,
    )


class ReleaseRequestTest(unittest.TestCase):
    def test_empty_inputs_preserve_native_mode(self):
        self.assertEqual(release_arguments("", ""), [])

    def test_rc_with_separate_package_targets(self):
        self.assertEqual(
            release_arguments(" rc ", "vestibule=0.2.0\nvestibule_github=0.3.0"),
            ["--pre", "rc", "--set", "vestibule=0.2.0", "--set", "vestibule_github=0.3.0"],
        )

    def test_explicit_promotion(self):
        self.assertEqual(release_arguments("none", ""), ["--pre", "none"])

    def test_rejects_invalid_mode_targets_and_shell_inputs(self):
        for pre, targets in (
            ("beta", ""),
            ("$(touch injected)", ""),
            ("", "--force"),
            ("", "vestibule=0.2"),
            ("", "vestibule=0.2.0-rc.0"),
            ("", "vestibule=0.2.0;touch injected"),
            ("", "vestibule=0.2.0 vestibule=0.3.0"),
        ):
            with self.subTest(pre=pre, targets=targets), self.assertRaises(ValueError):
                release_arguments(pre, targets)


class ReleaseReadyTest(unittest.TestCase):
    def test_accepts_completed_release_and_excludes_workspace_members(self):
        self.assertEqual(missing(packages=[
            package(), package("example", lifecycle="workspace", releasable=False),
        ]), [])

    def test_blocks_pending_tags(self):
        self.assertTrue(missing(tags=[{"tag": "vestibule-v0.2.0"}]))

    def test_blocks_missing_or_draft_releases(self):
        for releases in ([], [release(draft=True)], [release("vestibule-v0.1.0")]):
            with self.subTest(releases=releases):
                self.assertTrue(missing(releases=releases))

    def test_requires_every_independent_package_release(self):
        packages = [package(), package("vestibule_github", "0.1.0")]
        self.assertTrue(missing(packages=packages))
        self.assertEqual(missing(packages=packages, releases=[
            release(), release("vestibule_github-v0.1.0"),
        ]), [])

    def test_checks_candidate_classification_and_retry_completion(self):
        packages = [package(version="0.2.0-rc.0")]
        self.assertTrue(missing(packages=packages, releases=[release("vestibule-v0.2.0-rc.0")]))
        self.assertEqual(missing(packages=packages, releases=[
            release("vestibule-v0.2.0-rc.0", prerelease=True),
        ]), [])
        self.assertTrue(missing(releases=[release(prerelease=True)]))

    def test_uses_configured_exact_tag_format(self):
        self.assertEqual(missing(
            releases=[release("v0.2.0")], exact_tag_format="v{version}",
        ), [])

    def test_rejects_hex_release_lifecycle(self):
        self.assertTrue(missing(packages=[package(lifecycle="hex")]))

    def test_rejects_unknown_native_schema(self):
        with self.assertRaises(ValueError):
            incomplete_releases(
                {"schema": "trellis.list/2", "packages": []},
                {"schema": "trellis.tag_plan/2", "tags": []}, [], "{name}-v{version}",
            )


if __name__ == "__main__":
    unittest.main()
