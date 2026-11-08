#!/usr/bin/env python3
"""Require the previous package versions to be tagged and released."""

import argparse
import json
from pathlib import Path
import sys
import tomllib


def incomplete_releases(
    packages: dict, tags: dict, releases: list[dict], exact_tag_format: str
) -> list[str]:
    failures = []
    if packages["schema"] != "trellis.list/1" or tags["schema"] != "trellis.tag_plan/2":
        raise ValueError("unsupported Trellis package or tag plan schema")
    if tags["tags"]:
        failures.append("Tags are still pending for the current package versions.")
    published = {release["tag_name"]: release for release in releases}
    for package in packages["packages"]:
        if not package["releasable"]:
            continue
        if package["lifecycle"] != "git_only":
            failures.append(f"{package['name']} must use the git_only lifecycle.")
            continue
        tag = exact_tag_format.format(name=package["name"], version=package["version"])
        release = published.get(tag)
        candidate = "-" in package["version"].split("+", 1)[0]
        if (
            release is None
            or release["draft"]
            or release["prerelease"] != candidate
        ):
            failures.append(f"{tag} needs a published GitHub Release with the correct prerelease flag.")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--tags", type=Path, required=True)
    parser.add_argument("--releases", type=Path, required=True)
    args = parser.parse_args()
    config = tomllib.loads(Path("gleam.toml").read_text())
    exact_tag_format = config["tools"]["trellis"]["publish"].get(
        "exact_tag_format", "{name}-v{version}"
    )
    failures = incomplete_releases(
        json.loads(args.packages.read_text()),
        json.loads(args.tags.read_text()),
        [release for page in json.loads(args.releases.read_text()) for release in page],
        exact_tag_format,
    )
    if failures:
        print("\n".join(f"ERROR: {failure}" for failure in failures), file=sys.stderr)
        print(
            "Retry Tag and release for the preceding reviewed merge SHA, then rerun "
            "Prepare release. Do not prepare another version before recovery.",
            file=sys.stderr,
        )
        return 1
    print("Current package versions are fully tagged and released.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
