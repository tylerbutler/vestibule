#!/usr/bin/env python3
"""Validate release inputs without interpreting release state."""

import argparse
import json
import re
import subprocess


def release_arguments(pre: str, targets: str) -> list[str]:
    pre = pre.strip()
    if pre not in ("", "rc", "none"):
        raise ValueError("pre must be empty, rc, or none")
    arguments = ["--pre", pre] if pre else []
    seen = set()
    for target in targets.split():
        if not re.fullmatch(r"[a-z][a-z0-9_]*=[0-9]+\.[0-9]+\.[0-9]+", target):
            raise ValueError(f"invalid target {target!r}; use package=X.Y.Z")
        package = target.split("=", 1)[0]
        if package in seen:
            raise ValueError(f"duplicate target for {package}")
        seen.add(package)
        arguments.extend(["--set", target])
    return arguments


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pre", default="")
    parser.add_argument("--targets", default="")
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    try:
        arguments = release_arguments(args.pre, args.targets)
    except ValueError as error:
        parser.error(str(error))
    if args.plan:
        subprocess.run(["trellis", "version", "plan", *arguments], check=True)
    else:
        print(json.dumps(arguments))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
