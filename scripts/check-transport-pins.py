#!/usr/bin/env python3
"""Fail when a consumer's resolved transport graph has drifted from the pins.

Usage: check-transport-pins.py [Cargo.lock] [transport-pins.toml]

With no path, reads ./Cargo.lock beside ./transport-pins.toml. Compares the
revisions Cargo actually resolved (so it catches drift however the patch was
expressed) and exits 1, naming every crate that is wrong.

Deliberately reads no network: a consumer's gate must pass offline.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


def load_pins(path: Path) -> dict[str, str]:
    pins = tomllib.loads(path.read_text())
    return {name: entry["rev"] for name, entry in pins.items() if isinstance(entry, dict)}


def resolved(locks: list[Path]) -> dict[str, set[str]]:
    """Every resolved revision per pinned crate.

    A set, not one value: if a lockfile ever carried the same crate from git at
    two revisions, taking only one would let a drifted copy pass.
    """
    found: dict[str, set[str]] = {}
    for lock in locks:
        data = tomllib.loads(lock.read_text())
        for package in data.get("package", []):
            name = package.get("name")
            if name in PINS_NAMES and package.get("source", "").startswith("git+"):
                rev = package["source"].rsplit("#", 1)[-1]
                found.setdefault(name, set()).add(rev)
    return found


def main(argv: list[str]) -> int:
    here = Path(__file__).resolve().parent.parent
    pins_path = Path(argv[2]) if len(argv) > 2 else here / "transport-pins.toml"
    lock_paths = [Path(argv[1])] if len(argv) > 1 else [Path("Cargo.lock")]
    global PINS_NAMES
    PINS_NAMES = set(load_pins(pins_path))
    expected = load_pins(pins_path)
    actual = resolved(lock_paths)
    missing = sorted(PINS_NAMES - actual.keys())
    wrong = {
        n: (expected[n], sorted(actual[n]))
        for n in sorted(PINS_NAMES & actual.keys())
        if actual[n] != {expected[n]}
    }
    if not missing and not wrong:
        print(f"transport pins agree with {pins_path}")
        return 0
    for name in missing:
        print(f"MISSING {name}: not resolved from git (expected rev {expected[name]})")
    for name, (want, got) in wrong.items():
        print(f"DRIFT {name}: expected {want}, resolved {', '.join(got)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
