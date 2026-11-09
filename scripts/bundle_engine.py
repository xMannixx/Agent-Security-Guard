#!/usr/bin/env python3
"""Copy the guard package into the plugin directory, or check that the copy is current.

A catalog install of Hermes checks out only ``plugin/`` (``subdir: plugin``),
so the package has to be inside it. The source of truth stays
``security/agent-security-guard/src/agent_security_guard``; the copy in
``plugin/agent_security_guard`` is generated from it and never edited by hand.

    python scripts/bundle_engine.py          # write the copy
    python scripts/bundle_engine.py --check  # exit 1 if the copy differs
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "security" / "agent-security-guard" / "src" / "agent_security_guard"
BUNDLE = ROOT / "plugin" / "agent_security_guard"


def _files(directory: Path) -> dict:
    """``{name: bytes}`` of the package's source files (no caches)."""
    if not directory.is_dir():
        return {}
    return {path.name: path.read_bytes() for path in sorted(directory.glob("*.py"))}


def differences() -> list:
    source, bundle = _files(SOURCE), _files(BUNDLE)
    problems = []
    for name in sorted(set(source) | set(bundle)):
        if name not in bundle:
            problems.append(f"missing in the plugin copy: {name}")
        elif name not in source:
            problems.append(f"not in the source package: {name}")
        elif source[name] != bundle[name]:
            problems.append(f"differs from the source package: {name}")
    if BUNDLE.is_dir():
        extra = [p.name for p in BUNDLE.iterdir() if p.suffix != ".py" and p.name != "__pycache__"]
        problems += [f"not a source file: {name}" for name in sorted(extra)]
    return problems


def write() -> None:
    if BUNDLE.exists():
        shutil.rmtree(BUNDLE)
    BUNDLE.mkdir()
    for name, data in _files(SOURCE).items():
        (BUNDLE / name).write_bytes(data)


def main(argv: list) -> int:
    if "--check" in argv:
        problems = differences()
        for problem in problems:
            print(problem, file=sys.stderr)
        if problems:
            print("run: python scripts/bundle_engine.py", file=sys.stderr)
        return 1 if problems else 0
    write()
    print(f"copied {len(_files(BUNDLE))} files to {BUNDLE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
