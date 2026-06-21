"""Make the stdlib-only package importable in tests without installation."""

import sys
from pathlib import Path

_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Repo root, so tests can `import plugin` (the Hermes plugin package).
_REPO_ROOT = Path(__file__).parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
