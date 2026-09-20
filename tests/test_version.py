#!/usr/bin/env python3
"""Keep the release version consistent across the places that state it.

Before v0.15 the version lived only as prose in the module docstring, and the
argparse description drifted two releases behind it (`--help` said v0.13 while
the docstring said v0.15). `__version__` is now the single source of truth and
this test fails if anything falls out of step with it.

Run standalone:   python tests/test_version.py
Run under pytest: pytest tests/test_version.py
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parent.parent / "mAIpper.py"
_REPO_ROOT = _MODULE_PATH.parent


def _load_maipper():
    spec = importlib.util.spec_from_file_location("maipper_version_check", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = _load_maipper()


def test_version_is_declared():
    assert hasattr(m, "__version__"), "mAIpper.py must define __version__"
    assert re.fullmatch(r"\d+\.\d+", m.__version__), (
        f"__version__ should look like '0.15', got {m.__version__!r}"
    )


def test_docstring_header_matches_version():
    """The docstring header line is the changelog anchor; keep it in step."""
    header = (m.__doc__ or "").strip().splitlines()[0]
    expected = f"mAIpper v{m.__version__}"
    assert header.startswith(expected), (
        f"docstring header {header!r} does not start with {expected!r} -- "
        "bump both the docstring and __version__"
    )


def test_changelog_has_an_entry_for_this_version():
    """A release should be described before it is tagged."""
    changelog = _REPO_ROOT / "CHANGELOG.md"
    assert changelog.exists(), "CHANGELOG.md is missing"
    text = changelog.read_text(encoding="utf-8")
    heading = f"## v{m.__version__}"
    assert heading in text, (
        f"CHANGELOG.md has no {heading!r} section -- "
        "add release notes before tagging"
    )


def test_no_stale_hardcoded_version_strings():
    """Catch a second copy of the version drifting, as --help once did."""
    source = _MODULE_PATH.read_text(encoding="utf-8")
    current = m.__version__
    # Any 'mAIpper v<x.y>' mention must be the current version. Historical
    # 'Changes from vX.Y:' changelog lines are expected and skipped.
    for mo in re.finditer(r"mAIpper v(\d+\.\d+)", source):
        found = mo.group(1)
        line_start = source.rfind("\n", 0, mo.start()) + 1
        line = source[line_start:source.find("\n", mo.end())]
        if line.lstrip().startswith("Changes from"):
            continue
        assert found == current, (
            f"stale version string 'mAIpper v{found}' (current is v{current}) "
            f"in line: {line.strip()!r}"
        )


def _main() -> int:
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            print(f"  FAIL  {name}: {exc}")
            failed.append(name)
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
            failed.append(name)
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
