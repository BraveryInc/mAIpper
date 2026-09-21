#!/usr/bin/env python3
"""Golden-output (characterization) tests for the six host-note writers.

These snapshots do NOT assert the output is *correct* -- they assert it is
*unchanged*. That is the right check for a refactor, which by definition should
not alter behaviour. The behavioural tests in test_note_writing.py check
specific guarantees; these catch everything else, including section reordering,
spacing changes and dropped lines that a targeted assertion would miss.

Each writer is captured in two scenarios:
  * ``<writer>_fresh``  -- writing a host note from scratch
  * ``<writer>_merge``  -- merging into a note that already holds content from
                           every other source plus operator-authored sections

Snapshots live in tests/golden/. Regenerate them ONLY when a change is meant to
alter writer output, and review the resulting diff as carefully as the code:

    python tests/test_writer_output.py --update
    git diff tests/golden/          # this diff is the behaviour change

Run standalone:   python tests/test_writer_output.py
Run under pytest: pytest tests/test_writer_output.py
"""

from __future__ import annotations

import difflib
import sys
import tempfile
from pathlib import Path

# Diffs printed on failure can contain characters (e.g. checkmarks in the NXC
# shares table) that a Windows console's legacy codepage cannot encode --
# without this, a real failure's own diagnostic output crashes before it can
# be read. Same fix as mAIpper.py's _force_utf8_stdio, applied here directly
# since this file may run without importing mAIpper's __main__ path.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures  # noqa: E402

m = fixtures.load_maipper("maipper_golden")

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


# ---------------------------------------------------------------------------
# scenarios: name -> callable(tmp_path) -> produced note text
# ---------------------------------------------------------------------------

def _nmap(hosts_dir):
    m._write_host_note(hosts_dir, fixtures.NMAP_HOST, "Internal - Nmap", "Internal", "Nmap")


def _nessus(hosts_dir):
    m._update_host_note_nessus(
        hosts_dir, "10.10.10.5", "dc01.corp.local",
        fixtures.NESSUS_FINDINGS, "Internal - Nessus",
    )


def _burp(hosts_dir):
    m._update_host_note_burp(
        hosts_dir, "10.10.10.5", "http://dc01.corp.local/",
        fixtures.BURP_ISSUES, "Internal - Burp",
    )


def _autorecon(hosts_dir):
    m._update_host_note_autorecon(
        hosts_dir, "10.10.10.5", "dc01.corp.local",
        fixtures.AUTORECON_TARGET, "10.10.10.5 - AutoRecon",
    )


def _loot(hosts_dir):
    m._update_host_note_loot(
        hosts_dir, "10.10.10.5", "dc01.corp.local", fixtures.LOOT_FILES, "Loot",
    )


def _nxc(hosts_dir):
    m._write_nxc_host_enrichment(hosts_dir, fixtures.NXC_HOST, "NXC")


WRITERS = {
    "nmap": _nmap,
    "nessus": _nessus,
    "burp": _burp,
    "autorecon": _autorecon,
    "loot": _loot,
    "nxc": _nxc,
}


def _produce(writer_name: str, mode: str) -> str:
    """Run one writer in one scenario and return the resulting note text."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        if mode == "merge":
            hosts_dir, _ = fixtures.seed_host_note(tmp)
        else:
            hosts_dir = fixtures.empty_hosts_dir(tmp)

        WRITERS[writer_name](hosts_dir)

        notes = sorted(hosts_dir.glob("*.md"))
        assert notes, f"{writer_name}/{mode}: writer produced no host note"
        # Concatenate when a writer creates more than one note, so the snapshot
        # also captures "how many notes did this produce".
        parts = []
        for note in notes:
            parts.append(f"===== {note.name} =====")
            parts.append(note.read_text(encoding="utf-8"))
        return "\n".join(parts)


def _scenarios() -> list[tuple[str, str]]:
    return [(w, mode) for w in WRITERS for mode in ("fresh", "merge")]


def _golden_path(writer_name: str, mode: str) -> Path:
    return GOLDEN_DIR / f"{writer_name}_{mode}.md"


# ---------------------------------------------------------------------------
# the test
# ---------------------------------------------------------------------------

def _check(writer_name: str, mode: str) -> None:
    golden = _golden_path(writer_name, mode)
    assert golden.exists(), (
        f"missing snapshot {golden.relative_to(GOLDEN_DIR.parent.parent)} -- "
        "generate it with: python tests/test_writer_output.py --update"
    )
    expected = golden.read_text(encoding="utf-8")
    actual = _produce(writer_name, mode)
    if actual != expected:
        diff = "\n".join(difflib.unified_diff(
            expected.splitlines(), actual.splitlines(),
            fromfile=f"golden/{golden.name}", tofile="produced now", lineterm="",
        ))
        raise AssertionError(
            f"{writer_name}/{mode}: writer output changed.\n"
            "If this change is intended, re-run with --update and review the diff.\n"
            + diff
        )


def test_nmap_fresh():        _check("nmap", "fresh")
def test_nmap_merge():        _check("nmap", "merge")
def test_nessus_fresh():      _check("nessus", "fresh")
def test_nessus_merge():      _check("nessus", "merge")
def test_burp_fresh():        _check("burp", "fresh")
def test_burp_merge():        _check("burp", "merge")
def test_autorecon_fresh():   _check("autorecon", "fresh")
def test_autorecon_merge():   _check("autorecon", "merge")
def test_loot_fresh():        _check("loot", "fresh")
def test_loot_merge():        _check("loot", "merge")
def test_nxc_fresh():         _check("nxc", "fresh")
def test_nxc_merge():         _check("nxc", "merge")


def test_writers_are_deterministic():
    """Two runs of the same scenario must agree, or snapshots are meaningless."""
    for writer_name, mode in _scenarios():
        first = _produce(writer_name, mode)
        second = _produce(writer_name, mode)
        assert first == second, f"{writer_name}/{mode} is not deterministic"


# ---------------------------------------------------------------------------
# runner / snapshot regeneration
# ---------------------------------------------------------------------------

def _update() -> int:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    for writer_name, mode in _scenarios():
        path = _golden_path(writer_name, mode)
        before = path.read_text(encoding="utf-8") if path.exists() else None
        text = _produce(writer_name, mode)
        path.write_text(text, encoding="utf-8")
        state = "unchanged" if before == text else ("created" if before is None else "UPDATED")
        print(f"  {state:9} {path.name}")
    print("\nReview the diff before committing:  git diff tests/golden/")
    return 0


def _main() -> int:
    if "--update" in sys.argv:
        return _update()
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            first_line = str(exc).splitlines()[0] if str(exc) else ""
            print(f"  FAIL  {name}: {first_line}")
            failed.append((name, str(exc)))
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
            failed.append((name, str(exc)))
    if failed:
        print("\n--- details ---")
        for name, detail in failed:
            print(f"\n{name}:\n{detail}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
