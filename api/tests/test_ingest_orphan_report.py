"""
Contract test: orphan sidecar detection.

Creates a temporary CORPUS_ROOT with an active/ subdirectory, seeds it with
a .metadata.json file that has no corresponding document, and asserts that
lint-corpus-orphans.sh reports it.  Then adds the document and asserts the
script exits cleanly.

Run standalone:
    python3 api/tests/test_ingest_orphan_report.py
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Locate the lint script relative to this file's repo layout:
# api/tests/ → api/ → keystone-gov/ → keystone-deploy/scripts/
_HERE = Path(__file__).resolve().parent
_LINT = _HERE.parent.parent.parent / "keystone-deploy" / "scripts" / "lint-corpus-orphans.sh"


def _run(corpus_root: str):
    """Run lint-corpus-orphans.sh against corpus_root; return (returncode, stdout)."""
    result = subprocess.run(
        ["bash", str(_LINT), corpus_root],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_orphan_detected():
    """A .metadata.json with no document must be reported and exit 1."""
    with tempfile.TemporaryDirectory() as tmp:
        active = Path(tmp) / "active"
        active.mkdir()
        orphan = active / "ghost-document.pdf.metadata.json"
        orphan.write_text('{"owner": "test"}')

        rc, out = _run(tmp)
        assert rc == 1, f"Expected exit 1 for orphan, got {rc}. Output:\n{out}"
        assert "ghost-document.pdf.metadata.json" in out, (
            f"Orphan path not in output:\n{out}"
        )
        assert "[FAIL]" in out, f"Expected [FAIL] in output:\n{out}"


def test_orphan_path_in_output():
    """The full absolute path to the orphan must appear in the output."""
    with tempfile.TemporaryDirectory() as tmp:
        active = Path(tmp) / "active"
        active.mkdir()
        orphan = active / "missing-source.txt.metadata.json"
        orphan.write_text("{}")

        rc, out = _run(tmp)
        assert rc == 1
        assert str(orphan) in out, f"Full orphan path not in output:\n{out}"


def test_no_orphan_exits_ok():
    """When sidecar and document both exist, must exit 0 with [OK]."""
    with tempfile.TemporaryDirectory() as tmp:
        active = Path(tmp) / "active"
        active.mkdir()
        doc = active / "real-doc.pdf"
        doc.write_bytes(b"%PDF-1.4 fake")
        sidecar = active / "real-doc.pdf.metadata.json"
        sidecar.write_text('{"owner": "ops"}')

        rc, out = _run(tmp)
        assert rc == 0, f"Expected exit 0 when no orphan, got {rc}. Output:\n{out}"
        assert "[OK]" in out, f"Expected [OK] in output:\n{out}"


def test_empty_active_dir_exits_ok():
    """Empty active/ has no sidecars → clean exit."""
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "active").mkdir()
        rc, out = _run(tmp)
        assert rc == 0, f"Expected exit 0 for empty dir, got {rc}. Output:\n{out}"


def test_multiple_orphans_all_reported():
    """Multiple orphans must all appear in output, sorted."""
    with tempfile.TemporaryDirectory() as tmp:
        active = Path(tmp) / "active"
        active.mkdir()
        names = ["beta.pdf", "alpha.pdf", "gamma.txt"]
        for n in names:
            (active / f"{n}.metadata.json").write_text("{}")

        rc, out = _run(tmp)
        assert rc == 1
        positions = [out.index(n) for n in ["alpha.pdf", "beta.pdf", "gamma.txt"]]
        assert positions == sorted(positions), "Output paths are not sorted"


def test_adding_document_clears_orphan():
    """After creating the corresponding document the orphan must clear."""
    with tempfile.TemporaryDirectory() as tmp:
        active = Path(tmp) / "active"
        active.mkdir()
        sidecar = active / "late-doc.pdf.metadata.json"
        sidecar.write_text('{"owner": "ops"}')

        rc, _ = _run(tmp)
        assert rc == 1, "Should be orphan before doc exists"

        (active / "late-doc.pdf").write_bytes(b"%PDF-1.4 fake")
        rc, out = _run(tmp)
        assert rc == 0, f"Should clear after doc created. Output:\n{out}"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not _LINT.exists():
        print(f"SKIP: lint script not found at {_LINT}")
        sys.exit(0)

    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except AssertionError as exc:
            print(f"  FAIL  {name}: {exc}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)
