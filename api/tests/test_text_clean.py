"""
Unit tests for text_clean.clean_lines() and make_summary().

Run standalone:
    python3 api/tests/test_text_clean.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from text_clean import clean_lines, make_summary

# ---------------------------------------------------------------------------
# Sample front-matter / TOC block representative of real corpus files
# ---------------------------------------------------------------------------

_FRONT_MATTER = """\
SOLO RESCUE DECON UNIT MODEL 4500
User Manual

RescueIntellitech, Inc.
www.rescueintellitech.com
info@rescueintellitech.com
1234 Industrial Pkwy, Katy, TX 77493
Copyright © 2024 RescueIntellitech, Inc. All Rights Reserved.

CONTENTS

1. Introduction ....................... 3
2. Safety Precautions ................. 5
3. Operation Procedures ............... 9
4. Maintenance ........................ 15

Step 1: Connect the water supply hose to the inlet port.
Step 2: Open the main valve by turning clockwise until fully open.
Warning: Do not exceed 120 PSI inlet pressure.
Step 3: Press the POWER button and verify the green LED is lit.

Caution: Allow the unit to warm up for 60 seconds before operating.
"""

_PROCEDURAL_WORDS = {
    "operation", "procedure", "step", "warning", "caution",
    "instructions", "troubleshoot",
}


# ---------------------------------------------------------------------------
# clean_lines tests
# ---------------------------------------------------------------------------

def test_no_contents_heading():
    result = clean_lines(_FRONT_MATTER)
    assert "CONTENTS" not in result, f"CONTENTS should be removed; got:\n{result}"


def test_no_url():
    result = clean_lines(_FRONT_MATTER)
    assert "rescueintellitech.com" not in result, "URL should be removed"


def test_no_email():
    result = clean_lines(_FRONT_MATTER)
    assert "@" not in result, "Email should be removed"


def test_no_city_state():
    result = clean_lines(_FRONT_MATTER)
    # Both Katy and TX should be gone (same line)
    assert "Katy" not in result, "City/state line should be removed"


def test_no_copyright():
    result = clean_lines(_FRONT_MATTER)
    assert "copyright" not in result.lower(), "Copyright line should be removed"


def test_keeps_procedural_words():
    result = clean_lines(_FRONT_MATTER)
    lower = result.lower()
    found = [w for w in _PROCEDURAL_WORDS if w in lower]
    assert found, f"Expected at least one procedural word; got:\n{result}"


def test_no_toc_dotted_leaders():
    result = clean_lines(_FRONT_MATTER)
    # TOC entries with dotted leaders should be gone
    assert "......." not in result, "Dotted TOC leaders should be removed"


# ---------------------------------------------------------------------------
# make_summary tests
# ---------------------------------------------------------------------------

def test_summary_max_length():
    summary = make_summary(_FRONT_MATTER, max_chars=200)
    assert len(summary) <= 200, f"summary length {len(summary)} exceeds 200"


def test_summary_no_contents():
    summary = make_summary(_FRONT_MATTER)
    assert "CONTENTS" not in summary, "make_summary should not include CONTENTS"


def test_summary_has_procedural():
    summary = make_summary(_FRONT_MATTER)
    lower = summary.lower()
    found = [w for w in _PROCEDURAL_WORDS if w in lower]
    assert found, f"Expected at least one procedural word in summary; got:\n{summary}"


def test_summary_default_fits():
    """Full front-matter with procedural lines should fit in 500 chars."""
    summary = make_summary(_FRONT_MATTER)
    assert len(summary) <= 500


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
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
