#!/usr/bin/env python3
"""
Keystone Retrieval Quality Eval Harness.

Runs test queries against the API, checks retrieval accuracy
and answer quality, reports pass/fail with scores.

Usage:
  python3 eval_harness.py --suite eval/alberta-demo.yaml \
    --api http://localhost:8002 \
    --user operator1 --password demo123

Output:
  - Console: pass/fail per query, summary stats
  - JSON: eval/results/alberta-demo-YYYYMMDD-HHMMSS.json
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
import yaml


def login(api: str, user: str, password: str) -> str:
    r = requests.post(f"{api}/auth/login",
                      json={"username": user, "password": password})
    r.raise_for_status()
    return r.json()["token"]


def run_query(api: str, token: str, question: str, mode: str) -> dict:
    """Submit query and fetch guidance. Returns full guidance response."""
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}

    r = requests.post(f"{api}/query",
                      json={"question": question, "mode": mode},
                      headers=headers)

    # If blocked by input sanitizer, return a marker
    if r.status_code == 200:
        data = r.json()
        query_id = data.get("query_id")
        scenario = data.get("scenario_key", "")

        if scenario == "policy_refusal":
            return {"blocked": True, "query_id": query_id,
                    "scenario_key": scenario}

        # Fetch guidance
        g = requests.get(f"{api}/guidance/{query_id}",
                         headers=headers)
        if g.status_code == 200:
            result = g.json()
            result["blocked"] = False
            return result

    return {"blocked": True, "error": r.status_code}


def evaluate_query(test: dict, result: dict) -> dict:
    """Evaluate a single query result against expectations."""
    outcome = {
        "id": test["id"],
        "question": test["question"],
        "pass": True,
        "checks": [],
    }

    # Check if query was blocked (for injection tests)
    if test.get("expect_blocked"):
        blocked = result.get("blocked", False)
        outcome["checks"].append({
            "check": "expect_blocked",
            "pass": blocked,
            "detail": "Blocked" if blocked else "NOT blocked — injection got through"
        })
        if not blocked:
            outcome["pass"] = False
        return outcome

    # Check if query was unexpectedly blocked
    if result.get("blocked"):
        outcome["pass"] = False
        outcome["checks"].append({
            "check": "not_blocked",
            "pass": False,
            "detail": "Query was unexpectedly blocked"
        })
        return outcome

    guidance = result.get("guidance", {})
    answer = guidance.get("answer", "") or ""
    confidence = guidance.get("confidence", {})
    evidence_titles = confidence.get("evidence_titles", [])
    result_type = guidance.get("type", "")

    # Check expected refusal
    if test.get("expect_refusal"):
        is_refusal = (
            "does not fully address" in answer.lower() or
            "does not contain" in answer.lower() or
            "no relevant" in answer.lower() or
            result_type == "refusal" or
            not answer.strip()
        )
        outcome["checks"].append({
            "check": "expect_refusal",
            "pass": is_refusal,
            "detail": f"type={result_type!r} answer={answer[:100]!r}"
        })
        if not is_refusal:
            outcome["pass"] = False
        return outcome

    # Check fail_if_type
    if test.get("fail_if_type"):
        bad_type = test["fail_if_type"]
        type_ok = result_type != bad_type
        outcome["checks"].append({
            "check": f"type != {bad_type}",
            "pass": type_ok,
            "detail": f"Got type: {result_type!r}"
        })
        if not type_ok:
            outcome["pass"] = False

    # Check expected documents in evidence titles (top-5)
    for expected_doc in test.get("expected_docs", []):
        found = any(expected_doc.lower() in t.lower()
                    for t in evidence_titles)
        outcome["checks"].append({
            "check": f"doc: {expected_doc}",
            "pass": found,
            "detail": f"evidence_titles: {evidence_titles}"
        })
        if not found:
            outcome["pass"] = False

    # Check expected keywords in LLM answer
    for keyword in test.get("expected_keywords", []):
        found = keyword.lower() in answer.lower()
        outcome["checks"].append({
            "check": f"keyword: {keyword}",
            "pass": found,
            "detail": f"keyword {'found' if found else 'MISSING'} in answer"
        })
        if not found:
            outcome["pass"] = False

    # Record metadata for the JSON report
    outcome["latency_ms"] = confidence.get("gen_latency_ms")
    outcome["retrieval_source"] = confidence.get("retrieval_source")
    outcome["or_expansion"] = confidence.get("or_expansion")
    outcome["answer_preview"] = answer[:200]
    outcome["evidence_titles"] = evidence_titles
    outcome["result_type"] = result_type

    return outcome


def main():
    parser = argparse.ArgumentParser(
        description="Keystone Retrieval Quality Eval")
    parser.add_argument("--suite", required=True,
                        help="Path to test suite YAML")
    parser.add_argument("--api", default="http://localhost:8002",
                        help="API base URL")
    parser.add_argument("--user", default="operator1")
    parser.add_argument("--password", default="demo123")
    parser.add_argument("--output-dir", default="eval/results")
    args = parser.parse_args()

    # Resolve suite path relative to repo root (one level up from api/)
    suite_path = Path(args.suite)
    if not suite_path.exists():
        # Try relative to script location (api/../eval/...)
        alt = Path(__file__).parent.parent / args.suite
        if alt.exists():
            suite_path = alt

    with open(suite_path) as f:
        suite = yaml.safe_load(f)

    print(f"Suite:   {suite['suite']}")
    print(f"Desc:    {suite.get('description', '')}")
    print(f"Queries: {len(suite['queries'])}")
    print(f"API:     {args.api}")
    print()

    # Login
    try:
        token = login(args.api, args.user, args.password)
    except Exception as exc:
        print(f"Login failed: {exc}", file=sys.stderr)
        sys.exit(2)
    print(f"Logged in as {args.user}")
    print()

    # Run queries
    results = []
    passed = 0
    failed = 0
    total_latency = 0

    for test in suite["queries"]:
        t0 = time.time()
        result = run_query(args.api, token, test["question"],
                           test.get("mode", "training"))
        wall_ms = round((time.time() - t0) * 1000)

        outcome = evaluate_query(test, result)
        outcome["wall_time_ms"] = wall_ms
        results.append(outcome)

        status = "PASS" if outcome["pass"] else "FAIL"
        if outcome["pass"]:
            passed += 1
        else:
            failed += 1

        latency = outcome.get("latency_ms") or wall_ms
        total_latency += latency

        checks_summary = ", ".join(
            f"{'ok' if c['pass'] else 'FAIL'}: {c['check']}"
            for c in outcome["checks"]
        )
        print(f"  [{status}] {test['id']:12s} ({wall_ms:>5d}ms)  {checks_summary}")

    # Summary
    total = passed + failed
    score = (passed / total * 100) if total > 0 else 0
    avg_latency = total_latency / total if total > 0 else 0

    print()
    print(f"{'='*60}")
    print(f"  PASS: {passed}/{total}  ({score:.0f}%)")
    print(f"  FAIL: {failed}/{total}")
    print(f"  Avg latency: {avg_latency:.0f}ms")
    print(f"{'='*60}")

    # Resolve output dir relative to suite file or cwd
    out_dir = Path(args.output_dir)
    if not out_dir.is_absolute():
        out_dir = suite_path.parent / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = out_dir / f"{suite['suite']}-{ts}.json"

    report = {
        "suite": suite["suite"],
        "description": suite.get("description", ""),
        "timestamp": datetime.now().isoformat(),
        "api": args.api,
        "user": args.user,
        "total": total,
        "passed": passed,
        "failed": failed,
        "score_pct": round(score, 1),
        "avg_latency_ms": round(avg_latency),
        "results": results,
    }

    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nResults saved: {out_path}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
