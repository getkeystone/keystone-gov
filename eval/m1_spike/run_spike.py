"""
Run the M1 qwen2.5:7b-instruct reliability spike.

Calls the local Ollama instance via the existing api/ollama_client.py.
Writes results to eval/m1_spike/results.jsonl and prints a summary.
"""

import json
import sys
import time
from pathlib import Path

# Use the existing client so the spike matches production call shape.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))
import ollama_client  # noqa: E402

from prompts import build_prompts, grade  # noqa: E402


SYSTEM_PROMPT = (
    "You are a tool-selecting assistant for an industrial safety knowledge system. "
    "Given the user's request, respond with ONLY a single JSON object on one line with the keys "
    '"tool" (string, one of lookup_procedure, queue_notification, draft_procedure_update) and '
    '"parameters" (object). Required parameter keys per tool: '
    "lookup_procedure -> query; "
    "queue_notification -> recipient, message; "
    "draft_procedure_update -> procedure_id, proposed_change. "
    "Do not include any prose, markdown, or explanation. Only the JSON object."
)


def call_model(prompt_text: str) -> tuple[str, float]:
    t0 = time.time()
    # Use whichever chat API ollama_client exposes; adjust call name to match.
    # The expected interface: ollama_client.chat(messages=[...], model=...).
    raw = ollama_client.chat(
        model="qwen2.5:7b-instruct",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt_text},
        ],
    )
    return raw, time.time() - t0


def extract_json(raw: str) -> dict | None:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    try:
        return json.loads(raw)
    except Exception:
        # Best-effort: find first { and last }
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(raw[start:end + 1])
            except Exception:
                return None
        return None


def main():
    prompts = build_prompts()
    out_path = Path(__file__).parent / "results.jsonl"
    n_pass = 0
    n_total = len(prompts)
    with out_path.open("w") as f:
        for i, item in enumerate(prompts):
            raw, latency = call_model(item["prompt"])
            obj = extract_json(raw)
            if obj is None:
                result = {"passed": False, "reasons": ["could not parse JSON from response"]}
            else:
                result = grade(obj, item["expected_tool_candidates"])
            if result["passed"]:
                n_pass += 1
            record = {
                "i": i,
                "prompt_excerpt": item["prompt"][:80],
                "tool_expected": item["expected_tool_candidates"],
                "role": item["role"],
                "severity": item["severity"],
                "raw_excerpt": raw[:200],
                "parsed": obj,
                "passed": result["passed"],
                "reasons": result["reasons"],
                "latency_s": round(latency, 2),
            }
            f.write(json.dumps(record) + "\n")
            print(f"[{i+1:2d}/{n_total}] {'PASS' if result['passed'] else 'FAIL'} "
                  f"role={item['role']} sev={item['severity']} "
                  f"({latency:.1f}s) {' | '.join(result['reasons']) if result['reasons'] else ''}")
    conformance = n_pass / n_total
    print()
    print(f"=== Spike result: {n_pass}/{n_total} = {conformance:.0%} parameter-shape conformance ===")
    if conformance >= 0.90:
        print("ACCEPT: >= 90% conformance. Proceed to M2 with qwen2.5:7b-instruct.")
        sys.exit(0)
    elif conformance >= 0.80:
        print("MARGINAL: 80-89% conformance. Proceed with mitigation (structured output / JSON Schema constrained decoding).")
        sys.exit(1)
    else:
        print("FAIL: < 80% conformance. Swap to qwen2.5:32b-instruct or equivalent before M2.")
        sys.exit(2)


if __name__ == "__main__":
    main()
