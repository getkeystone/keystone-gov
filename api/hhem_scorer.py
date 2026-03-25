"""
Stage 4 trust check: hallucination detection via Vectara HHEM-2.1-Open.

Loads the model once at module import time.  All public surface is score().
Degrades gracefully: if the model cannot be loaded, score() returns None
and the pipeline continues without blocking.

Model must be pre-downloaded on the host.  Inside Docker, mount the cache:
  -v ~/.cache/huggingface:/root/.cache/huggingface

Environment variable:
  HHEM_THRESHOLD  — float 0.0-1.0, default 0.5.
                    Scores below this are treated as hallucinated.
"""
import logging
import os
import time

log = logging.getLogger("keystone.hhem")

HHEM_THRESHOLD: float = float(os.environ.get("HHEM_THRESHOLD", "0.5"))

_model = None
_load_failed = False


def _load_model() -> None:
    global _model, _load_failed
    t0 = time.monotonic()
    try:
        from transformers import AutoModelForSequenceClassification  # type: ignore
        m = AutoModelForSequenceClassification.from_pretrained(
            "vectara/hallucination_evaluation_model",
            trust_remote_code=True,
        )
        m.to("cpu")           # GPU reserved for Ollama
        _model = m
        elapsed = time.monotonic() - t0
        log.info("[keystone] HHEM model loaded in %.1fs (CPU)", elapsed)
    except Exception as exc:
        _load_failed = True
        log.warning(
            "[keystone] HHEM model failed to load: %s — hallucination scoring disabled",
            exc,
        )


_load_model()


def score(premise: str, hypothesis: str) -> "float | None":
    """Return factual-consistency score in [0, 1], or None on error.

    >0.5  factually consistent with premise
    <0.5  likely hallucinated / inconsistent

    premise   — concatenated retrieved chunk texts fed to the LLM
    hypothesis — the LLM-generated answer
    """
    if _load_failed or _model is None:
        return None
    if not premise or not hypothesis:
        return None
    try:
        scores = _model.predict([[premise, hypothesis]])
        return float(scores[0])
    except Exception as exc:
        log.warning("[keystone] HHEM score() failed for hypothesis snippet %r: %s",
                    hypothesis[:80], exc)
        return None
