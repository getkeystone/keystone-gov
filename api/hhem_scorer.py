"""
Stage 4 trust check: hallucination detection via Vectara HHEM-2.1-Open.

Loads the model once at module import time.  All public surface is score()
and get_threshold().  Degrades gracefully: if the model cannot be loaded,
score() returns None and the pipeline continues without blocking.

Model must be pre-downloaded on the host.  Inside Docker, mount the cache:
  -v ~/.cache/huggingface:/root/.cache/huggingface

Two thresholds are used because answer_source strongly predicts score range:

  HHEM_THRESHOLD_DETERMINISTIC (env: HHEM_THRESHOLD_DETERMINISTIC, default 0.5)
    For answers where answer_source == "deterministic": the answer text is the
    raw retrieved chunk, so premise and hypothesis are nearly identical.  HHEM
    reliably scores these 0.9+.  A threshold of 0.5 is appropriate — anything
    below that is a genuine mismatch (wrong chunk surfaced).

  HHEM_THRESHOLD_LLM (env: HHEM_THRESHOLD_LLM, default 0.20)
    For LLM-synthesized answers: the model paraphrases and recombines evidence,
    producing scores in the 0.3-0.9 range even for correct answers.  A threshold
    of 0.5 would refuse good answers constantly.  0.20 catches only clear
    hallucinations while passing reasonable paraphrases.

  HHEM_THRESHOLD (alias for HHEM_THRESHOLD_LLM)
    Kept for backwards compatibility with deployments that set the old env var.
    Reading HHEM_THRESHOLD has no effect on the deterministic path.
"""
import logging
import os
import time

log = logging.getLogger("keystone.hhem")

HHEM_THRESHOLD_DETERMINISTIC: float = float(
    os.environ.get("HHEM_THRESHOLD_DETERMINISTIC", "0.5")
)
HHEM_THRESHOLD_LLM: float = float(
    os.environ.get("HHEM_THRESHOLD_LLM", "0.20")
)
# Backwards-compat alias — callers that still reference HHEM_THRESHOLD get the
# LLM threshold, which is the more permissive of the two.
HHEM_THRESHOLD = HHEM_THRESHOLD_LLM

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


def get_threshold(answer_source: str) -> float:
    """Return the appropriate HHEM threshold for the answer source type.

    Deterministic answers (raw chunk text) score 0.9+ and use a higher threshold.
    LLM-synthesized answers score 0.3-0.9 due to paraphrasing and use a lower threshold.
    Unknown answer_source defaults to the LLM threshold (more permissive).
    """
    if answer_source == "deterministic":
        return HHEM_THRESHOLD_DETERMINISTIC
    return HHEM_THRESHOLD_LLM


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
