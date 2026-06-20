"""Prompt-injection detection patterns.

The detector is intentionally **explainable**: every match produces a tag and
a short snippet, so the telemetry log tells you *why* something was flagged.

We track three confidence levels:
- "low"  — soft signal (e.g. words like "ignore" appear), might be benign
- "med"  — multiple soft signals OR a known phrase fragment
- "high" — well-known jailbreak phrase, role-override, or system-prompt exfil

This is research-grade heuristics, NOT a complete defense.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass


# High-confidence phrases — full or substring
HIGH_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
    r"disregard\s+(the\s+)?(system|previous|prior)\s+(prompt|instructions?|rules?)",
    r"you\s+are\s+now\s+(a|an|the)\s+\w+",           # "you are now DAN", etc.
    r"forget\s+everything",
    r"reveal\s+(the\s+|your\s+)?(system\s+)?prompt",
    r"print\s+(the\s+|your\s+)?(initial|system|original)\s+(prompt|instructions?)",
    r"act\s+as\s+(a\s+)?(jailbroken|uncensored|unrestricted)",
    r"DAN\s+mode",
    r"developer\s+mode",
    r"bypass\s+(safety|content|moderation)\s+(filters?|rules?)",
]

# Medium-confidence — single suspicious word/structure
MED_PATTERNS = [
    r"\bnew\s+instructions?\b",
    r"\bnew\s+persona\b",
    r"\boverride\b",
    r"\bbypass\b",
    r"\bjailbreak\b",
    r"\bprompt\s*injection\b",
    r"\bexfiltrat\w*\b",
    r"\bleak\b",
    r"\bwithout\s+(restrictions?|filters?|rules?|limitations?)\b",
    r"\bdo\s+anything\s+now\b",
    r"\bno\s+(rules?|restrictions?|limits?)\b",
    r"<\s*system\s*>",                              # fake system tag
    r"\[\s*system\s*\]",
    r"###\s*system\s*:",
    r"</?\s*(system|assistant|user)\s*>",
]

# Low-confidence — words that often co-occur with attacks
LOW_WORDS = [
    "ignore", "disregard", "override", "system prompt", "developer prompt",
    "hidden", "secret", "instructions", "bypass", "unlock", "jailbreak",
]


@dataclass
class DetectionResult:
    confidence: str            # "low" | "med" | "high"
    matched_patterns: list[str]
    tags: list[str]
    score: int

    def is_attack(self, threshold: str = "med") -> bool:
        order = {"low": 0, "med": 1, "high": 2}
        return order[self.confidence] >= order[threshold]


def detect(text: str) -> DetectionResult:
    """Score the input text for prompt-injection signals."""
    if not text:
        return DetectionResult(confidence="low", matched_patterns=[], tags=[], score=0)

    t = text.lower()
    matched: list[str] = []
    tags: list[str] = []
    score = 0

    # High patterns
    for pat in HIGH_PATTERNS:
        m = re.search(pat, t, flags=re.IGNORECASE)
        if m:
            matched.append(pat)
            tags.append("high-confidence-phrase")
            score += 10

    # Medium patterns
    med_hits = 0
    for pat in MED_PATTERNS:
        m = re.search(pat, t, flags=re.IGNORECASE)
        if m:
            med_hits += 1
            tags.append("medium-signal")
    score += med_hits * 3

    # Low signals — count distinct suspicious words
    low_hits = sum(1 for w in LOW_WORDS if w in t)
    score += low_hits
    if low_hits:
        tags.append("low-signal")

    # Base64 long payloads — common exfil trick.
    # NOTE: do this on the *original* text, not the lowercased one —
    # base64 decode is case-insensitive but inverting case can introduce
    # whitespace or change padding boundaries in some texts.
    b64 = _maybe_base64_payload(text)
    if b64:
        matched.append("base64-payload")
        tags.append("base64")
        score += 5

    # Multi-language injection markers (very small set, just to flag)
    multi = _maybe_multilingual_injection(t)
    if multi:
        matched.append("multilingual-marker")
        tags.append("multilingual")
        score += 4

    # Determine confidence bucket
    if any("high-confidence-phrase" in t2 for t2 in tags):
        confidence = "high"
    elif med_hits >= 1 or low_hits >= 2 or score >= 4:
        confidence = "med"
    elif low_hits or med_hits:
        confidence = "low"
    else:
        confidence = "low"

    return DetectionResult(
        confidence=confidence,
        matched_patterns=matched,
        tags=sorted(set(tags)),
        score=score,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _maybe_base64_payload(t: str) -> bool:
    """True if text contains a long base64-looking blob (>= 64 chars)."""
    for m in re.finditer(r"[A-Za-z0-9+/=]{64,}", t):
        s = m.group(0)
        # Try decoding — be permissive; if it decodes to printable text, suspect.
        try:
            decoded = base64.b64decode(s, validate=True)
            if len(decoded) >= 16 and all(32 <= b < 127 or b in (9, 10, 13) for b in decoded):
                return True
        except Exception:
            continue
    return False


def _maybe_multilingual_injection(t: str) -> bool:
    """Tiny seed list — extend as you discover new patterns in the wild."""
    triggers = [
        "忽略之前的指令",          # zh: "ignore previous instructions"
        "忽略以上指令",
        "réinitialiser les instructions",  # fr: "reset instructions"
        "ignora las instrucciones anteriores",  # es
        "vergiss die vorherigen anweisungen",  # de
        "前の指示を無視して",      # ja
    ]
    return any(trg in t for trg in triggers)
