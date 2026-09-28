"""Explainable admission signals, not a proof that arbitrary text is safe.

Scan normalized views but retain the original bytes for provenance and review.
Rules target behavior changes, not isolated modal words such as 'must'.
"""

import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from recallguard.models import Claim

POLICY_VERSION = "context-screening-v1"
CREDENTIAL = re.compile(
    r"\b(password|api[_ -]?key|secret[_ -]?key|access[_ -]?token)\s*[:=]\s*\S+", re.I
)

# Keep each signal independent: benign text must never whitelist a second payload.
RULES = {
    "control_override": (
        r"\b(?:ignore|disregard|forget|bypass|disable|override|skip|supersede)\b"
        r".{0,240}\b(?:instructions?|rules?|polic(?:y|ies)|checks?|approvals?|"
        r"reviews?|verification|safeguards?|restrictions?|safety|security|prompts?|constraints?)\b"
    ),
    "persistent_directive": (
        r"\b(?:remember|memorize|record|store|save|retain|treat|adopt|set|update)\b"
        r".{0,180}\b(?:preferences?|instructions?|directives?|rules?|default|"
        r"permanent|future|from now on)\b|"
        r"\b(?:from now on|in future (?:sessions|conversations)|for all future)\b"
    ),
    "role_spoofing": (
        r"<\|(?:im_start|im_end|system|assistant|endoftext)\|>|"
        r"\[/?(?:inst|system)\]|</?(?:system|developer|assistant)(?:\s[^>]*|)>|"
        r"(?:^|\n)\s*(?:#{1,6}\s*)?(?:system|developer)\s*(?:message|prompt)?\s*:|"
        r"\b(?:you are now|act as|pretend to be)\b.{0,100}"
        r"\b(?:system|developer|assistant|agent|administrator|unrestricted)\b"
    ),
    "financial_redirect": (
        r"\b(?:send|transfer|pay|route|redirect|remit|wire|deposit)\b.{0,180}"
        r"\b(?:account|money|funds|payments?|invoices?|iban|wallet)\b|"
        r"\b(?:change|replace|switch|use)\b.{0,100}"
        r"\b(?:bank account|payment destination|beneficiary|iban|wallet address)\b"
    ),
    "data_exfiltration": (
        r"\b(?:send|upload|post|forward|export|leak|reveal|print|expose|return)\b"
        r".{0,180}\b(?:secrets?|passwords?|credentials?|tokens?|api[ _-]?keys?|"
        r"system prompts?|private (?:data|files?)|conversation history)\b"
    ),
    "tool_execution": (
        r"\b(?:execute|run|invoke|call)\b.{0,100}"
        r"\b(?:shell|bash|powershell|python|commands?|scripts?|tools?|functions?)\b"
    ),
    "answer_manipulation": (
        r"\b(?:you|assistant|agent)\s+(?:must|should|will|shall)\b.{0,100}"
        r"\b(?:answer|respond|say|output|obey|follow|ignore|use|send|execute)\b|"
        r"\b(?:always|never|only)\s+(?:answer|respond|say|output|obey|follow)\b|"
        r"\b(?:do not|don't|never)\s+(?:tell|inform|notify|mention|disclose)\b"
        r".{0,80}\b(?:user|reviewer|operator|this instruction)\b"
    ),
}
PATTERNS = tuple((name, re.compile(pattern, re.I | re.S)) for name, pattern in RULES.items())


def normalized_views(text: str) -> tuple[str, ...]:
    """Bounded decoding of common wrappers; never execute or fetch payloads.

    This does not decode arbitrary languages, homoglyphs, ciphers or base64.
    """
    views = [text]
    for _ in range(2):
        text = unicodedata.normalize("NFKC", unquote(html.unescape(text)))
        text = "".join(c for c in text if unicodedata.category(c) != "Cf")
        views.append(text)
    # Markdown emphasis and HTML tags can split trigger words. Keep the other
    # views as well so removing markup cannot hide a forged role delimiter.
    views.append(re.sub(r"<[^>]{0,200}>|[`*_~]", "", text))
    return tuple(dict.fromkeys(views))


@dataclass(frozen=True)
class Screening:
    instruction_signals: tuple[str, ...]
    credential: bool

    @property
    def blocked(self) -> bool:
        return self.credential or bool(self.instruction_signals)


def screen_memory(content: str, claim: Claim | None = None) -> Screening:
    fields = [content]
    if claim is not None:
        # The retrieval response and structured summarizer expose these fields too.
        fields += [claim.entity, claim.attribute, claim.value]
    views = normalized_views("\n".join(fields))
    return Screening(
        instruction_signals=tuple(
            name for name, pattern in PATTERNS if any(pattern.search(view) for view in views)
        ),
        credential=any(CREDENTIAL.search(view) for view in views),
    )
