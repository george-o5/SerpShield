"""Normalization pipeline — runs before any signal detector.

Produces two string views per text field:
  clean_view    — NFKC, invisible chars stripped, entities decoded.  Safe to pass on.
  evidence_view — clean_view + spaced-out/leet collapsed + decoded payloads appended.
                  What detectors scan.

Also produces a NormalizedBundle with all findings metadata.

All functions are pure (no I/O, no global state).
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants — invisible / Cf character sets
# ---------------------------------------------------------------------------

# Zero-width characters
_ZERO_WIDTH: frozenset[int] = frozenset(range(0x200B, 0x2010))  # U+200B–U+200F

# Bidi controls  (U+202A–U+202E and U+2066–U+2069)
_BIDI_CONTROLS: frozenset[int] = frozenset(range(0x202A, 0x202F)) | frozenset(
    range(0x2066, 0x206A)
)

# Miscellaneous invisible
_MISC_INVISIBLE: frozenset[int] = frozenset(
    [
        0x2060,  # WORD JOINER
        0xFEFF,  # BOM / ZERO WIDTH NO-BREAK SPACE
        0x00AD,  # SOFT HYPHEN
    ]
)

# Combined set of codepoints we always strip from clean_view.
# Additionally, any character whose Unicode category is "Cf" (format char)
# not already in the above sets will also be stripped (checked dynamically).
_ALWAYS_STRIP: frozenset[int] = _ZERO_WIDTH | _BIDI_CONTROLS | _MISC_INVISIBLE


def _is_invisible(ch: str) -> bool:
    """Return True if *ch* is an invisible/format character we should strip."""
    cp = ord(ch)
    if cp in _ALWAYS_STRIP:
        return True
    # Catch other Cf (format) category chars not explicitly listed above.
    return unicodedata.category(ch) == "Cf"


# ---------------------------------------------------------------------------
# Leetspeak substitution table (for match copy only)
# ---------------------------------------------------------------------------

_LEET_TABLE: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
    "|": "i",
    "8": "b",
}
_LEET_RE = re.compile("[" + re.escape("".join(_LEET_TABLE)) + "]")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class InvisibleCharInfo(NamedTuple):
    """Details about a single invisible character occurrence."""

    codepoint: int  # Unicode codepoint
    position: int   # Position in the *original* string (after NFKC)
    category: str   # Unicode general category
    kind: str       # 'zero_width' | 'bidi' | 'misc' | 'cf_other'


class DecodedPayload(NamedTuple):
    """A successfully decoded Base64 or hex candidate."""

    encoding: str    # 'base64' | 'hex'
    original: str    # The original candidate token
    decoded: str     # The printable decoded text


class URLInfo(NamedTuple):
    """Parsed URL metadata."""

    original: str
    host: str                   # As found in the URL
    idna_host: str              # Encoded to IDNA/punycode (or same if ASCII)
    mixed_script: bool          # True if host contains chars from multiple scripts


@dataclass
class NormalizedBundle:
    """
    The full normalisation result for a single text field.

    Attributes
    ----------
    clean_view:
        NFKC-normalised, invisible-stripped, entity-decoded text.
        This is what gets passed on to the next pipeline stage.
    evidence_view:
        clean_view  +  spaced-out/leet collapsed inline  +  decoded payloads
        appended at the end.  Only detectors read this.
    invisible_count:
        Total number of stripped invisible/format characters.
    invisible_chars:
        Per-occurrence details (codepoint, position, kind).
    decoded_payloads:
        Bounded Base64/hex candidates that decoded successfully.
    urls:
        URLInfo for each URL found in the text.
    """

    clean_view: str = ""
    evidence_view: str = ""
    invisible_count: int = 0
    invisible_chars: list[InvisibleCharInfo] = field(default_factory=list)
    decoded_payloads: list[DecodedPayload] = field(default_factory=list)
    urls: list[URLInfo] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Step 1 + 2: NFKC + invisible char detection
# ---------------------------------------------------------------------------


def find_invisible_chars(text: str) -> tuple[str, list[InvisibleCharInfo]]:
    """
    Scan *text* (already NFKC-normalised) for invisible/format characters.

    Returns
    -------
    clean : str
        Text with every invisible/format char removed.
    infos : list[InvisibleCharInfo]
        One entry per occurrence, in original-position order.
    """
    clean_chars: list[str] = []
    infos: list[InvisibleCharInfo] = []

    for pos, ch in enumerate(text):
        if _is_invisible(ch):
            cp = ord(ch)
            if cp in _ZERO_WIDTH:
                kind = "zero_width"
            elif cp in _BIDI_CONTROLS:
                kind = "bidi"
            elif cp in _MISC_INVISIBLE:
                kind = "misc"
            else:
                kind = "cf_other"
            infos.append(
                InvisibleCharInfo(
                    codepoint=cp,
                    position=pos,
                    category=unicodedata.category(ch),
                    kind=kind,
                )
            )
        else:
            clean_chars.append(ch)

    return "".join(clean_chars), infos


# ---------------------------------------------------------------------------
# Step 3: HTML entity decode (single pass)
# ---------------------------------------------------------------------------


def _decode_html_entities(text: str) -> str:
    """Single-pass HTML entity decode using stdlib html.unescape."""
    return html.unescape(text)


# ---------------------------------------------------------------------------
# Step 4: Spaced-out / leet match copy (for evidence_view only)
# ---------------------------------------------------------------------------

# Matches single letters separated by spaces, e.g. "i g n o r e"
_SPACED_OUT_RE = re.compile(r"(?<!\w)([a-zA-Z](?:\s[a-zA-Z]){3,})(?!\w)")


def _collapse_spaced_out(text: str) -> str:
    """Replace spaced-out words with collapsed forms for matching only."""

    def _collapse(m: re.Match) -> str:
        collapsed = m.group(0).replace(" ", "")
        # Wrap with spaces so collapsed word is a token boundary.
        return f" {collapsed} "

    return _SPACED_OUT_RE.sub(_collapse, text)


def _apply_leet(text: str) -> str:
    """Apply leetspeak substitutions for matching only."""
    return _LEET_RE.sub(lambda m: _LEET_TABLE[m.group()], text)


def build_match_copy(clean_text: str) -> str:
    """
    Build a match copy of *clean_text* with spaced-out collapse and leet subs.
    This is never used as displayed text — only to extend evidence_view.
    """
    mc = _collapse_spaced_out(clean_text)
    mc = _apply_leet(mc)
    return mc


# ---------------------------------------------------------------------------
# Step 5: Bounded Base64 / hex decode
# ---------------------------------------------------------------------------

_BASE64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])"  # not preceded by base64 chars
    r"([A-Za-z0-9+/]{20,}(?:={0,2}))"  # at least 20 b64 chars + optional padding
    r"(?![A-Za-z0-9+/=])"   # not followed by base64 chars
)

_HEX_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f])"      # not preceded by hex chars
    r"([0-9A-Fa-f]{20,})"   # at least 20 hex chars (>=10 bytes)
    r"(?![0-9A-Fa-f])"       # not followed by hex chars
)

_MAX_CANDIDATE_BYTES = 1024  # <= 1 KB raw candidate


def _is_mostly_printable(text: str, threshold: float = 0.80) -> bool:
    """Return True if >= *threshold* fraction of chars are printable ASCII."""
    if not text:
        return False
    printable = sum(1 for ch in text if 0x20 <= ord(ch) <= 0x7E or ch in "\t\n\r")
    return (printable / len(text)) >= threshold


def decode_payload_candidates(text: str) -> list[DecodedPayload]:
    """
    Find Base64 and hex candidates (>=20 chars, <=1KB), decode one level,
    and return those that are mostly printable.

    Never mutates *text*.  Returns an empty list when nothing qualifies.
    """
    results: list[DecodedPayload] = []
    seen_b64: set[str] = set()  # deduplicate for base64
    seen_hex: set[str] = set()  # deduplicate for hex

    # --- Base64 ---
    for m in _BASE64_CANDIDATE_RE.finditer(text):
        candidate = m.group(1)
        if candidate in seen_b64:
            continue
        if len(candidate) > _MAX_CANDIDATE_BYTES:
            continue
        seen_b64.add(candidate)
        try:
            # Pad to valid length
            padded = candidate + "=" * (-len(candidate) % 4)
            raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode("utf-8", errors="replace")
            if _is_mostly_printable(decoded):
                results.append(DecodedPayload("base64", candidate, decoded))
        except Exception:
            pass

    # --- Hex ---
    for m in _HEX_CANDIDATE_RE.finditer(text):
        candidate = m.group(1)
        # Hex must be even length to decode
        if len(candidate) % 2 != 0:
            continue
        if candidate in seen_hex:
            continue
        if len(candidate) > _MAX_CANDIDATE_BYTES:
            continue
        seen_hex.add(candidate)
        try:
            raw = binascii.unhexlify(candidate)
            decoded = raw.decode("utf-8", errors="replace")
            if _is_mostly_printable(decoded):
                results.append(DecodedPayload("hex", candidate, decoded))
        except Exception:
            pass

    return results


# ---------------------------------------------------------------------------
# Step 6: URL IDNA / punycode + mixed-script detection
# ---------------------------------------------------------------------------

# Regex to find bare URLs in text (http/https/ftp)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+|ftp://[^\s\"'<>]+", re.IGNORECASE)

# Simple Unicode script detection — covers common Latin vs non-Latin mix.
_LATIN_RE = re.compile(r"[a-zA-Z\u00C0-\u024F]")
_NON_LATIN_RE = re.compile(
    r"[\u0400-\u04FF\u0370-\u03FF\u4E00-\u9FFF\u0600-\u06FF\u0900-\u097F]"
)


def _detect_mixed_script(host: str) -> bool:
    """
    Return True if *host* mixes Latin characters with characters from another
    well-known script (Cyrillic, Greek, CJK, Arabic, Devanagari).
    """
    has_latin = bool(_LATIN_RE.search(host))
    has_other = bool(_NON_LATIN_RE.search(host))
    return has_latin and has_other


def normalize_url(url: str) -> URLInfo:
    """
    Parse *url*, encode the host to IDNA/punycode, detect mixed scripts.

    Returns a URLInfo.  On any parse/encode error the original host is kept.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except Exception:
        host = ""

    mixed = _detect_mixed_script(host)

    # Encode the host to IDNA (punycode for non-ASCII labels)
    try:
        idna_host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        idna_host = host  # fallback: keep original

    return URLInfo(
        original=url,
        host=host,
        idna_host=idna_host,
        mixed_script=mixed,
    )


def extract_urls(text: str) -> list[URLInfo]:
    """Find all URLs in *text* and return their URLInfo."""
    return [normalize_url(m.group()) for m in _URL_RE.finditer(text)]


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def normalize_text(text: str) -> NormalizedBundle:
    """
    Run the full normalisation pipeline on a single text field.

    Pipeline
    --------
    1. NFKC normalisation.
    2. Invisible/Cf-char detection -> record + strip for clean_view.
    3. Single-pass HTML entity decode.
    4. Build match copy (spaced-out collapse + leet subs) for evidence_view.
    5. Bounded Base64/hex decode.
    6. URL IDNA/punycode extraction.

    Returns a NormalizedBundle.  Pure function — no I/O.
    """
    # 1. NFKC
    nfkc = unicodedata.normalize("NFKC", text)

    # 2. Invisible chars
    stripped, inv_infos = find_invisible_chars(nfkc)

    # 3. HTML entities (single pass)
    clean = _decode_html_entities(stripped)

    # 4. Match copy for evidence
    match_copy = build_match_copy(clean)

    # evidence_view = clean + leet/spaced match copy (only if different)
    if match_copy.strip() != clean.strip():
        evidence = clean + "\n" + match_copy
    else:
        evidence = clean

    # 5. Base64 / hex decode — search evidence (may surface payloads in match copy)
    payloads = decode_payload_candidates(evidence)
    if payloads:
        decoded_text = "\n".join(p.decoded for p in payloads)
        evidence = evidence + "\n" + decoded_text

    # 6. URLs
    urls = extract_urls(clean)

    return NormalizedBundle(
        clean_view=clean,
        evidence_view=evidence,
        invisible_count=len(inv_infos),
        invisible_chars=inv_infos,
        decoded_payloads=payloads,
        urls=urls,
    )
