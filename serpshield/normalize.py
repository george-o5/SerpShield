"""Normalization (runs before any rule). Produces clean_view and evidence_view.

Steps: NFKC -> invisible/control char detection -> HTML entities (single pass)
-> spaced-out/leet match copy -> bounded Base64/hex decode -> URL IDNA/punycode.
"""


def normalize_text(text: str):
    raise NotImplementedError


def find_invisible_chars(text: str):
    raise NotImplementedError


def decode_payload_candidates(text: str):
    """Base64/hex candidates, >=20 chars, <=1KB, one decode level, printable-only."""
    raise NotImplementedError


def normalize_url(url: str):
    raise NotImplementedError
