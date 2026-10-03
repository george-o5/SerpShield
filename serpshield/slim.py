"""Per-engine compaction + untrusted-data envelope.

Keep: position, title, link, domain, snippet (<=300 chars), trust, findings.
"""


def slim_result(result: dict) -> dict:
    raise NotImplementedError


def wrap_envelope(query: str, engine: str, results: list, meta: dict) -> dict:
    raise NotImplementedError


def measure_size(raw: dict, slim: dict) -> dict:
    """Bytes + approximate tokens, raw vs slim."""
    raise NotImplementedError
