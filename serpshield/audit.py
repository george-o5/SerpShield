"""Append-only JSONL audit log (file only, never stdout). Evidence hashed (SHA-256, truncated). Size cap/rotation."""


def log_search(entry: dict) -> None:
    raise NotImplementedError


def hash_evidence(text: str) -> str:
    raise NotImplementedError
