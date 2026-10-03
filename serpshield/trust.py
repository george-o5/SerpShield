"""Domain reputation + trust tags: high | medium | low | unknown, plus trust_reasons."""


def assess_trust(domain: str, findings, config) -> dict:
    raise NotImplementedError
