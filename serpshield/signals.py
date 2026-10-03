"""Signals S1-S6. Pure functions: (normalized_text_bundle) -> list[Finding].

S1 instruction intent | S2 fake control markers | S3 hidden delivery
S4 encoded payload    | S5 exfiltration plumbing | S6 URL provenance (tag only)
Pattern lists live in config/constants, not hard-coded here.
Evidence is hashed, never echoed.
"""


def s1_instruction_intent(bundle): raise NotImplementedError
def s2_fake_control_markers(bundle): raise NotImplementedError
def s3_hidden_delivery(bundle): raise NotImplementedError
def s4_encoded_payload(bundle): raise NotImplementedError
def s5_exfiltration(bundle): raise NotImplementedError
def s6_url_provenance(bundle): raise NotImplementedError


ALL_SIGNALS = {}  # id -> function, filled in later (needed for ablation)
