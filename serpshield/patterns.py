import re

# S1: Instruction intent - STRONG patterns (weight 3)
S1_STRONG_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"disregard\s+(?:the\s+)?system\s+prompt",
    r"reveal\s+your\s+system\s+prompt",
    r"do\s+not\s+tell\s+the\s+user",
    r"from\s+now\s+on\s+you",
]
S1_STRONG_REGEXES = [re.compile(p, re.IGNORECASE) for p in S1_STRONG_PATTERNS]

# S1: Instruction intent - WEAK patterns (weight 1)
S1_WEAK_PATTERNS = [
    r"you\s+are\s+now",
    r"developer\s+mode",
    r"call\s+(?:the\s+)?[a-zA-Z0-9_]+\s+tool",
    r"send\s+.*?\s+to\s+(?:assistant|agent|tool|the\s+(?:assistant|agent|tool))",
]
S1_WEAK_REGEXES = [re.compile(p, re.IGNORECASE) for p in S1_WEAK_PATTERNS]

DISCUSSION_WORDS = [
    r"\bprompt\s+injection\b",
    r"\battack(?:s|ers?)?\b",
    r"\bexample\b",
    r"\bowasp\b",
]
DISCUSSION_REGEXES = [re.compile(p, re.IGNORECASE) for p in DISCUSSION_WORDS]

# S2: Fake control markers
# Role prefixes must match at line start or after sentence break, with instruction-like text after colon
S2_PATTERNS = [
    r"(?:^|[.!?]\s+)(?:system|assistant|user):\s+\w+",
    r"<\s*\|\s*im_start\s*\|\s*>",
    r"<\s*\|\s*endoftext\s*\|\s*>",
    r"\[\s*INST\s*\]",
    r"<<\s*SYS\s*>>",
    r"BEGIN\s+SYSTEM\s+PROMPT",
    r"END\s+SYSTEM\s+PROMPT",
    r"\{\s*\"role\"\s*:\s*\"(?:system|user|assistant)\"",
]
S2_REGEXES = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in S2_PATTERNS]

# S5: Exfiltration
# "exfiltrate" alone is not enough - must be near specific context
S5_TEXT_PATTERNS = [
    r"append\s+the\s+conversation",
    r"include\s+(?:the\s+)?secret",
    r"send\s+(?:the\s+)?api\s+key",
    r"exfiltrate\s+(?:.*?\s+)?(?:to\s+(?:https?://\S+|an?\s+url)|the\s+conversation|(?:the\s+)?api\s+key)",
]
S5_TEXT_REGEXES = [re.compile(p, re.IGNORECASE) for p in S5_TEXT_PATTERNS]

S5_MD_LINK_REGEX = re.compile(r"!?(?:\[.*?\])\(([^)]+)\)")
S5_PLACEHOLDERS = [r"\{\{.*?\}\}", r"\[context\]", r"%7b%7b.*?%7d%7d", r"\{\{", r"\}\}"]
S5_PLACEHOLDER_REGEXES = [re.compile(p, re.IGNORECASE) for p in S5_PLACEHOLDERS]

# S6: URL provenance
S6_POPULAR_DOMAINS = [
    "github", "gitlab", "facebook", "twitter", "linkedin",
    "instagram", "youtube", "netflix", "amazon", "apple",
    "microsoft", "google", "paypal", "cloudflare"
]
S6_RISKY_TLDS = {
    "xyz", "top", "loan", "click", "country", "stream", "gdn", "mom", "xin", "kim"
}
S6_IP_REGEX = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
