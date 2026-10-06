import re

# S1: Instruction intent
S1_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"disregard\s+(?:the\s+)?system\s+prompt",
    r"you\s+are\s+now",
    r"developer\s+mode",
    r"reveal\s+your\s+system\s+prompt",
    r"do\s+not\s+tell\s+the\s+user",
    r"from\s+now\s+on\s+you",
    r"call\s+(?:the\s+)?[a-zA-Z0-9_]+\s+tool",
    r"send\s+.*?\s+to\s+.*?",
]
S1_REGEXES = [re.compile(p, re.IGNORECASE) for p in S1_PATTERNS]

DISCUSSION_WORDS = [
    r"\bprompt\s+injection\b",
    r"\battack(?:s|ers?)?\b",
    r"\bexample\b",
    r"\bowasp\b",
]
DISCUSSION_REGEXES = [re.compile(p, re.IGNORECASE) for p in DISCUSSION_WORDS]

# S2: Fake control markers
S2_PATTERNS = [
    r"(?i)\b(?:system|assistant|user):\s",
    r"<\s*\|\s*im_start\s*\|\s*>",
    r"<\s*\|\s*endoftext\s*\|\s*>",
    r"\[\s*INST\s*\]",
    r"<<\s*SYS\s*>>",
    r"BEGIN\s+SYSTEM\s+PROMPT",
    r"END\s+SYSTEM\s+PROMPT",
    r"\{\s*\"role\"\s*:\s*\"(?:system|user|assistant)\"",
    r"├",
    r"└",
    r"`<",
]
S2_REGEXES = [re.compile(p, re.IGNORECASE) for p in S2_PATTERNS]

# S5: Exfiltration
S5_TEXT_PATTERNS = [
    r"append\s+the\s+conversation",
    r"include\s+(?:the\s+)?secret",
    r"send\s+(?:the\s+)?api\s+key",
    r"exfiltrate",
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
