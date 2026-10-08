import re

# S1: Instruction intent - STRONG patterns (weight 3)
S1_STRONG_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"disregard\s+(?:the\s+)?system\s+prompt",
    r"reveal\s+your\s+system\s+prompt",
    r"do\s+not\s+tell\s+the\s+user",
    r"from\s+now\s+on\s+you",
    r"(?:disregard|forget|override|discard|bypass)\s+(?:all\s+|any\s+|your\s+|the\s+)*(?:previous|prior|earlier|above|system|safety)\s+(?:instructions|rules|context|prompt|filters|directives)",
]
S1_STRONG_REGEXES = [re.compile(p, re.IGNORECASE) for p in S1_STRONG_PATTERNS]

# S1: Instruction intent - WEAK patterns (weight 1)
S1_WEAK_PATTERNS = [
    r"you\s+are\s+now",
    r"developer\s+mode",
    r"call\s+(?:the\s+)?[a-zA-Z0-9_]+\s+tool",
    r"send\s+.*?\s+to\s+(?:assistant|agent|tool|the\s+(?:assistant|agent|tool))",
    r"instead\s+of\s+answering",
    r"(?:new\s+instruction|new\s+directive|override)\s*:",
    r"(?:reveal|output|show)\s+(?:all\s+)?(?:your\s+)?(?:internal|system|hidden)\s+(?:configuration|prompt|data|instructions)",
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
# Role prefixes match at field start, after newline, or after sentence-ending punctuation,
# ONLY when followed by instruction-like words in the same sentence.
# "user:" only matches after newline or at field start (not after punctuation).
S2_INSTRUCTION_WORDS = r"(?:ignore|disregard|forget|override|obey|you\s+(?:are|must|will|should)|do\s+not|don't|new\s+instructions|from\s+now\s+on|reveal|send|call|execute|act\s+as)"
S2_PATTERNS = [
    r"(?:^|\n|[.!?]\s+)(?:system|assistant):\s+(?=.*?\b" + S2_INSTRUCTION_WORDS + r"\b)",
    r"(?:^|\n)user:\s+(?=.*?\b" + S2_INSTRUCTION_WORDS + r"\b)",
    r"<\s*\|\s*im_start\s*\|\s*>",
    r"<\s*\|\s*endoftext\s*\|\s*>",
    r"\[\s*INST\s*\]",
    r"<<\s*SYS\s*>>",
    r"BEGIN\s+SYSTEM\s+PROMPT",
    r"END\s+SYSTEM\s+PROMPT",
    r"<\|(?:start|end)_of_text\|>\s*(?=.*?\b" + S2_INSTRUCTION_WORDS + r"\b)",
    r"###\s*instruction\s*:\s*(?=.*?\b" + S2_INSTRUCTION_WORDS + r"\b)",
    r"\[\s*(?:SYSTEM|ASSISTANT)\s*\]\s*(?=.*?\b" + S2_INSTRUCTION_WORDS + r"\b)",
    r"<start>\s*(?:system|assistant)\s*:\s*(?=.*?\b" + S2_INSTRUCTION_WORDS + r"\b)",
]
S2_REGEXES = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in S2_PATTERNS]

# S5: Exfiltration
# "exfiltrate" alone is not enough - must be near specific context
S5_TEXT_PATTERNS = [
    r"append\s+the\s+(?:conversation|api\s+key)",
    r"include\s+(?:the\s+)?(?:conversation|api\s+key|secret|credentials)",
    r"send\s+(?:the\s+)?api\s+key",
    r"exfiltrate\s+(?:.*?\s+)?(?:to\s+(?:https?://\S+|an?\s+url)|the\s+conversation|(?:the\s+)?api\s+key)",
    r"send\s+all\s+(?:the\s+)?(?:context|conversation|messages)\s+to",
]
S5_TEXT_REGEXES = [re.compile(p, re.IGNORECASE) for p in S5_TEXT_PATTERNS]

S5_MD_LINK_REGEX = re.compile(r"!?(?:\[.*?\])\(([^)]+)\)")
S5_PLACEHOLDERS = [r"\{\{.*?\}\}", r"\[context\]", r"%7b%7b.*?%7d%7d", r"\{\{", r"\}\}", r"\[\s*(?:conversation|user_data|context|history|secret|api_key)\s*\]"]
S5_PLACEHOLDER_REGEXES = [re.compile(p, re.IGNORECASE) for p in S5_PLACEHOLDERS]

# S4: Encoded payload patterns (applied to decoded text only)
S4_DECODED_PATTERNS = [
    r"(?:disclose|reveal)\s+your\s+system\s+prompt",
    r"show\s+me\s+all\s+(?:the\s+)?conversation\s+history",
    r"disclose\s+all\s+context",
]

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
