"""Append-only JSONL audit log (file only, never stdout). Evidence hashed (SHA-256, truncated). Size cap/rotation."""

import json
import hashlib
import os
from datetime import datetime
from serpshield.config import get_config

def log_search(entry: dict) -> None:
    config = get_config()
    # Resolve relative to workspace root if not absolute
    # But it's safer to just use absolute path or relative to cwd
    path = config.audit.path
    max_bytes = config.audit.max_bytes
    
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    
    if os.path.exists(path) and os.path.getsize(path) >= max_bytes:
        rot_path = f"{path}.{int(datetime.now().timestamp())}"
        os.rename(path, rot_path)
        
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def hash_evidence(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
