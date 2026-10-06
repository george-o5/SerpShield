"""In-memory TTL cache (default 1h) + credit accounting (per-session, per-day, hard max)."""

import time
from typing import Any, Tuple, Optional
from serpshield.config import get_config

class Cache:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self.store = {}
        
    def get(self, key: Tuple[str, str, int]) -> Optional[Any]:
        if key in self.store:
            val, ts = self.store[key]
            if time.time() - ts < self.ttl_seconds:
                return val
            else:
                del self.store[key]
        return None
        
    def set(self, key: Tuple[str, str, int], value: Any):
        self.store[key] = (value, time.time())


class Budget:
    def __init__(self, config=None):
        if not config:
            config = get_config()
        self.session_cap = config.budget.session_cap
        self.daily_cap = config.budget.daily_cap
        self.hard_max = config.budget.hard_max
        self.session_used = 0
        self.daily_used = 0
        
    def check(self) -> bool:
        if self.session_used >= self.session_cap:
            return False
        if self.daily_used >= self.daily_cap:
            return False
        if self.session_used >= self.hard_max or self.daily_used >= self.hard_max:
            return False
        return True
        
    def record_live_call(self) -> None:
        self.session_used += 1
        self.daily_used += 1
        
    def status(self) -> dict:
        return {
            "session_used": self.session_used,
            "session_cap": self.session_cap,
            "daily_used": self.daily_used,
            "daily_cap": self.daily_cap
        }
