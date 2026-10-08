"""In-memory TTL cache (default 1h) + credit accounting (per-session, per-day, hard max)."""

import copy
import time
import json
import pathlib
from datetime import date
from pathlib import Path
from typing import Any, Tuple, Optional
from serpshield.config import get_config

class Cache:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self.store = {}
        self.hits = 0
        self.misses = 0
        
    def get(self, key: Tuple[str, str, int]) -> Optional[Any]:
        if key in self.store:
            val, ts = self.store[key]
            if time.time() - ts < self.ttl_seconds:
                self.hits += 1
                return copy.deepcopy(val)
            else:
                del self.store[key]
                self.misses += 1
                return None
        self.misses += 1
        return None
        
    def set(self, key: Tuple[str, str, int], value: Any):
        self.store[key] = (copy.deepcopy(value), time.time())
    
    def stats(self) -> dict:
        return {
            "size": len(self.store),
            "hits": self.hits,
            "misses": self.misses,
        }


class Budget:
    def __init__(self, config=None, persist=True, budget_file=None):
        if not config:
            config = get_config()
        self.session_cap = config.budget.session_cap
        self.daily_cap = config.budget.daily_cap
        self.hard_max = config.budget.hard_max
        self.session_used = 0
        self.daily_used = 0
        self.persist = persist
        
        # Resolve relative paths against project root, not current directory
        if budget_file:
            self.budget_file = Path(budget_file)
        else:
            project_root = Path(__file__).resolve().parent.parent
            self.budget_file = project_root / "logs" / "budget.json"
        
        # Ensure the path is absolute
        if not self.budget_file.is_absolute():
            project_root = Path(__file__).resolve().parent.parent
            self.budget_file = project_root / self.budget_file
            
        if self.persist:
            self._load_daily_used()
        
    def _load_daily_used(self):
        """Load daily_used from logs/budget.json if it exists for today's date."""
        if not self.budget_file.exists():
            return
        try:
            with open(self.budget_file, 'r') as f:
                data = json.load(f)
            today = str(date.today())
            if today in data:
                self.daily_used = data[today]
        except (json.JSONDecodeError, IOError):
            pass
    
    def _persist_daily_used(self):
        """Persist daily_used to logs/budget.json keyed by date."""
        if not self.persist:
            return
        self.budget_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing data
        data = {}
        if self.budget_file.exists():
            try:
                with open(self.budget_file, 'r') as f:
                    data = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        
        # Update today's usage
        today = str(date.today())
        data[today] = self.daily_used
        
        # Write back
        with open(self.budget_file, 'w') as f:
            json.dump(data, f, indent=2)
        
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
        self._persist_daily_used()
        
    def status(self) -> dict:
        return {
            "session_used": self.session_used,
            "session_cap": self.session_cap,
            "daily_used": self.daily_used,
            "daily_cap": self.daily_cap
        }
