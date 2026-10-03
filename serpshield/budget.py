"""In-memory TTL cache (default 1h) + credit accounting (per-session, per-day, hard max)."""


class Cache:
    def get(self, key): raise NotImplementedError
    def set(self, key, value): raise NotImplementedError


class Budget:
    def check(self) -> bool: raise NotImplementedError
    def record_live_call(self) -> None: raise NotImplementedError
    def status(self) -> dict: raise NotImplementedError
