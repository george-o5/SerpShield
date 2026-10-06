import pytest
import time
from serpshield.budget import Cache, Budget
from serpshield.config import get_config

def test_cache():
    cache = Cache(ttl_seconds=1)
    cache.set(("google", "q", 10), "val")
    assert cache.get(("google", "q", 10)) == "val"
    time.sleep(1.1)
    assert cache.get(("google", "q", 10)) is None

def test_budget():
    budget = Budget()
    budget.session_cap = 2
    budget.daily_cap = 2
    assert budget.check() is True
    budget.record_live_call()
    assert budget.check() is True
    budget.record_live_call()
    assert budget.check() is False
    
    status = budget.status()
    assert status["session_used"] == 2
