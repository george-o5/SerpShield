import pytest
import time
import json
from datetime import date
from serpshield.budget import Cache, Budget
from serpshield.config import get_config

def test_cache():
    cache = Cache(ttl_seconds=1)
    cache.set(("google", "q", 10), "val")
    assert cache.get(("google", "q", 10)) == "val"
    time.sleep(1.1)
    assert cache.get(("google", "q", 10)) is None

def test_budget():
    budget = Budget(persist=False)
    budget.session_cap = 2
    budget.daily_cap = 2
    assert budget.check() is True
    budget.record_live_call()
    assert budget.check() is True
    budget.record_live_call()
    assert budget.check() is False
    
    status = budget.status()
    assert status["session_used"] == 2

def test_budget_persistence(tmp_path):
    budget_file = tmp_path / "budget.json"
    
    # First budget instance
    budget1 = Budget(persist=True, budget_file=str(budget_file))
    budget1.record_live_call()
    assert budget1.daily_used == 1
    
    # Second budget instance should load the persisted data
    budget2 = Budget(persist=True, budget_file=str(budget_file))
    assert budget2.daily_used == 1
    
    # Verify file content
    with open(budget_file, 'r') as f:
        data = json.load(f)
    today = str(date.today())
    assert today in data
    assert data[today] == 1
