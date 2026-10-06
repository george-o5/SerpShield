import os
import pytest
import json
from serpshield.audit import log_search, hash_evidence

def test_hash_evidence():
    h = hash_evidence("test")
    assert len(h) == 16

def test_log_search(tmp_path, monkeypatch):
    from serpshield.config import get_config
    cfg = get_config()
    log_file = tmp_path / "audit.jsonl"
    
    # We must patch get_config to return our modified config
    original_get_config = get_config
    
    def mock_get_config(preset="balanced"):
        c = original_get_config(preset)
        c.audit.path = str(log_file)
        c.audit.max_bytes = 1000
        return c
        
    monkeypatch.setattr("serpshield.audit.get_config", mock_get_config)
    
    log_search({"test": 1})
    assert log_file.exists()
    
    with open(log_file, "r") as f:
        data = json.loads(f.read().strip())
        assert data["test"] == 1
        
    # Test rotation
    with open(log_file, "a") as f:
        f.write("x" * 2000)
        
    log_search({"test": 2})
    # the old one is rotated, the new one has test: 2
    with open(log_file, "r") as f:
        data = json.loads(f.read().strip())
        assert data["test"] == 2
