import pytest
from serpshield.slim import slim_result, wrap_envelope, measure_size
from serpshield.models import ResultItem, Finding

def test_slim_result():
    item = ResultItem(position=1, title="Test", link="https://www.example.com/path", snippet="a" * 400)
    item.findings.append(Finding(signal_id="S1", field="title", evidence_hash="hash"))
    setattr(item, "trust", "high")
    
    slim = slim_result(item)
    assert slim["position"] == 1
    assert slim["title"] == "Test"
    assert slim["link"] == "https://www.example.com/path"
    assert slim["domain"] == "example.com"
    assert len(slim["snippet"]) == 300
    assert slim["snippet"].endswith("...")
    assert slim["trust"] == "high"
    assert len(slim["findings"]) == 1

def test_wrap_envelope():
    res = wrap_envelope("q", "google", [], {"meta": "data"})
    assert "UNTRUSTED" in res["notice"]
    assert res["query"] == "q"
    assert res["engine"] == "google"

def test_measure_size():
    raw = {"data": "x" * 1000}
    slim = {"data": "x"}
    sizes = measure_size(raw, slim)
    assert sizes["raw_bytes"] > sizes["slim_bytes"]
    assert sizes["savings_bytes"] > 0
