import json
from scripts.normalize import merge_ioc_lists

def test_dedup_basic():
    a = [{"ioc_value":"1.1.1.1","ioc_type":"ip","source":"x","first_seen":None,"confidence":"low","raw_source":{}}]
    b = [{"ioc_value":"1.1.1.1","ioc_type":"ip","source":"y","first_seen":None,"confidence":"high","raw_source":{}}]
    merged = merge_ioc_lists([a,b])
    assert len(merged) == 1
    assert merged[0]["confidence"] == "high"

def test_schema_keys_exist():
    sample = [{"ioc_value":"example.com","ioc_type":"domain","source":"x","first_seen":None,"confidence":"medium","raw_source":{}}]
    merged = merge_ioc_lists([sample])
    obj = merged[0]
    for k in ["ioc_value","ioc_type","source","first_seen","confidence","raw_source"]:
        assert k in obj
