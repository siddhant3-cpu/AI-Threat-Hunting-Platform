import pytest
import datetime
from app.routers.auth import hash_password, verify_password, create_jwt_token, SECRET_KEY, ALGORITHM
from app.enrichment.threat_intel import enrich_ioc
from app.detection.engine import SigmaEngine
import jwt

def test_password_hashing():
    pwd = "password123!"
    hashed = hash_password(pwd)
    
    # Verify hash stability and verification helper
    assert hashed != pwd
    assert len(hashed) == 64  # SHA-256 hex length
    assert verify_password(pwd, hashed) is True
    assert verify_password("wrongpassword", hashed) is False

def test_jwt_token_creation():
    data = {"sub": "analyst_bob", "role": "analyst"}
    token = create_jwt_token(data, expires_delta=datetime.timedelta(minutes=10))
    
    # Decode and verify payload
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == "analyst_bob"
    assert payload["role"] == "analyst"
    assert "exp" in payload

@pytest.mark.anyio
async def test_threat_intel_enrichment():
    # 1. Test simulated malicious IP indicator
    res_malicious = await enrich_ioc("198.51.100.45")
    assert res_malicious["value"] == "198.51.100.45"
    assert res_malicious["reputation"] == "Malicious"
    assert res_malicious["threat_score"] == 95
    assert res_malicious["provider"] == "AbuseIPDB"
    assert "Russia" in res_malicious["details"]["country"]

    # 2. Test fallback generic clean IP indicator
    res_clean = await enrich_ioc("8.8.8.8")
    assert res_clean["value"] == "8.8.8.8"
    assert res_clean["reputation"] == "Clean"
    assert res_clean["threat_score"] == 0
    assert "Mock" in res_clean["provider"]

def test_sigma_engine_case_insensitive_lookup():
    engine = SigmaEngine()
    
    # Mock event where keys are camelCase or mixed case
    event = {
        "event_id": 4625,
        "source": "Winlogbeat-Security",
        "fields": {
            "CommandLine": "net user /add hacker",
            "Image": "C:\\Windows\\System32\\net.exe"
        }
    }
    
    # 1. Rule checks capitalized "EventID"
    sel_1 = {"EventID": 4625}
    assert engine._evaluate_selection(sel_1, event) is True
    
    # 2. Rule checks lowercase "commandline"
    sel_2 = {"commandline|contains": "hacker"}
    assert engine._evaluate_selection(sel_2, event) is True
    
    # 3. Rule checks mixed case "ImAgE"
    sel_3 = {"ImAgE|endswith": "net.exe"}
    assert engine._evaluate_selection(sel_3, event) is True
    
    # 4. Non-matching command line checks
    sel_4 = {"commandline|contains": "cleancommand"}
    assert engine._evaluate_selection(sel_4, event) is False
