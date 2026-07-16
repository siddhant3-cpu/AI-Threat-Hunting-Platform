import pytest
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.models import RawEvent, Alert, Incident
from app.detection.engine import SigmaEngine
from app.correlation.engine import CorrelationEngine

# Setup in-memory SQLite database for test runtime isolated from development db
TEST_DATABASE_URL = "sqlite:///:memory:"

@pytest.fixture
def db_session():
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)

def test_sigma_engine_encoded_powershell():
    engine = SigmaEngine()
    
    # Register rule structure in engine manually
    powershell_rule = {
        "id": "powershell_encoded",
        "title": "Encoded PowerShell",
        "severity": "High",
        "category": "process_creation",
        "logsource": {"product": "windows", "service": "sysmon"},
        "detection": {
            "selection": {
                "CommandLine|contains": ["-enc", "-encoded"],
                "Image|endswith": ["\\powershell.exe"]
            },
            "condition": "selection"
        }
    }
    engine.rules.append(powershell_rule)

    # 1. Matching Event (obfuscated powershell)
    matching_event = {
        "source": "Winlogbeat-Sysmon",
        "host": "WS-PROD-01",
        "user": "admin",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIA",
        "timestamp": datetime.datetime.utcnow()
    }
    
    alerts = engine.run_rules(matching_event)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "powershell_encoded"
    assert alerts[0]["severity"] == "High"

    # 2. Non-matching Event (normal powershell execution)
    non_matching_event = {
        "source": "Winlogbeat-Sysmon",
        "host": "WS-PROD-01",
        "user": "admin",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File script.ps1",
        "timestamp": datetime.datetime.utcnow()
    }
    alerts = engine.run_rules(non_matching_event)
    assert len(alerts) == 0

def test_correlation_engine_alert_grouping(db_session):
    engine = CorrelationEngine(window_minutes=5)
    
    # 1. Dispatch first low severity alert on host WS-PROD-01
    alert_1 = Alert(
        id="alert-uuid-1",
        rule_id="failed_login",
        rule_name="Failed Login Attempt",
        severity="Low",
        host="WS-PROD-01",
        user="admin",
        log_source="Security",
        mitre_techniques=["T1110"],
        timestamp=datetime.datetime.utcnow()
    )
    db_session.add(alert_1)
    db_session.commit()
    
    incident_1 = engine.correlate_alert(db_session, alert_1)
    db_session.refresh(alert_1)
    
    assert incident_1 is not None
    assert alert_1.incident_id == incident_1.id
    assert incident_1.risk_score == 10
    assert incident_1.severity == "Low"
    assert incident_1.host_affected == "WS-PROD-01"

    # 2. Dispatch second high severity alert on same host within the window
    alert_2 = Alert(
        id="alert-uuid-2",
        rule_id="powershell_encoded",
        rule_name="Encoded PowerShell Execution",
        severity="High",
        host="WS-PROD-01",
        user="admin",
        log_source="Sysmon",
        mitre_techniques=["T1059.001"],
        timestamp=datetime.datetime.utcnow()
    )
    db_session.add(alert_2)
    db_session.commit()
    
    incident_2 = engine.correlate_alert(db_session, alert_2)
    db_session.refresh(alert_2)
    
    # Verify both alerts map to the same incident record
    assert incident_2.id == incident_1.id
    assert alert_2.incident_id == incident_1.id
    
    # Cumulative risk score should grow: 10 (Low) + 70 (High) + 15 (Multiple alerts bonus) + 40 (techniques correlation bonus)
    # Total score should cap or hit values
    assert incident_2.risk_score > 70
    assert incident_2.severity in ["High", "Critical"]
