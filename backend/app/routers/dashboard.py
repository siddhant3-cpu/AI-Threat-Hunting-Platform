from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
import datetime
from ..database import get_db
from ..models import Alert, Incident
from typing import Dict, Any, List

router = APIRouter(prefix="/dashboard", tags=["Dashboard Stats"])

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_alerts = db.query(Alert).count()
    active_incidents = db.query(Incident).filter(Incident.status.in_(["New", "Investigating"])).count()
    critical_alerts = db.query(Alert).filter(Alert.severity.in_(["High", "Critical"])).count()
    
    # Calculate average risk score
    avg_risk_query = db.query(func.avg(Incident.risk_score)).filter(Incident.status.in_(["New", "Investigating"])).scalar()
    avg_risk_score = round(float(avg_risk_query), 1) if avg_risk_query is not None else 0.0
    
    return {
        "total_alerts": total_alerts,
        "active_incidents": active_incidents,
        "critical_alerts": critical_alerts,
        "avg_risk_score": avg_risk_score
    }

@router.get("/mitre-matrix")
def get_mitre_attack_matrix(db: Session = Depends(get_db)):
    """
    Scans all alerts, extracts MITRE ATT&CK techniques, and counts active occurrences for the heatmap.
    """
    alerts = db.query(Alert).all()
    matrix_counts = {}
    
    # Map technique ID to names for cleaner UI labeling
    technique_names = {
        "T1059.001": "PowerShell Scripting",
        "T1059.004": "Unix Shell execution",
        "T1003.001": "LSASS Memory Dumping",
        "T1547.001": "Registry Run Keys",
        "T1110": "Brute Force Logins",
        "T1569.002": "PsExec Service Abuse",
        "T1090": "Proxy C2 Tunneling",
        "T1053": "Scheduled Task Abuse"
    }

    for alert in alerts:
        if alert.mitre_techniques:
            for tech in alert.mitre_techniques:
                if tech not in matrix_counts:
                    matrix_counts[tech] = {
                        "technique": tech,
                        "name": technique_names.get(tech, tech),
                        "count": 0,
                        "severity": alert.severity
                    }
                matrix_counts[tech]["count"] += 1
                # Elevate severity color mapping to maximum triggered
                sev_order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
                current_max = matrix_counts[tech]["severity"]
                if sev_order.get(alert.severity, 0) > sev_order.get(current_max, 0):
                    matrix_counts[tech]["severity"] = alert.severity
                    
    return list(matrix_counts.values())

@router.get("/timeline")
def get_alerts_timeline(db: Session = Depends(get_db)):
    """
    Returns alerts count grouped by hour for the last 24 hours to populate the trend graph.
    """
    now = datetime.datetime.utcnow()
    twenty_four_hours_ago = now - datetime.timedelta(hours=24)
    
    # Query logs in last 24 hours
    alerts = db.query(Alert).filter(Alert.timestamp >= twenty_four_hours_ago).all()
    
    # Initialize 24 hourly buckets
    buckets = {}
    for h in range(24):
        hour_dt = now - datetime.timedelta(hours=h)
        hour_str = hour_dt.strftime("%m-%d %H:00")
        buckets[hour_str] = {"time": hour_str, "Low": 0, "Medium": 0, "High": 0, "Critical": 0, "total": 0}
        
    for alert in alerts:
        hour_str = alert.timestamp.strftime("%m-%d %H:00")
        if hour_str in buckets:
            buckets[hour_str][alert.severity] += 1
            buckets[hour_str]["total"] += 1
            
    # Return chronologically sorted
    return sorted(list(buckets.values()), key=lambda x: x["time"])
