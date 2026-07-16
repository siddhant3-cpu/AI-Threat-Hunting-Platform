import datetime
import logging
from sqlalchemy.orm import Session
from ..models import Alert, Incident
from typing import List, Optional

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "Low": 10,
    "Medium": 30,
    "High": 70,
    "Critical": 100
}

class CorrelationEngine:
    def __init__(self, window_minutes: int = 15):
        self.window_minutes = window_minutes

    def correlate_alert(self, db: Session, alert: Alert) -> Incident:
        """
        Takes a new Alert, checks for existing open Incidents on the same Host or User
        within the correlation window, and either groups the Alert into that Incident
        or creates a new Incident.
        """
        time_threshold = datetime.datetime.utcnow() - datetime.timedelta(minutes=self.window_minutes)
        
        # 1. Search for an existing active (New or Investigating) incident matching Host or User
        existing_incident = None
        
        if alert.host:
            existing_incident = db.query(Incident).filter(
                Incident.host_affected == alert.host,
                Incident.status.in_(["New", "Investigating"]),
                Incident.created_at >= time_threshold
            ).order_by(Incident.updated_at.desc()).first()
            
        if not existing_incident and alert.user:
            existing_incident = db.query(Incident).filter(
                Incident.user_affected == alert.user,
                Incident.status.in_(["New", "Investigating"]),
                Incident.created_at >= time_threshold
            ).order_by(Incident.updated_at.desc()).first()

        # 2. If an incident exists, attach this alert to it
        if existing_incident:
            alert.incident_id = existing_incident.id
            db.add(alert)
            db.commit()
            db.refresh(existing_incident)
            
            # Recalculate Incident Severity and Risk Score
            self._update_incident_metrics(db, existing_incident)
            logger.info(f"Correlated Alert {alert.id} ({alert.rule_name}) to existing Incident {existing_incident.id}")
            return existing_incident
        else:
            # 3. Create a new Incident
            title = f"Suspicious Activity on {alert.host or 'Unknown Host'}"
            if alert.rule_id == "failed_login":
                title = f"Potential Brute Force Activity on {alert.host or 'Unknown Host'}"
            elif alert.rule_id == "mimikatz_detection":
                title = f"Credential Dumping Detected on {alert.host or 'Unknown Host'}"
            elif alert.rule_id == "reverse_shell":
                title = f"Reverse Shell Connection on {alert.host or 'Unknown Host'}"
            
            incident = Incident(
                title=title,
                severity=alert.severity,
                status="New",
                host_affected=alert.host,
                user_affected=alert.user,
                risk_score=SEVERITY_WEIGHTS.get(alert.severity, 10),
                description=f"Incident generated due to alert: {alert.rule_name}. {alert.description or ''}"
            )
            
            db.add(incident)
            db.commit()
            db.refresh(incident)
            
            # Link alert to newly created incident
            alert.incident_id = incident.id
            db.add(alert)
            db.commit()
            
            logger.info(f"Created new Incident {incident.id} for Alert {alert.id} ({alert.rule_name})")
            return incident

    def _update_incident_metrics(self, db: Session, incident: Incident):
        """
        Recalculates risk score and severity based on all correlated alerts.
        """
        alerts = incident.alerts
        if not alerts:
            return
            
        # Calculate cumulative score
        total_score = 0
        techniques = set()
        
        for alert in alerts:
            total_score += SEVERITY_WEIGHTS.get(alert.severity, 10)
            if alert.mitre_techniques:
                # Add to technique set
                for tech in alert.mitre_techniques:
                    techniques.add(tech)
                    
        # Apply correlation bonus:
        # 1. Multiple alerts bonus
        if len(alerts) > 1:
            total_score += (len(alerts) - 1) * 15
            
        # 2. Multi-stage attack bonus (multiple distinct MITRE ATT&CK techniques)
        if len(techniques) > 1:
            total_score += len(techniques) * 20
            
        # Limit max risk score to 100
        incident.risk_score = min(total_score, 100)
        
        # Re-evaluate Severity based on final risk score
        if incident.risk_score >= 90:
            incident.severity = "Critical"
        elif incident.risk_score >= 60:
            incident.severity = "High"
        elif incident.risk_score >= 30:
            incident.severity = "Medium"
        else:
            incident.severity = "Low"
            
        # Set description summarizing multiple alerts
        rule_counts = {}
        for alert in alerts:
            rule_counts[alert.rule_name] = rule_counts.get(alert.rule_name, 0) + 1
            
        summary_lines = [f"- {count}x {rule_name}" for rule_name, count in rule_counts.items()]
        incident.description = (
            f"Multiple correlated events detected on asset. Related triggers:\n" + 
            "\n".join(summary_lines)
        )
        
        # Auto-update incident title for complex attacks
        if len(techniques) >= 3:
            incident.title = f"Multi-Stage Attack Campaign Targeting {incident.host_affected or 'Endpoint'}"
        elif any(a.rule_id == "failed_login" for a in alerts) and any(a.rule_id in ["powershell_encoded", "reverse_shell"] for a in alerts):
            incident.title = f"Compromise Chain: Brute Force & execution on {incident.host_affected or 'Endpoint'}"
            
        incident.updated_at = datetime.datetime.utcnow()
        db.add(incident)
        db.commit()
        db.refresh(incident)
