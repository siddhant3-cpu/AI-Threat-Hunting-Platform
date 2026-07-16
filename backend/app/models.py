from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON, Table
from sqlalchemy.orm import relationship
import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="Analyst")  # Analyst, Senior Analyst, Admin
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, default="Low")  # Low, Medium, High, Critical
    status = Column(String, default="New")  # New, Investigating, Remediated, Closed
    host_affected = Column(String, nullable=True)
    user_affected = Column(String, nullable=True)
    risk_score = Column(Integer, default=0)
    description = Column(Text, nullable=True)
    assigned_analyst = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # AI generated content
    ai_summary = Column(Text, nullable=True)
    ai_playbook = Column(Text, nullable=True)
    
    alerts = relationship("Alert", back_populates="incident")
    comments = relationship("Comment", back_populates="incident", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(String, primary_key=True, index=True)  # UUID or custom ID
    rule_id = Column(String, index=True)
    rule_name = Column(String, nullable=False)
    severity = Column(String, default="Low")
    description = Column(Text, nullable=True)
    host = Column(String, nullable=True, index=True)
    user = Column(String, nullable=True, index=True)
    log_source = Column(String, nullable=True)
    mitre_techniques = Column(JSON, nullable=True)  # List of technique IDs e.g. ["T1059.001", "T1003"]
    details = Column(JSON, nullable=True)  # Raw details of matching event
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    incident = relationship("Incident", back_populates="alerts")

class Comment(Base):
    __tablename__ = "comments"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    author = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    incident = relationship("Incident", back_populates="comments")

class SigmaRule(Base):
    __tablename__ = "sigma_rules"
    
    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="Low")
    category = Column(String, nullable=False)  # process_creation, network_connection, etc.
    yaml_content = Column(Text, nullable=False)
    status = Column(String, default="active")  # active, inactive
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class RawEvent(Base):
    """
    Acts as the simulated log index repository (Mock Elasticsearch) for SIEM log hunting.
    """
    __tablename__ = "raw_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    host = Column(String, nullable=True, index=True)
    user = Column(String, nullable=True, index=True)
    source = Column(String, nullable=False, index=True)  # Winlogbeat-Sysmon, Filebeat-auditd, etc.
    event_id = Column(Integer, nullable=True)  # Windows event ID e.g. 1 (Process Create), 3 (Network)
    message = Column(Text, nullable=True)  # Full command line or description text
    fields = Column(JSON, nullable=True)  # Dynamic fields (e.g. process_name, image_path, command_line, ip, hash, registry)
