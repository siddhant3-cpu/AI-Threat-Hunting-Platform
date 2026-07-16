from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# User Schemas
class UserBase(BaseModel):
    username: str
    role: str

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(UserBase):
    id: int
    created_at: datetime
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

# Alert Schemas
class AlertBase(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: str
    description: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    log_source: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime

class AlertOut(AlertBase):
    incident_id: Optional[int] = None
    class Config:
        from_attributes = True

# Comment Schemas
class CommentBase(BaseModel):
    content: str

class CommentCreate(CommentBase):
    pass

class CommentOut(CommentBase):
    id: int
    incident_id: int
    author: str
    created_at: datetime
    class Config:
        from_attributes = True

# Incident Schemas
class IncidentBase(BaseModel):
    title: str
    severity: str
    status: str
    host_affected: Optional[str] = None
    user_affected: Optional[str] = None
    risk_score: int
    description: Optional[str] = None
    assigned_analyst: Optional[str] = None

class IncidentCreate(IncidentBase):
    pass

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_analyst: Optional[str] = None
    description: Optional[str] = None
    risk_score: Optional[int] = None

class IncidentOut(IncidentBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class IncidentDetailOut(IncidentOut):
    alerts: List[AlertOut] = []
    comments: List[CommentOut] = []
    ai_summary: Optional[str] = None
    ai_playbook: Optional[str] = None
    class Config:
        from_attributes = True

# SigmaRule Schemas
class SigmaRuleBase(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    severity: str
    category: str
    yaml_content: str
    status: str = "active"

class SigmaRuleCreate(SigmaRuleBase):
    pass

class SigmaRuleOut(SigmaRuleBase):
    created_at: datetime
    class Config:
        from_attributes = True

# RawEvent Schemas (Log Search)
class RawEventBase(BaseModel):
    timestamp: datetime
    host: Optional[str] = None
    user: Optional[str] = None
    source: str
    event_id: Optional[int] = None
    message: Optional[str] = None
    fields: Optional[Dict[str, Any]] = None

class RawEventOut(RawEventBase):
    id: int
    class Config:
        from_attributes = True

# Dashboard Stats Schemas
class KPIStats(BaseModel):
    total_alerts: int
    active_incidents: int
    critical_alerts: int
    avg_risk_score: float

class MitreCount(BaseModel):
    technique: str
    name: str
    count: int
    severity: str

class AlertTimelineItem(BaseModel):
    time: str
    count: int
    severity: str
