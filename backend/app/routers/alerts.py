from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from ..database import get_db
from ..models import Alert, RawEvent
from ..schemas import AlertOut, RawEventOut

router = APIRouter(tags=["Alerts & Hunting"])

@router.get("/alerts", response_model=List[AlertOut])
def get_alerts(
    severity: Optional[str] = None,
    host: Optional[str] = None,
    unassigned: Optional[bool] = False,
    db: Session = Depends(get_db)
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if host:
        query = query.filter(Alert.host == host)
    if unassigned:
        query = query.filter(Alert.incident_id == None)
        
    return query.order_by(Alert.timestamp.desc()).all()

@router.get("/hunting/logs", response_model=List[RawEventOut])
def hunt_logs(
    search: Optional[str] = Query(None, description="Lucene-style or simple message search query"),
    host: Optional[str] = Query(None, description="Filter by hostname"),
    user: Optional[str] = Query(None, description="Filter by username"),
    source: Optional[str] = Query(None, description="Filter by log source name"),
    event_id: Optional[int] = Query(None, description="Filter by Windows Event ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(RawEvent)
    
    if host:
        query = query.filter(RawEvent.host.ilike(f"%{host}%"))
    if user:
        query = query.filter(RawEvent.user.ilike(f"%{user}%"))
    if source:
        query = query.filter(RawEvent.source.ilike(f"%{source}%"))
    if event_id is not None:
        query = query.filter(RawEvent.event_id == event_id)
        
    if search:
        # Full text search simulation using SQL LIKE
        query = query.filter(
            RawEvent.message.ilike(f"%{search}%") | 
            RawEvent.host.ilike(f"%{search}%") | 
            RawEvent.user.ilike(f"%{search}%") | 
            RawEvent.source.ilike(f"%{search}%")
        )
        
    return query.order_by(RawEvent.timestamp.desc()).limit(limit).offset(offset).all()
