from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from ..database import get_db
from ..models import Incident, Alert, Comment
from ..schemas import IncidentOut, IncidentDetailOut, IncidentUpdate, CommentCreate, CommentOut
from ..reporting.pdf_generator import generate_pdf_report
from ..ai.analyst import generate_incident_analysis

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("", response_model=List[IncidentOut])
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    analyst: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if analyst:
        query = query.filter(Incident.assigned_analyst == analyst)
        
    return query.order_by(Incident.created_at.desc()).all()

@router.get("/{incident_id}", response_model=IncidentDetailOut)
def get_incident_detail(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.put("/{incident_id}", response_model=IncidentOut)
def update_incident(incident_id: int, inc_update: IncidentUpdate, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    update_data = inc_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(incident, key, value)
        
    db.commit()
    db.refresh(incident)
    return incident

@router.post("/{incident_id}/comments", response_model=CommentOut)
def add_incident_comment(incident_id: int, comment_in: CommentCreate, author: str = "Analyst", db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    comment = Comment(
        incident_id=incident_id,
        author=author,
        content=comment_in.content
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment

@router.post("/{incident_id}/analyze-ai")
async def trigger_ai_analysis(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
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
    
    try:
        ai_report = await generate_incident_analysis(incident_data, alerts_list)
        incident.ai_summary = ai_report.get("summary")
        incident.ai_playbook = ai_report.get("playbook")
        
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return {
            "status": "success",
            "ai_summary": incident.ai_summary,
            "ai_playbook": incident.ai_playbook
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate AI analysis: {str(e)}")

@router.get("/{incident_id}/report")
def export_incident_report(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    alerts_data = [
        {
            "rule_name": a.rule_name,
            "severity": a.severity,
            "description": a.description,
            "log_source": a.log_source,
            "timestamp": a.timestamp
        } for a in incident.alerts
    ]
    
    comments_data = [
        {
            "author": c.author,
            "content": c.content,
            "created_at": c.created_at
        } for c in incident.comments
    ]
    
    incident_dict = {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "host_affected": incident.host_affected,
        "user_affected": incident.user_affected,
        "risk_score": incident.risk_score,
        "description": incident.description,
        "assigned_analyst": incident.assigned_analyst,
        "created_at": incident.created_at,
        "ai_summary": incident.ai_summary,
        "ai_playbook": incident.ai_playbook
    }
    
    pdf_buffer = generate_pdf_report(incident_dict, alerts_data, comments_data)
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=incident_{incident_id}_report.pdf"}
    )
