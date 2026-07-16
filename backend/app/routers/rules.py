import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ..database import get_db
from ..models import SigmaRule
from ..schemas import SigmaRuleOut, SigmaRuleCreate
from ..simulator.attack_simulator import RULES_DIR
from ..detection.engine import SigmaEngine

router = APIRouter(prefix="/rules", tags=["Sigma Rules"])

# Initialize dynamic engine instance for runtime verification
verifier_engine = SigmaEngine()

@router.get("", response_model=List[SigmaRuleOut])
def get_rules(db: Session = Depends(get_db)):
    # 1. Fetch rules stored in database
    db_rules = db.query(SigmaRule).all()
    
    # If DB is empty, let's load rules from disk and bootstrap database for easy first-time experience
    if not db_rules:
        import os
        engine_disk = SigmaEngine(RULES_DIR)
        for rule in engine_disk.rules:
            db_rule = SigmaRule(
                id=rule.get('id', 'unknown'),
                title=rule.get('title', 'Unknown Title'),
                description=rule.get('description', ''),
                severity=rule.get('severity', 'Low').capitalize(),
                category=rule.get('category', 'process_creation'),
                yaml_content=yaml.dump(rule),
                status='active'
            )
            db.add(db_rule)
        db.commit()
        db_rules = db.query(SigmaRule).all()
        
    return db_rules

@router.post("", response_model=SigmaRuleOut)
def create_custom_rule(rule_in: SigmaRuleCreate, db: Session = Depends(get_db)):
    # Validate YAML content
    try:
        rule_data = yaml.safe_load(rule_in.yaml_content)
        if not rule_data or not isinstance(rule_data, dict):
            raise ValueError("YAML is not a dictionary")
        if 'detection' not in rule_data or 'condition' not in rule_data['detection']:
            raise ValueError("Missing detection or condition logic block in rule")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Sigma YAML Syntax: {str(e)}"
        )
        
    # Check if duplicate ID
    existing = db.query(SigmaRule).filter(SigmaRule.id == rule_in.id).first()
    if existing:
         raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Rule ID '{rule_in.id}' already exists."
        )

    db_rule = SigmaRule(
        id=rule_in.id,
        title=rule_in.title,
        description=rule_in.description,
        severity=rule_in.severity.capitalize(),
        category=rule_in.category,
        yaml_content=rule_in.yaml_content,
        status=rule_in.status
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

@router.put("/{rule_id}/toggle", response_model=SigmaRuleOut)
def toggle_rule_status(rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(SigmaRule).filter(SigmaRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    rule.status = "inactive" if rule.status == "active" else "active"
    db.commit()
    db.refresh(rule)
    return rule

@router.delete("/{rule_id}")
def delete_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = db.query(SigmaRule).filter(SigmaRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    db.delete(rule)
    db.commit()
    return {"status": "success", "message": f"Rule '{rule_id}' deleted."}
