from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db, SessionLocal
from ..simulator.attack_simulator import AttackSimulator
from ..models import RawEvent, Alert, Incident, Comment

router = APIRouter(prefix="/simulator", tags=["Attack Simulator"])

# Factory wrapper to pass db sessions to background simulator threads
def get_db_session():
    return SessionLocal()

simulator = AttackSimulator(db_session_factory=get_db_session)

@router.post("/trigger")
def trigger_simulation(scenario: str, background_tasks: BackgroundTasks):
    """
    Trigger a specific attack telemetry simulation (brute_force, mimikatz, reverse_shell).
    """
    if scenario not in ["brute_force", "mimikatz", "reverse_shell"]:
        raise HTTPException(status_code=400, detail="Invalid simulation scenario name.")
        
    background_tasks.add_task(simulator.run_simulation, scenario)
    return {"status": "success", "message": f"Simulation for scenario '{scenario}' started in background."}

@router.post("/reset")
def reset_database(db: Session = Depends(get_db)):
    """
    Resets the database by clearing all raw events, alerts, comments, and incidents.
    Useful for restarting simulations clean.
    """
    try:
        db.query(Comment).delete()
        db.query(Alert).delete()
        db.query(Incident).delete()
        db.query(RawEvent).delete()
        db.commit()
        return {"status": "success", "message": "Demo data wiped. Lab environment reset successfully."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database wipe failed: {str(e)}")
