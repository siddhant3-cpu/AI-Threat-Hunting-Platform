import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import engine, Base, SessionLocal
from .models import User
from .routers import auth, incidents, alerts, rules, simulator, threat_intel, dashboard
from .config import settings
from .routers.auth import hash_password

# Initialize FastAPI App
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Backend API for real-time security events correlation and Sigma rule based threat hunting.",
    version="1.0.0"
)

# Set CORS origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(auth.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(rules.router, prefix="/api")
app.include_router(simulator.router, prefix="/api")
app.include_router(threat_intel.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")

@app.on_event("startup")
def startup_event():
    # 1. Create database tables if they do not exist
    Base.metadata.create_all(bind=engine)
    
    # 2. Seed initial analyst user if not present
    db = SessionLocal()
    try:
        analyst = db.query(User).filter(User.username == "analyst").first()
        if not analyst:
            hashed_pw = hash_password("cybersecurity2026")
            db.add(User(
                username="analyst",
                password_hash=hashed_pw,
                role="Analyst"
            ))
            db.commit()
            
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            hashed_pw = hash_password("admin123")
            db.add(User(
                username="admin",
                password_hash=hashed_pw,
                role="Admin"
            ))
            db.commit()
    finally:
        db.close()
        
    # 3. Bootstrap rules by triggering rule fetch (which copies them from disk rules if empty)
    db = SessionLocal()
    try:
        from .routers.rules import get_rules
        get_rules(db)
    except Exception as e:
        print(f"Error bootstrapping Sigma rules: {e}")
    finally:
        db.close()

@app.get("/")
def read_root():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "api_docs": "/docs"
    }
