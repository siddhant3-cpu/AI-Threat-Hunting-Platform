import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI Threat Hunting & Detection Platform"
    
    # Database Configuration (Postgres/SQLite fallback)
    DATABASE_URL: str = "sqlite:///./threat_hunting.db"
    
    # Elasticsearch connection configuration
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    USE_MOCK_ELASTICSEARCH: bool = True  # Fallback to local SQLite/Memory store if Elasticsearch is not running
    
    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    ALIENVAULT_OTX_KEY: Optional[str] = None
    
    # AI Analyst configuration
    GEMINI_API_KEY: Optional[str] = None
    AI_PROVIDER: str = "gemini"  # "gemini" or "mock"
    
    # CORS Configuration
    ALLOWED_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000", "*"]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()
