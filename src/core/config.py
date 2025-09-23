"""
Application configuration settings.
"""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Application settings."""
    
    project_name: str = "Generated FastAPI Project"
    api_v1_str: str = "/api/v1"
    database_url: str = "sqlite:///./app.db"
    secret_key: str = "change-this-secret-key-in-production"
    access_token_expire_minutes: int = 30
    backend_cors_origins: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    class Config:
        env_file = ".env"


settings = Settings()
