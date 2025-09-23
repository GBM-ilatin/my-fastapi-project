"""
Main FastAPI application entry point.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="my-fastapi-project",
    description="Generated FastAPI application",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Welcome to my-fastapi-project"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

# Include routers here
# from src.api import router
# app.include_router(router, prefix="/api/v1")
