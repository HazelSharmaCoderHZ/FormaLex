from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.services.analyzer import URLAnalyzer


app = FastAPI(
    title="FormaLex API",
    description="Grammar-Based URL Phishing Detection",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

analyzer = URLAnalyzer()


class URLRequest(BaseModel):
    url: str


@app.get("/")
def root():
    return {
        "project": "FormaLex",
        "status": "running"
    }


@app.post("/analyze")
def analyze_url(request: URLRequest):
    return analyzer.analyze(request.url)