"""FastAPI service.

Endpoints:

    GET  /healthz     liveness probe
    GET  /metrics     Prometheus scrape endpoint
    POST /analyze     body: {"password": "...", "offline": false}

Passwords are accepted as Pydantic SecretStr and are never echoed into any
log or metric label.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field, SecretStr
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from pwscore import __version__
from pwscore.analyzer import analyze
from pwscore.models import AnalysisResult

REQUESTS = Counter(
    "pwscore_requests_total",
    "Analysis requests by verdict.",
    ["verdict"],
)
LATENCY = Histogram(
    "pwscore_analyze_seconds",
    "Time spent servicing /analyze.",
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)


class AnalyzeRequest(BaseModel):
    password: SecretStr = Field(description="Password to analyze. Never logged.")
    offline: bool = Field(
        default=False,
        description="Skip the HaveIBeenPwned lookup (faster, weaker signal).",
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.hibp_client = httpx.AsyncClient(
        timeout=5.0,
        headers={
            "User-Agent": f"pwscore/{__version__}",
            "Add-Padding": "true",
        },
    )
    try:
        yield
    finally:
        await app.state.hibp_client.aclose()


limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

app = FastAPI(
    title="pwscore",
    version=__version__,
    description="Password strength analysis service.",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(_: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"error": "rate_limit_exceeded", "detail": str(exc.detail)},
    )


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/analyze", response_model=AnalysisResult)
@limiter.limit("20/minute")
async def analyze_endpoint(request: Request, body: AnalyzeRequest) -> AnalysisResult:
    with LATENCY.time():
        result = await analyze(
            body.password.get_secret_value(),
            skip_hibp=body.offline,
            hibp_client=request.app.state.hibp_client,
        )
    REQUESTS.labels(verdict=result.verdict.value).inc()
    return result
