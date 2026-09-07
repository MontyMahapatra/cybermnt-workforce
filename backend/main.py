import asyncio
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import Base, engine, SessionLocal
from routers import ingest, auth_router, dashboard, devices
from rate_limit import limiter
from alerts import sweep_missed_heartbeats

Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async def sweep_loop():
        while True:
            db = SessionLocal()
            try:
                sweep_missed_heartbeats(db)
            finally:
                db.close()
            await asyncio.sleep(60)

    # Fine for a single-instance deployment. Running more than one backend
    # replica? Move this to a proper scheduler (cron hitting an internal
    # endpoint, or Celery beat) so it doesn't run once per replica.
    task = asyncio.create_task(sweep_loop())
    yield
    task.cancel()


app = FastAPI(title="CyberMNT Remote Team Monitor", version="0.2.0", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:5500").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Signature"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Assumes TLS is terminated in front of this app (reverse proxy) --
    # HSTS is meaningless served over plain HTTP.
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


app.include_router(ingest.router)
app.include_router(auth_router.router)
app.include_router(dashboard.router)
app.include_router(devices.router)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
