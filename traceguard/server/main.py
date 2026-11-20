import time
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from . import detections, ingest
from .api import router
from .config import CONSOLE_BUILD_DIR, DB_PATH, EVIDENCE_DIR, WEB_DIR
from .persistence import SQLitePersistence, SupabasePersistence
from .store import Store, utcnow

CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store = Store(DB_PATH)
    app.state.store = store
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    if bool(supabase_url) != bool(supabase_key):
        raise RuntimeError("Set both SUPABASE_URL and SUPABASE_KEY, or leave both unset.")
    if supabase_url and supabase_key:
        try:
            from supabase import create_client
            app.state.persistence = SupabasePersistence(create_client(supabase_url, supabase_key))
            app.state.persistence.health()
        except Exception as exc:
            raise RuntimeError(f"Supabase was configured but could not be initialized: {exc}") from exc
    else:
        app.state.persistence = SQLitePersistence(store)
    started = time.perf_counter()
    summary = ingest.ingest_all(store, EVIDENCE_DIR)
    events = store.one("SELECT COUNT(*) n FROM events")["n"]
    if events and not store.get_meta("last_run"):
        run = detections.run_all(store, actor="system")
        store.set_meta("last_run", run["run_id"])
    app.state.boot = {
        "events": events,
        "files": len(summary["results"]),
        "drift_verdict": summary["drift"].get("verdict"),
        "last_sync_utc": utcnow(),
        "seconds": round(time.perf_counter() - started, 2),
    }
    print(f"traceguard: {events} events from {len(summary['results'])} evidence artefacts "
          f"in {app.state.boot['seconds']}s (E05 clock: {app.state.boot['drift_verdict']})")
    yield
    if hasattr(app.state.persistence, "engine"):
        app.state.persistence.engine.dispose()
    store.conn.close()


app = FastAPI(title="Orbit", version="0.1", lifespan=lifespan)
app.add_middleware(CORSMiddleware,
                   allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_credentials=False, allow_methods=["GET", "POST", "OPTIONS"],
                   allow_headers=["Authorization", "Content-Type", "Accept", "Idempotency-Key"])
app.include_router(router)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = CSP
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
def healthz():
    return {"status": "ok", **getattr(app.state, "boot", {})}


@app.get("/review")
@app.get("/review/{path:path}")
def retire_case_review(path: str = ""):
    return RedirectResponse(url="/console/", status_code=307)


if CONSOLE_BUILD_DIR.is_dir():
    app.mount("/console", StaticFiles(directory=CONSOLE_BUILD_DIR, html=True), name="console")
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
