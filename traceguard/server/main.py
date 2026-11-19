import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import detections, ingest
from .api import router
from .config import DB_PATH, EVIDENCE_DIR, WEB_DIR
from .store import Store

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
        "seconds": round(time.perf_counter() - started, 2),
    }
    print(f"traceguard: {events} events from {len(summary['results'])} evidence artefacts "
          f"in {app.state.boot['seconds']}s (E05 clock: {app.state.boot['drift_verdict']})")
    yield
    store.conn.close()


app = FastAPI(title="Orbit", version="0.1", lifespan=lifespan)
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


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
