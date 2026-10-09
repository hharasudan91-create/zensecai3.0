from dotenv import load_dotenv
load_dotenv()
from services.copilot import get_copilot_response, RateLimitError, generate_fallback_summary

from fastapi import FastAPI, HTTPException, Request, Depends, WebSocket, WebSocketDisconnect
import sqlalchemy
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List
from datetime import datetime, timedelta
import random
import time
import asyncio
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("zentrasec")

from database import get_db, engine
from schemas import EventIngestRequest, WebsiteConnectionCreate, WebsiteConnectionResponse
from services.correlation import CorrelationEngine
from services.rules_engine import classify_risk
import models

inspector = sqlalchemy.inspect(engine)
if inspector.has_table("security_events"):
    columns = [col['name'] for col in inspector.get_columns("security_events")]
    if "connection_id" not in columns or "secure_token" not in columns:
        print("Schema changed (connection/secure_token columns missing). Recreating database...")
        models.Base.metadata.drop_all(bind=engine)

if inspector.has_table("website_connections"):
    columns = [col['name'] for col in inspector.get_columns("website_connections")]
    if "status" not in columns:
        print("Schema changed (status column missing in website_connections). Recreating database...")
        models.Base.metadata.drop_all(bind=engine)

# Safe SQLite migration: add new ThreatIntelligence columns if they don't exist yet.
_TI_NEW_COLUMNS = [
    ("threat_actor",     "VARCHAR(128)"),
    ("campaign",         "VARCHAR(255)"),
    ("country",          "VARCHAR(8)"),
    ("organization",     "VARCHAR(255)"),
    ("asn",              "VARCHAR(64)"),
    ("mitre_techniques", "JSON"),
]
if inspector.has_table("threat_intelligence"):
    _existing_ti_cols = {col["name"] for col in inspector.get_columns("threat_intelligence")}
    with engine.connect() as _conn:
        for _col_name, _col_type in _TI_NEW_COLUMNS:
            if _col_name not in _existing_ti_cols:
                print(f"[Migration] Adding column threat_intelligence.{_col_name}")
                _conn.execute(
                    sqlalchemy.text(f"ALTER TABLE threat_intelligence ADD COLUMN {_col_name} {_col_type}")
                )
        _conn.commit()

models.Base.metadata.create_all(bind=engine)


# Seed initial connection if none exists; ensure it always has a secure_token.
# IMPORTANT: If ZENTRASEC_TOKEN env var is set, it is used as the canonical token
# so the DB always matches what DevHub's vite.config.ts sends.
import secrets as _secrets
import os as _os

_ENV_TOKEN = _os.environ.get("ZENTRASEC_TOKEN", "").strip()

with Session(engine) as db:
    default_conn = db.query(models.WebsiteConnection).filter(
        models.WebsiteConnection.connection_id == "default-zensec-001"
    ).first()
    if not default_conn:
        # First run: create with env token if provided, else generate one
        _token = _ENV_TOKEN if _ENV_TOKEN else _secrets.token_hex(32)
        default_conn = models.WebsiteConnection(
            connection_id="default-zensec-001",
            secure_token=_token,
            website_url="https://admin.zensec.ai",
            customer_name="Zensec Default Customer"
        )
        db.add(default_conn)
        db.commit()
        logger.info("[STARTUP] Created default connection: default-zensec-001")
        logger.info("[STARTUP] Token source: %s", "ZENTRASEC_TOKEN env" if _ENV_TOKEN else "generated")
    elif not default_conn.secure_token:
        # Patch: existing row was seeded without a token
        _token = _ENV_TOKEN if _ENV_TOKEN else _secrets.token_hex(32)
        default_conn.secure_token = _token
        db.commit()
        logger.info("[STARTUP] Patched missing token for default-zensec-001")
    elif _ENV_TOKEN and default_conn.secure_token != _ENV_TOKEN:
        # Token mismatch: ZENTRASEC_TOKEN env overrides the stored token so
        # the backend stays in sync with DevHub's vite.config.ts.
        default_conn.secure_token = _ENV_TOKEN
        db.commit()
        logger.info("[STARTUP] Updated default-zensec-001 token to match ZENTRASEC_TOKEN env")
    else:
        logger.info("[STARTUP] default-zensec-001 OK (token aligned)")

app = FastAPI(title="ZentraSec API", description="AI-Powered Cybersecurity APIs", version="1.0.0")

# ---------------------------------------------------------------------------
# In-memory page-block ledger: connection_id → expiry datetime (UTC).
# This is the source-of-truth for the "Block Page" mitigation action.
# ---------------------------------------------------------------------------
_page_blocks: dict[str, datetime] = {}

# ---------------------------------------------------------------------------
# CORS — explicit origins; "*" is kept for development convenience but
# allow_credentials must be False when allow_origins contains a wildcard.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        # Demo-portal: opened via file:// sends Origin: null
        "null",
        # Demo-portal served via local HTTP server (e.g. python -m http.server)
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request logging middleware — fires BEFORE any route handler or LLM call
# ---------------------------------------------------------------------------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info("► %s %s (from %s)", request.method, request.url.path, request.client)
    response = await call_next(request)
    logger.info("◄ %s %s → %s", request.method, request.url.path, response.status_code)
    return response

class ResponseAction(BaseModel):
    action_id: str
    target: str

class ResponseExecutionRequest(BaseModel):
    incident_id: str
    actions: List[ResponseAction]
    analyst_id: str

class ActionStatus(BaseModel):
    action_id: str
    status: str # SUCCESS, FAILED
    reason: str = ""

class CopilotRequest(BaseModel):
    incident: dict
    question: str
    # Optional conversation history — list of {"role": "user"|"assistant", "content": str}.
    # The backend caps how many turns are used (see services/copilot.py MAX_HISTORY_TURNS).
    history: List[dict] = []

@app.post("/api/v1/incidents/{incident_id}/response-actions")
async def execute_response_actions(incident_id: str, request: ResponseExecutionRequest):
    """Simulate executing a list of security response actions against an incident.

    Each action has a 10 % chance of failure to mimic real-world partial failures.
    Returns the per-action results and an overall containment status.
    """
    await asyncio.sleep(2)  # Simulate processing delay

    results = []
    for action in request.actions:
        # 10% chance of failure for simulation realism
        if random.random() < 0.1:
            results.append(ActionStatus(
                action_id=action.action_id,
                status="FAILED",
                reason="Target unreachable or access denied",
            ))
        else:
            results.append(ActionStatus(
                action_id=action.action_id,
                status="SUCCESS",
                reason="Action executed successfully",
            ))

    return {
        "incident_id": incident_id,
        "results": results,
        "timestamp": time.time(),
        "status": "Contained" if all(r.status == "SUCCESS" for r in results) else "Containing",
    }

# ---------------------------------------------------------------------------
# Timeout tuning:
#   COPILOT_TIMEOUT_SECONDS (25s) is intentionally shorter than the frontend
#   AbortController limit (28s).  When timed out or unreachable, the copilot
#   falls back to a structured incident summary so the user is never stranded.
# ---------------------------------------------------------------------------
COPILOT_TIMEOUT_SECONDS = 25

@app.post("/api/v1/copilot/chat")
async def copilot_chat(request: CopilotRequest):
    """Accept a user question and incident context, call Google Gemini in a thread-pool
    executor, and return the AI answer or a structured fallback summary on timeout/error.

    Raises HTTP 429 if Gemini is rate-limiting.
    Falls back to a structured incident summary if Gemini times out or errors.
    """
    logger.info(
        "[Copilot] Request received (incident=%s, history_len=%d)",
        request.incident.get("id", "?"),
        len(request.history),
    )
    logger.debug("[Copilot] Question: %r", request.question)

    loop = asyncio.get_event_loop()
    try:
        answer = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                get_copilot_response,
                request.incident,
                request.question,
                request.history,   # ← pass conversation history
            ),
            timeout=COPILOT_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "[Copilot] Gemini call timed out after %ds — serving structured fallback summary",
            COPILOT_TIMEOUT_SECONDS,
        )
        answer = generate_fallback_summary(request.incident)
    except RateLimitError as exc:
        logger.warning("[Copilot] Rate limited by Gemini: %s", exc)
        raise HTTPException(
            status_code=429,
            detail=str(exc),
            headers={"Retry-After": "60"},
        )
    except Exception as exc:
        logger.exception("[Copilot] Gemini call failed: %s — serving structured fallback summary", exc)
        answer = generate_fallback_summary(request.incident)
    return {"answer": answer}

@app.get("/")
def read_root():
    return {"status": "ZentraSec Backend Running", "modules": ["ML Anomaly Detection", "RAG Copilot", "Event Correlation"]}

ENRICHMENT_EVENT_TYPES = {"LOGIN_FAILURE", "LOGIN_FAILED", "LOGIN_SUCCESS",
                          "PRIVILEGE_ACCESS", "PRIVILEGE_ESCALATION",
                          "LARGE_FILE_DOWNLOAD", "DATA_EXPORT"}


async def generate_ai_explanation(enriched: dict):
    """Task 2.5 - trigger the Gemini AI Copilot dynamically when a correlated
    fault is detected, then broadcast the explanation over WebSocket.
    Falls back to the structured summary if Gemini errors/times out.
    """
    fault = enriched.get("fault_description") or {}
    incident_ctx = {
        "id": enriched.get("event_id"),
        "title": ", ".join(fault.get("detections", [])) or "Anomaly detected",
        "description": fault.get("summary", ""),
        "severity": enriched.get("risk_band"),
        "risk_score": enriched.get("anomaly_score"),
        "user_id": enriched.get("user_id"),
        "source_ip": enriched.get("source_ip"),
        "event_type": enriched.get("event_type"),
    }
    question = (
        "Explain this correlated security fault concisely for a SOC analyst: "
        "what happened, why it is dangerous, and the recommended response actions."
    )
    loop = asyncio.get_event_loop()
    try:
        answer = await asyncio.wait_for(
            loop.run_in_executor(None, get_copilot_response, incident_ctx, question, []),
            timeout=COPILOT_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.warning("[AI Copilot] fallback used: %s", exc)
        answer = generate_fallback_summary(incident_ctx)

    await manager.broadcast(
        {
            "type": "FAULT_EXPLANATION",
            "timestamp": datetime.utcnow().isoformat(),
            "connection_id": enriched.get("connection_id"),
            "event_id": enriched.get("event_id"),
            "detections": fault.get("detections", []),
            "affected_user": enriched.get("user_id"),
            "source_ip": enriched.get("source_ip"),
            "risk_band": enriched.get("risk_band"),
            "explanation": answer,
            "recommended_actions": [
                "Verify recent login activity for the affected account",
                "Force password reset and revoke active sessions",
                "Block or rate-limit the source IP at the edge firewall",
                "Review privilege changes and recent large downloads",
            ],
        },
        enriched.get("connection_id"),
    )


@app.post("/api/v1/events")
async def ingest_event(request: EventIngestRequest, http_request: Request, db: Session = Depends(get_db)):
    # DEBUG EVENT - entry point
    logger.info("[DEBUG EVENT] request received")
    try:
        # Extract actual client IP
        client_ip = http_request.client.host if http_request.client else request.source_ip
        xff = http_request.headers.get("x-forwarded-for")
        if xff:
            client_ip = xff.split(",")[0].strip()

        # Connection and token validation
        connection_id = request.connection_id
        logger.info(f"[DEBUG EVENT] connection_id={connection_id}")
        logger.info(f"[DEBUG EVENT] event_type={request.event_type}")
        auth_header = http_request.headers.get("authorization") or http_request.headers.get("Authorization")
        token = None
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
        logger.info(f"[DEBUG EVENT] token_present={'true' if token else 'false'}")
        from models import WebsiteConnection
        db_conn = db.query(WebsiteConnection).filter(WebsiteConnection.connection_id == connection_id).first()
        if not db_conn:
            logger.warning("[ZENTRASEC] Unknown connection ID: %s", connection_id)
            raise HTTPException(status_code=404, detail="Connection ID not found")
        if not token or db_conn.secure_token != token:
            logger.warning("[ZENTRASEC] Invalid token for connection %s", connection_id)
            raise HTTPException(status_code=401, detail="Invalid secure token")

        # Log received event details
        logger.info("[ZENTRASEC EVENT RECEIVED] Connection ID: %s | Event Type: %s | Source IP: %s | Timestamp: %s",
                    connection_id, request.event_type, client_ip, request.timestamp)

        engine = CorrelationEngine(db)
        logger.info("[DEBUG EVENT] correlation started")
        event = engine.process_event(request, client_ip=client_ip)
        logger.info("[DEBUG EVENT] correlation completed")
        logger.info("[DEBUG EVENT] ingestion_success=true")

        rules = getattr(event, "rules_result", None) or {
            "score": event.anomaly_score or 0,
            "risk_band": classify_risk(event.anomaly_score or 0),
            "detections": [],
            "fault_description": None,
        }

        # Enrich for WS broadcast
        enriched = {
            "type": "SECURITY_EVENT",
            "event_id": event.event_id,
            "connection_id": event.connection_id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else datetime.utcnow().isoformat(),
            "event_type": event.event_type,
            "user_id": event.user_id,
            "source_ip": event.source_ip,
            "authentication_status": event.authentication_status,
            "anomaly_score": float(event.anomaly_score or 0.0),
            "risk_band": rules.get("risk_band", classify_risk(float(event.anomaly_score or 0.0))),
            "detections": rules.get("detections", []),
            "fault_description": rules.get("fault_description"),
            "metadata": request.metadata,
            "threat_intel": getattr(event, "threat_intel", None),
        }

        # DEBUG WS broadcast
        logger.info(f"[DEBUG WS] SECURITY_EVENT broadcast | connection_id={event.connection_id} | event_type={event.event_type} | anomaly_score={enriched['anomaly_score']} | risk_band={enriched['risk_band']}")
        await manager.broadcast(enriched, event.connection_id)


        # 2.5 - trigger AI Copilot dynamically for correlated faults
        if enriched["fault_description"]:
            asyncio.create_task(generate_ai_explanation(enriched))

        return {
            "status": "success",
            "event_id": event.event_id,
            "anomaly_score": enriched["anomaly_score"],
            "risk_band": enriched["risk_band"],
            "detections": enriched["detections"],
        }
    except Exception as e:
        logger.exception("Error processing event ingestion")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {repr(e)}")

@app.post("/api/v1/simulate/timeline")
def simulate_timeline(db: Session = Depends(get_db)):
    engine = CorrelationEngine(db)
    
    user = "employee01"
    ip = "10.10.10.25"
    unusual_ip = "192.168.1.100"
    
    now = datetime.utcnow()
    
    events = [
        {"type": "LOGIN_FAILED", "ip": ip, "time_offset": 0, "desc": "Failed login attempt"},
        {"type": "LOGIN_FAILED", "ip": ip, "time_offset": 1, "desc": "Failed login attempt"},
        {"type": "LOGIN_FAILED", "ip": ip, "time_offset": 2, "desc": "Failed login attempt"},
        {"type": "LOGIN_FAILED", "ip": ip, "time_offset": 3, "desc": "Failed login attempt"},
        {"type": "LOGIN_FAILED", "ip": ip, "time_offset": 4, "desc": "Failed login attempt"},
        {"type": "LOGIN_SUCCESS", "ip": ip, "time_offset": 5, "desc": "Successful login after failures"},
        {"type": "SUSPICIOUS_LOGIN", "ip": unusual_ip, "time_offset": 10, "desc": "Login from unusual location"},
        {"type": "PRIVILEGE_ESCALATION", "ip": unusual_ip, "time_offset": 15, "desc": "User added to Administrators group"},
        {"type": "MASS_FILE_ACCESS", "ip": unusual_ip, "time_offset": 20, "desc": "Accessed 500+ documents in 1 minute"},
        {"type": "DATA_EXPORT", "ip": unusual_ip, "time_offset": 25, "desc": "Large outbound data transfer detected"}
    ]
    
    processed = []
    
    for ev in events:
        req = EventIngestRequest(
            timestamp=now + timedelta(minutes=ev["time_offset"]),
            user_id=user,
            source_ip=ev["ip"],
            event_type=ev["type"],
            metadata={"description": ev["desc"]}
        )
        saved_ev = engine.process_event(req)
        processed.append(saved_ev.event_id)
        
    from models import Incident, AttackTimeline
    latest_incident = db.query(Incident).order_by(Incident.created_at.desc()).first()
        
    return {
        "status": "Simulation complete", 
        "events_processed": len(processed),
        "incident_id": latest_incident.incident_id if latest_incident else None
    }

@app.get("/api/v1/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: str, db: Session = Depends(get_db)):
    from models import Incident, AttackTimeline
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    timeline_entries = db.query(AttackTimeline).filter(AttackTimeline.incident_id == incident.id).order_by(AttackTimeline.sequence.asc()).all()
    
    stages = []
    events_data = []
    
    for t in timeline_entries:
        stage = "Unknown"
        event_name = "Unknown"
        if "] " in t.description:
            parts = t.description.split("] ", 1)
            stage = parts[0].strip("[")
            if ":" in parts[1]:
                event_name = parts[1].split(":")[0]
            else:
                event_name = parts[1]
                
        stages.append(stage)
        events_data.append({
            "sequence": t.sequence,
            "timestamp": t.timestamp,
            "description": t.description,
            "stage": stage,
            "event_name": event_name,
            "source": t.source,
            "anomaly_score": t.anomaly_score,
            "severity": t.severity,
            "risk_contribution": t.risk_contribution
        })
        
    # Remove duplicates from stages while preserving order
    unique_stages = []
    for s in stages:
        if s not in unique_stages:
            unique_stages.append(s)
    
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "description": incident.description,
        "stages": unique_stages,
        "timeline": events_data
    }

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, connection_id: str):
        await websocket.accept()
        if connection_id not in self.active_connections:
            self.active_connections[connection_id] = []
        self.active_connections[connection_id].append(websocket)

    def disconnect(self, websocket: WebSocket, connection_id: str):
        if connection_id in self.active_connections:
            self.active_connections[connection_id].remove(websocket)

    async def broadcast(self, message: dict, connection_id: str):
        if connection_id in self.active_connections:
            for connection in self.active_connections[connection_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.warning(f"Failed to send to websocket: {e}")

manager = ConnectionManager()

import secrets
import string

@app.post("/api/v1/connections", response_model=WebsiteConnectionResponse)
def create_connection(conn: WebsiteConnectionCreate, db: Session = Depends(get_db)):
    if not (conn.website_url.startswith("http://") or conn.website_url.startswith("https://")):
        raise HTTPException(status_code=400, detail="Website URL must use http:// or https://")
        
    random_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    new_connection_id = f"INC-{random_id}"
    new_token = secrets.token_hex(32)

    db_conn = models.WebsiteConnection(
        connection_id=new_connection_id,
        secure_token=new_token,
        website_url=conn.website_url,
        customer_name=conn.customer_name
    )
    try:
        db.add(db_conn)
        db.commit()
        db.refresh(db_conn)
        return db_conn
    except sqlalchemy.exc.IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="This website is already connected.")

@app.get("/api/v1/connections", response_model=List[WebsiteConnectionResponse])
def get_connections(db: Session = Depends(get_db)):
    return db.query(models.WebsiteConnection).all()

@app.post("/api/v1/incidents/{incident_id}/suspend-10sec")
async def suspend_account_7min(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    incident.status = "Mitigated"
    db.commit()
    
    return {
        "status": "Success",
        "message": "User account temporarily blocked for 10 seconds.",
        "incident_id": incident_id,
        "mitigation_time": 10
    }


# ---------------------------------------------------------------------------
# Block Page mitigation — temporarily blocks all access to a connected app.
# The in-memory _page_blocks dict is the source-of-truth.
# ---------------------------------------------------------------------------

@app.post("/api/v1/connections/{connection_id}/block-page")
async def block_page(connection_id: str, db: Session = Depends(get_db)):
    """Activate a 7-minute page block for the given connection."""
    conn = db.query(models.WebsiteConnection).filter(
        models.WebsiteConnection.connection_id == connection_id
    ).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")

    expiry = datetime.utcnow() + timedelta(seconds=10)
    _page_blocks[connection_id] = expiry
    logger.info("[BLOCK-PAGE] Activated for %s until %s", connection_id, expiry.isoformat())

    return {
        "status": "Success",
        "message": f"Page access blocked for 10 seconds on {connection_id}.",
        "connection_id": connection_id,
        "expiry": expiry.isoformat(),
        "mitigation_time": 10
    }


@app.get("/api/v1/connections/{connection_id}/block-status")
async def get_block_status(connection_id: str):
    """Check whether page access is currently blocked for a connection.

    DevHub polls this endpoint (via its Vite proxy) to decide whether
    to render the security block page.  The server-side expiry is the
    single source of truth so a browser refresh cannot bypass the block.
    """
    expiry = _page_blocks.get(connection_id)
    if expiry is None or datetime.utcnow() >= expiry:
        # Expired or never set — clean up and return unblocked
        _page_blocks.pop(connection_id, None)
        return {"blocked": False, "remaining_seconds": 0}

    remaining = int((expiry - datetime.utcnow()).total_seconds())
    return {"blocked": True, "remaining_seconds": max(remaining, 0)}

@app.websocket("/api/v1/ws/security-flow/{connection_id}")
async def websocket_endpoint(websocket: WebSocket, connection_id: str):
    await manager.connect(websocket, connection_id)
    try:
        while True:
            await asyncio.sleep(3)
            
            flow_event = {
                "type": "FLOW_UPDATE",
                "timestamp": datetime.utcnow().isoformat(),
                "metrics": {
                    "active_sessions": random.randint(100, 500),
                    "traffic_rate": f"{random.randint(5, 50)} req/s",
                    "threat_level": random.choice(["Low", "Medium", "High", "Critical"])
                },
                "events": [
                    {
                        "source": "Firewall",
                        "event": "Traffic Analyzed",
                        "status": "OK"
                    },
                    {
                        "source": "WAF",
                        "event": "Anomaly Detected" if random.random() > 0.7 else "Traffic OK",
                        "status": "Blocked" if random.random() > 0.8 else "Logged"
                    }
                ]
            }
            await manager.broadcast(flow_event, connection_id)
    except WebSocketDisconnect:
        manager.disconnect(websocket, connection_id)


# ---------------------------------------------------------------------------
# Threat Intelligence API
# ---------------------------------------------------------------------------
from services.threat_intel import ThreatIntelService, validate_ioc

@app.get("/api/v1/threat-intel/summary")
def get_ti_summary(db: Session = Depends(get_db)):
    """Return counts of IOCs by reputation category."""
    try:
        svc = ThreatIntelService(db)
        return svc.get_summary()
    except Exception as exc:
        print("[TI] summary error:", exc)
        raise HTTPException(status_code=500, detail="Failed to load threat intelligence summary")


@app.get("/api/v1/threat-intel/iocs")
def get_ti_iocs(limit: int = 50, db: Session = Depends(get_db)):
    """Return the most recently seen IOCs (max 100)."""
    limit = min(limit, 100)
    try:
        svc = ThreatIntelService(db)
        return {"iocs": svc.get_recent_iocs(limit=limit)}
    except Exception as exc:
        print("[TI] iocs list error:", exc)
        raise HTTPException(status_code=500, detail="Failed to load IOC list")


@app.get("/api/v1/threat-intel/ioc/{indicator:path}")
def get_ti_ioc(indicator: str, db: Session = Depends(get_db)):
    """Look up a single IOC (IP / domain / URL / hash) by value."""
    valid, ioc_type, err = validate_ioc(indicator)
    if not valid:
        raise HTTPException(status_code=422, detail=err)
    try:
        svc = ThreatIntelService(db)
        result = svc.lookup_ioc(indicator, ioc_type)
        if "error" in result:
            raise HTTPException(status_code=422, detail=result["message"])
        return result
    except HTTPException:
        raise
    except Exception as exc:
        print("[TI] ioc lookup error:", exc)
        raise HTTPException(status_code=500, detail="Threat intelligence lookup failed")


from schemas import ThreatIntelLookupRequest

@app.post("/api/v1/threat-intel/lookup")
def lookup_ti_ioc(request: ThreatIntelLookupRequest, db: Session = Depends(get_db)):
    """POST-based IOC lookup using the existing ThreatIntelLookupRequest schema."""
    valid, ioc_type, err = validate_ioc(request.indicator)
    if not valid:
        raise HTTPException(status_code=422, detail=err)
    try:
        svc = ThreatIntelService(db)
        result = svc.lookup_ioc(request.indicator, ioc_type)
        if "error" in result:
            raise HTTPException(status_code=422, detail=result["message"])
        return result
    except HTTPException:
        raise
    except Exception as exc:
        print("[TI] lookup error:", exc)
        raise HTTPException(status_code=500, detail="Threat intelligence lookup failed")


@app.get("/api/v1/threat-intel/actors")
def get_ti_actors(db: Session = Depends(get_db)):
    """Return deduplicated threat actor profiles seen in enriched IOCs."""
    try:
        svc = ThreatIntelService(db)
        return {"actors": svc.get_actors()}
    except Exception as exc:
        print("[TI] actors error:", exc)
        raise HTTPException(status_code=500, detail="Failed to load threat actor data")


@app.get("/api/v1/threat-intel/feeds/status")
def get_ti_feed_status(db: Session = Depends(get_db)):
    """Return the current status of all configured threat intelligence providers."""
    try:
        svc = ThreatIntelService(db)
        return svc.get_feed_status()
    except Exception as exc:
        print("[TI] feed status error:", exc)
        return {
            "overall_status": "ERROR",
            "label": "Unable to determine feed status",
            "ioc_database": "ERROR",
            "enrichment": "ERROR",
            "last_updated": None,
            "providers": [],
        }
