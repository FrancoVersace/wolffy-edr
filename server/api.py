from __future__ import annotations

import asyncio
import hmac
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from sqlalchemy import func, select, update

from agent.rules_engine import SEVERITIES, load_rules
from common import VERSION
from common.config import load_server_config, resolve_path
from common.paths import DATA_DIR, ROOT, ensure_dirs
from common.security import resolve_dashboard_token, resolve_secret, verify

from .database import Agent, Alert, Database, Event, Metric, iso, utcnow
from .schemas import AgentInfo, EventBatch

log = logging.getLogger("wolffy.server")

DASHBOARD_DIR = ROOT / "dashboard"
MAX_BODY_BYTES = 4 * 1024 * 1024
SEVERITY_PATTERN = "^(" + "|".join(SEVERITIES) + ")$"
PURGE_INTERVAL = 3600

SCORE_WEIGHTS = {"low": 1, "medium": 5, "high": 15, "critical": 40}
SCORE_DECAY_PER_HOUR = 1.0
SCORE_LEVELS = [(61, "compromised"), (31, "investigate"), (11, "suspicious"), (0, "clean")]


def parse_timestamp(value) -> datetime:
    now = utcnow()
    if not value:
        return now
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return now
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    if parsed > now + timedelta(minutes=5):
        return now
    return parsed


def load_json(text):
    try:
        return json.loads(text) if text else {}
    except ValueError:
        return {}


def alert_out(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "agent_id": alert.agent_id,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "message": alert.message,
        "mitre_attack": alert.mitre_attack,
        "timestamp": iso(alert.timestamp),
        "acknowledged": alert.acknowledged,
        "acknowledged_at": iso(alert.acknowledged_at),
        "event": load_json(alert.event_data),
    }


def event_out(event: Event) -> dict:
    return {
        "id": event.id,
        "agent_id": event.agent_id,
        "event_type": event.event_type,
        "timestamp": iso(event.timestamp),
        "data": load_json(event.data),
    }


def compute_risk_score(session, agent_id: str) -> dict:
    """Compute risk score for an agent based on recent unacknowledged alerts."""
    now = utcnow()
    cutoff = now - timedelta(hours=24)
    alerts = session.execute(
        select(Alert.severity, Alert.timestamp).where(
            Alert.agent_id == agent_id,
            Alert.acknowledged.is_(False),
            Alert.timestamp >= cutoff,
        )
    ).all()
    score = 0.0
    for severity, timestamp in alerts:
        weight = SCORE_WEIGHTS.get(severity, 1)
        hours_ago = max(0, (now - timestamp).total_seconds() / 3600)
        decayed = max(0, weight - (hours_ago * SCORE_DECAY_PER_HOUR))
        score += decayed
    score = round(min(score, 100), 1)
    level = "clean"
    for threshold, label in SCORE_LEVELS:
        if score >= threshold:
            level = label
            break
    return {"score": score, "level": level}


def agent_out(agent: Agent, offline_after: int, open_alerts: int = 0, risk: dict = None) -> dict:
    online = agent.last_seen >= utcnow() - timedelta(seconds=offline_after)
    result = {
        "id": agent.id,
        "hostname": agent.hostname,
        "ip_address": agent.ip_address,
        "os_info": agent.os_info,
        "version": agent.version,
        "status": "online" if online else "offline",
        "first_seen": iso(agent.first_seen),
        "last_seen": iso(agent.last_seen),
        "open_alerts": open_alerts,
    }
    if risk is not None:
        result["risk_score"] = risk["score"]
        result["risk_level"] = risk["level"]
    return result


def get_session(request: Request):
    session = request.app.state.db.session()
    try:
        yield session
    finally:
        session.close()


def require_read(request: Request):
    token = request.app.state.dashboard_token
    if not token:
        return
    header = request.headers.get("authorization", "")
    supplied = header[7:] if header.lower().startswith("bearer ") else ""
    if not hmac.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(401, "token de dashboard invalido", headers={"WWW-Authenticate": "Bearer"})


async def signed_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(413, "cuerpo demasiado grande")
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(413, "cuerpo demasiado grande")
    timestamp = request.headers.get("x-wolffy-timestamp", "")
    signature = request.headers.get("x-wolffy-signature", "")
    if not verify(request.app.state.secret, timestamp, signature, body):
        raise HTTPException(401, "firma invalida o reloj desfasado")
    return body


def upsert_agent(session, info: AgentInfo) -> Agent:
    agent = session.get(Agent, info.agent_id)
    now = utcnow()
    if agent is None:
        agent = Agent(id=info.agent_id, first_seen=now)
        session.add(agent)
        log.info("agente nuevo: %s (%s)", info.agent_id, info.hostname)
    agent.hostname = info.hostname or agent.hostname or ""
    agent.os_info = info.os_info or agent.os_info or ""
    agent.ip_address = info.ip_address or agent.ip_address or ""
    agent.version = info.version or agent.version or ""
    agent.last_seen = now
    return agent


def send_notification(alert: dict, config: dict):
    topic = config.get("notifications", {}).get("ntfy_topic")
    if not topic:
        return
    min_sev = config.get("notifications", {}).get("min_severity", "high")
    sev_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if sev_levels.get(alert["severity"], 0) < sev_levels.get(min_sev, 3):
        return
    try:
        url = f"https://ntfy.sh/{topic}"
        headers = {
            "Title": f"Wolffy EDR: {alert['rule_name']} ({alert['severity'].upper()})",
            "Priority": "high" if alert["severity"] == "critical" else "default",
        }
        body = f"Agente: {alert['agent_id']}\nMensaje: {alert['message']}"
        httpx.post(url, data=body.encode("utf-8"), headers=headers, timeout=5.0)
    except Exception as e:
        log.warning("fallo al enviar notificacion ntfy: %s", e)


router = APIRouter(prefix="/api/v1")
read_router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_read)])


@router.post("/agents/register")
def register_agent(body: bytes = Depends(signed_body), session=Depends(get_session)):
    try:
        info = AgentInfo.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(422, json.loads(exc.json())) from None
    upsert_agent(session, info)
    session.commit()
    return {"status": "registered", "agent_id": info.agent_id}


@router.post("/events")
def receive_events(request: Request, bg_tasks: BackgroundTasks, body: bytes = Depends(signed_body), session=Depends(get_session)):
    try:
        batch = EventBatch.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(422, json.loads(exc.json())) from None
    upsert_agent(session, batch)

    uids = [str(ev["uid"])[:64] for ev in batch.events if ev.get("uid")]
    known_events = set(session.scalars(select(Event.uid).where(Event.uid.in_(uids)))) if uids else set()
    known_alerts = set(session.scalars(select(Alert.uid).where(Alert.uid.in_(uids)))) if uids else set()

    accepted = duplicates = alerts = 0
    new_alerts = []
    for ev in batch.events:
        etype = str(ev.get("type") or "unknown")[:64]
        uid = str(ev.get("uid") or uuid.uuid4().hex)[:64]
        stamp = parse_timestamp(ev.get("timestamp"))
        if etype == "alert":
            if uid in known_alerts:
                duplicates += 1
                continue
            data = ev.get("alert") if isinstance(ev.get("alert"), dict) else {}
            severity = str(data.get("severity") or "medium").lower()
            rule_name = str(data.get("rule_name") or "Alerta")[:255]
            message = str(data.get("message") or "")
            session.add(Alert(
                uid=uid,
                agent_id=batch.agent_id,
                rule_id=str(data.get("rule_id") or "unknown")[:64],
                rule_name=rule_name,
                severity=severity if severity in SEVERITIES else "medium",
                message=message,
                mitre_attack=(str(data["mitre_attack"])[:32] if data.get("mitre_attack") else None),
                timestamp=stamp,
                event_data=json.dumps(data.get("event") or {}, default=str),
            ))
            new_alerts.append({
                "severity": severity if severity in SEVERITIES else "medium",
                "rule_name": rule_name,
                "agent_id": batch.agent_id,
                "message": message,
            })
            known_alerts.add(uid)
            alerts += 1
            log.warning("alerta [%s] %s en %s: %s", severity, data.get("rule_id"), batch.agent_id, data.get("message"))
        elif etype == "system_metrics":
            session.add(Metric(
                agent_id=batch.agent_id,
                cpu_percent=float(ev.get("cpu_percent") or 0),
                memory_percent=float(ev.get("memory_percent") or 0),
                disk_percent=float(ev.get("disk_percent") or 0),
                timestamp=stamp,
            ))
        else:
            if uid in known_events:
                duplicates += 1
                continue
            payload = {k: v for k, v in ev.items() if k not in ("uid", "type", "timestamp")}
            session.add(Event(
                uid=uid, agent_id=batch.agent_id, event_type=etype,
                timestamp=stamp, data=json.dumps(payload, default=str),
            ))
            known_events.add(uid)
        accepted += 1
    session.commit()
    
    cfg = request.app.state.config
    for a in new_alerts:
        bg_tasks.add_task(send_notification, a, cfg)
        
    return {"status": "ok", "accepted": accepted, "duplicates": duplicates, "alerts": alerts}


@read_router.get("/stats")
def stats(request: Request, session=Depends(get_session)):
    offline_after = request.app.state.offline_after
    now = utcnow()
    open_by_severity = dict.fromkeys(SEVERITIES, 0)
    for severity, count in session.execute(
        select(Alert.severity, func.count()).where(Alert.acknowledged.is_(False)).group_by(Alert.severity)
    ):
        open_by_severity[severity] = count
    return {
        "agents": {
            "total": session.scalar(select(func.count()).select_from(Agent)) or 0,
            "online": session.scalar(
                select(func.count()).select_from(Agent).where(
                    Agent.last_seen >= now - timedelta(seconds=offline_after)
                )
            ) or 0,
        },
        "alerts": {
            "total": session.scalar(select(func.count()).select_from(Alert)) or 0,
            "open": sum(open_by_severity.values()),
            "open_by_severity": open_by_severity,
            "last_24h": session.scalar(
                select(func.count()).select_from(Alert).where(Alert.timestamp >= now - timedelta(hours=24))
            ) or 0,
        },
        "events": {
            "total": session.scalar(select(func.count()).select_from(Event)) or 0,
            "last_hour": session.scalar(
                select(func.count()).select_from(Event).where(Event.timestamp >= now - timedelta(hours=1))
            ) or 0,
        },
        "generated_at": iso(now),
    }


@read_router.get("/agents")
def list_agents(request: Request, session=Depends(get_session)):
    offline_after = request.app.state.offline_after
    open_counts = dict(session.execute(
        select(Alert.agent_id, func.count()).where(Alert.acknowledged.is_(False)).group_by(Alert.agent_id)
    ).all())
    agents = session.scalars(select(Agent).order_by(Agent.last_seen.desc())).all()
    result = []
    for a in agents:
        risk = compute_risk_score(session, a.id)
        result.append(agent_out(a, offline_after, open_counts.get(a.id, 0), risk))
    return result


@read_router.get("/agents/{agent_id}")
def get_agent(agent_id: str, request: Request, session=Depends(get_session)):
    agent = session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, "agente no encontrado")
    open_alerts = session.scalar(
        select(func.count()).select_from(Alert).where(Alert.agent_id == agent_id, Alert.acknowledged.is_(False))
    ) or 0
    risk = compute_risk_score(session, agent_id)
    return agent_out(agent, request.app.state.offline_after, open_alerts, risk)


@read_router.get("/agents/{agent_id}/risk")
def agent_risk(agent_id: str, session=Depends(get_session)):
    agent = session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404, "agente no encontrado")
    return compute_risk_score(session, agent_id)


@read_router.get("/search")
def search(
    q: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(30, ge=1, le=100),
    session=Depends(get_session),
):
    pattern = f"%{q}%"
    alerts = session.scalars(
        select(Alert).where(
            (Alert.message.ilike(pattern)) |
            (Alert.rule_id.ilike(pattern)) |
            (Alert.agent_id.ilike(pattern))
        ).order_by(Alert.timestamp.desc()).limit(limit)
    ).all()
    events = session.scalars(
        select(Event).where(
            (Event.data.ilike(pattern)) |
            (Event.agent_id.ilike(pattern)) |
            (Event.event_type.ilike(pattern))
        ).order_by(Event.timestamp.desc()).limit(limit)
    ).all()
    return {
        "alerts": [alert_out(a) for a in alerts],
        "events": [event_out(e) for e in events],
    }


@read_router.get("/alerts/timeline")
def alerts_timeline(
    hours: int = Query(24, ge=1, le=168),
    agent_id: Optional[str] = None,
    session=Depends(get_session),
):
    now = utcnow()
    cutoff = now - timedelta(hours=hours)
    query = select(Alert.severity, Alert.timestamp).where(Alert.timestamp >= cutoff)
    if agent_id:
        query = query.where(Alert.agent_id == agent_id)
    rows = session.execute(query.order_by(Alert.timestamp)).all()
    # Group by hour
    buckets = {}
    for severity, timestamp in rows:
        hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
        key = iso(hour_key)
        if key not in buckets:
            buckets[key] = {"timestamp": key, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        buckets[key][severity] = buckets[key].get(severity, 0) + 1
        buckets[key]["total"] += 1
    return sorted(buckets.values(), key=lambda x: x["timestamp"])


@read_router.get("/agents/{agent_id}/metrics")
def agent_metrics(agent_id: str, limit: int = Query(60, ge=1, le=1000), session=Depends(get_session)):
    rows = session.scalars(
        select(Metric).where(Metric.agent_id == agent_id).order_by(Metric.timestamp.desc()).limit(limit)
    ).all()
    return [
        {"timestamp": iso(m.timestamp), "cpu": m.cpu_percent, "memory": m.memory_percent, "disk": m.disk_percent}
        for m in reversed(rows)
    ]


@read_router.get("/alerts")
def list_alerts(
    severity: Optional[str] = Query(None, pattern=SEVERITY_PATTERN),
    agent_id: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session=Depends(get_session),
):
    query = select(Alert)
    if severity:
        query = query.where(Alert.severity == severity)
    if agent_id:
        query = query.where(Alert.agent_id == agent_id)
    if acknowledged is not None:
        query = query.where(Alert.acknowledged.is_(acknowledged))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(Alert.timestamp.desc(), Alert.id.desc()).offset(offset).limit(limit)).all()
    return {"total": total, "items": [alert_out(a) for a in rows]}


@read_router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, session=Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "alerta no encontrada")
    return alert_out(alert)


@read_router.post("/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: int, session=Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "alerta no encontrada")
    if not alert.acknowledged:
        alert.acknowledged = True
        alert.acknowledged_at = utcnow()
        session.commit()
    return alert_out(alert)


@read_router.post("/alerts/ack-all")
def acknowledge_all(
    severity: Optional[str] = Query(None, pattern=SEVERITY_PATTERN),
    agent_id: Optional[str] = None,
    session=Depends(get_session),
):
    statement = update(Alert).where(Alert.acknowledged.is_(False))
    if severity:
        statement = statement.where(Alert.severity == severity)
    if agent_id:
        statement = statement.where(Alert.agent_id == agent_id)
    result = session.execute(statement.values(acknowledged=True, acknowledged_at=utcnow()))
    session.commit()
    return {"acknowledged": result.rowcount or 0}

@read_router.post("/purge")
def purge_all_data(session=Depends(get_session)):
    from sqlalchemy import delete
    from .database import Event, Metric, RiskScore
    session.execute(delete(Event))
    session.execute(delete(Alert))
    session.execute(delete(Metric))
    session.execute(delete(RiskScore))
    session.execute(delete(Agent))
    session.commit()
    return {"status": "ok", "message": "Base de datos limpiada"}


@read_router.get("/events")
def list_events(
    event_type: Optional[str] = Query(None, max_length=64),
    agent_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session=Depends(get_session),
):
    query = select(Event)
    if event_type:
        query = query.where(Event.event_type == event_type)
    if agent_id:
        query = query.where(Event.agent_id == agent_id)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(Event.timestamp.desc(), Event.id.desc()).offset(offset).limit(limit)).all()
    return {"total": total, "items": [event_out(e) for e in rows]}


@read_router.get("/rules")
def list_rules(request: Request):
    rules, errors = load_rules(request.app.state.rules_path)
    return {
        "errors": errors,
        "items": [
            {
                "id": r.id, "name": r.name, "description": r.description,
                "severity": r.severity, "event_type": r.event_type,
                "platforms": sorted(r.platforms), "mitre": r.mitre, "enabled": r.enabled,
            }
            for r in rules
        ],
    }


def create_app(cfg: Optional[dict] = None, db_path: Optional[Path] = None) -> FastAPI:
    ensure_dirs()
    cfg = cfg or load_server_config()
    server_cfg = cfg["server"]
    database_path = db_path or (resolve_path(cfg["database"]["path"], DATA_DIR) if cfg["database"]["path"] else DATA_DIR / "wolffy.db")
    database_path.parent.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async def purge_loop():
            while True:
                try:
                    removed = await asyncio.to_thread(app.state.db.purge, cfg["retention"])
                    if any(removed.values()):
                        log.info("retencion: eliminados %s", removed)
                except Exception:
                    log.exception("fallo la limpieza de retencion")
                await asyncio.sleep(PURGE_INTERVAL)

        task = asyncio.create_task(purge_loop())
        try:
            yield
        finally:
            task.cancel()

    app = FastAPI(title="Wolffy EDR", version=VERSION, lifespan=lifespan)
    app.state.db = Database(database_path)
    app.state.secret = resolve_secret(server_cfg.get("secret_key"))
    app.state.dashboard_token = resolve_dashboard_token(server_cfg.get("dashboard_token"), server_cfg["host"])
    app.state.offline_after = int(server_cfg["agent_offline_after"])
    app.state.rules_path = resolve_path(cfg["rules"]["file"])
    app.state.config = cfg

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "frame-ancestors 'none'"
        )
        return response

    @app.get("/health")
    def health(request: Request):
        ok = request.app.state.db.healthy()
        body = {"status": "healthy" if ok else "degraded", "version": VERSION}
        return JSONResponse(body, status_code=200 if ok else 503)

    @app.get("/api/v1/info")
    def info(request: Request):
        return {"service": "wolffy-edr", "version": VERSION, "auth_required": bool(request.app.state.dashboard_token)}

    app.include_router(router)
    app.include_router(read_router)

    if DASHBOARD_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        def dashboard():
            return FileResponse(DASHBOARD_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    return app
