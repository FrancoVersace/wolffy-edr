from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, DateTime, Float, Integer, String, Text, create_engine, delete, event, func, select,
)
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat(timespec="seconds") + "Z" if value else None


class Base(DeclarativeBase):
    pass


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    os_info: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(32), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uid: Mapped[str] = mapped_column(String(64), unique=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    data: Mapped[str] = mapped_column(Text, default="{}")


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uid: Mapped[str] = mapped_column(String(64), unique=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_name: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    mitre_attack: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    event_data: Mapped[str] = mapped_column(Text, default="{}")


from sqlalchemy import Index
Index('ix_alerts_agent_timestamp', Alert.agent_id, Alert.timestamp)


class RiskScore(Base):
    __tablename__ = "risk_scores"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    level: Mapped[str] = mapped_column(String(16), default="clean")
    last_alert_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Metric(Base):
    __tablename__ = "metrics"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    memory_percent: Mapped[float] = mapped_column(Float, default=0.0)
    disk_percent: Mapped[float] = mapped_column(Float, default=0.0)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)


def _sqlite_pragmas(dbapi_connection, _record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class Database:
    def __init__(self, path):
        url = URL.create("sqlite", database=str(path))
        self.engine = create_engine(
            url, connect_args={"check_same_thread": False, "timeout": 30}
        )
        event.listen(self.engine, "connect", _sqlite_pragmas)
        Base.metadata.create_all(self.engine)
        self._factory = sessionmaker(self.engine, expire_on_commit=False)

    def session(self):
        return self._factory()

    def purge(self, retention) -> dict:
        now = utcnow()
        removed = {}
        with self.session() as session:
            for name, model, days in (
                ("events", Event, retention["events_days"]),
                ("metrics", Metric, retention["metrics_days"]),
                ("alerts", Alert, retention["alerts_days"]),
            ):
                result = session.execute(
                    delete(model).where(model.timestamp < now - timedelta(days=int(days)))
                )
                removed[name] = result.rowcount or 0
            limit = int(retention["max_events"])
            cutoff = session.scalar(
                select(Event.id).order_by(Event.id.desc()).offset(limit).limit(1)
            )
            if cutoff is not None:
                result = session.execute(delete(Event).where(Event.id <= cutoff))
                removed["events"] += result.rowcount or 0
            session.commit()
        return removed

    def healthy(self) -> bool:
        try:
            with self.session() as session:
                session.scalar(select(func.count()).select_from(Agent))
            return True
        except Exception:
            return False
