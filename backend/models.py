from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="ANALYST")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class WebsiteConnection(Base):
    __tablename__ = "website_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    connection_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    secure_token: Mapped[Optional[str]] = mapped_column(String(255))
    website_url: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    customer_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="Registered")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(128), index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    destination: Mapped[Optional[str]] = mapped_column(String(255))
    device_id: Mapped[Optional[str]] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(32), default="low")
    authentication_status: Mapped[Optional[str]] = mapped_column(String(32))
    location: Mapped[Optional[str]] = mapped_column(String(128))
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float)
    anomaly_classification: Mapped[Optional[str]] = mapped_column(String(32))
    connection_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    threat_indicators: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    metadata_json: Mapped[Optional[dict]] = mapped_column("metadata", JSON, default=dict)
    ml_status: Mapped[str] = mapped_column(String(32), default="ok")
    ti_status: Mapped[str] = mapped_column(String(32), default="pending")
    pipeline_phase: Mapped[str] = mapped_column(String(32), default="INGEST")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    __table_args__ = (UniqueConstraint("indicator", "indicator_type", name="uq_indicator_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator: Mapped[str] = mapped_column(String(255), index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), index=True)
    reputation: Mapped[str] = mapped_column(String(32))
    threat_level: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(128))
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(32), default="active")
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    # New TI fields (all Optional so existing rows / SQLite alters are safe)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(128))
    campaign: Mapped[Optional[str]] = mapped_column(String(255))
    country: Mapped[Optional[str]] = mapped_column(String(8))
    organization: Mapped[Optional[str]] = mapped_column(String(255))
    asn: Mapped[Optional[str]] = mapped_column(String(64))
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    raw_result: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default="Medium")
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="New")
    user_id: Mapped[Optional[str]] = mapped_column(String(128))
    source_ip: Mapped[Optional[str]] = mapped_column(String(64))
    asset: Mapped[Optional[str]] = mapped_column(String(128))
    threat_intel_status: Mapped[str] = mapped_column(String(64), default="none")
    connection_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    copilot_summary: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    response_status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    events: Mapped[list["IncidentEvent"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    timeline_entries: Mapped[list["AttackTimeline"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    recommended_actions: Mapped[list["RecommendedAction"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    response_actions: Mapped[list["ResponseAction"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("security_events.id"), index=True)
    relationship_type: Mapped[str] = mapped_column(String(64), default="correlated")

    incident: Mapped["Incident"] = relationship(back_populates="events")
    event: Mapped["SecurityEvent"] = relationship()


class AttackTimeline(Base):
    __tablename__ = "attack_timeline"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    event_id: Mapped[Optional[int]] = mapped_column(ForeignKey("security_events.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    description: Mapped[str] = mapped_column(Text)
    source: Mapped[Optional[str]] = mapped_column(String(128))
    user_id: Mapped[Optional[str]] = mapped_column(String(128))
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float)
    threat_intelligence_status: Mapped[Optional[str]] = mapped_column(String(64))
    severity: Mapped[Optional[str]] = mapped_column(String(32))
    risk_contribution: Mapped[Optional[float]] = mapped_column(Float)

    incident: Mapped["Incident"] = relationship(back_populates="timeline_entries")


class RecommendedAction(Base):
    __tablename__ = "recommended_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    action_id: Mapped[str] = mapped_column(String(64), index=True)
    action_type: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(String(16), default="medium")
    reason: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="RECOMMENDED")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="recommended_actions")


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    action_id: Mapped[str] = mapped_column(String(64), index=True)
    action_type: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255))
    requested_by: Mapped[str] = mapped_column(String(64))
    approved_by: Mapped[Optional[str]] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="PENDING")
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    result: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    incident: Mapped["Incident"] = relationship(back_populates="response_actions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[Optional[int]] = mapped_column(ForeignKey("incidents.id"), index=True)
    event_id: Mapped[Optional[int]] = mapped_column(ForeignKey("security_events.id"))
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    status: Mapped[str] = mapped_column(String(32), default="SUCCESS")
    details: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    incident: Mapped[Optional["Incident"]] = relationship(back_populates="audit_logs")
