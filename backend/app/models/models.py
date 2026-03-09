"""
GATOR PRO — Database Models
PostgreSQL tables for all scan data
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text,
    DateTime, ForeignKey, Enum, JSON, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import uuid
import enum


# ─── Enums ───────────────────────────────────────────────────
class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    FINISHED = "finished"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    FULL = "full"
    RECON = "recon"
    PORTSCAN = "portscan"
    WEBSCAN = "webscan"
    API = "api"
    AUTH = "auth"
    SSL = "ssl"
    AD = "ad"
    BIZLOGIC = "bizlogic"
    PCI = "pci"
    NETWORK = "network"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngagementStatus(str, enum.Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    PAUSED = "paused"
    ARCHIVED = "archived"


# ─── User ────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))

    engagements = relationship("Engagement", back_populates="owner")
    scans = relationship("Scan", back_populates="owner")


# ─── Engagement (client project) ─────────────────────────────
class Engagement(Base):
    __tablename__ = "engagements"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    client_name = Column(String(255), nullable=False)
    audit_type = Column(String(100))              # Black/Grey/White/Red Team
    methodology = Column(String(100))             # OWASP/PTES/OSSTMM
    scope = Column(JSONB, default=list)           # List of targets
    out_of_scope = Column(JSONB, default=list)
    standards = Column(JSONB, default=list)       # PCI DSS, SWIFT etc
    status = Column(String(50), default="active")
    start_date = Column(DateTime(timezone=True))
    end_date = Column(DateTime(timezone=True))
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    owner = relationship("User", back_populates="engagements")
    scans = relationship("Scan", back_populates="engagement", cascade="all, delete-orphan")


# ─── Scan ─────────────────────────────────────────────────────
class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    engagement_id = Column(UUID(as_uuid=True), ForeignKey("engagements.id"), nullable=True)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    target = Column(String(500), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(50), default="pending")

    # Config
    options = Column(JSONB, default=dict)

    # Results summary
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    open_ports_count = Column(Integer, default=0)
    subdomains_count = Column(Integer, default=0)

    # Timing
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)

    # Raw results (JSON)
    raw_results = Column(JSONB, default=dict)

    # Celery task
    celery_task_id = Column(String(255))
    error_message = Column(Text)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    engagement = relationship("Engagement", back_populates="scans")
    owner = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    events = relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scans_target", "target"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_created_at", "created_at"),
    )


# ─── Finding ─────────────────────────────────────────────────
class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)

    # Classification
    severity = Column(String(20), nullable=False, index=True)
    cvss_score = Column(Float, nullable=False)
    cvss_vector = Column(String(100))             # CVSS:3.1/AV:N/AC:L/...
    cve_ids = Column(JSONB, default=list)         # ["CVE-2021-44228", ...]
    cwe_ids = Column(JSONB, default=list)         # ["CWE-89", ...]
    owasp_category = Column(String(100))          # A01:2021-Broken Access Control
    pci_dss_req = Column(JSONB, default=list)     # ["6.3.1", "6.3.2"]
    swift_control = Column(JSONB, default=list)   # ["1.1", "2.2A"]

    # Details
    title = Column(String(500), nullable=False)
    description = Column(Text)
    recommendation = Column(Text)
    evidence = Column(Text)
    poc = Column(Text)                            # Proof of Concept

    # Location
    host = Column(String(255))
    port = Column(Integer)
    url = Column(Text)
    parameter = Column(String(255))
    payload = Column(Text)

    # Status
    is_false_positive = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    is_remediated = Column(Boolean, default=False)
    notes = Column(Text)

    # Source
    tool = Column(String(100))                    # nmap/nuclei/custom/...
    category = Column(String(100))                # recon/web/api/auth/...

    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_cvss", "cvss_score"),
    )


# ─── Scan Event (real-time log) ───────────────────────────────
class ScanEvent(Base):
    __tablename__ = "scan_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    event_type = Column(String(50))               # log/port/finding/phase/done/error
    level = Column(String(20))                    # info/ok/warn/err/data
    message = Column(Text)
    data = Column(JSONB)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="events")

    __table_args__ = (
        Index("ix_events_scan_id", "scan_id"),
        Index("ix_events_timestamp", "timestamp"),
    )


# ─── CVE Cache ────────────────────────────────────────────────
class CVECache(Base):
    __tablename__ = "cve_cache"

    cve_id = Column(String(50), primary_key=True)
    data = Column(JSONB, nullable=False)
    cached_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))


# ─── Report ───────────────────────────────────────────────────
class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    engagement_id = Column(UUID(as_uuid=True), ForeignKey("engagements.id"), nullable=True)
    scan_ids = Column(JSONB, default=list)

    report_type = Column(String(50))               # pdf/docx/json
    language = Column(String(10), default="ru")    # ru/en/ru+en
    title = Column(String(500))
    executive_summary = Column(Text)
    methodology = Column(Text)
    conclusion = Column(Text)

    file_path = Column(String(500))
    file_size = Column(Integer)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
