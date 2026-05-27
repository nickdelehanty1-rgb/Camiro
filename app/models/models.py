import uuid
from datetime import datetime, date
from typing import Optional
from sqlalchemy import (
    String, Text, Boolean, Float, Integer, DateTime, Date,
    ForeignKey, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


def new_uuid():
    return str(uuid.uuid4())


def now():
    return datetime.utcnow()


class Organisation(Base):
    __tablename__ = "organisations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    sector: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    jurisdiction: Mapped[str] = mapped_column(Text, default="EU")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    organisation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("organisations.id"))
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    repository_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    organisation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("organisations.id"))
    project_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=True)
    scan_type: Mapped[str] = mapped_column(Text, default="code_paste")
    status: Mapped[str] = mapped_column(Text, default="queued")
    input_summary: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class LegalSource(Base):
    __tablename__ = "legal_sources"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    short_name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    jurisdiction: Mapped[str] = mapped_column(Text, nullable=False)
    celex_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    official_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sector: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, default="in_force")
    effective_from: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    effective_to: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)

    chunks: Mapped[list["LegalChunk"]] = relationship("LegalChunk", back_populates="source")


class LegalChunk(Base):
    __tablename__ = "legal_chunks"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    legal_source_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("legal_sources.id"))
    citation_label: Mapped[str] = mapped_column(Text, nullable=False)
    chunk_type: Mapped[str] = mapped_column(Text, nullable=False)
    article_number: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recital_number: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    annex_number: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    heading: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    text_hash: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)

    source: Mapped["LegalSource"] = relationship("LegalSource", back_populates="chunks")


class Obligation(Base):
    __tablename__ = "obligations"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    legal_source_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("legal_sources.id"))
    legal_chunk_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("legal_chunks.id"), nullable=True)
    obligation_code: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    actor_role: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    trigger_conditions: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    required_actions: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    evidence_required: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    control_family: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity_default: Mapped[str] = mapped_column(Text, default="high")
    applies_to_sectors: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    effective_from: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class Control(Base):
    __tablename__ = "controls"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    control_code: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    control_family: Mapped[str] = mapped_column(Text, nullable=False)
    mapped_obligation_ids: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    test_procedure: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_examples: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    organisation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("organisations.id"))
    project_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=True)
    node_type: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    external_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    organisation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("organisations.id"))
    project_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=True)
    source_node_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("graph_nodes.id"))
    target_node_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("graph_nodes.id"))
    edge_type: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    evidence_item_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), nullable=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    organisation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("organisations.id"))
    project_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=True)
    scan_run_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_runs.id"), nullable=True)
    evidence_type: Mapped[str] = mapped_column(Text, nullable=False)
    source_name: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    function_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    line_start: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    line_end: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    excerpt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    redacted_excerpt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scanner_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    hash: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    organisation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("organisations.id"))
    project_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=True)
    scan_run_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_runs.id"), nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    risk_domain: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, default="open")
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    observed_or_inferred: Mapped[str] = mapped_column(Text, default="inferred")
    legal_references: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    evidence_item_ids: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    obligation_ids: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    human_review_required: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    organisation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("organisations.id"))
    project_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=True)
    finding_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(Text, default="high")
    status: Mapped[str] = mapped_column(Text, default="open")
    owner_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner_email: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    due_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    external_ticket_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_required: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    completion_evidence_item_ids: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    organisation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("organisations.id"))
    project_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=True)
    scan_run_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), ForeignKey("scan_runs.id"), nullable=True)
    report_type: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, default="draft")
    content: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    rendered_markdown: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    organisation_id: Mapped[str] = mapped_column(UUID(as_uuid=False), ForeignKey("organisations.id"))
    actor: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_id: Mapped[Optional[str]] = mapped_column(UUID(as_uuid=False), nullable=True)
    before: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    after: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
