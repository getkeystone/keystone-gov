from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, Text, Integer
from database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    role = Column(String, nullable=False, default="member")
    password_hash = Column(String, nullable=False)


class CFUser(Base):
    """User provisioned from Cloudflare Access identity + role config."""
    __tablename__ = "cf_users"
    id = Column(String, primary_key=True)           # UUID
    email = Column(String, unique=True, nullable=False)  # lowercase
    display_name = Column(String, nullable=False)
    assigned_role = Column(String, nullable=False)
    status = Column(String, nullable=False, default="active")
    source = Column(String, nullable=False, default="cloudflare_access")
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=False)


class Document(Base):
    """One row per (document_id, page) pair."""
    __tablename__ = "documents"
    key = Column(String, primary_key=True)  # "{document_id}:{page}"
    document_id = Column(String, nullable=False, index=True)
    page = Column(Integer, nullable=False)
    title = Column(String, nullable=False)
    section = Column(String, nullable=False)
    status = Column(String, nullable=False)
    effective_date = Column(String)
    review_date = Column(String)
    owner = Column(String)
    excerpt = Column(Text)
    highlight = Column(String)
    notes_json = Column(JSON, default=list)
    min_role_level = Column(Integer, nullable=False, default=0)  # 0=any, 1=officer+, 2=admin+


class Query(Base):
    __tablename__ = "queries"
    id = Column(String, primary_key=True)
    question = Column(String, nullable=False)
    role = Column(String, nullable=False)
    mode = Column(String, nullable=False)
    scenario_key = Column(String, nullable=False)
    guidance_json = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditEntry(Base):
    __tablename__ = "audit_log"
    id = Column(String, primary_key=True)
    query_id = Column(String, nullable=False, index=True)
    receipt_id = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)
    role_used = Column(String, nullable=False)
    mode_used = Column(String, nullable=False)
    policy_outcome = Column(String, nullable=False)
    sources_considered_json = Column(JSON, nullable=False, default=list)
    citations_returned_json = Column(JSON, nullable=False, default=list)
    prev_hash = Column(String, nullable=False, default="")
    entry_hash = Column(String, nullable=False)
    # Identity columns (nullable for backward compat with existing records)
    user_id = Column(String, nullable=True)
    user_email = Column(String, nullable=True)
    user_display_name = Column(String, nullable=True)
    auth_source = Column(String, nullable=True)
    simulated_role_used = Column(String, nullable=True)  # set when sim_role was active


class Session(Base):
    __tablename__ = "sessions"
    token = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    username = Column(String, nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ManagedUser(Base):
    """Canonical user management state. Seeded from config, managed by Authority."""
    __tablename__ = "managed_users"
    email          = Column(String, primary_key=True)
    display_name   = Column(String, nullable=False, default="")
    role           = Column(String, nullable=False, default="member")
    status         = Column(String, nullable=False, default="disabled")  # 'enabled' | 'disabled'
    provisioned_at = Column(DateTime(timezone=True))
    enabled_at     = Column(DateTime(timezone=True))
    disabled_at    = Column(DateTime(timezone=True))
    enabled_by     = Column(String)
    disabled_by    = Column(String)
    last_login     = Column(DateTime(timezone=True))


class UserManagementEvent(Base):
    """Governance audit trail for user management actions."""
    __tablename__ = "user_management_events"
    id            = Column(String, primary_key=True)
    ts_utc        = Column(DateTime(timezone=True), nullable=False)
    actor_email   = Column(String, nullable=False)
    actor_role    = Column(String, nullable=False)
    subject_email = Column(String, nullable=False)
    action        = Column(String, nullable=False)  # 'enabled' | 'disabled' | 'role_changed'
    old_value     = Column(String)
    new_value     = Column(String)
    note          = Column(String)


class DocumentVersion(Base):
    __tablename__ = "document_versions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    doc_id = Column(Integer, nullable=False, index=True)
    version_number = Column(Integer, nullable=False, default=1)
    status = Column(String, nullable=False, default="draft")
    effective_from = Column(DateTime(timezone=True))
    effective_to = Column(DateTime(timezone=True))
    supersedes_version_id = Column(Integer)
    content_hash = Column(String)
    file_path = Column(String)
    change_summary = Column(Text)
    created_by = Column(String, nullable=False)
    approved_by = Column(String)
    published_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True))


class VersionEvent(Base):
    __tablename__ = "version_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    version_id = Column(Integer, nullable=False, index=True)
    event_type = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    actor_role = Column(String, nullable=False)
    detail = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True))


class ReviewTask(Base):
    __tablename__ = "review_tasks"
    id = Column(String, primary_key=True)
    feedback_signal_id = Column(String, nullable=False)
    doc_id = Column(Integer, nullable=False)
    source_version_id = Column(Integer)
    status = Column(String, nullable=False, default="open")
    assigned_to = Column(String)
    priority = Column(String, default="normal")
    resolution_type = Column(String)
    resolution_note = Column(Text)
    resolved_by = Column(String)
    created_at = Column(DateTime(timezone=True))
    assigned_at = Column(DateTime(timezone=True))
    resolved_at = Column(DateTime(timezone=True))


class ReviewComment(Base):
    __tablename__ = "review_comments"
    id = Column(String, primary_key=True)
    task_id = Column(String, nullable=False)
    author = Column(String, nullable=False)
    author_role = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True))


class PublicationDecision(Base):
    __tablename__ = "publication_decisions"
    id = Column(String, primary_key=True)
    review_task_id = Column(String, nullable=False)
    old_version_id = Column(Integer)
    new_version_id = Column(Integer)
    decision = Column(String, nullable=False)
    decided_by = Column(String, nullable=False)
    decided_by_role = Column(String, nullable=False)
    decided_at = Column(DateTime(timezone=True))
