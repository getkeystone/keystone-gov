from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, Text, Integer
from database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    role = Column(String, nullable=False, default="member")
    password_hash = Column(String, nullable=False)


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


class Session(Base):
    __tablename__ = "sessions"
    token = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    username = Column(String, nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
