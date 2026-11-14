import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Integer, String, DateTime, Text, JSON, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

class Base(DeclarativeBase): pass

class Event(Base):
    __tablename__ = 'events'
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    duration: Mapped[float | None] = mapped_column(nullable=True)
    connection_uid: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    query: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source_format: Mapped[str] = mapped_column(String(30), default='generic')
    raw_event: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    bytes_transferred: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

class ImportRecord(Base):
    __tablename__ = 'imports'
    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True)

class Alert(Base):
    __tablename__ = 'alerts'
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    rule: Mapped[str] = mapped_column(String(60), index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    title: Mapped[str] = mapped_column(String(150))
    evidence: Mapped[dict] = mapped_column(JSON)
    attack: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    investigation_steps: Mapped[list] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default='new')
    note: Mapped[str] = mapped_column(Text, default='')
    event_ids: Mapped[list] = mapped_column(JSON)
    fingerprint: Mapped[str] = mapped_column(String(200), unique=True)

class Incident(Base):
    __tablename__ = 'incidents'
    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(200), unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    title: Mapped[str] = mapped_column(String(160))
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    severity: Mapped[str] = mapped_column(String(10))
    confidence: Mapped[float] = mapped_column()
    severity_reason: Mapped[str] = mapped_column(String(300), default='')
    stages: Mapped[list] = mapped_column(JSON)
    event_ids: Mapped[list] = mapped_column(JSON)
    alert_ids: Mapped[list] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default='open')
    assigned_to: Mapped[str] = mapped_column(String(100), default='')
    note: Mapped[str] = mapped_column(Text, default='')

class IncidentAudit(Base):
    __tablename__ = 'incident_audit'
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(Integer, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(50))
    details: Mapped[str] = mapped_column(Text)

DATABASE_URL = os.getenv('NETSENTRY_DATABASE_URL', 'sqlite:///./netsentry.db')
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(bind=engine)
DEMO_DATABASE_URL = os.getenv('NETSENTRY_DEMO_DATABASE_URL', 'sqlite:///./netsentry-demo.db')
if DEMO_DATABASE_URL == DATABASE_URL:
    raise RuntimeError('Demo database must be separate from the main database')
demo_engine = create_engine(DEMO_DATABASE_URL, connect_args={'check_same_thread': False} if DEMO_DATABASE_URL.startswith('sqlite') else {})
DemoSessionLocal = sessionmaker(bind=demo_engine)

def reset_demo_db():
    Base.metadata.drop_all(demo_engine)
    Base.metadata.create_all(demo_engine)

def init_db():
    Base.metadata.create_all(engine)
    Base.metadata.create_all(demo_engine)
    # Additive migration for existing prototype SQLite databases.
    if engine.dialect.name == 'sqlite':
        wanted = {
            'events': {'source_port':'INTEGER','protocol':'VARCHAR(20)','duration':'FLOAT','connection_uid':'VARCHAR(100)','hostname':'VARCHAR(255)','query':'VARCHAR(500)','source_format':"VARCHAR(30) DEFAULT 'generic'",'raw_event':'JSON'},
            'alerts': {'attack':'JSON'},
            'incidents': {'severity_reason':"VARCHAR(300) DEFAULT ''"},
        }
        with engine.begin() as connection:
            for table, columns in wanted.items():
                existing={c['name'] for c in inspect(connection).get_columns(table)}
                for name, definition in columns.items():
                    if name not in existing: connection.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {definition}'))
