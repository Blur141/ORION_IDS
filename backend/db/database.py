from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Enum
from datetime import datetime
import enum

DATABASE_URL = "sqlite+aiosqlite:///./ids_events.db"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class SeverityLevel(str, enum.Enum):
    INFO = "info"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class NetworkEvent(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(20))
    packet_size = Column(Integer)
    severity = Column(String(20), default="info")
    attack_type = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    raw_summary = Column(Text, nullable=True)
    flags = Column(String(50), nullable=True)
    ttl = Column(Integer, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    alert_type = Column(String(100))
    severity = Column(String(20))
    src_ip = Column(String(45))
    dst_ip = Column(String(45), nullable=True)
    description = Column(Text)
    packet_count = Column(Integer, default=1)
    is_acknowledged = Column(Integer, default=0)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
