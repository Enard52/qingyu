import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

class ArchiveObject(Base):
    __tablename__ = "archive_objects"
    __table_args__ = (UniqueConstraint("sha256", "size_bytes", name="uq_archive_objects_sha256_size"),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    relative_path: Mapped[str] = mapped_column(Text, nullable=False)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    media_type: Mapped[str] = mapped_column(String(255), nullable=False)
    source_platform: Mapped[str] = mapped_column(String(100), nullable=False)
    integrity_status: Mapped[str] = mapped_column(String(32), nullable=False, default="verified")
    first_archived_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
