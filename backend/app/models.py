from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    prediction: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )

    attack: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False
    )

    attack_probability: Mapped[float] = mapped_column(
        Float,
        nullable=False
    )

    threshold: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.5
    )

    model: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    features: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True
    )

    source_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    transport_protocol: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True
    )

    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    threat_provider: Mapped[str | None] = mapped_column(
    String(50),
    nullable=True
    )

    threat_intelligence: Mapped[dict | None] = mapped_column(
    JSONB,
    nullable=True
    )

    enriched_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True
    )