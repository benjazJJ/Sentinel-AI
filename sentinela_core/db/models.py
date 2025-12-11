from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from .base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
