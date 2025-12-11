from fastapi import APIRouter
from sentinela_core.db.base import SessionLocal
from sentinela_core.db.models import Alert

router = APIRouter()

@router.get("/alerts")
def list_alerts(limit: int = 20):
    db = SessionLocal()
    try:
        alerts = (
            db.query(Alert)
            .order_by(Alert.timestamp.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "id": a.id,
                "type": a.type,
                "severity": a.severity,
                "message": a.message,
                "timestamp": a.timestamp,
            }
            for a in alerts
        ]

    finally:
        db.close()
