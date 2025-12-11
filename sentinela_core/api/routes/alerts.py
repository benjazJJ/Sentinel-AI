from fastapi import APIRouter, Query
from sentinela_core.db.base import SessionLocal
from sentinela_core.db.models import Alert

router = APIRouter()

@router.get("/alerts")
def list_alerts(limit: int | None = Query(None, description="Número máximo de alertas a devolver. Si no se indica, devuelve todas.")):
    """
    Devuelve la lista de alertas ordenadas por ID descendente.
    Si 'limit' no se especifica, retorna TODAS las alertas.
    """
    db = SessionLocal()
    try:
        query = db.query(Alert).order_by(Alert.id.desc())

        if limit is not None:
            query = query.limit(limit)

        alerts = query.all()

        return [
            {
                "id": a.id,
                "type": a.type.upper(),
                "severity": a.severity.upper(),
                "message": a.message,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in alerts
        ]

    finally:
        db.close()
