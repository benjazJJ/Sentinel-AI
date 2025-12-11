from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse

from sentinela_core.db.base import Base, engine, SessionLocal
from sentinela_core.db.models import Alert

from sentinela_core.ai.analysis import analyze_alert_with_ollama


app = FastAPI(title="Sentinela-Core EDR")

#STATIC FILES (CSS, JS)
app.mount("/static", StaticFiles(directory="sentinela_core/ui/static"), name="static")

#TEMPLATES
templates = Jinja2Templates(directory="sentinela_core/ui/templates")


#DASHBOARD UI


@app.get("/", response_class=HTMLResponse)
def root():
    # Redirigir al dashboard principal
    return RedirectResponse("/dashboard/alerts")


@app.get("/dashboard/alerts", response_class=HTMLResponse)
def dashboard_alerts(request: Request):
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.id.desc()).limit(50).all()
    db.close()

    return templates.TemplateResponse(
        "alerts.html",
        {"request": request, "alerts": alerts}
    )


@app.get("/dashboard/alert/{alert_id}", response_class=HTMLResponse)
def dashboard_alert_detail(request: Request, alert_id: int):
    db = SessionLocal()
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    db.close()

    if not alert:
        return HTMLResponse("<h1>Alerta no encontrada</h1>", status_code=404)

    return templates.TemplateResponse(
        "alert_detail.html",
        {"request": request, "alert": alert}
    )


@app.get("/dashboard/alert/{alert_id}/analyze", response_class=HTMLResponse)
def dashboard_alert_analyze(request: Request, alert_id: int):
    """Ejecuta análisis IA y muestra el resultado."""
    result = analyze_alert_with_ollama(alert_id)

    return templates.TemplateResponse(
        "alert_detail.html",
        {"request": request, "alert": result}
    )
