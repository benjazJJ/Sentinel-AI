import typer

from sentinela_core.db import init_db
from sentinela_core.db.base import SessionLocal
from sentinela_core.db.models import Alert
from sentinela_core.detection.yara_scanner import load_rules, scan_path

app = typer.Typer(
    help="Sentinela-Core CLI",
    no_args_is_help=True,
)


@app.command("version")
def version_cmd():
    """
    Muestra la versión actual de Sentinela-Core.
    """
    from sentinela_core import __version__
    typer.echo(f"Sentinela-Core v{__version__}")


@app.command("initdb")
def initdb_cmd():
    """
    Inicializa la base de datos y crea las tablas necesarias.
    """
    init_db()
    typer.echo("Base de datos inicializada.")


@app.command("scan-yara")
def scan_yara_cmd(
    path: str = typer.Argument(..., help="Ruta al archivo o carpeta a escanear"),
    rules_path: str = typer.Argument(..., help="Ruta al archivo de reglas YARA"),
):
    """
    Escanea un archivo o directorio usando reglas YARA y crea alertas en la BD.
    """
    typer.echo(f" Escaneando {path} con reglas {rules_path} ...")

    try:
        compiled_rules = load_rules(rules_path)
    except Exception as e:
        typer.echo(f" Error al cargar reglas YARA: {e}")
        raise typer.Exit(code=1)

    created = scan_path(path, compiled_rules)
    typer.echo(f" Escaneo completado. Alertas creadas: {created}")


@app.command("alerts")
def alerts_cmd(limit: int = typer.Option(20, help="Cantidad de alertas a mostrar")):
    """
    Muestra las últimas alertas registradas en la BD.
    """
    db = SessionLocal()
    try:
        alerts = (
            db.query(Alert)
            .order_by(Alert.timestamp.desc())
            .limit(limit)
            .all()
        )
        if not alerts:
            typer.echo("No hay alertas registradas.")
            return

        for a in alerts:
            typer.echo(
                f"[{a.id}] {a.timestamp} "
                f"[{a.severity}] {a.type}: {a.message}"
            )
    finally:
        db.close()

@app.command("api")
def api_cmd(host: str = "127.0.0.1", port: int = 8000):
    """
    Inicia la API FastAPI interna.
    """
    import uvicorn
    uvicorn.run("sentinela_core.api.main:app", host=host, port=port, reload=True)


@app.command("monitor")
def monitor_cmd(interval: int = 5):
    """
    Inicia el monitoreo de procesos en tiempo real.
    """
    from sentinela_core.detection.process_monitor import start_monitor
    start_monitor(interval)



@app.command("analyze-alert")
def analyze_alert_cmd(alert_id: int = typer.Argument(..., help="ID de la alerta a analizar con IA local")):
    """
    Analiza una alerta usando un modelo local de Ollama (por ejemplo llama3.2).
    """
    from sentinela_core.ai.analysis import analyze_alert_with_ollama

    typer.echo(f"🧠 Analizando alerta {alert_id} con IA local...")

    try:
        result = analyze_alert_with_ollama(alert_id)
    except ValueError as ve:
        typer.echo(f"❌ {ve}")
        raise typer.Exit(code=1)
    except RuntimeError as re:
        typer.echo(f"❌ {re}")
        raise typer.Exit(code=1)

    typer.echo("")
    typer.echo(f"Alerta #{result.alert_id}: {result.alert_message}")
    typer.echo("")
    typer.echo("===== EXPLICACIÓN =====")
    typer.echo(result.explanation)
    typer.echo("")
    typer.echo("===== ACCIONES RECOMENDADAS =====")

    if result.recommended_actions.strip():
        typer.echo(result.recommended_actions)
    else:
        typer.echo("(El modelo no entregó acciones específicas.)")





if __name__ == "__main__":
    app()
