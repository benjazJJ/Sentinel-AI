import psutil
import time
from datetime import datetime
from sentinela_core.db.base import SessionLocal
from sentinela_core.db.models import Alert

#PALABRAS CLAVE SOSPECHOSAS EN NOMBRES O CMDLINES DE PROCESOS
SUSPICIOUS_KEYWORDS = [
    "powershell", "cmd", "wmic", "schtasks",
    "mshta", "wscript", "cscript",
    "python", "debug", "remote"
]

#PUERTOS SOSPECHOSOS COMUNES
SUSPICIOUS_PORTS = {4444, 1337, 6969, 3389}


def detect_suspicious_processes():
    """
    Recorre todos los procesos y detecta comportamientos sospechosos.
    """
    alerts = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            cmd = " ".join(proc.info["cmdline"] or [])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        # Palabras clave sospechosas
        if any(keyword.lower() in cmd.lower() for keyword in SUSPICIOUS_KEYWORDS):
            alerts.append(f"Proceso sospechoso detectado: {name} (CMD: {cmd})")

        # Puertos sospechosos abiertos por el proceso
        try:
            connections = proc.connections(kind="inet")
            for conn in connections:
                if conn.laddr.port in SUSPICIOUS_PORTS:
                    alerts.append(
                        f"Proceso {name} abrió puerto sospechoso {conn.laddr.port}"
                    )
        except Exception:
            continue

    return alerts


def record_alerts(alerts: list[str]):
    """
    Guarda alertas en la BD.
    """
    db = SessionLocal()
    try:
        for msg in alerts:
            alert = Alert(
                type="process",
                severity="MEDIUM",
                message=msg,
                timestamp=datetime.utcnow(),
            )
            db.add(alert)
        db.commit()
    finally:
        db.close()


def start_monitor(interval: int = 5):
    """
    Bucle infinito: revisa procesos cada X segundos.
    """
    print(f"Iniciando monitor de procesos (cada {interval} segundos)...")

    while True:
        alerts = detect_suspicious_processes()

        if alerts:
            print(f"{len(alerts)} procesos sospechosos detectados!")
            record_alerts(alerts)

        time.sleep(interval)
