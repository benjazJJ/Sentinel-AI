import time
from typing import List, Set

import psutil

from sentinela_core.db.base import SessionLocal
from sentinela_core.db.models import Alert


# Procesos que queremos vigilar (LOLbins / intérpretes típicos)
SUSPICIOUS_NAMES = {
    "powershell.exe",
    "powershell",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "cmd.exe",  # pero lo filtramos más abajo por parámetros
}

# Tokens sospechosos en la línea de comandos
SUSPICIOUS_TOKENS = {
    "/c ",           # ejecutar comando y cerrar
    "-enc",
    "-encodedcommand",
    "http://",
    "https://",
    ".ps1",
    ".vbs",
    ".js ",
    ".bat",
    ".cmd ",
}

# Algunos patrones MUY comunes y legítimos que queremos ignorar
BENIGN_TOKENS = {
    "chcp 65001",    # típico de terminal configurando UTF-8
    "code.exe",      # VS Code lanzando cosas
}

# Para no alertar mil veces por el mismo proceso
ALERTED_PIDS: Set[int] = set()


def _is_process_suspicious(proc: psutil.Process) -> bool:
    """
    Heurística muy simple pero menos ruidosa:
    - El nombre debe estar en SUSPICIOUS_NAMES.
    - Y la línea de comando debe contener algún SUSPICIOUS_TOKEN.
    - Y NO debe coincidir con patrones claramente benignos.
    """

    try:
        info = proc.as_dict(attrs=["pid", "name", "cmdline", "exe"])
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

    name = (info.get("name") or "").lower()
    cmdline_list = info.get("cmdline") or []
    cmdline = " ".join(cmdline_list).lower()

    if name not in SUSPICIOUS_NAMES:
        return False

    # Si la línea de comandos parece claramente benigna, la ignoramos
    for token in BENIGN_TOKENS:
        if token in cmdline:
            return False

    # Solo consideramos sospechoso si hay algún token “raro”
    has_suspicious_token = any(tok in cmdline for tok in SUSPICIOUS_TOKENS)
    if not has_suspicious_token:
        return False

    return True


def find_suspicious_processes() -> List[psutil.Process]:
    """
    Devuelve una lista de procesos considerados sospechosos
    según la heurística anterior. No repite PIDs ya alertados.
    """
    suspicious = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
        if proc.pid in ALERTED_PIDS:
            continue

        if _is_process_suspicious(proc):
            suspicious.append(proc)
            ALERTED_PIDS.add(proc.pid)

    return suspicious


def monitor_processes(interval: int = 5):
    """
    Bucle principal: cada `interval` segundos revisa procesos
    y guarda alertas en la base de datos.
    """
    print(f"Iniciando monitor de procesos (cada {interval} segundos)...")

    while True:
        try:
            suspicious = find_suspicious_processes()
        except Exception as e:
            print(f"[monitor_processes] Error al inspeccionar procesos: {e}")
            suspicious = []

        if suspicious:
            db = SessionLocal()
            try:
                print(f"{len(suspicious)} procesos sospechosos detectados!")
                for proc in suspicious:
                    try:
                        info = proc.as_dict(attrs=["pid", "name", "cmdline"])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                    name = info.get("name") or "desconocido"
                    cmdline = " ".join(info.get("cmdline") or [])
                    message = f"Proceso sospechoso detectado: {name} (PID: {proc.pid}, CMD: {cmdline})"

                    alert = Alert(
                        type="process",
                        severity="MEDIUM",
                        message=message,
                    )
                    db.add(alert)
                db.commit()
            except Exception as e:
                db.rollback()
                print(f"[monitor_processes] Error al guardar alertas: {e}")
            finally:
                db.close()
        else:
            # Si no hay nada, puedes descomentar para debug:
            # print("Sin procesos sospechosos en este ciclo.")
            pass

        time.sleep(interval)

def start_monitor(interval: int = 5):
    """
    Función de entrada para iniciar el monitoreo de procesos.
    """
    monitor_processes(interval)

if __name__ == "__main__":
    start_monitor()