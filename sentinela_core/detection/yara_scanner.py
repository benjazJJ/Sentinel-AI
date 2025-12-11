import pathlib
from typing import Iterable

import yara
from sqlalchemy.orm import Session

from sentinela_core.db.base import SessionLocal
from sentinela_core.db.models import Alert


def load_rules(rules_path: str) -> yara.Rules:
    """
    Carga y compila un archivo de reglas YARA.
    """
    return yara.compile(filepath=rules_path)


def iter_files(root: str) -> Iterable[pathlib.Path]:
    """
    Recorre recursivamente todos los archivos desde un directorio raíz.
    """
    base = pathlib.Path(root)
    if base.is_file():
        yield base
        return

    for p in base.rglob("*"):
        if p.is_file():
            yield p


def scan_path(path: str, rules: yara.Rules) -> int:
    """
    Escanea un path usando reglas YARA y guarda alertas en la BD.
    Devuelve el número de alertas creadas.
    """
    db: Session = SessionLocal()
    created = 0

    try:
        for file_path in iter_files(path):
            try:
                matches = rules.match(str(file_path))
            except yara.Error:
                # Archivos que YARA no puede leer (permisos, etc.)
                continue

            if matches:
                # Tomamos el nombre de la primera regla que matcheó
                rule_name = matches[0].rule
                message = f"YARA match: {rule_name} en {file_path}"

                alert = Alert(
                    type="yara",
                    severity="HIGH",
                    message=message,
                )
                db.add(alert)
                created += 1

        db.commit()
    finally:
        db.close()

    return created
