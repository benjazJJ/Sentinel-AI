import re
import requests
from dataclasses import dataclass

from sentinela_core.db.base import SessionLocal
from sentinela_core.db.models import Alert


OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3.2"


@dataclass
class AnalysisResult:
    alert_id: int
    alert_message: str
    explanation: str
    recommended_actions: str


def _build_prompt(alert: Alert) -> str:
    """
    Genera el prompt que se enviará a Ollama para analizar la alerta.
    """
    return f"""
Eres un analista de ciberseguridad que trabaja en un SOC defensivo.
Tu tarea es analizar una alerta EDR y explicar únicamente desde la perspectiva
de defensa, sin instrucciones ofensivas ni técnicas de explotación.

Debes responder siempre con estas tres ideas principales:

1) Por qué esta alerta podría ser sospechosa o inofensiva.
2) Qué tipo de técnica, patrón o comportamiento legítimo/malicioso podría representar.
3) Acciones defensivas concretas: 3 a 5 pasos prácticos que un analista debe realizar.

REGLAS IMPORTANTES:
- No describir cómo explotar vulnerabilidades.
- No inventar malware ni payloads.
- No dar comandos ofensivos.
- No más de 4 párrafos en la explicación.
- Las ACCIONES deben ser prácticas, defensivas y claras.

ALERTA DETECTADA:
- Tipo: {alert.type}
- Severidad: {alert.severity}
- Mensaje: {alert.message}

Responde en español y con el siguiente FORMATO EXACTO:

[EXPLICACIÓN]
(Tu análisis en 2–4 párrafos)

[ACCIONES RECOMENDADAS]
- Acción 1
- Acción 2
- Acción 3
- (Opcional: Acción 4 o 5)
""".strip()


def _split_sections(content: str) -> tuple[str, str]:
    """
    Separa el contenido devuelto por el modelo en:
    - explicación
    - acciones recomendadas

    Soporta variaciones como:
    [ACCIONES RECOMENDADAS]
    ACCIONES RECOMENDADAS
    ACCIONES RECOMENDADAS:
    """

    # Normalizamos
    text = content.strip()

    # 1) Eliminar marcador de explicación si lo puso
    text = text.replace("[EXPLICACIÓN]", "").replace("**EXPLICACIÓN**", "")

    # 2) Buscar el bloque de acciones con una regex flexible
    #    Soporta corchetes, asteriscos, dos puntos, etc.
    acciones_pattern = re.compile(
        r"\[?\s*\**\s*ACCIONES\s+RECOMENDADAS\s*\**\s*\]?:?",
        re.IGNORECASE,
    )

    match = acciones_pattern.search(text)

    if not match:
        # No pudimos separar: todo es explicación, sin acciones separadas
        return text.strip(), ""

    # Explicación = todo lo anterior al encabezado de acciones
    explanation = text[: match.start()].strip()

    # Acciones = todo lo posterior al encabezado
    actions = text[match.end() :].strip()

    return explanation, actions


def analyze_alert_with_ollama(alert_id: int) -> AnalysisResult:
    """
    Carga una alerta desde la BD, la analiza con Ollama
    y devuelve un AnalysisResult con explicación y acciones.
    """
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise ValueError(f"No se encontró alerta con id={alert_id}")
    finally:
        db.close()

    prompt = _build_prompt(alert)

    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Eres un analista de ciberseguridad defensiva. "
                    "Nunca entregues instrucciones ofensivas o de explotación."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "stream": False,
    }

    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
        resp.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"Error al comunicar con Ollama: {e}")

    data = resp.json()
    content = data.get("message", {}).get("content", "").strip()

    explanation, actions = _split_sections(content)

    return AnalysisResult(
        alert_id=alert.id,
        alert_message=alert.message,
        explanation=explanation,
        recommended_actions=actions,
    )
