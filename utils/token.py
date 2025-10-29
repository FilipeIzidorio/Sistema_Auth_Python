import base64
from datetime import datetime
from typing import Dict

def gerar_token(dados_usuario: Dict) -> str:
    texto = f"{dados_usuario['email']}|{dados_usuario['numero_documento']}|{datetime.utcnow().isoformat()}"
    b = texto.encode("utf-8")
    return base64.urlsafe_b64encode(b).decode("utf-8")

def decodificar_token(token: str) -> str:
    try:
        return base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
    except Exception:
        return ""
