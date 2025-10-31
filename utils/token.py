from cryptography.fernet import Fernet
import os
from datetime import datetime, timezone
import json

# ==========================
# CHAVE DE CRIPTOGRAFIA
# ==========================
# Gera automaticamente se não existir no .env
chave_criptografia = os.getenv("CHAVE_CRIPTOGRAFIA")

if not chave_criptografia:
    chave_criptografia = Fernet.generate_key().decode()
    with open(".env", "a", encoding="utf-8") as f:
        f.write(f"\nCHAVE_CRIPTOGRAFIA={chave_criptografia}")
    print("🔐 Chave criptográfica gerada e salva no .env")

fernet = Fernet(chave_criptografia.encode())


# ==========================
# FUNÇÕES DE TOKEN
# ==========================

def gerar_token(dados_usuario: dict) -> str:
    """
    Gera um token seguro criptografando os dados do usuário.
    """
    dados = {
        "email": dados_usuario["email"],
        "numero_documento": dados_usuario["numero_documento"],
        "gerado_em": datetime.now(timezone.utc).isoformat()
    }

    texto = json.dumps(dados)
    token = fernet.encrypt(texto.encode("utf-8"))
    return token.decode()


def decodificar_token(token: str) -> dict:
    """
    Descriptografa o token e retorna os dados do usuário.
    """
    try:
        dados = fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        return json.loads(dados)
    except Exception:
        return {}


def token_expirado(token: str, minutos_validade: int = 60) -> bool:
    """
    Verifica se o token passou do tempo de validade.
    """
    dados = decodificar_token(token)
    if not dados or "gerado_em" not in dados:
        return True

    tempo = datetime.fromisoformat(dados["gerado_em"])
    agora = datetime.now(timezone.utc)

    return (agora - tempo).total_seconds() > minutos_validade * 60
