# utils/cache.py
import os, time, threading
from typing import Tuple
from dotenv import load_dotenv

load_dotenv()  # garante leitura do .env

try:
    import redis  # pip install redis>=5
except ImportError:
    redis = None

# ===========================
# Fallback em memória
# ===========================
_trava = threading.Lock()
_cache_local = {}  # {chave: (contador, expira_em_epoch)}

# ===========================
# Configuração Redis pelo .env
# ===========================
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_SENHA = os.getenv("REDIS_PASSWORD", None)

def _conectar_redis():
    """Retorna conexão Redis se disponível, senão None."""
    if not redis:
        return None
    try:
        conexao = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_SENHA,
            decode_responses=True
        )
        conexao.ping()
        return conexao
    except Exception:
        return None

redis_conexao = _conectar_redis()


def registrar_taxa(chave: str, limite: int, janela_segundos: int) -> Tuple[bool, int, int]:
    """
    Controle de Rate Limit

    Retorna:
      permitido -> True/False
      restante -> requisições restantes
      tempo_reset -> segundos até reset
    """

    agora = int(time.time())

    # ===========================
    # Se Redis estiver funcional
    # ===========================
    if redis_conexao:
        try:
            pipeline = redis_conexao.pipeline()
            pipeline.incr(chave, 1)
            pipeline.ttl(chave)
            contador, ttl = pipeline.execute()

            # Se ainda não tem TTL
            if ttl == -1:
                redis_conexao.expire(chave, janela_segundos)
                ttl = janela_segundos

            # Se a chave não existia
            elif ttl == -2:
                redis_conexao.set(chave, 1, ex=janela_segundos)
                contador, ttl = 1, janela_segundos

            permitido = contador <= limite
            restante = max(0, limite - contador)
            return permitido, restante, ttl
        except Exception:
            pass  # fallback automático para cache local

    # ===========================
    # Fallback local na RAM
    # ===========================
    with _trava:
        contador, expira_em = _cache_local.get(chave, (0, agora + janela_segundos))

        if agora >= expira_em:  # reinicia janela
            contador, expira_em = 0, agora + janela_segundos

        contador += 1
        _cache_local[chave] = (contador, expira_em)

        permitido = contador <= limite
        restante = max(0, limite - contador)
        tempo_reset = max(0, expira_em - agora)

        return permitido, restante, tempo_reset
