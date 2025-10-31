import os, hashlib, re
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Security, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from typing import Optional
from database import consultar_um, executar, executar_retorno
from utils.token import gerar_token, decodificar_token
from utils.cache import registrar_taxa
from passlib.context import CryptContext

# -------------------- LIMITES (vêm do .env) --------------------
LIMITE_SIGNUP_IP = int(os.getenv("LIMITE_SIGNUP_IP", 5))         # req/min
LIMITE_LOGIN_IP  = int(os.getenv("LIMITE_LOGIN_IP", 10))         # req/min
LIMITE_LOGIN_EMAIL = int(os.getenv("LIMITE_LOGIN_EMAIL", 5))     # req/min
LIMITE_ME_USUARIO = int(os.getenv("LIMITE_ME_USUARIO", 30))      # req/min
LIMITE_REC_EMAIL_10M = int(os.getenv("LIMITE_REC_EMAIL_10M", 3)) # req/10min
LIMITE_REC_IP_10M = int(os.getenv("LIMITE_REC_IP_10M", 10))      # req/10min

# -------------------- CONFIG --------------------
security = HTTPBearer(auto_error=False)
criptografia = CryptContext(schemes=["bcrypt"], deprecated="auto")
rota = APIRouter(prefix="/api/v1/auth", tags=["Autenticação"])

# -------------------- MODELOS --------------------
class CriarConta(BaseModel):
    email: EmailStr
    numero_documento: str
    senha: str
    nome_usuario: Optional[str] = None
    nome_completo: Optional[str] = None

class Login(BaseModel):
    login: EmailStr
    senha: str

class RecuperarSenha(BaseModel):
    documento: str
    email: EmailStr
    nova_senha: str

# -------------------- HELPERS --------------------
def normalizar_senha(senha: str) -> str:
    return hashlib.sha256(senha.encode("utf-8")).hexdigest()

def hash_senha(senha: str) -> str:
    return criptografia.hash(normalizar_senha(senha))

def verificar_senha(senha_clara: str, senha_hash: str) -> bool:
    return criptografia.verify(normalizar_senha(senha_clara), senha_hash)

def obter_usuario_por_email(email: str):
    return consultar_um("SELECT * FROM usuarios WHERE email = %s", (email,))

def obter_usuario_por_doc_email(doc: str, email: str):
    return consultar_um(
        "SELECT * FROM usuarios WHERE numero_documento = %s AND email = %s",
        (doc, email)
    )

def salvar_token(id_usuario: int, token: str):
    executar("INSERT INTO tokens (id_usuario, token) VALUES (%s, %s)", (id_usuario, token))

def buscar_token(token: str):
    sql = """
        SELECT 
            t.id AS token_id,
            t.token,
            t.criado_em,
            u.id AS id_usuario,
            u.email,
            u.numero_documento,
            u.nome_usuario,
            u.nome_completo,
            u.logado,
            u.criado_em AS criado_em_usuario,
            u.atualizado_em AS atualizado_em_usuario
        FROM tokens t
        JOIN usuarios u ON u.id = t.id_usuario
        WHERE t.token = %s
    """
    return consultar_um(sql, (token,))

def apagar_token(token: str):
    executar("DELETE FROM tokens WHERE token = %s", (token,))

def atualizar_status_login(id_usuario: int, status: bool):
    executar("UPDATE usuarios SET logado = %s, atualizado_em = now() WHERE id = %s", (status, id_usuario))

def criar_tabela_tentativas():
    executar("""
        CREATE TABLE IF NOT EXISTS tentativas_login (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            tentativas INT DEFAULT 0,
            ultimo_erro TIMESTAMP WITH TIME ZONE
        );
    """)

def senha_forte(s: str) -> bool:
    if len(s) < 8:
        return False
    checks = [
        re.search(r"[a-z]", s),
        re.search(r"[A-Z]", s),
        re.search(r"\d", s),
        re.search(r"[^\w\s]", s),
    ]
    return sum(1 for c in checks if c) >= 3

def get_ip(req: Request) -> str:
    fwd = req.headers.get("x-forwarded-for") or req.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return req.client.host if req.client else "0.0.0.0"

# -------------------- ENDPOINTS --------------------
@rota.post("/signup", summary="RF01 - Criar nova conta")
def criar_conta(dados: CriarConta, request: Request):
    criar_tabela_tentativas()

    # rate-limit por IP para cadastros (env)
    ip = get_ip(request)
    permitido, _, _ = registrar_taxa(f"rl:signup:ip:{ip}", limite=LIMITE_SIGNUP_IP, janela_segundos=60)
    if not permitido:
        raise HTTPException(status_code=429, detail="Muitas requisições de cadastro. Tente novamente em instantes.")

    existente = consultar_um(
        "SELECT 1 FROM usuarios WHERE email = %s OR numero_documento = %s",
        (dados.email, dados.numero_documento)
    )
    if existente:
        raise HTTPException(status_code=400, detail="Email ou documento já cadastrados.")

    if not senha_forte(dados.senha):
        raise HTTPException(status_code=400, detail="Senha fraca. Use 8+ caracteres e combine letras, números e símbolos.")

    senha_hash = hash_senha(dados.senha)

    usuario = executar_retorno("""
        INSERT INTO usuarios (email, numero_documento, senha_hash, nome_usuario, nome_completo, logado)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (dados.email, dados.numero_documento, senha_hash, dados.nome_usuario, dados.nome_completo, True))

    if not usuario:
        raise HTTPException(status_code=500, detail="Erro ao criar usuário.")

    token = gerar_token({"email": usuario["email"], "numero_documento": usuario["numero_documento"], "uid": usuario["id"]})
    salvar_token(usuario["id"], token)
    atualizar_status_login(usuario["id"], True)

    return {"token": token, "id_usuario": usuario["id"]}


@rota.post("/login", summary="RF02 - Fazer login com bloqueio e verificação de sessão")
def login(dados: Login, request: Request):
    criar_tabela_tentativas()
    ip = get_ip(request)

    # rate-limit por IP (env)
    permitido_ip, _, _ = registrar_taxa(f"rl:login:ip:{ip}", limite=LIMITE_LOGIN_IP, janela_segundos=60)
    if not permitido_ip:
        raise HTTPException(status_code=429, detail="Muitas tentativas de login deste IP. Aguarde um minuto.")

    usuario = obter_usuario_por_email(dados.login)
    if not usuario:
        # rate-limit por email (env) – não vaza existência
        registrar_taxa(f"rl:login:email:{dados.login}", limite=LIMITE_LOGIN_EMAIL, janela_segundos=60)
        raise HTTPException(status_code=401, detail="Usuário ou senha inválidos.")

    if usuario["logado"]:
        raise HTTPException(status_code=403, detail="Usuário já está logado.")

    token_ativo = consultar_um("""
        SELECT 1 FROM tokens t JOIN usuarios u ON u.id = t.id_usuario WHERE u.email = %s
    """, (dados.login,))
    if token_ativo:
        raise HTTPException(status_code=403, detail="Usuário já possui uma sessão ativa.")

    tentativa = consultar_um("SELECT * FROM tentativas_login WHERE email = %s", (dados.login,))
    if tentativa and tentativa["tentativas"] >= 3:
        ultimo_erro = tentativa["ultimo_erro"]
        if ultimo_erro and datetime.now(timezone.utc) - ultimo_erro < timedelta(minutes=10):
            raise HTTPException(status_code=403, detail="Usuário bloqueado por 10 minutos devido a falhas consecutivas.")
        else:
            executar("UPDATE tentativas_login SET tentativas = 0 WHERE email = %s", (dados.login,))

    if not verificar_senha(dados.senha, usuario["senha_hash"]):
        if tentativa:
            executar("""UPDATE tentativas_login SET tentativas = tentativas + 1, ultimo_erro = now() WHERE email = %s""",
                     (dados.login,))
        else:
            executar("""INSERT INTO tentativas_login (email, tentativas, ultimo_erro) VALUES (%s, 1, now())""",
                     (dados.login,))
        registrar_taxa(f"rl:login:email:{dados.login}", limite=LIMITE_LOGIN_EMAIL, janela_segundos=60)
        raise HTTPException(status_code=401, detail="Usuário ou senha inválidos.")

    executar("DELETE FROM tentativas_login WHERE email = %s", (dados.login,))

    token = gerar_token({"email": usuario["email"], "numero_documento": usuario["numero_documento"], "uid": usuario["id"]})
    salvar_token(usuario["id"], token)
    atualizar_status_login(usuario["id"], True)
    return {"token": token}


@rota.post("/recuperar-senha", summary="RF03 - Recuperação de senha")
def recuperar_senha(dados: RecuperarSenha, request: Request):
    ip = get_ip(request)
    # rate-limit IP e e-mail (env) para reduzir brute force
    ok_ip, _, _   = registrar_taxa(f"rl:recsenha:ip:{ip}", limite=LIMITE_REC_IP_10M, janela_segundos=600)      # 10 min
    ok_mail, _, _ = registrar_taxa(f"rl:recsenha:mail:{dados.email}", limite=LIMITE_REC_EMAIL_10M, janela_segundos=600)
    if not (ok_ip and ok_mail):
        raise HTTPException(status_code=429, detail="Muitas solicitações de recuperação. Tente novamente mais tarde.")

    usuario = obter_usuario_por_doc_email(dados.documento, dados.email)
    if not usuario:
        # resposta genérica (não vaza existência)
        return {"mensagem": "Se os dados forem válidos, a senha será atualizada."}

    if not senha_forte(dados.nova_senha):
        raise HTTPException(status_code=400, detail="Senha fraca. Use 8+ caracteres e combine letras, números e símbolos.")

    # proibir reutilização
    if verificar_senha(dados.nova_senha, usuario["senha_hash"]):
        raise HTTPException(status_code=400, detail="A nova senha não pode ser igual à senha atual.")

    nova_hash = hash_senha(dados.nova_senha)
    executar("UPDATE usuarios SET senha_hash = %s, atualizado_em = now() WHERE id = %s",
             (nova_hash, usuario["id"]))

    # invalida TODAS as sessões ativas do usuário
    executar("DELETE FROM tokens WHERE id_usuario = %s", (usuario["id"],))
    atualizar_status_login(usuario["id"], False)

    # resposta genérica (evita enumeração)
    return {"mensagem": "Se os dados forem válidos, a senha foi atualizada e as sessões foram encerradas."}


@rota.post("/logout", summary="RF04 - Fazer logout")
def logout(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials if credentials else None
    if not token:
        raise HTTPException(status_code=400, detail="Token ausente no header Authorization.")

    # valida integridade/expiração do token criptografado
    try:
        decodificar_token(token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token inválido: {e}")

    encontrado = buscar_token(token)
    if not encontrado:
        raise HTTPException(status_code=400, detail="Token inválido ou já expirado.")

    apagar_token(token)
    atualizar_status_login(encontrado["id_usuario"], False)
    return {"mensagem": "Logout realizado com sucesso."}


@rota.get("/me", summary="RF05 - Retorna os dados do usuário autenticado")
def me(credentials: HTTPAuthorizationCredentials = Security(security), request: Request = None):
    token = credentials.credentials if credentials else None
    if not token:
        raise HTTPException(status_code=400, detail="Token ausente no header Authorization.")

    encontrado = buscar_token(token)
    if not encontrado:
        raise HTTPException(status_code=400, detail="Token inválido.")

    uid = encontrado.get("id_usuario")

    # throttling por usuário (env)
    permitido, _, _ = registrar_taxa(f"throttle:me:uid:{uid}", limite=LIMITE_ME_USUARIO, janela_segundos=60)
    if not permitido:
        raise HTTPException(status_code=429, detail="Muitas requisições ao recurso /me. Aguarde um pouco.")

    # valida integridade/expiração do token
    try:
        claims = decodificar_token(token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token inválido: {e}")

    usuario = {
        "id": uid,
        "email": encontrado.get("email"),
        "numero_documento": encontrado.get("numero_documento"),
        "nome_usuario": encontrado.get("nome_usuario"),
        "nome_completo": encontrado.get("nome_completo"),
        "logado": encontrado.get("logado"),
        "criado_em": encontrado.get("criado_em_usuario"),
        "atualizado_em": encontrado.get("atualizado_em_usuario"),
        "claims": {"iat": claims.get("iat"), "exp": claims.get("exp"), "jti": claims.get("jti")},
    }
    return {"usuario": usuario}
