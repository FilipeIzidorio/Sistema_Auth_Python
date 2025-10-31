from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from routes.auth import rota as rota_autenticacao
from database import criar_tabelas_automaticamente
from dotenv import load_dotenv
import os

# Carregar variáveis do .env
load_dotenv()

# ==========================================================
# CONFIGURAÇÃO DO APLICATIVO
# ==========================================================
app = FastAPI(
    title="Micro Auth - Serviço de Autenticação",
    description="""
API REST desenvolvida em **FastAPI** com banco de dados **PostgreSQL**.

Este serviço gerencia o **processo de autenticação e sessão de usuários**, incluindo:

| RF  | Método | Endpoint | Descrição |
|------|--------|-----------|-----------|
| RF01 | POST   | `/api/v1/auth/signup`          | Criar nova conta |
| RF02 | POST   | `/api/v1/auth/login`           | Fazer login |
| RF03 | POST   | `/api/v1/auth/recuperar-senha` | Recuperar senha |
| RF04 | POST   | `/api/v1/auth/logout`          | Fazer logout |
| RF05 | GET    | `/api/v1/auth/me`              | Dados do usuário autenticado |

Use **Authorize 🔒** no Swagger para autenticar requisições.
""",
    version="1.1.0",
    docs_url="/docs"
)

# ==========================================================
# CORS
# ==========================================================
origens_permitidas = os.getenv("CORS_ORIGINS", "http://localhost,http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origens_permitidas,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Segurança (mantido para coerência, mesmo sem uso direto aqui)
security_scheme = HTTPBearer()

# ==========================================================
# EVENTO DE STARTUP
# ==========================================================
@app.on_event("startup")
def inicializar_banco():
    """
    Garante que as tabelas definidas em models.sql sejam criadas ao iniciar o serviço.
    """
    print("\n🔄 Inicializando banco de dados...")
    try:
        criar_tabelas_automaticamente()
        print("✅ Banco de dados pronto e tabelas verificadas!\n")
    except Exception as e:
        print(f"❌ Erro ao inicializar banco: {e}\n")

# ==========================================================
# ROTAS
# ==========================================================
app.include_router(rota_autenticacao)

@app.get("/", tags=["Verificação"])
def verificar_status():
    """
    Verifica se o serviço está online.
    """
    return {
        "status": "online",
        "serviço": "Micro Auth - Serviço de Autenticação",
        "versão": "1.1.0",
        "documentação_swagger": "/docs"
    }

# ==========================================================
# EXECUÇÃO LOCAL
# ==========================================================
if __name__ == "__main__":
    import uvicorn
    print("🚀 Iniciando servidor FastAPI em http://127.0.0.1:8000 ...")
    uvicorn.run(
        "main:app",
        host=os.getenv("APP_HOST", "127.0.0.1"),
        port=int(os.getenv("APP_PORT", 8000)),
        reload=True
    )
