from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from routes.auth import rota as rota_autenticacao
from database import criar_tabelas_automaticamente

# ==========================================================
# CONFIGURAÇÃO DO APLICATIVO
# ==========================================================
app = FastAPI(
    title="Micro Auth - Serviço de Autenticação",
    description="""
API REST desenvolvida em **FastAPI** com banco de dados **PostgreSQL**.

Este serviço é responsável pelo **controle de autenticação de usuários** no sistema,
incluindo os seguintes endpoints principais:

| RF  | Método | Endpoint | Descrição |
|------|---------|-----------|-----------|
| **RF01** | POST | `/api/v1/auth/signup` | Criar nova conta |
| **RF02** | POST | `/api/v1/auth/login` | Fazer login |
| **RF03** | POST | `/api/v1/auth/recuperar-senha` | Recuperar senha |
| **RF04** | POST | `/api/v1/auth/logout` | Fazer logout |
| **RF05** | GET  | `/api/v1/auth/me` | Retornar dados do usuário autenticado |

Use o botão **Authorize 🔒** no canto superior direito do Swagger para autenticar suas requisições.
    """,
    version="1.0.0",
    docs_url="/docs"
)

# ==========================================================
# SEGURANÇA E CORS
# ==========================================================
security_scheme = HTTPBearer()

origens_permitidas = [
    "http://localhost",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origens_permitidas,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================================
# EVENTO DE INICIALIZAÇÃO (STARTUP)
# ==========================================================
@app.on_event("startup")
def inicializar_banco():
    """
    Executado automaticamente ao iniciar o FastAPI.
    Garante que as tabelas definidas em models.sql existam.
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
    Endpoint simples para verificar se o serviço está online.
    """
    return {
        "status": "online",
        "serviço": "Micro Auth - Serviço de Autenticação",
        "versão": "1.0.0",
        "documentação_swagger": "/docs"
    }

# ==========================================================
# EXECUÇÃO LOCAL
# ==========================================================
if __name__ == "__main__":
    import uvicorn
    print("🚀 Iniciando o servidor FastAPI em http://127.0.0.1:8000 ...")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
