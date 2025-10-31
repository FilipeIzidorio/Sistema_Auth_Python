import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv


load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_PORT = int(os.getenv("DB_PORT"))
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")


# Caminho do arquivo SQL com os modelos
SQL_MODELS_FILE = os.path.join(os.path.dirname(__file__), "models.sql")

# ==========================
# CONEXÃO COM O BANCO
# ==========================
def obter_conexao():
    """
    Retorna uma conexão ativa com o banco de dados PostgreSQL.
    """
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

# ==========================
# FUNÇÕES DE ACESSO AO BANCO
# ==========================
def consultar_um(sql: str, params: tuple = ()):
    conn = obter_conexao()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchone()
    finally:
        conn.close()


def consultar_todos(sql: str, params: tuple = ()):
    conn = obter_conexao()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchall()
    finally:
        conn.close()


def executar(sql: str, params: tuple = ()):
    conn = obter_conexao()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            conn.commit()
            return cur.rowcount
    finally:
        conn.close()


def executar_retorno(sql: str, params: tuple = ()):
    """
    Executa um comando SQL e retorna o registro inserido/atualizado.
    Adiciona RETURNING * apenas se ainda não existir.
    Evita duplicações e erros de sintaxe.
    """
    conn = obter_conexao()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            sql_corrigido = sql.strip().rstrip(";")

            # Evita duplicar a cláusula RETURNING
            if "returning" not in sql_corrigido.lower():
                sql_corrigido += " RETURNING *"

            cur.execute(sql_corrigido, params)
            resultado = cur.fetchone()
            conn.commit()
            return resultado
    finally:
        conn.close()

# ==========================
# CRIAÇÃO AUTOMÁTICA DAS TABELAS
# ==========================
def criar_tabelas_automaticamente():
    """
    Lê o conteúdo do arquivo models.sql e executa os comandos SQL
    para garantir que as tabelas estejam criadas.
    """
    if not os.path.exists(SQL_MODELS_FILE):
        print("⚠️  Arquivo 'models.sql' não encontrado!")
        return

    with open(SQL_MODELS_FILE, "r", encoding="utf-8") as f:
        sql_script = f.read()

    conn = obter_conexao()
    try:
        with conn.cursor() as cur:
            cur.execute(sql_script)
            conn.commit()
            print("✅ Tabelas verificadas/criadas com sucesso!")
    except Exception as e:
        print(f"❌ Erro ao criar tabelas: {e}")
        conn.rollback()
    finally:
        conn.close()

# Executa automaticamente ao importar o módulo
criar_tabelas_automaticamente()
