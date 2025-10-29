-- ========================
-- TABELA DE USUÁRIOS
-- ========================
CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    numero_documento TEXT NOT NULL UNIQUE,
    senha_hash TEXT NOT NULL,
    nome_usuario TEXT,
    nome_completo TEXT,
    logado BOOLEAN NOT NULL DEFAULT FALSE,
    criado_em TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    atualizado_em TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ========================
-- TABELA DE TOKENS
-- ========================
CREATE TABLE IF NOT EXISTS tokens (
    id SERIAL PRIMARY KEY,
    id_usuario INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    criado_em TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_usuario
        FOREIGN KEY (id_usuario)
        REFERENCES usuarios (id)
        ON DELETE CASCADE
);

-- Índice para busca rápida por token
CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens (token);

-- ========================
-- TABELA DE TENTATIVAS DE LOGIN
-- ========================
CREATE TABLE IF NOT EXISTS tentativas_login (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    tentativas INT NOT NULL DEFAULT 0 CHECK (tentativas >= 0),
    ultimo_erro TIMESTAMP WITH TIME ZONE
);

-- Índice para busca rápida por e-mail
CREATE INDEX IF NOT EXISTS idx_tentativas_email ON tentativas_login (email);
