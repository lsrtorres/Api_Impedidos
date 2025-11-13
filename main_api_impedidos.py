from fastapi import FastAPI, HTTPException, Depends, Security, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, Float, Text, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from collections import defaultdict
from threading import Lock
from contextlib import asynccontextmanager
import hashlib
import jwt
from jwt.exceptions import ExpiredSignatureError, PyJWTError
import requests
import tempfile
import time
import urllib
import uuid
import json
import os
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend

# ============================================================
# 🔧 CONFIGURAÇÕES GERAIS
# ============================================================
SECRET_KEY = "0987654321"  # 🔒 Mude em produção
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480
ADMIN_TOKEN_EXPIRE_MINUTES = 480

PFX_PATH = "/home/azureuser/projetos/impedidos/certificates/e-CNPJ_F12.p12"
SENHA_PFX = "GEWYTGHP"

TOKEN_FILE = "/home/azureuser/projetos/impedidos/certificates/token_gov.json"  # cache persistente do token GOV

# ============================================================
# ⚙️ SQL SERVER ENGINE OTIMIZADA
# ============================================================
params = urllib.parse.quote_plus(
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=187.87.134.107;"
    "DATABASE=Api_Impedidos;"
    "UID=leandro.torres;"
    "PWD=Lsrt@2109@;"
    "TrustServerCertificate=yes;"
    "Encrypt=yes;"
    "Connection Timeout=30;"
    "APP=API_Impedidos"
)
engine = create_engine(
    f"mssql+pyodbc:///?odbc_connect={params}",
    pool_pre_ping=True,
    pool_size=20,
    max_overflow=40,
    pool_recycle=1800,
    future=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ============================================================
# ⚡ CONTROLES DE LIMITE E CACHE
# ============================================================
rate_limit_data = defaultdict(lambda: {"count": 0, "reset_time": datetime.now()})
rate_limit_lock = Lock()

token_cache = {"token": None, "expira_em": None}
token_lock = Lock()

app = FastAPI(title="API de Consulta de Impedidos - Produção", version="3.2.0")
security = HTTPBearer()

# ============================================================
# 🧱 MODELOS DO BANCO
# ============================================================

class UsuarioDB(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    ativo = Column(Boolean, default=True, nullable=False)
    max_requests_per_minute = Column(Integer, default=10, nullable=False)
    criado_em = Column(DateTime, default=datetime.now, nullable=False)
    ultimo_acesso = Column(DateTime, nullable=True)


class TransacaoDB(Base):
    __tablename__ = "transacoes"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    transaction_id = Column(String(36), unique=True, index=True, nullable=False)
    usuario = Column(String(50), index=True, nullable=False)
    cpf = Column(String(11), index=True, nullable=False)
    status = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.now, nullable=False, index=True)
    tempo_resposta_ms = Column(Float, nullable=False)
    ip_origem = Column(String(45), nullable=True)


class LogAcessoDB(Base):
    __tablename__ = "logs_acesso"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    usuario = Column(String(50), index=True, nullable=False)
    endpoint = Column(String(255), nullable=False)
    metodo = Column(String(10), nullable=False)
    status_code = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=datetime.now, nullable=False, index=True)
    ip_origem = Column(String(45), nullable=True)
    mensagem_erro = Column(Text, nullable=True)

# ============================================================
# 📦 MODELOS PYDANTIC
# ============================================================

class UsuarioCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    is_admin: bool = False
    max_requests_per_minute: int = 10

class UsuarioLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class ConsultaResponse(BaseModel):
    transaction_id: str
    cpf: str
    status: str
    motivo: str
    timestamp: str
    usuario: str

# ============================================================
# 🧠 FUNÇÕES AUXILIARES
# ============================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def criar_token_jwt(data: dict, expires_delta: timedelta = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {**data, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verificar_token_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

def verificar_rate_limit(username: str, max_requests: int):
    with rate_limit_lock:
        agora = datetime.now()
        user_data = rate_limit_data[username]
        if agora >= user_data["reset_time"]:
            user_data["count"] = 0
            user_data["reset_time"] = agora + timedelta(minutes=1)
        if user_data["count"] >= max_requests:
            tempo_restante = (user_data["reset_time"] - agora).seconds
            raise HTTPException(status_code=429, detail=f"Limite excedido. Tente em {tempo_restante}s.")
        user_data["count"] += 1

def obter_usuario_atual(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)) -> UsuarioDB:
    payload = verificar_token_jwt(credentials.credentials)
    username = payload.get("sub")
    usuario = db.query(UsuarioDB).filter(UsuarioDB.username == username).first()
    if not usuario:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    if not usuario.ativo:
        raise HTTPException(status_code=403, detail="Usuário inativo")
    usuario.ultimo_acesso = datetime.now()
    db.commit()
    return usuario
def verificar_admin(usuario: UsuarioDB = Depends(obter_usuario_atual)) -> UsuarioDB:
    """Verifica se o usuário é administrador"""
    if not usuario.is_admin:
        raise HTTPException(status_code=403, detail="Acesso negado. Apenas administradores.")
    return usuario
def registrar_log(db: Session, usuario: str, endpoint: str, metodo: str, status_code: int, ip: str, erro: str = None):
    try:
        db.add(LogAcessoDB(usuario=usuario, endpoint=endpoint, metodo=metodo,
                           status_code=status_code, timestamp=datetime.now(),
                           ip_origem=ip, mensagem_erro=erro))
        db.commit()
    except Exception as e:
        print(f"[⚠️ LOG] Falha ao registrar log: {e}")
        db.rollback()

# ============================================================
# 💾 CACHE PERSISTENTE DO TOKEN GOV
# ============================================================

def carregar_token_persistido():
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r") as f:
                data = json.load(f)
                expira_em = datetime.fromisoformat(data["expira_em"])
                if datetime.now() < expira_em:
                    token_cache.update(data)
                    token_cache["expira_em"] = expira_em
                    print("♻️ Token GOV carregado do cache persistente.")
        except Exception as e:
            print(f"⚠️ Falha ao carregar token persistido: {e}")

def salvar_token_persistido():
    try:
        with open(TOKEN_FILE, "w") as f:
            json.dump({
                "token": token_cache["token"],
                "expira_em": token_cache["expira_em"].isoformat()
            }, f)
    except Exception as e:
        print(f"⚠️ Falha ao salvar token persistente: {e}")

# ============================================================
# 🔐 TOKEN GOV - CACHE 24 HORAS
# ============================================================

def extrair_certificados_do_pfx(pfx_path: str, senha: str):
    with open(pfx_path, 'rb') as f:
        pfx_data = f.read()
    private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_data, senha.encode(), backend=default_backend())
    temp_key = tempfile.NamedTemporaryFile(delete=False, suffix='.key')
    temp_cert = tempfile.NamedTemporaryFile(delete=False, suffix='.crt')
    temp_key.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    temp_cert.write(cert.public_bytes(Encoding.PEM))
    temp_key.close(), temp_cert.close()
    return temp_cert.name, temp_key.name

def obter_token_api_gov(cert_path: str, key_path: str) -> tuple[str, int]:
    url = "https://auth-sigap-rec.ni.estaleiro.serpro.gov.br/recepcao-autenticacao/token"
    response = requests.post(url, cert=(cert_path, key_path), verify=True, timeout=30)
    if response.status_code == 200:
        data = response.json()
        token = data.get("token") or data.get("access_token")
        validade_segundos = data.get("expires_in", 604800)
        return token, int(validade_segundos / 3600)
    raise HTTPException(status_code=500, detail=f"Erro ao obter token GOV: {response.status_code}")

def obter_token_valido() -> str:
    with token_lock:
        agora = datetime.now()
        if token_cache["token"] and token_cache["expira_em"] and agora < token_cache["expira_em"]:
            return token_cache["token"]

        print("🔄 Token GOV expirado ou inexistente. Renovando...")
        cert_path, key_path = extrair_certificados_do_pfx(PFX_PATH, SENHA_PFX)
        novo_token, validade_horas = obter_token_api_gov(cert_path, key_path)
        expira_em = agora + timedelta(hours=validade_horas)
        token_cache["token"] = novo_token
        token_cache["expira_em"] = expira_em
        salvar_token_persistido()
        print(f"✅ Novo token GOV obtido. Expira em {expira_em.isoformat()}")
        return novo_token

# ============================================================
# 🌐 CONSULTA AO SERPRO
# ============================================================

def consultar_cpf_impedido(cpf: str, token: str) -> dict:
    cpf_limpo = cpf.replace('.', '').replace('-', '').strip()
    if not cpf_limpo.isdigit() or len(cpf_limpo) != 11:
        raise HTTPException(status_code=400, detail="CPF inválido.")
    url = f"https://sigap-impedidos.fazenda.gov.br/impedimento/v1/condicao/{cpf_limpo}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    inicio = time.time()
    resp = requests.get(url, headers=headers, timeout=30)
    tempo_resposta = (time.time() - inicio) * 1000
    if resp.status_code == 200:
        return {"cpf": cpf_limpo, "status": resp.json().get("resultado", "indefinido"), "motivo":resp.json().get("motivo", ""),"tempo_resposta_ms": tempo_resposta}
    elif resp.status_code == 404:
        return {"cpf": cpf_limpo, "status": "não encontrado", "tempo_resposta_ms": tempo_resposta}
    elif resp.status_code == 401:
        token_cache.update({"token": None, "expira_em": None})
        raise HTTPException(status_code=401, detail="Token GOV expirado.")
    else:
        raise HTTPException(status_code=resp.status_code, detail=f"Erro GOV: {resp.text}")

# ============================================================
# 🚀 ENDPOINT PRINCIPAL OTIMIZADO
# ============================================================
@app.post("/admin/registrar")
def registrar_usuario(
    usuario: UsuarioCreate,
    db: Session = Depends(get_db),
    admin: UsuarioDB = Depends(verificar_admin)
):
    """
    Registra um novo usuário (apenas administradores)
    """
    # Verifica se usuário já existe
    if db.query(UsuarioDB).filter(UsuarioDB.username == usuario.username).first():
        raise HTTPException(status_code=400, detail="Nome de usuário já existe")
    
    if db.query(UsuarioDB).filter(UsuarioDB.email == usuario.email).first():
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    
    novo_usuario = UsuarioDB(
        username=usuario.username,
        email=usuario.email,
        hashed_password=hash_password(usuario.password),
        is_admin=usuario.is_admin,
        ativo=True,
        max_requests_per_minute=usuario.max_requests_per_minute,
        criado_em=datetime.now()
    )
    
    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)
    
    registrar_log(db, admin.username, "/admin/registrar", "POST", 200, "sistema")
    
    return {
        "mensagem": "Usuário registrado com sucesso",
        "username": novo_usuario.username,
        "email": novo_usuario.email,
        "is_admin": novo_usuario.is_admin,
        "max_requests_per_minute": novo_usuario.max_requests_per_minute
    }


@app.get("/")
def root():
    """Endpoint de boas-vindas"""
    return {
        "mensagem": "API de Consulta de Impedidos - Produção",
        "versao": "3.0.0",
        "autenticacao": "JWT Bearer Token",
        "endpoints": {
            "login": "POST /auth/login",
            "registrar": "POST /admin/registrar (admin only)",
            "consulta": "GET /consultar/{cpf}",
            "transacao": "GET /transacao/{transaction_id}",
            "historico": "GET /historico",
            "estatisticas": "GET /admin/estatisticas (admin only)",
            "documentacao": "/docs"
        }
    }

@app.get("/consultar/{cpf}", response_model=ConsultaResponse)
def consultar_impedido(
    cpf: str,
    request: Request,
    background_tasks: BackgroundTasks,
    usuario: UsuarioDB = Depends(obter_usuario_atual),
    db: Session = Depends(get_db)
):
    verificar_rate_limit(usuario.username, usuario.max_requests_per_minute)
    ip_origem = request.client.host if request.client else "desconhecido"
    transaction_id = str(uuid.uuid4())
    timestamp = datetime.now()
    token = obter_token_valido()
    resultado = consultar_cpf_impedido(cpf, token)

    response = ConsultaResponse(
        transaction_id=transaction_id,
        cpf=resultado["cpf"],
        status=resultado["status"],
        motivo = resultado["motivo"],
        timestamp=timestamp.isoformat(),
        usuario=usuario.username,
    )

    background_tasks.add_task(
        registrar_transacao_e_log,
        usuario.username,
        resultado,
        transaction_id,
        timestamp,
        ip_origem,
    )
    return response

def registrar_transacao_e_log(usuario, resultado, transaction_id, timestamp, ip_origem):
    try:
        db = SessionLocal()
        db.add(TransacaoDB(
            transaction_id=transaction_id,
            usuario=usuario,
            cpf=resultado["cpf"],
            status=resultado["status"],
            timestamp=timestamp,
            tempo_resposta_ms=resultado.get("tempo_resposta_ms", 0),
            ip_origem=ip_origem,
        ))
        db.commit()
        registrar_log(db, usuario, f"/consultar/{resultado['cpf']}", "GET", 200, ip_origem)
        db.close()
        print(f"[✅ LOG-ASYNC] Transação registrada: {transaction_id}")
    except Exception as e:
        print(f"[⚠️ LOG-ASYNC] Erro ao registrar transação: {e}")
        
@app.post("/auth/login", response_model=Token)
def login(credenciais: UsuarioLogin, db: Session = Depends(get_db)):
    """
    Realiza login e retorna um token JWT
    """
    usuario = db.query(UsuarioDB).filter(UsuarioDB.username == credenciais.username).first()
    
    if not usuario or usuario.hashed_password != hash_password(credenciais.password):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos")
    
    if not usuario.ativo:
        raise HTTPException(status_code=403, detail="Usuário inativo")
    
    # Determina tempo de expiração baseado em ser admin ou não
    expires_delta = timedelta(minutes=ADMIN_TOKEN_EXPIRE_MINUTES if usuario.is_admin else ACCESS_TOKEN_EXPIRE_MINUTES)
    
    token = criar_token_jwt(
        data={"sub": usuario.username, "admin": usuario.is_admin},
        expires_delta=expires_delta
    )
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": int(expires_delta.total_seconds())
    }
    
@app.post("/admin/registrar")
def registrar_usuario(
    usuario: UsuarioCreate,
    db: Session = Depends(get_db),
    admin: UsuarioDB = Depends(verificar_admin)
):
    """
    Registra um novo usuário (apenas administradores)
    """
    # Verifica se usuário já existe
    if db.query(UsuarioDB).filter(UsuarioDB.username == usuario.username).first():
        raise HTTPException(status_code=400, detail="Nome de usuário já existe")
    
    if db.query(UsuarioDB).filter(UsuarioDB.email == usuario.email).first():
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    
    novo_usuario = UsuarioDB(
        username=usuario.username,
        email=usuario.email,
        hashed_password=hash_password(usuario.password),
        is_admin=usuario.is_admin,
        ativo=True,
        max_requests_per_minute=usuario.max_requests_per_minute,
        criado_em=datetime.now()
    )
    
    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)
    
    registrar_log(db, admin.username, "/admin/registrar", "POST", 200, "sistema")
    
    return {
        "mensagem": "Usuário registrado com sucesso",
        "username": novo_usuario.username,
        "email": novo_usuario.email,
        "is_admin": novo_usuario.is_admin,
        "max_requests_per_minute": novo_usuario.max_requests_per_minute
    }

@app.get("/")
def root():
    """Endpoint de boas-vindas"""
    return {
        "mensagem": "API de Consulta de Impedidos - Produção",
        "versao": "3.0.0",
        "autenticacao": "JWT Bearer Token",
        "endpoints": {
            "login": "POST /auth/login",
            "registrar": "POST /admin/registrar (admin only)",
            "consulta": "GET /consultar/{cpf}",
            "transacao": "GET /transacao/{transaction_id}",
            "historico": "GET /historico",
            "estatisticas": "GET /admin/estatisticas (admin only)",
            "documentacao": "/docs"
        }
    }


# ============================================================
# 🩺 HEALTHCHECK
# ============================================================

@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "ok",
            "database": "connected",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "status": "error in health",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# ============================================================
# 🧭 STARTUP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    carregar_token_persistido()
    print("✅ Tabelas criadas e token GOV carregado (se disponível)")
    yield
    print("🧹 Encerrando aplicação...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False, loop="uvloop", workers=2)
