from fastapi import FastAPI, HTTPException, Depends, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import requests
import tempfile
import time
import uuid
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
import jwt
from jwt import ExpiredSignatureError, PyJWTError
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, Float, Text
from sqlalchemy.orm  import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import urllib
from collections import defaultdict
from threading import Lock
from contextlib import asynccontextmanager

# ==================== CONFIGURAÇÕES ====================
SECRET_KEY = "0987654321"  # MUDAR EM PRODUÇÃO
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
ADMIN_TOKEN_EXPIRE_MINUTES = 480  # 8 horas

#PFX_PATH = "/Users/leandrotorres/Documents/Projetos-Bet/e-CNPJ_F12.p12"
PFX_PATH = "/home/azureuser/projetos/e-CNPJ_F12.p12"
SENHA_PFX = "GEWYTGHP"

# Configuração do SQL Server
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
engine = create_engine(f"mssql+pyodbc:///?odbc_connect={params}", pool_pre_ping=True, pool_size=20,pool_recycle=3600, max_overflow=40)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Rate Limiting
rate_limit_data = defaultdict(lambda: {"count": 0, "reset_time": datetime.now()})
rate_limit_lock = Lock()

# Cache do token da API externa
token_cache = {"token": None, "expira_em": None}
token_lock = Lock()

app = FastAPI(title="API de Consulta de Impedidos - Produção", version="3.0.0")
security = HTTPBearer()



# ==================== MODELOS DO BANCO DE DADOS ====================
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


# ==================== MODELOS PYDANTIC ====================
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
    timestamp: str
    usuario: str


# ==================== FUNÇÕES AUXILIARES ====================
def get_db():
    """Dependency para obter sessão do banco"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    """Gera hash SHA-256 da senha"""
    return hashlib.sha256(password.encode()).hexdigest()


def criar_token_jwt(data: dict, expires_delta: timedelta = None) -> str:
    """Cria um token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt




def verificar_token_jwt(token: str) -> dict:
    """Verifica e decodifica um token JWT"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")


def verificar_rate_limit(username: str, max_requests: int):
    """Verifica e aplica rate limiting por usuário"""
    with rate_limit_lock:
        agora = datetime.now()
        user_data = rate_limit_data[username]
        
        # Reseta contador a cada minuto
        if agora >= user_data["reset_time"]:
            user_data["count"] = 0
            user_data["reset_time"] = agora + timedelta(minutes=1)
        
        # Verifica limite
        if user_data["count"] >= max_requests:
            tempo_restante = (user_data["reset_time"] - agora).seconds
            raise HTTPException(
                status_code=429,
                detail=f"Limite de requisições excedido. Tente novamente em {tempo_restante} segundos."
            )
        
        user_data["count"] += 1


def obter_usuario_atual(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
) -> UsuarioDB:
    """Verifica o token JWT e retorna o usuário atual"""
    token = credentials.credentials
    payload = verificar_token_jwt(token)
    
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    usuario = db.query(UsuarioDB).filter(UsuarioDB.username == username).first()
    if not usuario:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    
    if not usuario.ativo:
        raise HTTPException(status_code=403, detail="Usuário inativo")
    
    # Atualiza último acesso
    usuario.ultimo_acesso = datetime.now()
    db.commit()
    
    return usuario


def verificar_admin(usuario: UsuarioDB = Depends(obter_usuario_atual)) -> UsuarioDB:
    """Verifica se o usuário é administrador"""
    if not usuario.is_admin:
        raise HTTPException(status_code=403, detail="Acesso negado. Apenas administradores.")
    return usuario


def registrar_log(db: Session, usuario: str, endpoint: str, metodo: str, status_code: int, ip: str, erro: str = None):
    """Registra log de acesso"""
    try:
        log = LogAcessoDB(
            usuario=usuario,
            endpoint=endpoint,
            metodo=metodo,
            status_code=status_code,
            timestamp=datetime.now(),
            ip_origem=ip,
            mensagem_erro=erro
        )
        db.add(log)
        db.commit()
    except Exception as e:
        print(f"Erro ao registrar log: {e}")
        db.rollback()


def extrair_certificados_do_pfx(pfx_path: str, senha: str):
    """Extrai certificado e chave privada do arquivo PFX"""
    with open(pfx_path, 'rb') as f:
        pfx_data = f.read()

    private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
        pfx_data, senha.encode(), backend=default_backend()
    )

    temp_key = tempfile.NamedTemporaryFile(delete=False, suffix='.key')
    temp_cert = tempfile.NamedTemporaryFile(delete=False, suffix='.crt')

    temp_key.write(
        private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL,
            NoEncryption()
        )
    )
    temp_key.close()

    temp_cert.write(cert.public_bytes(Encoding.PEM))
    temp_cert.close()

    return temp_cert.name, temp_key.name


def obter_token_api_gov(cert_path: str, key_path: str) -> str:
    """Obtém token de autenticação da API do governo"""
    url = "https://auth-sigap-rec.ni.estaleiro.serpro.gov.br/recepcao-autenticacao/token"
    
    try:
        response = requests.post(url, cert=(cert_path, key_path), verify=True, timeout=30)
        
        if response.status_code == 200:
            return response.json()["token"]
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Erro ao obter token: {response.status_code}"
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro na autenticação gov: {str(e)}")


def obter_token_valido() -> str:
    """Retorna token válido da API do governo, renovando se necessário (thread-safe)"""
    with token_lock:
        agora = datetime.now()
        
        if token_cache["token"] and token_cache["expira_em"] and agora < token_cache["expira_em"]:
            return token_cache["token"]
        
        cert_path, key_path = extrair_certificados_do_pfx(PFX_PATH, SENHA_PFX)
        novo_token = obter_token_api_gov(cert_path, key_path)
        
        token_cache["token"] = novo_token
        token_cache["expira_em"] = agora + timedelta(minutes=50)
        
        return novo_token


def consultar_cpf_impedido(cpf: str, token: str, retries: int = 3, backoff: int = 5) -> dict:
    """Consulta se um CPF está impedido"""
    cpf_limpo = cpf.replace('.', '').replace('-', '').strip()
    
    if not cpf_limpo.isdigit() or len(cpf_limpo) != 11:
        raise HTTPException(status_code=400, detail="CPF inválido. Deve conter 11 dígitos.")
    
    url = f"https://sigap-impedidos.fazenda.gov.br/impedimento/v1/condicao/{cpf_limpo}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    for tentativa in range(retries):
        try:
            inicio = time.time()
            resp = requests.get(url, headers=headers, timeout=30)
            tempo_resposta = (time.time() - inicio) * 1000
            
            if resp.status_code == 200:
                resultado = resp.json().get("resultado", "indefinido")
                return {"cpf": cpf_limpo, "status": resultado, "tempo_resposta_ms": tempo_resposta}
            elif resp.status_code == 401:
                with token_lock:
                    token_cache["token"] = None
                    token_cache["expira_em"] = None
                raise HTTPException(status_code=401, detail="Token gov expirado. Tente novamente.")
            elif resp.status_code == 404:
                return {"cpf": cpf_limpo, "status": "não encontrado", "tempo_resposta_ms": tempo_resposta}
            else:
                raise HTTPException(
                    status_code=resp.status_code,
                    detail=f"Erro na consulta: {resp.text}"
                )
                
        except requests.exceptions.Timeout:
            if tentativa < retries - 1:
                time.sleep(backoff * (tentativa + 1))
            else:
                raise HTTPException(status_code=504, detail="Timeout ao consultar API")
                
        except HTTPException:
            raise
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Erro na consulta: {str(e)}")
    
    raise HTTPException(status_code=500, detail="Falha após múltiplas tentativas")


# ==================== ENDPOINTS ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    print("✅ Tabelas criadas/verificadas no SQL Server")
    yield
    print("🧹 Encerrando aplicação...")

#app = FastAPI(lifespan=lifespan)
app = FastAPI(title="API de Consulta de Impedidos - Produção", version="3.0.0", lifespan=lifespan)

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


@app.get("/consultar/{cpf}", response_model=ConsultaResponse)
def consultar_impedido(
    cpf: str,
    request: Request,
    usuario: UsuarioDB = Depends(obter_usuario_atual),
    db: Session = Depends(get_db)
):
    """
    Consulta se um CPF está impedido (requer autenticação JWT)
    """
    # Rate limiting
    verificar_rate_limit(usuario.username, usuario.max_requests_per_minute)
    
    ip_origem = request.client.host if request.client else "desconhecido"
    
    try:
        transaction_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        token = obter_token_valido()
        resultado = consultar_cpf_impedido(cpf, token)
        
        # Registra transação
        transacao = TransacaoDB(
            transaction_id=transaction_id,
            usuario=usuario.username,
            cpf=resultado["cpf"],
            status=resultado["status"],
            timestamp=timestamp,
            tempo_resposta_ms=resultado.get("tempo_resposta_ms", 0),
            ip_origem=ip_origem
        )
        db.add(transacao)
        db.commit()
        
        registrar_log(db, usuario.username, f"/consultar/{cpf}", "GET", 200, ip_origem)
        
        return ConsultaResponse(
            transaction_id=transaction_id,
            cpf=resultado["cpf"],
            status=resultado["status"],
            timestamp=timestamp.isoformat(),
            usuario=usuario.username
        )
    except HTTPException as he:
        registrar_log(db, usuario.username, f"/consultar/{cpf}", "GET", he.status_code, ip_origem, he.detail)
        raise
    except Exception as e:
        registrar_log(db, usuario.username, f"/consultar/{cpf}", "GET", 500, ip_origem, str(e))
        raise HTTPException(status_code=500, detail=f"Erro inesperado: {str(e)}")


@app.get("/transacao/{transaction_id}")
def consultar_transacao(
    transaction_id: str,
    usuario: UsuarioDB = Depends(obter_usuario_atual),
    db: Session = Depends(get_db)
):
    """Consulta os detalhes de uma transação específica"""
    transacao = db.query(TransacaoDB).filter(TransacaoDB.transaction_id == transaction_id).first()
    
    if not transacao:
        raise HTTPException(status_code=404, detail="Transação não encontrada")
    
    # Usuário só pode ver suas próprias transações (admin pode ver todas)
    if transacao.usuario != usuario.username and not usuario.is_admin:
        raise HTTPException(status_code=403, detail="Acesso negado a esta transação")
    
    return {
        "transaction_id": transacao.transaction_id,
        "usuario": transacao.usuario,
        "cpf": transacao.cpf,
        "status": transacao.status,
        "timestamp": transacao.timestamp.isoformat(),
        "tempo_resposta_ms": transacao.tempo_resposta_ms,
        "ip_origem": transacao.ip_origem
    }


@app.get("/historico")
def consultar_historico(
    limite: int = 10,
    usuario: UsuarioDB = Depends(obter_usuario_atual),
    db: Session = Depends(get_db)
):
    """Retorna o histórico de transações do usuário"""
    query = db.query(TransacaoDB).filter(TransacaoDB.usuario == usuario.username)
    
    transacoes = query.order_by(TransacaoDB.timestamp.desc()).limit(limite).all()
    
    return {
        "usuario": usuario.username,
        "total_transacoes": query.count(),
        "transacoes": [
            {
                "transaction_id": t.transaction_id,
                "cpf": t.cpf,
                "status": t.status,
                "timestamp": t.timestamp.isoformat(),
                "tempo_resposta_ms": t.tempo_resposta_ms
            }
            for t in transacoes
        ]
    }


@app.get("/admin/estatisticas")
def obter_estatisticas(
    admin: UsuarioDB = Depends(verificar_admin),
    db: Session = Depends(get_db)
):
    """Retorna estatísticas gerais da API (apenas admin)"""
    total_usuarios = db.query(UsuarioDB).count()
    usuarios_ativos = db.query(UsuarioDB).filter(UsuarioDB.ativo == True).count()
    total_transacoes = db.query(TransacaoDB).count()
    
    # Transações nas últimas 24 horas
    ontem = datetime.now() - timedelta(days=1)
    transacoes_24h = db.query(TransacaoDB).filter(TransacaoDB.timestamp >= ontem).count()
    
    return {
        "total_usuarios": total_usuarios,
        "usuarios_ativos": usuarios_ativos,
        "total_transacoes": total_transacoes,
        "transacoes_ultimas_24h": transacoes_24h,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Verifica se a API e o banco de dados estão funcionando"""
    try:
        # Testa conexão com banco
        db.execute("SELECT 1")
        return {
            "status": "ok",
            "database": "connected",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, workers=8)