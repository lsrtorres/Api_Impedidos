import hashlib
import json
import os
import tempfile
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Annotated, Optional
import urllib

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Security, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt import ExpiredSignatureError, PyJWTError
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, Float, Text, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

load_dotenv()

# ==================== CONFIGURAÇÕES ====================
SECRET_KEY = os.getenv("SECRET_KEY", "0987654321")  # MUDAR EM PRODUÇÃO
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
ADMIN_TOKEN_EXPIRE_MINUTES = 480  # 8 horas

PFX_PATH   = os.getenv("PFX_PATH",   "/home/azureuser/projetos/e-CNPJ_F12.p12")
SENHA_PFX  = os.getenv("SENHA_PFX",  "GEWYTGHP")
TOKEN_FILE = os.getenv("TOKEN_FILE", os.path.join(os.path.dirname(__file__), "certificates", "token_gov.json"))

# Configuração do SQL Server
params = urllib.parse.quote_plus(
    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
    f"SERVER={os.getenv('DB_SERVER', '187.87.134.107')};"
    f"DATABASE={os.getenv('DB_NAME', 'Api_Impedidos')};"
    f"UID={os.getenv('DB_USER', 'leandro.torres')};"
    f"PWD={os.getenv('DB_PASS', 'Lsrt@2109@')};"
    "TrustServerCertificate=yes;"
    "Encrypt=yes;"
    "Connection Timeout=30;"
    "APP=API_Impedidos"
)
engine = create_engine(
    f"mssql+pyodbc:///?odbc_connect={params}",
    pool_pre_ping=True, pool_size=20, pool_recycle=1800, max_overflow=40, future=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Rate Limiting
rate_limit_data = defaultdict(lambda: {"count": 0, "reset_time": datetime.now()})
rate_limit_lock = Lock()

# Cache do token da API externa
token_cache = {"token": None, "expira_em": None}
token_lock = Lock()

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
    motivos = Column(Text, nullable=True)          # JSON array ex: ["PROGRAMA_SOCIAL"]
    data_autoexclusao = Column(String(50), nullable=True)  # dataSolicitacaoAutoexclusao do SERPRO
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


class UsuarioUpdate(BaseModel):
    ativo: Optional[bool] = None
    max_requests_per_minute: Optional[int] = None
    nova_senha: Optional[str] = None


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
    motivos: list[str]
    data_autoexclusao: Optional[str] = None  # presente só quando AUTOEXCLUSAO_CENTRALIZADA
    timestamp: str
    usuario: str


class ConsultaLoteRequest(BaseModel):
    cpfs: Annotated[list[str], Field(min_length=1, max_length=200)]


class ResultadoLote(BaseModel):
    cpf: str
    status: Optional[str] = None
    motivos: list[str] = []
    data_autoexclusao: Optional[str] = None
    transaction_id: Optional[str] = None
    erro: Optional[str] = None


class ConsultaLoteResponse(BaseModel):
    total: int
    processados: int
    erros: int
    usuario: str
    timestamp: str
    resultados: list[ResultadoLote]


# ==================== FUNÇÕES AUXILIARES ====================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def criar_token_jwt(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verificar_token_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")


def verificar_rate_limit(username: str, max_requests: int, n: int = 1):
    with rate_limit_lock:
        agora = datetime.now()
        user_data = rate_limit_data[username]
        if agora >= user_data["reset_time"]:
            user_data["count"] = 0
            user_data["reset_time"] = agora + timedelta(minutes=1)
        # Batch maior que o limite total do usuário — nunca vai passar
        if n > max_requests:
            raise HTTPException(
                status_code=429,
                detail=f"Lote de {n} CPFs excede o limite do usuário ({max_requests}/min). "
                       f"Reduza o batch para no máximo {max_requests} CPFs ou solicite aumento de limite."
            )
        if user_data["count"] + n > max_requests:
            tempo_restante = (user_data["reset_time"] - agora).seconds
            disponivel = max_requests - user_data["count"]
            raise HTTPException(
                status_code=429,
                detail=f"Limite excedido. {disponivel} slots disponíveis neste minuto. "
                       f"Aguarde {tempo_restante}s ou reduza o batch para {disponivel} CPFs."
            )
        user_data["count"] += n


def obter_usuario_atual(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
) -> UsuarioDB:
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
    usuario.ultimo_acesso = datetime.now()
    db.commit()
    return usuario


def verificar_admin(usuario: UsuarioDB = Depends(obter_usuario_atual)) -> UsuarioDB:
    if not usuario.is_admin:
        raise HTTPException(status_code=403, detail="Acesso negado. Apenas administradores.")
    return usuario


def registrar_log(db: Session, usuario: str, endpoint: str, metodo: str, status_code: int, ip: str, erro: str = None):
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


# ==================== CACHE PERSISTENTE DO TOKEN GOV ====================
def carregar_token_persistido():
    """Carrega token do disco no startup, evitando autenticação desnecessária com o SERPRO."""
    if not os.path.exists(TOKEN_FILE):
        return
    try:
        with open(TOKEN_FILE, "r") as f:
            data = json.load(f)
        expira_em = datetime.fromisoformat(data["expira_em"])
        if datetime.now() < expira_em:
            token_cache["token"] = data["token"]
            token_cache["expira_em"] = expira_em
            print(f"Token GOV carregado do cache persistente. Expira em {expira_em.isoformat()}")
        else:
            print("Cache de token GOV encontrado mas expirado. Será renovado na primeira consulta.")
    except Exception as e:
        print(f"Falha ao carregar token persistido: {e}")


def salvar_token_persistido():
    """Persiste o token em disco para sobreviver a restarts da aplicação."""
    try:
        os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
        with open(TOKEN_FILE, "w") as f:
            json.dump({"token": token_cache["token"], "expira_em": token_cache["expira_em"].isoformat()}, f)
    except Exception as e:
        print(f"Falha ao salvar token persistente: {e}")


def extrair_certificados_do_pfx(pfx_path: str, senha: str):
    with open(pfx_path, 'rb') as f:
        pfx_data = f.read()
    private_key, cert, _ = pkcs12.load_key_and_certificates(
        pfx_data, senha.encode(), backend=default_backend()
    )
    temp_key = tempfile.NamedTemporaryFile(delete=False, suffix='.key')
    temp_cert = tempfile.NamedTemporaryFile(delete=False, suffix='.crt')
    temp_key.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    temp_key.close()
    temp_cert.write(cert.public_bytes(Encoding.PEM))
    temp_cert.close()
    return temp_cert.name, temp_key.name


def obter_token_api_gov(cert_path: str, key_path: str) -> tuple[str, int]:
    """Retorna (token, expires_in_segundos) da API de autenticação SERPRO."""
    url = "https://auth-sigap-rec.ni.estaleiro.serpro.gov.br/recepcao-autenticacao/token"
    try:
        response = requests.post(url, cert=(cert_path, key_path), verify=True, timeout=30)
        if response.status_code == 200:
            data = response.json()
            token = data.get("token") or data.get("access_token")
            expires_in = int(data.get("expires_in", 604800))  # default 7 dias se não informado
            return token, expires_in
        raise HTTPException(status_code=500, detail=f"Erro ao obter token: {response.status_code}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro na autenticação gov: {str(e)}")


def obter_token_valido() -> str:
    with token_lock:
        agora = datetime.now()
        if token_cache["token"] and token_cache["expira_em"] and agora < token_cache["expira_em"]:
            return token_cache["token"]

        print("Token GOV expirado ou inexistente. Renovando...")
        cert_path, key_path = extrair_certificados_do_pfx(PFX_PATH, SENHA_PFX)
        novo_token, expires_in = obter_token_api_gov(cert_path, key_path)
        # 5 minutos de margem de segurança antes do vencimento real
        expira_em = agora + timedelta(seconds=expires_in - 300)
        token_cache["token"] = novo_token
        token_cache["expira_em"] = expira_em
        salvar_token_persistido()
        print(f"Novo token GOV obtido. Expira em {expira_em.isoformat()}")
        return novo_token


def consultar_cpf_impedido(cpf: str, token: str, retries: int = 3, backoff: int = 5) -> dict:
    cpf_limpo = cpf.replace('.', '').replace('-', '').strip()
    if not cpf_limpo.isdigit() or len(cpf_limpo) != 11:
        raise HTTPException(status_code=400, detail="CPF inválido. Deve conter 11 dígitos.")

    url = f"https://sigap-impedidos.fazenda.gov.br/impedimento/v2/condicao/{cpf_limpo}"
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
                dados = resp.json()
                return {
                    "cpf": cpf_limpo,
                    "status": dados.get("resultado", "indefinido"),
                    "motivos": dados.get("motivos", []),
                    "data_autoexclusao": dados.get("dataSolicitacaoAutoexclusao"),
                    "tempo_resposta_ms": tempo_resposta,
                }
            elif resp.status_code == 401:
                with token_lock:
                    token_cache["token"] = None
                    token_cache["expira_em"] = None
                raise HTTPException(status_code=401, detail="Token gov expirado. Tente novamente.")
            elif resp.status_code == 404:
                return {"cpf": cpf_limpo, "status": "não encontrado", "motivos": [], "data_autoexclusao": None, "tempo_resposta_ms": tempo_resposta}
            else:
                raise HTTPException(status_code=resp.status_code, detail=f"Erro na consulta: {resp.text}")

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


# ==================== APP ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    carregar_token_persistido()
    print("Tabelas verificadas e token GOV carregado (se disponível em cache).")
    yield
    print("Encerrando aplicação...")


app = FastAPI(title="API de Consulta de Impedidos - Produção", version="3.0.0", lifespan=lifespan)

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")


# ==================== ROTAS DO FRONTEND ====================
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def pagina_login():
    with open(os.path.join(WEB_DIR, "login.html"), encoding="utf-8") as f:
        return f.read()


@app.get("/consulta", response_class=HTMLResponse, include_in_schema=False)
def pagina_consulta():
    with open(os.path.join(WEB_DIR, "consulta.html"), encoding="utf-8") as f:
        return f.read()


@app.get("/painel-admin", response_class=HTMLResponse, include_in_schema=False)
def pagina_admin():
    with open(os.path.join(WEB_DIR, "admin.html"), encoding="utf-8") as f:
        return f.read()


# ==================== AUTENTICAÇÃO ====================
@app.post("/auth/login", response_model=Token)
def login(credenciais: UsuarioLogin, db: Session = Depends(get_db)):
    """Realiza login e retorna um token JWT"""
    usuario = db.query(UsuarioDB).filter(UsuarioDB.username == credenciais.username).first()
    if not usuario or usuario.hashed_password != hash_password(credenciais.password):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos")
    if not usuario.ativo:
        raise HTTPException(status_code=403, detail="Usuário inativo")
    expires_delta = timedelta(minutes=ADMIN_TOKEN_EXPIRE_MINUTES if usuario.is_admin else ACCESS_TOKEN_EXPIRE_MINUTES)
    token = criar_token_jwt(
        data={"sub": usuario.username, "admin": usuario.is_admin},
        expires_delta=expires_delta
    )
    return {"access_token": token, "token_type": "bearer", "expires_in": int(expires_delta.total_seconds())}


# ==================== ADMINISTRAÇÃO ====================
@app.post("/admin/registrar")
def registrar_usuario(
    usuario: UsuarioCreate,
    db: Session = Depends(get_db),
    admin: UsuarioDB = Depends(verificar_admin)
):
    """Registra um novo usuário (apenas administradores)"""
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
        "id": novo_usuario.id,
        "username": novo_usuario.username,
        "email": novo_usuario.email,
        "is_admin": novo_usuario.is_admin,
        "max_requests_per_minute": novo_usuario.max_requests_per_minute,
    }


@app.get("/admin/usuarios")
def listar_usuarios(
    _admin: UsuarioDB = Depends(verificar_admin),
    db: Session = Depends(get_db)
):
    """Lista todos os usuários (apenas administradores)"""
    usuarios = db.query(UsuarioDB).order_by(UsuarioDB.criado_em.desc()).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_admin": u.is_admin,
            "ativo": u.ativo,
            "max_requests_per_minute": u.max_requests_per_minute,
            "criado_em": u.criado_em.isoformat() if u.criado_em else None,
            "ultimo_acesso": u.ultimo_acesso.isoformat() if u.ultimo_acesso else None,
        }
        for u in usuarios
    ]


@app.patch("/admin/usuarios/{usuario_id}")
def atualizar_usuario(
    usuario_id: int,
    dados: UsuarioUpdate,
    admin: UsuarioDB = Depends(verificar_admin),
    db: Session = Depends(get_db)
):
    """Ativa, desativa ou altera limite de requisições de um usuário (apenas administradores)"""
    if admin.id == usuario_id:
        raise HTTPException(status_code=400, detail="Não é possível alterar o próprio usuário por aqui")
    usuario = db.query(UsuarioDB).filter(UsuarioDB.id == usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if dados.ativo is not None:
        usuario.ativo = dados.ativo
    if dados.max_requests_per_minute is not None:
        usuario.max_requests_per_minute = dados.max_requests_per_minute
    if dados.nova_senha is not None:
        if len(dados.nova_senha) < 6:
            raise HTTPException(status_code=400, detail="A nova senha deve ter no mínimo 6 caracteres")
        usuario.hashed_password = hash_password(dados.nova_senha)
    db.commit()
    registrar_log(db, admin.username, f"/admin/usuarios/{usuario_id}", "PATCH", 200, "sistema")
    return {"mensagem": "Usuário atualizado", "id": usuario_id, "ativo": usuario.ativo}


@app.get("/admin/estatisticas")
def obter_estatisticas(
    admin: UsuarioDB = Depends(verificar_admin),
    db: Session = Depends(get_db)
):
    """Retorna estatísticas gerais da API (apenas admin)"""
    total_usuarios = db.query(UsuarioDB).count()
    usuarios_ativos = db.query(UsuarioDB).filter(UsuarioDB.ativo == True).count()
    total_transacoes = db.query(TransacaoDB).count()
    ontem = datetime.now() - timedelta(days=1)
    transacoes_24h = db.query(TransacaoDB).filter(TransacaoDB.timestamp >= ontem).count()
    return {
        "total_usuarios": total_usuarios,
        "usuarios_ativos": usuarios_ativos,
        "total_transacoes": total_transacoes,
        "transacoes_ultimas_24h": transacoes_24h,
        "timestamp": datetime.now().isoformat(),
    }


# ==================== CONSULTA ====================
def registrar_lote_e_log(
    username: str, transacoes: list[dict], timestamp: datetime, ip_origem: str
):
    """Grava todas as transações do lote em background numa única sessão."""
    if not transacoes:
        return
    try:
        db = SessionLocal()
        for tx in transacoes:
            db.add(TransacaoDB(
                transaction_id=tx["transaction_id"],
                usuario=username,
                cpf=tx["cpf"],
                status=tx["status"],
                motivos=json.dumps(tx["motivos"]),
                data_autoexclusao=tx.get("data_autoexclusao"),
                timestamp=timestamp,
                tempo_resposta_ms=tx.get("tempo_resposta_ms", 0),
                ip_origem=ip_origem,
            ))
        db.commit()
        registrar_log(db, username, "/consultar/lote", "POST", 200, ip_origem)
        db.close()
    except Exception as e:
        print(f"[BG] Erro ao registrar lote ({len(transacoes)} itens): {e}")


def registrar_transacao_e_log(
    username: str, resultado: dict, transaction_id: str, timestamp: datetime, ip_origem: str
):
    """Grava transação e log em background, sem bloquear o response ao cliente."""
    try:
        db = SessionLocal()
        db.add(TransacaoDB(
            transaction_id=transaction_id,
            usuario=username,
            cpf=resultado["cpf"],
            status=resultado["status"],
            motivos=json.dumps(resultado["motivos"]),
            data_autoexclusao=resultado.get("data_autoexclusao"),
            timestamp=timestamp,
            tempo_resposta_ms=resultado.get("tempo_resposta_ms", 0),
            ip_origem=ip_origem,
        ))
        db.commit()
        registrar_log(db, username, f"/consultar/{resultado['cpf']}", "GET", 200, ip_origem)
        db.close()
    except Exception as e:
        print(f"[BG] Erro ao registrar transação {transaction_id}: {e}")


@app.get("/consultar/{cpf}", response_model=ConsultaResponse)
def consultar_impedido(
    cpf: str,
    request: Request,
    background_tasks: BackgroundTasks,
    usuario: UsuarioDB = Depends(obter_usuario_atual),
    db: Session = Depends(get_db)
):
    """Consulta se um CPF está impedido (requer autenticação JWT)"""
    verificar_rate_limit(usuario.username, usuario.max_requests_per_minute)
    ip_origem = request.client.host if request.client else "desconhecido"
    try:
        transaction_id = str(uuid.uuid4())
        timestamp = datetime.now()
        token = obter_token_valido()
        resultado = consultar_cpf_impedido(cpf, token)

        # Retorna o response imediatamente; DB e log são gravados em background
        background_tasks.add_task(
            registrar_transacao_e_log,
            usuario.username, resultado, transaction_id, timestamp, ip_origem,
        )
        return ConsultaResponse(
            transaction_id=transaction_id,
            cpf=resultado["cpf"],
            status=resultado["status"],
            motivos=resultado["motivos"],
            data_autoexclusao=resultado.get("data_autoexclusao"),
            timestamp=timestamp.isoformat(),
            usuario=usuario.username,
        )
    except HTTPException as he:
        registrar_log(db, usuario.username, f"/consultar/{cpf}", "GET", he.status_code, ip_origem, he.detail)
        raise
    except Exception as e:
        registrar_log(db, usuario.username, f"/consultar/{cpf}", "GET", 500, ip_origem, str(e))
        raise HTTPException(status_code=500, detail=f"Erro inesperado: {str(e)}")


@app.post("/consultar/lote", response_model=ConsultaLoteResponse)
def consultar_lote(
    payload: ConsultaLoteRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    usuario: UsuarioDB = Depends(obter_usuario_atual),
):
    """Consulta até 200 CPFs em uma única chamada. Cada CPF consome 1 token do rate limit."""
    n = len(payload.cpfs)
    verificar_rate_limit(usuario.username, usuario.max_requests_per_minute, n=n)

    ip_origem = request.client.host if request.client else "desconhecido"
    timestamp = datetime.now()

    _serpro_url = "https://sigap-impedidos.fazenda.gov.br/impedimento/v2/condicao/{cpf}"

    def consultar_um(cpf_raw: str) -> tuple[ResultadoLote, dict | None]:
        """
        Versão enxuta para uso em lote:
        - timeout de 15 s (sem retry com sleep — evita 504 no Nginx)
        - retry único em 401 para renovar o token SERPRO
        """
        cpf = cpf_raw.replace('.', '').replace('-', '').strip()
        if not cpf.isdigit() or len(cpf) != 11:
            return ResultadoLote(cpf=cpf_raw, erro="CPF inválido"), None

        for tentativa in range(2):  # tentativa 0 normal; tentativa 1 após refresh do token
            try:
                inicio = time.time()
                token = obter_token_valido()
                resp = requests.get(
                    _serpro_url.format(cpf=cpf),
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    timeout=15,
                )
                tempo_ms = (time.time() - inicio) * 1000

                if resp.status_code == 200:
                    dados = resp.json()
                    tx_id = str(uuid.uuid4())
                    return (
                        ResultadoLote(
                            cpf=cpf,
                            status=dados.get("resultado", "indefinido"),
                            motivos=dados.get("motivos", []),
                            data_autoexclusao=dados.get("dataSolicitacaoAutoexclusao"),
                            transaction_id=tx_id,
                        ),
                        {
                            "transaction_id": tx_id,
                            "cpf": cpf,
                            "status": dados.get("resultado", "indefinido"),
                            "motivos": dados.get("motivos", []),
                            "data_autoexclusao": dados.get("dataSolicitacaoAutoexclusao"),
                            "tempo_resposta_ms": tempo_ms,
                        },
                    )
                elif resp.status_code == 401 and tentativa == 0:
                    # Token expirou: limpa cache e tenta uma vez mais
                    with token_lock:
                        token_cache["token"] = None
                        token_cache["expira_em"] = None
                    continue
                elif resp.status_code == 404:
                    tx_id = str(uuid.uuid4())
                    return (
                        ResultadoLote(cpf=cpf, status="não encontrado", motivos=[], transaction_id=tx_id),
                        {"transaction_id": tx_id, "cpf": cpf, "status": "não encontrado",
                         "motivos": [], "data_autoexclusao": None, "tempo_resposta_ms": tempo_ms},
                    )
                else:
                    return ResultadoLote(cpf=cpf, erro=f"SERPRO HTTP {resp.status_code}"), None

            except requests.exceptions.Timeout:
                return ResultadoLote(cpf=cpf, erro="Timeout SERPRO (15s)"), None
            except Exception as e:
                return ResultadoLote(cpf=cpf, erro=str(e)), None

        return ResultadoLote(cpf=cpf, erro="Token SERPRO inválido após renovação"), None

    resultados: list[ResultadoLote] = []
    transacoes_bg: list[dict] = []

    workers = min(n, 30)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(consultar_um, cpf): cpf for cpf in payload.cpfs}
        for future in as_completed(futures):
            try:
                res, tx = future.result()
            except Exception as e:
                res, tx = ResultadoLote(cpf="desconhecido", erro=str(e)), None
            resultados.append(res)
            if tx:
                transacoes_bg.append(tx)

    background_tasks.add_task(
        registrar_lote_e_log,
        usuario.username, transacoes_bg, timestamp, ip_origem,
    )

    erros = sum(1 for r in resultados if r.erro)
    return ConsultaLoteResponse(
        total=n,
        processados=n - erros,
        erros=erros,
        usuario=usuario.username,
        timestamp=timestamp.isoformat(),
        resultados=resultados,
    )


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
    if transacao.usuario != usuario.username and not usuario.is_admin:
        raise HTTPException(status_code=403, detail="Acesso negado a esta transação")
    return {
        "transaction_id": transacao.transaction_id,
        "usuario": transacao.usuario,
        "cpf": transacao.cpf,
        "status": transacao.status,
        "motivos": json.loads(transacao.motivos) if transacao.motivos else [],
        "data_autoexclusao": transacao.data_autoexclusao,
        "timestamp": transacao.timestamp.isoformat(),
        "tempo_resposta_ms": transacao.tempo_resposta_ms,
        "ip_origem": transacao.ip_origem,
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
                "motivos": json.loads(t.motivos) if t.motivos else [],
                "data_autoexclusao": t.data_autoexclusao,
                "timestamp": t.timestamp.isoformat(),
                "tempo_resposta_ms": t.tempo_resposta_ms,
            }
            for t in transacoes
        ],
    }


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Verifica se a API e o banco de dados estão funcionando"""
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        return {"status": "error", "database": "disconnected", "error": str(e), "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, workers=8)
