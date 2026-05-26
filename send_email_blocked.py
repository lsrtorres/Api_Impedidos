#!/usr/bin/env python3
import os
import sys
import json
from datetime import date, datetime, timedelta
from typing import Optional
import urllib
import logging

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import URL

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Mail, Email, To, Personalization, ReplyTo, Category, CustomArg
)

from pathlib import Path
from dotenv import load_dotenv
from urllib.parse import quote_plus

# ============================================================
# Carregar variáveis de ambiente
# ============================================================
load_dotenv()

SENDGRID_API_KEY_F12 = os.getenv("SENDGRID_API_KEY_F12", "")

FROM_EMAIL_F12 = Email("atendimento@f12.bet", name="F12.bet – Atendimento")
REPLY_TO_F12   = ReplyTo("atendimento@f12.bet", name="F12.bet – Customer Service")

ASSUNTO_F12 = "Bloqueio | Apostas em aberto | usuário beneficiário de programa social do Governo"

# ============================================================
# Logging
# ============================================================
LOG_DIR = Path(__file__).parent / 'logs'
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f'Enviar_Email_Blocked_F12_{datetime.now().strftime("%Y%m")}.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# ============================================================
# Conexão com SQL Server (F12_SIGAP)
# ============================================================

def sqlserver_engine():
    params = urllib.parse.quote_plus(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=192.168.130.9;"
        "DATABASE=F12_SIGAP;"
        "UID=app.sigap;"
        "PWD=F1~mH2bU5-E>;"
        "TrustServerCertificate=yes;"
        "APP=Enviar_Emails_Impedidos"
    )
    conn_str = f"mssql+pyodbc:///?odbc_connect={params}"
    return create_engine(conn_str, fast_executemany=True)

engine_sql = sqlserver_engine()

# ============================================================
# Carregar template HTML
# ============================================================

def load_template(brand: str, tipo: str) -> str:
    brand = brand.upper()

    base_dir = os.path.join(os.path.dirname(__file__), "templates")
    if tipo == "BF":
        file_name = "cod_f12.html"
    else:
        file_name = "Modelo-Autoexcluido_F12.html"

    path = os.path.join(base_dir, file_name)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Template HTML não encontrado: {path}")

    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# ============================================================
# Utilidade
# ============================================================

def _to_datestr(d: date | str) -> str:
    if isinstance(d, date):
        return d.strftime("%Y-%m-%d")
    return str(d)

# ============================================================
# Buscar candidatos no SQL Server
# ============================================================

def fetch_candidates_sqlserver():
    sql = text("""
        SELECT 
            user_id,
            player_name AS nome,
            player_email AS email,
            player_check_date,
            player_reason
        FROM IMPEDIDOS_BF
        WHERE player_sent_email = 0
        ORDER BY player_check_date ASC
    """)

    with engine_sql.connect() as conn:
        rows = conn.execute(sql).mappings().all()
        return [dict(r) for r in rows]

# ============================================================
# Atualizar registro após enviar o e-mail
# ============================================================

def update_sent_status(user_id: int):
    sql = text("""
        UPDATE IMPEDIDOS_BF
        SET player_sent_email = 1,
            player_sent_email_date = GETDATE()
        WHERE user_id = :uid
    """)

    with engine_sql.begin() as conn:
        conn.execute(sql, {"uid": user_id})

# ============================================================
# Enviar e-mail
# ============================================================

def send_email(tipo,brand, player_id: int, to_email: str, send_date: date | str, nome: str | None = None):
    
    SENDGRID_API_KEY = SENDGRID_API_KEY_F12
    FROM_EMAIL = FROM_EMAIL_F12
    REPLY_TO = REPLY_TO_F12
    ASSUNTO = ASSUNTO_F12

    if not SENDGRID_API_KEY:
        raise RuntimeError("Configuração de SendGrid ausente (API key).")

    send_date_str = _to_datestr(send_date)
    send_date_pt = datetime.fromisoformat(send_date_str).strftime("%d/%m/%Y")
    nome_exibicao = nome or to_email.split("@")[0]

    html_template = load_template(brand, tipo)

    html_content = (
        html_template
        .replace("{{nome_jogador}}", nome_exibicao)
        .replace("{{player_id}}", str(player_id))
        .replace("{{hoje}}", send_date_pt)
        .replace("{{brand}}", brand)
    )

    sg = SendGridAPIClient(SENDGRID_API_KEY)

    mail = Mail(
        from_email=FROM_EMAIL,
        to_emails=to_email,
        subject=ASSUNTO,
        html_content=html_content,
    )
    mail.reply_to = REPLY_TO

    mail.add_category(Category("IMPEDIDOS"))
    mail.add_category(Category("BLOQUEIO-BF"))
    mail.add_custom_arg(CustomArg("player_id", str(player_id)))
    mail.add_custom_arg(CustomArg("risk_level", "A BLOQUEAR"))

    resp = sg.send(mail)

    msg_id = None
    headers = getattr(resp, "headers", {}) or {}
    msg_id = headers.get("X-Message-Id") or headers.get("x-message-id") or headers.get("X-Message-ID")

    return resp.status_code, msg_id

# ============================================================
# Job principal
# ============================================================

def run_rg_email_job(brand: Optional[str], send_date: date | str):

    candidatos = fetch_candidates_sqlserver()
    logger.info(f"[INFO] Candidatos encontrados: {len(candidatos)}")

    enviados = 0
    falhas = 0

    for row in candidatos:
        pid = row["user_id"]
        email = row["email"]
        nome = row["nome"]
        if row['player_reason'] == 'AUTOEXCLUSAO_CENTRALIZADA':
            tipo="AE"
        else:
            tipo = "BF"
        try:
            status_code, message_id = send_email(
                tipo,
                brand=brand,
                player_id=pid,
                to_email=email,
                send_date=send_date,
                nome=nome
            )

            if status_code in (200, 202):
                update_sent_status(pid)
                enviados += 1
                logger.info(f"[OK] Email enviado para {email} pid={pid}")
            else:
                falhas += 1
                logger.error(f"[WARN] Falha SendGrid pid={pid} email={email} status={status_code}")

        except Exception as e:
            falhas += 1
            logger.error(f"[ERROR] pid={pid} email={email} err={e}")

    logger.info(f"✅ Enviados: {enviados} | ❌ Falhas: {falhas}")

# ============================================================
# Execução (Cron)
# ============================================================

if __name__ == "__main__":
    send = date.today().strftime("%Y-%m-%d")
    run_rg_email_job(brand="F12", send_date=send)
