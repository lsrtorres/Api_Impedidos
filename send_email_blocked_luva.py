#!/usr/bin/env python3
import os
import sys
import json
from datetime import date, datetime, timedelta
from typing import Optional
import urllib
import logging
from logging import StreamHandler
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

SENDGRID_API_KEY_LUVA = 'REMOVED_SECRET_LUVA'

FROM_EMAIL_LUVA = Email("atendimento@luva.bet", name="Luva.bet – Atendimento")
REPLY_TO_LUVA   = ReplyTo("jogo.responsavel@Luva.bet.br", name="Luva.bet – Customer Service")

ASSUNTO_LUVA = "Bloqueio | Apostas em aberto | usuário beneficiário de programa social do Governo"

# ============================================================
# Logging
# ============================================================
LOG_DIR = Path(__file__).parent / 'logs'
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f'Enviar_Email_Blocked_Luva_{datetime.now().strftime("%Y%m")}.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# ============================================================
# Conexão com SQL Server (agora impedidos_luva)
# ============================================================

def sqlserver_engine():
    params = urllib.parse.quote_plus(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=192.168.70.5;"
        "DATABASE=impedidos_luva;"
        "UID=Leandro.torres;"
        "PWD=Lsrt@2109@;"
        "TrustServerCertificate=yes;"
        "APP=Enviar_Emails_Impedidos"
    )
    conn_str = f"mssql+pyodbc:///?odbc_connect={params}"
    return create_engine(conn_str, fast_executemany=True)

engine_sql = sqlserver_engine()

# ============================================================
# Carregar template HTML
# ============================================================

def load_template(brand: str, tipo) -> str:
    brand = brand.upper()
    base_dir = os.path.join(os.path.dirname(__file__), "templates")
    if tipo == "BF":
        file_name = "cod_luva.html"
    else:
        file_name = "Modelo-Autoexcluido_Luva.html"
    path = os.path.join(base_dir, file_name)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Template HTML não encontrado: {path}")

    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# ============================================================
# Utils
# ============================================================

def _to_datestr(d: date | str) -> str:
    if isinstance(d, date):
        return d.strftime("%Y-%m-%d")
    return str(d)

# ============================================================
# Buscar candidatos no SQL Server (impedidos_luva)
# ============================================================

def fetch_candidates_sqlserver():
    sql = text("""
        SELECT 
            user_id,
            player_name AS nome,
            player_email AS email,
            player_check_date,
            player_reason
        FROM dbo.Impedidos_BF
        WHERE Player_sent_email = 0
        ORDER BY player_check_date ASC
    """)

    with engine_sql.connect() as conn:
        rows = conn.execute(sql).mappings().all()
        return [dict(r) for r in rows]

# ============================================================
# Atualizar status após envio
# ============================================================

def update_sent_status(user_id: int):
    sql = text("""
        UPDATE dbo.Impedidos_BF
        SET Player_sent_email = 1,
            player_sent_email_date = GETDATE()
        WHERE user_id = :uid
    """)

    with engine_sql.begin() as conn:
        conn.execute(sql, {"uid": user_id})

# ============================================================
# Enviar e-mail
# ============================================================

def send_email(tipo,brand, player_id: int, to_email: str, send_date: date | str, nome: str | None = None):

    SENDGRID_API_KEY = SENDGRID_API_KEY_LUVA
    FROM_EMAIL = FROM_EMAIL_LUVA
    REPLY_TO = REPLY_TO_LUVA
    ASSUNTO = ASSUNTO_LUVA

    if not SENDGRID_API_KEY:
        raise RuntimeError("SendGrid API key ausente.")

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

    resp = sg.send(mail)

    msg_id = None
    headers = getattr(resp, "headers", {}) or {}
    msg_id = headers.get("X-Message-Id") or headers.get("x-message-id") or headers.get("X-Message-ID")

    return resp.status_code, msg_id

# ============================================================
# JOB PRINCIPAL
# ============================================================

def run_rg_email_job(brand: Optional[str], send_date: date | str):

    candidatos = fetch_candidates_sqlserver()
    logger.info(f"[INFO] Candidatos para envio: {len(candidatos)}")

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
                tipo = tipo,
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

    logger.info(f"🏁 Finalizado | Enviados: {enviados} | Falhas: {falhas}")

# ============================================================
# EXECUÇÃO (crontab)
# ============================================================

if __name__ == "__main__":
    send = date.today().strftime("%Y-%m-%d")
    run_rg_email_job(brand="LUVA", send_date=send)
