#!/usr/bin/env python3
import sys
import traceback
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
import urllib.parse

# ============================================================
# 1) CONEXÕES
# ============================================================

def mysql_engine():
    """Cria engine para MySQL (diogene)"""
    url = URL.create(
        "mysql+mysqlconnector",
        username="f12",
        password="xYA&ZMT@n7FfctA",
        host="35.198.55.82",
        port=3306,
        database="diogene",
    )
    return create_engine(url)


def sqlserver_engine():
    """Cria engine para SQL Server (F12_SIGAP)"""
    params = urllib.parse.quote_plus(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=192.168.130.9;"
        "DATABASE=F12_SIGAP;"
        "UID=app.sigap;"
        "PWD=F1~mH2bU5-E>;"
        "TrustServerCertificate=yes;"
        "APP=Importar_Impedidos"
    )
    conn_str = f"mssql+pyodbc:///?odbc_connect={params}"
    return create_engine(conn_str)


# ============================================================
# 2) BUSCAR max(player_check_date) DO SQL SERVER
# ============================================================

def get_last_check_date(engine_sql):
    sql = text("SELECT MAX(player_check_date) AS dt FROM IMPEDIDOS_BF")
    with engine_sql.connect() as conn:
        result = conn.execute(sql).fetchone()
        return result.dt if result and result.dt else datetime(1970, 1, 1)


# ============================================================
# 3) BUSCAR NOVOS REGISTROS NO MYSQL
# ============================================================

def fetch_new_records(engine_mysql, last_dt):
    sql = text("""
            WITH cte AS (
                SELECT
                    user_id,
                    name,
                    value,
                    CASE
                        WHEN name = 'br_gov_aid_check_date'
                        THEN DATE_SUB(FROM_UNIXTIME(value), INTERVAL 3 HOUR)
                    END AS check_date_brt
                FROM `111_player_auto_exclusion`
            )
            SELECT 
                a.user_id,
                a.value AS br_gov_aid,
                b.value AS aid_timestamp,
                b.check_date_brt AS aid_check_date_brt,
                c.value AS br_gov_aid_check_reason,
                info.email,
                info.first_name AS nome
            FROM cte a
            JOIN cte b 
                ON a.user_id = b.user_id
            AND b.name = 'br_gov_aid_check_date'
            LEFT JOIN cte c
                ON a.user_id = c.user_id
            AND c.name = 'br_gov_aid_check_reason'
            JOIN `111_player_info` info
                ON info.user_id = a.user_id
            WHERE 
                a.name = 'br_gov_aid'
                AND a.value = 1
                AND b.check_date_brt > :last_dt
            ORDER BY 
                b.check_date_brt ASC;
    """)

    with engine_mysql.connect() as conn:
        result = conn.execute(sql, {"last_dt": last_dt}).mappings().all()
        return [dict(r) for r in result]


# ============================================================
# 4) INSERIR NO SQL SERVER (SEM DUPLICAR user_id)
# ============================================================

def insert_records(engine_sql, records):
    sql = text("""
        IF NOT EXISTS (SELECT 1 FROM IMPEDIDOS_BF WHERE user_id = :user_id)
        INSERT INTO IMPEDIDOS_BF (
            user_id,
            player_name,
            player_email,
            player_check_date,
            player_sent_email,
            player_sent_email_date,
            player_date_blocked,
            player_blocked,
            player_reason
        )
        VALUES (
            :user_id,
            :player_name,
            :player_email,
            :player_check_date,
            0,        -- player_sent_email
            NULL,     -- player_sent_email_date
            DATEADD(HOUR, 72, :player_check_date),     -- player_date_blocked
            0,         -- player_blocked inicia sempre 0
            :player_reason
        );
    """)

    inserted = 0
    with engine_sql.begin() as conn:
        for r in records:
            params = {
                "user_id": r["user_id"],
                "player_name": r["nome"],
                "player_email": r["email"],
                "player_check_date": r["aid_check_date_brt"],
                "player_reason":r["br_gov_aid_check_reason"] if r["br_gov_aid_check_reason"] else "Não informado",
            }
            conn.execute(sql, params)
            inserted += 1

    return inserted


# ============================================================
# 5) MAIN EXECUTION (para CRONTAB)
# ============================================================

def main():
    try:
        eng_mysql = mysql_engine()
        eng_sql = sqlserver_engine()

        print(f"[INFO] {datetime.now()} - Iniciando importação...")

        last_dt = get_last_check_date(eng_sql)
        print(f"[INFO] Última data importada: {last_dt}")

        novos = fetch_new_records(eng_mysql, last_dt)
        print(f"[INFO] Registros novos encontrados: {len(novos)}")

        if novos:
            inserted = insert_records(eng_sql, novos)
            print(f"[INFO] Registros inseridos na tabela IMPEDIDOS_BF: {inserted}")
        else:
            print("[INFO] Nenhum novo registro para inserir.")

        print("[INFO] Finalizado com sucesso.")

    except Exception as e:
        print(f"[ERRO] {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
