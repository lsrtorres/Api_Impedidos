from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import urllib
import hashlib

params = urllib.parse.quote_plus(
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=192.168.70.5;"
    "DATABASE=Api_Impedidos;"
    "UID=leandro.torres;"
    "PWD=Lsrt@2109@;"
    "TrustServerCertificate=yes;"
)
engine = create_engine(f"mssql+pyodbc:///?odbc_connect={params}")
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

# Importar modelo (após rodar a API uma vez para criar tabelas)
from main import UsuarioDB, hash_password

admin = UsuarioDB(
    username="admin",
    email="leandro.torres@f12corp.com",
    hashed_password=hash_password("admin2109"),
    is_admin=True,
    ativo=True,
    max_requests_per_minute=100
)
db.add(admin)
db.commit()
print("✅ Admin criado!")