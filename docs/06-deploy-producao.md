# Deploy em Produção (Rocky Linux 9)

## Estrutura no servidor

```
/home/projects/impedidos/Api_Impedidos/
├── main.py
├── .env                        ← não versionado
├── certificates/
│   ├── e-CNPJ_F12.p12
│   └── token_gov.json          ← gerado automaticamente
├── impedidos/                  ← virtualenv
├── web/
├── docs/
└── migrations/
```

## 1. Pré-requisitos do sistema

```bash
sudo dnf update -y
sudo dnf install -y git curl nano wget unzip python3.11 python3.11-pip \
                    python3.11-devel openssl-devel libffi-devel
```

## 2. ODBC Driver 18 para SQL Server

```bash
curl -sSL https://packages.microsoft.com/config/rhel/9/prod.repo \
     | sudo tee /etc/yum.repos.d/mssql-release.repo

sudo ACCEPT_EULA=Y dnf install -y msodbcsql18
sudo dnf install -y unixODBC-devel

# Confirmar
odbcinst -q -d -n "ODBC Driver 18 for SQL Server"
```

## 3. Clonar e configurar

```bash
mkdir -p /home/projects/impedidos
cd /home/projects/impedidos

git clone <URL_DO_REPO> Api_Impedidos
cd Api_Impedidos

python3.11 -m venv impedidos
source impedidos/bin/activate

pip install --upgrade pip
pip install fastapi "uvicorn[standard]" sqlalchemy pyodbc pyjwt \
            cryptography requests "pydantic[email]" python-dotenv
```

## 4. Copiar o certificado PFX

Execute no seu Mac (não no servidor):

```bash
scp /caminho/local/e-CNPJ_F12.p12 \
    user@<IP>:/home/projects/impedidos/Api_Impedidos/certificates/
```

## 5. Configurar o .env

```bash
cp .env.example .env
nano .env   # preencher todos os valores
```

Gere o SECRET_KEY:

```bash
python3.11 -c "import secrets; print(secrets.token_hex(32))"
```

## 6. Rodar as migrations

Execute uma única vez em cada migration nova:

```bash
source impedidos/bin/activate

python3.11 - <<'EOF'
from sqlalchemy import create_engine, text
import os
from dotenv import load_dotenv
load_dotenv()

conn_str = (
    f"mssql+pyodbc://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}"
    f"@{os.getenv('DB_SERVER')}/{os.getenv('DB_NAME')}"
    f"?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
)
engine = create_engine(conn_str)
with engine.connect() as conn:
    r = conn.execute(text(
        "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_NAME='transacoes' AND COLUMN_NAME='motivos'"
    ))
    if r.scalar() == 0:
        conn.execute(text("ALTER TABLE transacoes ADD motivos NVARCHAR(MAX) NULL"))
        conn.execute(text("ALTER TABLE transacoes ADD data_autoexclusao NVARCHAR(50) NULL"))
        conn.commit()
        print("Migrations aplicadas.")
    else:
        print("Colunas ja existem, nada a fazer.")
EOF
```

## 7. Criar o usuário admin inicial

```bash
source impedidos/bin/activate
python3.11 create_admin.py
```

## 8. Testar antes do systemd

```bash
source impedidos/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000

# Em outro terminal
curl http://localhost:8000/health
# Esperado: {"status":"ok"}
```

`Ctrl+C` para parar após confirmar.

## 9. Serviço systemd

```bash
sudo nano /etc/systemd/system/api-impedidos.service
```

```ini
[Unit]
Description=API Impedidos SIGAP
After=network.target

[Service]
User=azureuser
WorkingDirectory=/home/projects/impedidos/Api_Impedidos
EnvironmentFile=/home/projects/impedidos/Api_Impedidos/.env
ExecStart=/home/projects/impedidos/Api_Impedidos/impedidos/bin/uvicorn \
          main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable api-impedidos
sudo systemctl start  api-impedidos
sudo systemctl status api-impedidos
```

## 10. SELinux (Rocky Linux 9)

```bash
# Permitir Nginx conectar a portas locais
sudo setsebool -P httpd_can_network_connect 1

# Se ainda houver negações, ver log e gerar política
sudo ausearch -m AVC -ts recent | tail -30
```

## 11. Nginx

```bash
sudo dnf install -y nginx
sudo systemctl enable nginx
sudo nano /etc/nginx/conf.d/api-impedidos.conf
```

```nginx
server {
    listen 80;
    server_name stg.opaservices.com.br;

    proxy_read_timeout 120s;
    proxy_connect_timeout 10s;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

```bash
sudo nginx -t
sudo systemctl restart nginx
```

## 12. Firewall (firewalld)

```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

> A porta 8000 não precisa ser aberta externamente — o Nginx faz o proxy internamente.

## 13. Comandos de operação

```bash
# Logs em tempo real
sudo journalctl -u api-impedidos -f

# Verificar saúde
curl http://localhost:8000/health
```

## 14. Atualizar código (workflow de deploy)

```bash
cd /home/projects/impedidos/Api_Impedidos
git pull
source impedidos/bin/activate
# pip install ... se houver novas dependências
sudo systemctl restart api-impedidos
```
