# Deploy em Produção — Rocky Linux 9

## Estrutura de diretórios

```
/home/projects/impedidos/Api_Impedidos/
├── main.py
├── .env                        ← não versionado
├── certificates/
│   ├── e-CNPJ_F12.p12          ← copiado manualmente
│   └── token_gov.json          ← gerado automaticamente na primeira consulta
├── impedidos/                  ← virtualenv Python
├── web/                        ← frontend servido pelo FastAPI
├── docs/
└── migrations/
```

---

## 1. Atualizar o sistema e instalar dependências base

```bash
sudo dnf update -y
sudo dnf install -y git curl nano wget unzip \
                    python3.12 python3.12-pip python3.12-devel \
                    openssl-devel libffi-devel
```

---

## 2. ODBC Driver 18 para SQL Server

```bash
# Adicionar repositório Microsoft
curl -sSL https://packages.microsoft.com/config/rhel/9/prod.repo \
     | sudo tee /etc/yum.repos.d/mssql-release.repo

# Instalar driver e ferramentas ODBC
sudo ACCEPT_EULA=Y dnf install -y msodbcsql18
sudo dnf install -y unixODBC-devel

# Verificar instalação
odbcinst -q -d -n "ODBC Driver 18 for SQL Server"
```

---

## 3. Clonar o repositório e criar o virtualenv

```bash
mkdir -p /home/projects/impedidos
cd /home/projects/impedidos

git clone https://github.com/lsrtorres/Api_Impedidos.git Api_Impedidos
cd Api_Impedidos

python3.11 -m venv impedidos
source impedidos/bin/activate

pip install --upgrade pip
pip install fastapi "uvicorn[standard]" sqlalchemy pyodbc pyjwt \
            cryptography requests "pydantic[email]" python-dotenv
```

---

## 4. Copiar o certificado PFX

Execute no seu Mac (não no servidor):

```bash
scp /Users/leandrotorres/Documents/Projetos-Bet/Api_Impedidos/certificates/e-CNPJ_F12.p12 \
    leandro.torres@5.78.220.21:/home/projects/impedidos/Api_Impedidos/certificates/
```

---

## 5. Configurar o `.env`

```bash
cd /home/projects/impedidos/Api_Impedidos
cp .env.example .env
nano .env
```

Gere um `SECRET_KEY` seguro:

```bash
python3.11 -c "import secrets; print(secrets.token_hex(32))"
```

Preencha todos os campos:

```env
SECRET_KEY=<valor_gerado_acima>
PFX_PATH=/home/projects/impedidos/Api_Impedidos/certificates/e-CNPJ_F12.p12
SENHA_PFX=<senha_do_pfx>
TOKEN_FILE=/home/projects/impedidos/Api_Impedidos/certificates/token_gov.json
DB_SERVER=<ip_do_banco>
DB_NAME=Api_Impedidos
DB_USER=<usuario_db>
DB_PASS=<senha_db>
SENDGRID_API_KEY_F12=<chave_sendgrid_f12>
SENDGRID_API_KEY_LUVA=<chave_sendgrid_luva>
```

---

## 6. Rodar as migrations

Execute uma única vez — o script verifica se as colunas já existem antes de aplicar:

```bash
source impedidos/bin/activate

python3.11 - <<'EOF'
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

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
        print("Migrations aplicadas com sucesso.")
    else:
        print("Colunas ja existem, nada a fazer.")
EOF
```

---

## 7. Criar o usuário admin inicial

```bash
source impedidos/bin/activate
python3.11 create_admin.py
```

---

## 8. Smoke test antes do systemd

```bash
source impedidos/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000
```

Em outro terminal, verifique API e frontend:

```bash
# Health check da API
curl http://localhost:8000/health
# Esperado: {"status":"ok"}

# Páginas do frontend (devem retornar HTTP 200)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/
curl -s -o /dev/null -w "%{http_code}" http://localhost:8100/consulta
curl -s -o /dev/null -w "%{http_code}" http://localhost:8100/painel-admin
```

Ou acesse pelo browser (se a porta 8000 estiver aberta no firewall):

```
http://<IP_DO_SERVIDOR>:8000/
```

`Ctrl+C` para parar após confirmar.

---

## 9. Serviço systemd

```bash
sudo nano /etc/systemd/system/api-impedidos.service
```

```ini
[Unit]
Description=API Impedidos SIGAP
After=network.target

[Service]
User=root
WorkingDirectory=/home/projects/impedidos/Api_Impedidos
EnvironmentFile=/home/projects/impedidos/Api_Impedidos/.env
ExecStart=/home/projects/impedidos/Api_Impedidos/impedidos/bin/uvicorn \
          main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> Ajuste `User=` para o usuário que tem leitura no diretório do projeto e no certificado PFX.

```bash
sudo systemctl daemon-reload
sudo systemctl enable  api-impedidos
sudo systemctl start   api-impedidos
sudo systemctl status  api-impedidos
```

---

## 10. SELinux

Rocky Linux 9 roda SELinux em modo **enforcing** por padrão. Sem esta configuração o Nginx não consegue fazer proxy:

```bash
sudo setsebool -P httpd_can_network_connect 1
```

Se houver erros de permissão de arquivo nos logs:

```bash
# Ver negações recentes
sudo ausearch -m AVC -ts recent | tail -30

# Gerar e aplicar política automática
sudo audit2allow -a -M api-impedidos-local
sudo semodule -i api-impedidos-local.pp
```

---

## 11. Nginx como proxy reverso

```bash
sudo dnf install -y nginx
sudo systemctl enable nginx
sudo nano /etc/nginx/conf.d/api-impedidos.conf
```

```nginx
server {
    listen 80;
    server_name stg.opaservices.com.br;   # ou IP do servidor

    proxy_read_timeout    120s;
    proxy_connect_timeout  10s;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    }
}
```

```bash
sudo nginx -t                  # validar sintaxe
sudo systemctl restart nginx
```

---

## 12. Firewall (firewalld)

```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

> A porta `8000` **não** precisa ser aberta — o tráfego externo passa pelo Nginx na 80/443.

---

## 13. Verificação final

```bash
# API via loopback
curl http://localhost:8000/health

# API via Nginx (externo)
curl http://<IP_DO_SERVIDOR>/health

# Frontend — todas devem retornar 200
curl -s -o /dev/null -w "login:       %{http_code}\n" http://<IP_DO_SERVIDOR>/
curl -s -o /dev/null -w "consulta:    %{http_code}\n" http://<IP_DO_SERVIDOR>/consulta
curl -s -o /dev/null -w "admin:       %{http_code}\n" http://<IP_DO_SERVIDOR>/painel-admin

# Logs do serviço em tempo real
sudo journalctl -u api-impedidos -f
```

Para acessar pelo browser:

| Página | URL |
|---|---|
| Login | `http://<IP_DO_SERVIDOR>/` |
| Consulta | `http://<IP_DO_SERVIDOR>/consulta` |
| Admin | `http://<IP_DO_SERVIDOR>/painel-admin` |
| Swagger | `http://<IP_DO_SERVIDOR>/docs` |

---

## 14. Workflow de atualização

```bash
cd /home/projects/impedidos/Api_Impedidos
git pull
source impedidos/bin/activate
pip install -r requirements.txt   # se houver novas dependências
sudo systemctl restart api-impedidos
sudo systemctl status  api-impedidos
```

---

## Referência rápida

| Ação | Comando |
|---|---|
| Ver logs | `sudo journalctl -u api-impedidos -f` |
| Reiniciar serviço | `sudo systemctl restart api-impedidos` |
| Status do serviço | `sudo systemctl status api-impedidos` |
| Health check | `curl http://localhost:8000/health` |
| Recarregar Nginx | `sudo systemctl reload nginx` |
| Status SELinux | `sudo getenforce` |
