# Deploy em Produção (Azure VM)

## Estrutura no servidor

```
/home/azureuser/projetos/impedidos/Api_Impedidos/
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

## 1. Clonar e configurar

```bash
cd /home/azureuser/projetos/impedidos
git clone <repo> Api_Impedidos
cd Api_Impedidos

python3 -m venv impedidos
source impedidos/bin/activate
pip install fastapi "uvicorn[standard]" sqlalchemy pyodbc pyjwt \
            cryptography requests "pydantic[email]" python-dotenv

cp .env.example .env
nano .env   # preencher todos os valores
```

## 2. Rodar as migrations

Execute uma única vez em cada migration nova:

```bash
sqlcmd -S $DB_SERVER -d Api_Impedidos -U $DB_USER \
       -i migrations/001_add_motivos_transacoes.sql

sqlcmd -S $DB_SERVER -d Api_Impedidos -U $DB_USER \
       -i migrations/002_add_data_autoexclusao_transacoes.sql
```

## 3. Criar o usuário admin inicial

```bash
source impedidos/bin/activate
python create_admin.py
```

## 4. Serviço systemd

Crie o arquivo de serviço:

```bash
sudo nano /etc/systemd/system/api-impedidos.service
```

```ini
[Unit]
Description=API Impedidos SIGAP
After=network.target

[Service]
User=azureuser
WorkingDirectory=/home/azureuser/projetos/impedidos/Api_Impedidos
EnvironmentFile=/home/azureuser/projetos/impedidos/Api_Impedidos/.env
ExecStart=/home/azureuser/projetos/impedidos/Api_Impedidos/impedidos/bin/uvicorn \
          main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Ative e inicie:

```bash
sudo systemctl daemon-reload
sudo systemctl enable api-impedidos
sudo systemctl start  api-impedidos
sudo systemctl status api-impedidos
```

## 5. Comandos de operação

```bash
# Ver logs em tempo real
sudo journalctl -u api-impedidos -f

# Reiniciar após deploy
git pull && sudo systemctl restart api-impedidos

# Verificar saúde
curl http://localhost:8000/health
```

## 6. Atualizar código

```bash
cd /home/azureuser/projetos/impedidos/Api_Impedidos
git pull
source impedidos/bin/activate
pip install -r requirements.txt   # se houver novas dependências
sudo systemctl restart api-impedidos
```

## Variáveis de ambiente no systemd

O `EnvironmentFile=` no serviço carrega o `.env` automaticamente.  
Alternativamente, as variáveis podem ser definidas diretamente na seção `[Service]`:

```ini
[Service]
Environment="SECRET_KEY=..."
Environment="PFX_PATH=..."
```

## Portas e firewall

A API roda na porta `8000`. Configure o NSG (Network Security Group) da Azure para expor apenas as portas necessárias. Se usar Nginx como proxy reverso:

```nginx
server {
    listen 443 ssl;
    server_name stg.opaservices.com.br;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```
