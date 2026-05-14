# API de Consulta de Impedidos — SIGAP

API FastAPI para consulta ao sistema SERPRO/SIGAP de pessoas impedidas de participar de apostas de quota fixa, conforme **Instrução Normativa SPA/MF nº 22/2025**.

Integra autenticação via certificado e-CNPJ, frontend web para equipe de atendimento e endpoint de varredura em lote para integrações.

## Funcionalidades

- Consulta individual e em lote ao SERPRO (motivos como lista, `dataSolicitacaoAutoexclusao`)
- Token SERPRO persistente em disco — sobrevive a restarts
- Frontend web: login, consulta de CPF, painel admin
- Gestão de usuários: criar, ativar/desativar, alterar senha
- Rate limiting por usuário, logs de acesso e histórico de transações
- Scripts de envio de e-mail para jogadores impedidos (F12 e Luva)

## Início rápido

```bash
# 1. Ambiente virtual
python3 -m venv impedidos && source impedidos/bin/activate

# 2. Dependências
pip install fastapi "uvicorn[standard]" sqlalchemy pyodbc pyjwt \
            cryptography requests "pydantic[email]" python-dotenv

# 3. Configuração
cp .env.example .env
# editar .env com as credenciais reais

# 4. Subir a API (também serve o frontend)
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 5. Acessar
# Frontend:  http://localhost:8000/
# Swagger:   http://localhost:8000/docs
```

## Estrutura do projeto

```
├── main.py                     # API FastAPI (backend + rotas do frontend)
├── create_admin.py             # Script para criar o primeiro usuário admin
├── blocked_load.py             # Importa impedidos do MySQL para o SQL Server
├── send_email_blocked.py       # Envia e-mails para impedidos (F12)
├── send_email_blocked_luva.py  # Envia e-mails para impedidos (Luva)
├── .env.example                # Template de variáveis de ambiente
├── certificates/               # Certificado PFX e cache do token SERPRO
├── migrations/                 # Scripts ALTER TABLE
├── templates/                  # Templates HTML dos e-mails
├── web/                        # Frontend (servido pelo FastAPI)
│   ├── login.html
│   ├── consulta.html
│   └── admin.html
└── docs/                       # Documentação
```

## Documentação

| Documento | Conteúdo |
|---|---|
| [01 — Configuração](docs/01-configuracao.md) | Instalação, variáveis de ambiente, certificado PFX |
| [02 — Banco e Migrations](docs/02-banco-e-migrations.md) | Schema das tabelas, scripts de migration |
| [03 — Referência da API](docs/03-api-referencia.md) | Todos os endpoints com exemplos |
| [04 — Frontend](docs/04-frontend.md) | Guia de uso da interface web |
| [05 — Varredura em Lote](docs/05-varredura-lote.md) | Consulta de grandes volumes de CPFs |
| [06 — Deploy em Produção](docs/06-deploy-producao.md) | Azure VM, systemd, Nginx |

## Endpoints principais

| Método | Rota | Descrição |
|---|---|---|
| `POST` | `/auth/login` | Login — retorna JWT |
| `GET` | `/consultar/{cpf}` | Consulta um CPF |
| `POST` | `/consultar/lote` | Consulta até 200 CPFs |
| `GET` | `/historico` | Últimas consultas do usuário |
| `GET` | `/admin/usuarios` | Lista usuários (admin) |
| `POST` | `/admin/registrar` | Cria usuário (admin) |
| `PATCH` | `/admin/usuarios/{id}` | Ativa/desativa/senha (admin) |
| `GET` | `/health` | Health check |

## Regulamentação

Atende à **IN SPA/MF nº 22/2025**, que veda o acesso de beneficiários de programas sociais e autoexcluídos centralizados aos serviços de apostas de quota fixa.
