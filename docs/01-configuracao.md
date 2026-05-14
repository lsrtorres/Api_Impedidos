# Configuração do Ambiente

## Pré-requisitos

| Componente | Versão mínima |
|---|---|
| Python | 3.11 |
| ODBC Driver for SQL Server | 18 |
| Certificado e-CNPJ (PFX) | — |
| SQL Server | 2019 ou Azure SQL |

## 1. Ambiente virtual

```bash
python3 -m venv impedidos
source impedidos/bin/activate          # Linux/macOS
impedidos\Scripts\activate             # Windows
```

## 2. Dependências

```bash
pip install fastapi "uvicorn[standard]" sqlalchemy pyodbc pyjwt \
            cryptography requests "pydantic[email]" python-dotenv
```

## 3. Variáveis de ambiente

Copie o template e preencha com os valores reais:

```bash
cp .env.example .env
```

| Variável | Descrição | Exemplo |
|---|---|---|
| `SECRET_KEY` | Chave de assinatura JWT — gere com `python -c "import secrets; print(secrets.token_hex(32))"` | `a1b2c3...` |
| `PFX_PATH` | Caminho absoluto do certificado e-CNPJ `.p12` | `/home/azureuser/projetos/e-CNPJ_F12.p12` |
| `SENHA_PFX` | Senha do arquivo PFX | — |
| `TOKEN_FILE` | Onde o cache do token SERPRO é salvo | `/home/azureuser/.../certificates/token_gov.json` |
| `DB_SERVER` | Endereço do SQL Server | `187.87.134.107` |
| `DB_NAME` | Nome do banco | `Api_Impedidos` |
| `DB_USER` | Usuário do banco | `leandro.torres` |
| `DB_PASS` | Senha do banco | — |

> **Nunca commite o arquivo `.env`** — ele está no `.gitignore`.

## 4. Criar o primeiro usuário admin

Após as tabelas serem criadas (primeiro `uvicorn main:app`), rode:

```bash
python create_admin.py
```

O script cria um usuário `admin` diretamente no banco. Ajuste username, e-mail e senha no arquivo antes de executar.

## 5. Certificado PFX

O arquivo `.p12` (e-CNPJ da empresa) é necessário para autenticar no SERPRO.  
Coloque-o em `certificates/` e aponte o `PFX_PATH` no `.env`.  
O token obtido é salvo em `TOKEN_FILE` e reaproveitado em restarts (validade de ~168 horas).
