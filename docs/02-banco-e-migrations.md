# Banco de Dados e Migrations

## Banco

**SQL Server** — banco `Api_Impedidos`

As tabelas são criadas automaticamente no startup via `Base.metadata.create_all()`.  
Colunas adicionadas após a criação inicial exigem migration manual (ver abaixo).

## Tabelas

### `usuarios`

| Coluna | Tipo | Descrição |
|---|---|---|
| `id` | INT PK | Identificador |
| `username` | VARCHAR(50) | Login único |
| `email` | VARCHAR(100) | E-mail único |
| `hashed_password` | VARCHAR(255) | SHA-256 da senha |
| `is_admin` | BIT | `1` = administrador |
| `ativo` | BIT | `1` = pode fazer login |
| `max_requests_per_minute` | INT | Limite de requisições por minuto |
| `criado_em` | DATETIME | Data de criação |
| `ultimo_acesso` | DATETIME | Último login bem-sucedido |

### `transacoes`

| Coluna | Tipo | Descrição |
|---|---|---|
| `id` | INT PK | Identificador |
| `transaction_id` | VARCHAR(36) | UUID da consulta |
| `usuario` | VARCHAR(50) | Username que consultou |
| `cpf` | VARCHAR(11) | CPF consultado (só dígitos) |
| `status` | VARCHAR(50) | `IMPEDIDO`, `REGULAR`, `não encontrado` |
| `motivos` | NVARCHAR(MAX) | JSON array ex: `["PROGRAMA_SOCIAL"]` |
| `data_autoexclusao` | NVARCHAR(50) | `dataSolicitacaoAutoexclusao` do SERPRO |
| `timestamp` | DATETIME | Momento da consulta |
| `tempo_resposta_ms` | FLOAT | Latência da chamada SERPRO |
| `ip_origem` | VARCHAR(45) | IP do solicitante |

### `logs_acesso`

| Coluna | Tipo | Descrição |
|---|---|---|
| `id` | INT PK | Identificador |
| `usuario` | VARCHAR(50) | Username |
| `endpoint` | VARCHAR(255) | Rota chamada |
| `metodo` | VARCHAR(10) | `GET`, `POST`, `PATCH` |
| `status_code` | INT | HTTP status da resposta |
| `timestamp` | DATETIME | Momento do acesso |
| `ip_origem` | VARCHAR(45) | IP do solicitante |
| `mensagem_erro` | TEXT | Detalhe do erro (quando aplicável) |

## Migrations

Execute os scripts em ordem no banco `Api_Impedidos`.

### 001 — Adicionar coluna `motivos`

> Necessário após atualização da API SERPRO que passou a retornar uma lista de motivos.

```sql
-- migrations/001_add_motivos_transacoes.sql
ALTER TABLE transacoes
ADD motivos NVARCHAR(MAX) NULL;
```

### 002 — Adicionar coluna `data_autoexclusao`

> Armazena a data desde quando o usuário está autoexcluído, conforme campo
> `dataSolicitacaoAutoexclusao` retornado pelo SERPRO.

```sql
-- migrations/002_add_data_autoexclusao_transacoes.sql
ALTER TABLE transacoes
ADD data_autoexclusao NVARCHAR(50) NULL;
```

## Executar via sqlcmd (Linux/Azure)

```bash
sqlcmd -S 187.87.134.107 -d Api_Impedidos -U leandro.torres \
       -i migrations/001_add_motivos_transacoes.sql

sqlcmd -S 187.87.134.107 -d Api_Impedidos -U leandro.torres \
       -i migrations/002_add_data_autoexclusao_transacoes.sql
```
