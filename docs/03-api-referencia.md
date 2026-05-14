# Referência da API

**Base URL:** `https://stg.opaservices.com.br`  
**Autenticação:** `Authorization: Bearer <token>`  
**Docs interativos:** `/docs` (Swagger UI)

---

## Autenticação

### `POST /auth/login`

Retorna um token JWT para uso nos demais endpoints.

**Request:**
```json
{
  "username": "joao",
  "password": "senha123"
}
```

**Response `200`:**
```json
{
  "access_token": "eyJhbGci...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

| Perfil | Expiração do token |
|---|---|
| Atendimento | 60 minutos |
| Admin | 480 minutos (8 horas) |

---

## Consulta de CPF

### `GET /consultar/{cpf}`

Consulta um CPF no SERPRO/SIGAP.

**Parâmetros:**  
`cpf` — 11 dígitos (aceita formatado `000.000.000-00` ou puro)

**Response `200`:**
```json
{
  "transaction_id": "e3b0c442-98fc-4def-...",
  "cpf": "12345678901",
  "status": "IMPEDIDO",
  "motivos": ["PROGRAMA_SOCIAL", "AUTOEXCLUSAO_CENTRALIZADA"],
  "data_autoexclusao": "2025-05-23T12:48:45.999",
  "timestamp": "2026-04-14T15:00:00",
  "usuario": "joao"
}
```

**Valores de `status`:**

| Valor | Significado |
|---|---|
| `REGULAR` | Não impedido |
| `IMPEDIDO` | Impedido (ver `motivos`) |
| `não encontrado` | CPF não consta na base SERPRO |

**Valores de `motivos`:**

| Valor | Descrição |
|---|---|
| `PROGRAMA_SOCIAL` | Beneficiário de programa social do governo |
| `AUTOEXCLUSAO_CENTRALIZADA` | Autoexcluído pelo sistema centralizado |

> `data_autoexclusao` só é preenchido quando `AUTOEXCLUSAO_CENTRALIZADA` está nos motivos.

---

### `POST /consultar/lote`

Consulta até **200 CPFs em uma única chamada**. Cada CPF consome 1 token do rate limit.

**Request:**
```json
{
  "cpfs": ["12345678901", "98765432100", "05987654321"]
}
```

**Response `200`:**
```json
{
  "total": 3,
  "processados": 2,
  "erros": 1,
  "usuario": "wa_user_api",
  "timestamp": "2026-04-14T15:00:00",
  "resultados": [
    {
      "cpf": "12345678901",
      "status": "IMPEDIDO",
      "motivos": ["PROGRAMA_SOCIAL"],
      "data_autoexclusao": null,
      "transaction_id": "uuid...",
      "erro": null
    },
    {
      "cpf": "98765432100",
      "status": "REGULAR",
      "motivos": [],
      "data_autoexclusao": null,
      "transaction_id": "uuid...",
      "erro": null
    },
    {
      "cpf": "00000000000",
      "status": null,
      "motivos": [],
      "data_autoexclusao": null,
      "transaction_id": null,
      "erro": "CPF inválido"
    }
  ]
}
```

> CPFs com erro aparecem no array com `erro` preenchido — a chamada inteira não falha por causa de um CPF inválido.

---

## Histórico

### `GET /historico?limite=10`

Retorna as últimas consultas do usuário autenticado.

**Response `200`:**
```json
{
  "usuario": "joao",
  "total_transacoes": 42,
  "transacoes": [
    {
      "transaction_id": "uuid...",
      "cpf": "12345678901",
      "status": "IMPEDIDO",
      "motivos": ["PROGRAMA_SOCIAL"],
      "data_autoexclusao": null,
      "timestamp": "2026-04-14T15:00:00",
      "tempo_resposta_ms": 124.5
    }
  ]
}
```

### `GET /transacao/{transaction_id}`

Detalhe de uma transação específica. Usuário só acessa as próprias; admin acessa todas.

---

## Administração

> Todos os endpoints `/admin/*` exigem token de um usuário com `is_admin = true`.

### `GET /admin/usuarios`

Lista todos os usuários cadastrados.

**Response `200`:** array de objetos com `id`, `username`, `email`, `is_admin`, `ativo`, `max_requests_per_minute`, `criado_em`, `ultimo_acesso`.

---

### `POST /admin/registrar`

Cria um novo usuário.

**Request:**
```json
{
  "username": "atendente01",
  "email": "atendente01@empresa.com",
  "password": "senha123",
  "is_admin": false,
  "max_requests_per_minute": 60
}
```

---

### `PATCH /admin/usuarios/{id}`

Atualiza status, limite ou senha de um usuário. Campos são opcionais.

**Request (desativar):**
```json
{ "ativo": false }
```

**Request (alterar limite):**
```json
{ "max_requests_per_minute": 200 }
```

**Request (alterar senha):**
```json
{ "nova_senha": "novaSenha456" }
```

> Não é possível alterar o próprio usuário por este endpoint.

---

### `GET /admin/estatisticas`

Totais gerais da API.

**Response `200`:**
```json
{
  "total_usuarios": 10,
  "usuarios_ativos": 8,
  "total_transacoes": 48320,
  "transacoes_ultimas_24h": 1204,
  "timestamp": "2026-04-14T15:00:00"
}
```

---

## Health Check

### `GET /health`

```json
{ "status": "ok", "database": "connected", "timestamp": "..." }
```

---

## Erros comuns

| Código | Causa |
|---|---|
| `400` | CPF inválido ou dado já existente |
| `401` | Token ausente, inválido ou expirado |
| `403` | Usuário inativo ou sem permissão de admin |
| `404` | Recurso não encontrado |
| `422` | Corpo da requisição inválido (Pydantic) |
| `429` | Rate limit atingido — aguardar reset do minuto |
| `504` | Timeout ao consultar o SERPRO |
