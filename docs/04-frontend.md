# Frontend Web

O frontend é servido pelo próprio FastAPI — não há servidor separado.

## Rotas

| URL | Arquivo | Acesso |
|---|---|---|
| `/` | `web/login.html` | Público |
| `/consulta` | `web/consulta.html` | Usuário autenticado |
| `/painel-admin` | `web/admin.html` | Somente admin |

O token JWT é armazenado em `sessionStorage` — expira automaticamente ao fechar o browser ou quando o tempo de validade é atingido.

---

## Tela de Login (`/`)

- Campos: **Usuário** e **Senha**
- Se já houver token válido no `sessionStorage`, redireciona automaticamente
- Após login bem-sucedido:
  - Usuário comum → `/consulta`
  - Admin → `/painel-admin`

---

## Tela de Consulta (`/consulta`)

### Consultar um CPF

1. Digite o CPF no campo (máscara automática `000.000.000-00`)
2. Clique em **Consultar**
3. O resultado aparece com:
   - **Status** — badge colorido (`IMPEDIDO` em vermelho, `REGULAR` em verde)
   - **Motivos** — badges `Programa Social` e/ou `Autoexclusão`
   - **Autoexcluído desde** — destaque amarelo com a data, quando aplicável
   - **ID da transação** — para rastreamento

### Histórico

A tabela abaixo do formulário exibe as últimas 20 consultas do usuário com CPF, status, motivos, data de autoexclusão e horário.

---

## Painel Administrativo (`/painel-admin`)

Acessível apenas por usuários com perfil **Admin**.

### Aba Usuários

| Ação | Como fazer |
|---|---|
| Criar usuário | Botão **Novo Usuário** → preencher modal |
| Desativar | Botão **Desativar** na linha do usuário |
| Reativar | Botão **Ativar** na linha do usuário |
| Alterar senha | Ícone de chave 🔑 → preencher modal |

**Campos do modal Novo Usuário:**
- Usuário, E-mail, Senha (mín. 6 caracteres)
- Req/minuto — rate limit individual
- Checkbox **Administrador**

> O admin logado não pode alterar o próprio usuário pela tabela.

### Aba Estatísticas

Exibe totais em tempo real:
- Total de usuários cadastrados / ativos
- Total de consultas realizadas
- Consultas nas últimas 24 horas
