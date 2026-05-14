# Varredura em Lote

Existem duas estratégias para consultar grandes volumes de CPFs.

---

## Estratégia 1 — SERPRO direto (recomendado para migrações)

Chama o SERPRO diretamente com o certificado PFX, sem passar pela API.  
**Melhor para:** varreduras únicas de migração, análises internas.

O token é compartilhado com a API via `TOKEN_FILE` — se a API já obteve o token, o script o reutiliza sem nova autenticação.

**Throughput observado:** ~115.000 CPFs em ~6 minutos com 30 workers.

Ver código de referência em `Teste_API_Impedidos.ipynb`.

---

## Estratégia 2 — Endpoint `/consultar/lote` (recomendado para integrações)

Usa a API como intermediária. Ideal quando o parceiro não tem acesso ao PFX.  
**Melhor para:** integração com sistemas externos, parceiros com acesso controlado.

**Throughput esperado:** ~8.000–15.000 CPFs/min (com `max_requests_per_minute` alto).

### Rate limit

Cada CPF do lote consome **1 token** do limite do usuário.  
Um usuário com `max_requests_per_minute = 10.000` pode enviar 50 lotes de 200 CPFs por minuto.

---

## Código de exemplo — `/consultar/lote`

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

API_URL   = "https://stg.opaservices.com.br"
LOTE_SIZE = 200   # CPFs por chamada
WORKERS   = 10    # chamadas paralelas → 2.000 CPFs em voo simultâneo

def login(usuario: str, senha: str) -> str:
    r = requests.post(f"{API_URL}/auth/login",
                      json={"username": usuario, "password": senha}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]

def consultar_lote(cpfs: list[str], token: str) -> list[dict]:
    r = requests.post(
        f"{API_URL}/consultar/lote",
        headers={"Authorization": f"Bearer {token}"},
        json={"cpfs": cpfs},
        timeout=60,
    )
    if r.status_code == 429:
        raise RuntimeError(f"Rate limit atingido: {r.json()['detail']}")
    r.raise_for_status()
    return r.json()["resultados"]

def varrer_base(todos_cpfs: list[str], token: str) -> list[dict]:
    batches = [todos_cpfs[i:i+LOTE_SIZE]
               for i in range(0, len(todos_cpfs), LOTE_SIZE)]

    impedidos = []
    erros = 0

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(consultar_lote, b, token): b for b in batches}
        for f in as_completed(futures):
            try:
                for r in f.result():
                    if r.get("erro"):
                        erros += 1
                    elif r["status"] == "IMPEDIDO":
                        impedidos.append(r)
            except Exception as e:
                print(f"Erro em lote: {e}")

    print(f"Impedidos: {len(impedidos)} | Erros: {erros}")
    return impedidos

if __name__ == "__main__":
    token = login("wa_user_api", "senha")
    cpfs  = ["12345678901", "98765432100"]  # substituir pela lista real
    resultado = varrer_base(cpfs, token)
```

---

## Comparativo de performance

| Estratégia | Workers | 115k CPFs | Requer PFX |
|---|---|---|---|
| SERPRO direto | 30 | ~6 min | Sim |
| `/consultar/lote` | 10 × 200 | ~15 min* | Não |
| `/consultar/{cpf}` unitário | 20 | ~8 horas** | Não |

\* Estimativa com `max_requests_per_minute = 100.000`  
\*\* Com rate limit de ~222/min observado em produção

---

## Usuário recomendado para varredura

Configure um usuário dedicado com limite alto:

```
POST /admin/registrar
{
  "username": "bulk_scanner",
  "email": "bulk@empresa.com",
  "password": "...",
  "max_requests_per_minute": 50000
}
```
