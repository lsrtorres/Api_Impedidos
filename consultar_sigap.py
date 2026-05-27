#!/usr/bin/env python3
"""
Consulta um CPF diretamente no SIGAP/SERPRO, sem passar pela API.
Uso: python consultar_sigap.py 00000000000
"""
import json, os, sys, tempfile
from datetime import datetime, timedelta
import requests
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

load_dotenv()

PFX_PATH   = os.getenv("PFX_PATH", "certificates/e-CNPJ_F12.p12")
SENHA_PFX  = os.getenv("SENHA_PFX", "")
TOKEN_FILE = os.getenv("TOKEN_FILE", "certificates/token_gov.json")

AUTH_URL   = "https://auth-sigap-rec.ni.estaleiro.serpro.gov.br/recepcao-autenticacao/token"
SIGAP_URL  = "https://sigap-impedidos.fazenda.gov.br/impedimento/v2/condicao/{cpf}"


def _obter_token():
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE) as f:
                cache = json.load(f)
            expira_em = datetime.fromisoformat(cache["expira_em"])
            if datetime.now() < expira_em - timedelta(seconds=300):
                return cache["token"]
        except Exception:
            pass

    with open(PFX_PATH, "rb") as f:
        pfx_data = f.read()
    private_key, cert, _ = pkcs12.load_key_and_certificates(
        pfx_data, SENHA_PFX.encode(), backend=default_backend()
    )
    tmp_key  = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    tmp_cert = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    tmp_key.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    tmp_cert.write(cert.public_bytes(Encoding.PEM))
    tmp_key.close(); tmp_cert.close()

    try:
        resp = requests.post(AUTH_URL, cert=(tmp_cert.name, tmp_key.name), verify=True, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        token = data.get("token") or data.get("access_token")
        expires_in = int(data.get("expires_in", 604800))
        expira_em = datetime.now() + timedelta(seconds=expires_in)
        os.makedirs(os.path.dirname(os.path.abspath(TOKEN_FILE)), exist_ok=True)
        with open(TOKEN_FILE, "w") as f:
            json.dump({"token": token, "expira_em": expira_em.isoformat()}, f)
        return token
    finally:
        os.unlink(tmp_cert.name); os.unlink(tmp_key.name)


def consultar(cpf: str):
    cpf = cpf.replace(".", "").replace("-", "").strip()
    if len(cpf) != 11 or not cpf.isdigit():
        print("CPF inválido.")
        sys.exit(1)

    token = _obter_token()
    resp = requests.get(SIGAP_URL.format(cpf=cpf),
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=15)

    if resp.status_code == 200:
        d = resp.json()
        status            = d.get("resultado", "INDEFINIDO")
        motivos           = d.get("motivos", [])
        data_autoexclusao = d.get("dataSolicitacaoAutoexclusao")

        print(f"CPF:               {cpf}")
        print(f"Status:            {status}")
        print(f"Motivos:           {', '.join(motivos) if motivos else '—'}")
        print(f"Data autoexclusão: {data_autoexclusao or '—'}")
    elif resp.status_code == 404:
        print(f"CPF {cpf} — não encontrado na base.")
    else:
        print(f"Erro {resp.status_code}: {resp.text}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python consultar_sigap.py <CPF>")
        sys.exit(1)
    consultar(sys.argv[1])
