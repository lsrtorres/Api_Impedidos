import requests

def login(usuario: str, senha: str) -> str | None:
    """Realiza login na API e retorna o access_token JWT."""
    url = "https://stg.opaservices.com.br/auth/login"  
    headers = {"Content-Type": "application/json"}
    data = {"username": usuario, "password": senha}

    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)


        print("Status:", response.status_code)
        print("Resposta:", response.text)

        if response.status_code == 200:
            json_data = response.json()
            token = json_data.get("access_token")
            if token:
                print("✅ Login bem-sucedido.")
                return token
            else:
                print("⚠️ Resposta não contém access_token.")
                return None
        else:
            print(f"❌ Falha no login: {response.status_code} → {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"❌ Erro de conexão: {e}")
        return None
 
if __name__ == "__main__":   
    token = login("joao", "senha123")
    listacpf = ['02502825180','44841253823','01768736359','07279069410','06264748765','08023523759'
                ,'04598751320','71582410259','13792358719','11854112597','01589262182','33763420835',
                '70147653452','34495876848','06059456405','36735718852','10581507908',
                '61706483333','51464578249','24532401291']
    for cpf in listacpf:
        url = f"https://stg.opaservices.com.br/consultar/{cpf}"

        headers = {
            "Authorization": f"Bearer {token}"
        }

        response = requests.get(url, headers=headers)

        print("Status:", response.status_code)
        try:
            print("Resposta JSON:", response.json())
        except Exception:
            print("Resposta bruta:", response.text)