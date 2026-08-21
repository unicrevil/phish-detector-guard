#!/usr/bin/env python
import tldextract, whois, requests, re, argparse, json, hashlib, time, sys
from termcolor import colored, cprint
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from tqdm import tqdm

VT_API_KEY = "570fc9efd500e361c4f7c766c5a523f9003ca738d7f47f2d7134facaf6b5b840"

BANNER = r"""
 ____ _ _ _ _ _____ _ _ _____ ____ _____ ____ ____ 
| _ \| |__ | |__ | |__ |__ | ___| | |_ _| | _ \_ _/ ___/ ___|
| |_) | '_ \| '_ \| '_ \| '_ \| |_ |_| | | || | \___ \___ \ 
| __/| |_) |_) |_) | _| | _ | | |_| || | ___) |__) |
|_| |_| |_|_.__/|_.__/|_.__/|_| |_| |_| |_| |____/ |_| |____/____/ 
            PHISH-DETECTOR-GUARD V3.3 CYBERPUNK
      by unicrevil cybersecurity Architect Microsoft
"""

def barra_loading(texto, tempo=1.2):
    for i in tqdm(range(100), desc=colored(texto, "cyan"), ncols=45):
        time.sleep(tempo/100)

def checar_url(url, verbose=False):
    cprint(BANNER, "magenta")
    barra_loading("Iniciando Varredura Quantica")
    
    pontuacao = 0; alertas = []; intel = {}
    ext = tldextract.extract(url); dominio = f"{ext.domain}.{ext.suffix}"
    
    barra_loading("Consultando VirusTotal + OSINT")
    risco_vt, a = checar_virustotal(url); pontuacao += risco_vt; alertas.extend(a)
    
    barra_loading("Analisando DNA do Dominio")
    risco_param, a = checar_parametros(url); pontuacao += risco_param; alertas.extend(a)
    risco_random, a = checar_dominio_aleatorio(ext.domain); pontuacao += risco_random; alertas.extend(a)
    
    barra_loading("Fazendo Recon do IP + GeoIP")
    try:
        ip = requests.get(f"https://dns.google/resolve?name={dominio}", timeout=5).json()['Answer'][0]['data']
        intel['ip'] = ip
        geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        intel['pais'] = geo['country']
        if geo['country'] in ['Russia', 'China', 'Nigeria']: pontuacao += 2; alertas.append(f"IP Hospedado em: {geo['country']}")
    except: ip = "N/A"
    
    score = min(pontuacao * 5, 100)
    resultado = "ALTO RISCO" if score >= 50 else "RISCO MEDIO" if score >= 20 else "BAIXO RISCO"
    cor = "red" if score >= 50 else "yellow" if score >= 20 else "green"

    print("\n" + "="*48)
    cprint(f" ALVO: {url}", "white", attrs=["bold"])
    cprint(f" DOMINIO: {dominio} | IP: {ip} | PAIS: {intel.get('pais','N/A')}", "white")
    cprint(f" SCORE: {score}/100", cor, attrs=["bold"])
    cprint(f" VEREDITO: {resultado}", cor, attrs=["bold"])
    print("="*48)
    
    if score >= 50: 
        cprint("\n[!] ALERTA CRITICO: AMEACA CONFIRMADA [!]\n", "red", attrs=["bold"])
        for a in alertas: cprint(f" > {a}", "red")
    else:
        for a in alertas: cprint(f" > {a}", "yellow")

def checar_virustotal(url):
    if VT_API_KEY == "SUA_API_KEY_AQUI": return 0, ["VirusTotal: Adicione sua API Key"]
    url_id = hashlib.sha256(url.encode()).hexdigest()
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            maliciosos = stats['malicious'] + stats['suspicious']
            if maliciosos > 0: return 10, [f"VirusTotal: {maliciosos}/{sum(stats.values())} detectaram"]
            return 0, [f"VirusTotal: Limpo 0/{sum(stats.values())}"]
        elif r.status_code == 404:
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
            return 0, ["VirusTotal: Enviado pra analise. Rode dnv em 1min"]
    except: return 0, ["VirusTotal: Erro"]
    time.sleep(15)
    return 0, []

def checar_parametros(url):
    parsed = urlparse(url); params = parse_qs(parsed.query); alertas = []; risco = 0
    for key in params.keys():
        if any(p in key.lower() for p in ['pid', 'fbclid', 'utm_', 'frompage']):
            risco += 3; alertas.append(f"Parametro de tracking de golpe: '{key}'")
    return risco, alertas

def checar_dominio_aleatorio(dominio):
    if len(dominio) <= 10 and re.search(r'\d', dominio) and re.search(r'[a-z]', dominio):
        return 4, ["Dominio aleatorio. Padrao de dominio descartavel"]
    return 0, []

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url"); parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if args.url: checar_url(args.url, verbose=args.verbose)
    else: url = input(colored("Cole o link alvo: ", "cyan")); checar_url(url, verbose=True)
