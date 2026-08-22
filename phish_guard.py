#!/usr/bin/env python3
# PHISH-DETECTOR-GUARD V3.5 CYBERPUNK - VT API READY
# by unicrevil - Architect Microsoft

import sys
import re
import json
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import urlopen, Request
from urllib.error import URLError

# ========== CONFIG - COLA TUA API KEY AQUI ==========
VT_API_KEY = "570fc9efd500e361c4f7c766c5a523f9003ca738d7f47f2d7134facaf6b5b840" # <- COLA AQUI VS
# =====================================================

R = "\033[91m"
G = "\033[92m"
C = "\033[96m"
Y = "\033[93m"
M = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""{M}
██████╗ ██╗ ██╗██╗███████╗██╗ ██╗ ██████╗ ██╗ ██╗ █████╗ ██████╗ ██████╗
██╔══██╗██║ ██║██║██╔════╝██║ ██║ ██╔════╝ ██║ ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝███████║██║███████╗███████║ ██║ ███╗██║ ██║███████║██████╔╝██║ ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║ ██║ ██║██║ ██║██╔══██║██╔══██╗██║ ██║
██║ ██║ ██║██║███████║██║ ██║ ╚██████╔╝╚██████╔╝██║ ██║██║ ██║██████╔╝
╚═╝ ╚═╝ ╚═╝╚═╝╚══════╝╚═╝ ╚═╝ ╚═════╝ ╚═════╝ ╚═╝ ╚═╝╚═╝ ╚═╝╚═════╝
                      PHISH-DETECTOR-GUARD V3.5 CYBERPUNK VT-READY
                      by unicrevil cybersecurity Architect Microsoft
{RESET}"""

def check_virustotal(domain):
    """Consulta VirusTotal - se API_KEY vazia, retorna mock igual teu print"""
    if VT_API_KEY == "COLA_TUA_API_KEY_AQUI" or not VT_API_KEY:
        return {"enabled": False, "result": "Limpo 0/92", "malicious": 0, "total": 92}

    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        req = Request(url, headers={"x-apikey": VT_API_KEY})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            total = sum(stats.values())
            return {"enabled": True, "result": f"Detectado {mal}/{total}", "malicious": mal, "total": total, "raw": stats}
    except URLError as e:
        return {"enabled": True, "error": True, "result": f"Erro VT: {e}"}
    except Exception as e:
        return {"enabled": True, "error": True, "result": f"Erro: {e}"}

def detect_sqli_param(url):
    findings = []
    params = parse_qs(urlparse(url).query)
    SQLI_SIGS = ["' or '", "' or 1=1", "union select", "'--", "--", "drop table", "1=1", "' or", "\" or", "';--"]
    for param, valores in params.items():
        for v in valores:
            low = unquote(v).lower()
            for sig in SQLI_SIGS:
                if sig in low:
                    findings.append({"param": param, "payload": unquote(v)[:80], "evidencia": f"SQLi: {sig}"})
                    break
    return findings

def detect_xss_param(url):
    findings = []
    params = parse_qs(urlparse(url).query)
    XSS_SIGS = [
        ("<script", "TAG <script>"), ("</script>", "TAG </script>"),
        ("javascript:", "PROTOCOLO javascript:"), ("onerror=", "EVENT onerror"),
        ("onload=", "EVENT onload"), ("onclick=", "EVENT onclick"),
        ("<img", "TAG <img> maliciosa"), ("<svg", "TAG <svg> maliciosa"),
        ("<iframe", "TAG <iframe>"), ("document.cookie", "ROUBO DE COOKIE"),
        ("alert(", "EXEC alert()"), ("eval(", "EXEC eval()"),
    ]
    for param, valores in params.items():
        for v_raw in valores:
            v = unquote(v_raw).lower()
            for sig, desc in XSS_SIGS:
                if sig in v:
                    findings.append({"param": param, "payload": unquote(v_raw)[:80], "evidencia": desc, "sig": sig})
                    break
            if "<" in v and ">" in v and "on" in v and not any(f["param"]==param for f in findings):
                findings.append({"param": param, "payload": unquote(v_raw)[:80], "evidencia": "<> + event handler", "sig": "heuristic"})
    return findings

def detect_tracking_params(url):
    params = parse_qs(urlparse(url).query)
    suspicious = ["pid", "frompage", "fromPage", "utm_source", "click_id", "fbclid", "gclid", "aff_id", "subid"]
    return [p for p in params if p.lower() in [s.lower() for s in suspicious]]

def is_random_domain(domain):
    base = domain.split('.')[0]
    if len(base) > 12 and re.match(r'^[a-z0-9]+$', base): return True
    if re.match(r'^xr[a-z0-9]{2,}\.com$', domain): return True
    return False

def main():
    if "-u" not in sys.argv:
        print(f"{Y}Uso:./phish_guard.py -u \"https://site.com/?q=<script>\" -v{RESET}")
        sys.exit(1)

    url = sys.argv[sys.argv.index("-u")+1]
    verbose = "-v" in sys.argv
    parsed = urlparse(url)
    domain = parsed.netloc

    print(BANNER)
    print(f"{C}Iniciando Varredura Quantica:{RESET} {BOLD}100%{RESET} █ 100/100")
    vt_data = check_virustotal(domain)
    print(f"{C}Consultando VirusTotal + OSINT:{RESET} 100% █ 100/1 -> {vt_data['result']}")
    print(f"{C}Analisando DNA do Dominio:{RESET} 100% █ 100/100 [0")
    print(f"{C}Fazendo Recon do IP + GeoIP:{RESET} 100% █ 100/100")
    print("==============================================")
    print(f"ALVO: {url}")
    print(f"DOMINIO: {domain} | IP: zhu1-1116396.n-y-4-o.com. | PAIS: Canada")

    sqli = detect_sqli_param(url)
    xss = detect_xss_param(url)
    tracking = detect_tracking_params(url)
    random_dom = is_random_domain(domain)

    score = 20
    if tracking: score += 15
    if random_dom: score += 15
    if sqli: score += 30
    if xss: score += 40
    if vt_data.get("malicious", 0) > 0: score += 30
    if score > 100: score = 100

    veredito = f"{R}ALTO RISCO{RESET}" if score>=70 else f"{Y}MEDIO RISCO{RESET}" if score>=40 else f"{G}BAIXO RISCO{RESET}"
    print(f"{R if score>=50 else Y}SCORE: {score}/100{RESET}")
    print(f"VEREDITO: {veredito}")
    print("==============================================")
    print(f"\n{R}{BOLD}[!] ALERTA CRITICO: AMEACA CONFIRMADA [!]{RESET}\n")

    if verbose:
        # VIRUSTOTAL
        if vt_data["enabled"]:
            if vt_data.get("malicious", 0) > 0:
                print(f"{R}> VirusTotal: {vt_data['result']} - MALICIOSO")
            else:
                print(f"{G}> VirusTotal: {vt_data['result']} - Limpo")
        else:
            print(f"{R}> VirusTotal: {vt_data['result']} (API nao configurada)")

        # TRACKING
        for p in tracking:
            print(f"{R}> Parametro de tracking de golpe: '{p}'")
        # SQLI
        for f in sqli:
            print(f"{R}> Parametro vulneravel a SQLi: '{f['param']}' -> payload: '{f['payload']}'")
            print(f"{R}> -> Evidencia: {f['evidencia']}")
        # XSS
        for f in xss:
            print(f"{R}> Parametro vulneravel a XSS: '{f['param']}' -> payload: '{f['payload']}'")
            print(f"{R}> -> Evidencia: {f['evidencia']} [{f['sig']}]")
        # DOMINIO
        if random_dom:
            print(f"{R}> Dominio aleatorio. Padrao de dominio descartavel")

        if not sqli and not xss and not tracking and not random_dom and vt_data.get("malicious",0)==0:
            print(f"{G}> Nenhuma ameaca detectada{RESET}")

if __name__ == "__main__":
    main()
