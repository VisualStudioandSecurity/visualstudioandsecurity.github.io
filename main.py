from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

app = FastAPI(title="Visual Studio Security Engine")

class ScanRequest(BaseModel):
    url: str

class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.results = []
        self.sqli_payloads = ["'", "''", "1' OR '1'='1", "SLEEP(5)"]

    def check_headers_and_files(self):
        try:
            res = requests.get(self.url, timeout=10, verify=False)
            headers = res.headers
            
            # Verificação de Headers
            checks = {
                "Content-Security-Policy": "critical",
                "X-Frame-Options": "high",
                "Strict-Transport-Security": "high"
            }
            for h, sev in checks.items():
                if h not in headers:
                    self.results.append({"name": f"{h} Ausente", "severity": sev, "layer": "HTTP Headers", "desc": f"Risco de injeção ou clickjacking."})

            # Verificação de Arquivos Sensíveis
            for path in ["/.env", "/.git/config"]:
                if requests.get(f"{self.url.rstrip('/')}{path}", timeout=5).status_code == 200:
                    self.results.append({"name": f"Exposição: {path}", "severity": "critical", "layer": "Info Leak", "desc": "Dados sensíveis expostos publicamente."})
        except: pass

    def run_fuzzer(self):
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in self.sqli_payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    start = time.time()
                    res = requests.get(test_url, timeout=10)
                    duration = time.time() - start
                    
                    if any(err in res.text.lower() for err in ["sql syntax", "mysql_fetch", "sqlite"]):
                        self.results.append({"name": "SQL Injection (Error-based)", "severity": "critical", "layer": "SQL Injection", "desc": f"Falha no parâmetro '{param}'."})
                        break
                    if "SLEEP" in payload and duration > 4:
                        self.results.append({"name": "Blind SQLi (Time-based)", "severity": "critical", "layer": "SQL Injection", "desc": f"Injeção detectada via delay no parâmetro '{param}'."})
                except: continue

@app.post("/api/v1/scan")
async def start_audit(request: ScanRequest):
    scanner = VulnerabilityScanner(request.url)
    scanner.check_headers_and_files()
    scanner.run_fuzzer()
    return {"status": "success", "url": request.url, "vulnerabilities": scanner.results}
