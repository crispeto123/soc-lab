#!/usr/bin/env python3
"""AG-06 DAST — pruebas de lógica y secretos. Perfil NO destructivo.

Cubre lo que ZAP/Nuclei no detectan bien:
  secrets -> busca API keys/JWT en los .js servidos por el objetivo   [T6]
  logic   -> rate limit (sin 429 bajo ráfaga) y enumeración de respuestas [T2, T3, T5]

NO hace: DoS, modificación/borrado de datos, ni explotación. Solo observa respuestas.
Las pruebas de OTP/CAPTCHA (T1, T4) requieren endpoints y credenciales del cliente,
así que aquí se dejan como marcadores para ejecución asistida.

Uso:
  python scripts/dast_logic.py secrets --target <url> --out secrets.json
  python scripts/dast_logic.py logic   --target <url> --out logic.json
"""
import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

UA = "AG-06-DAST/1.0 (+autorizado)"
TIMEOUT = 15

SECRET_PATTERNS = [
    ("api_key", re.compile(r"(?i)api[-_]?key[\"'=: ]+([A-Za-z0-9]{16,})")),
    ("subscription_key", re.compile(r"(?i)ocp-apim-subscription-key[\"'=: ]+([A-Za-z0-9]{16,})")),
    ("aws_key", re.compile(r"(AKIA|ASIA)[A-Z0-9]{16}")),
    ("bearer", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
]


def fetch(url, method="GET", headers=None, timeout=TIMEOUT):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(500000).decode("utf-8", "replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), ""
    except Exception:
        return None, {}, ""


def mask(v):
    return (v[:6] + "****") if v and len(v) > 6 else "****"


def find_js(base, html):
    urls = set()
    for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html):
        src = m.group(1)
        if src.startswith("http"):
            urls.add(src)
        elif src.startswith("/"):
            urls.add(base.rstrip("/") + src)
    return list(urls)[:25]


def run_secrets(target, out):
    findings = []
    _, _, html = fetch(target)
    for js in find_js(target, html):
        _, _, body = fetch(js)
        for name, pat in SECRET_PATTERNS:
            for m in pat.finditer(body):
                val = m.group(1) if m.groups() else m.group(0)
                findings.append({
                    "category": "secret", "title": f"Posible secreto expuesto en JS ({name})",
                    "cwe": "CWE-798", "cvss": 5.3, "priority": "P2",
                    "location": js, "evidence": f"{name}={mask(val)}",
                    "recommendation": "Mover el secreto al servidor; usar tokens de corta vida. Rotar la clave.",
                    "status": "confirmado",
                })
    # dedup simple por valor
    seen, uniq = set(), []
    for f in findings:
        if f["evidence"] in seen:
            continue
        seen.add(f["evidence"]); uniq.append(f)
    json.dump(uniq, open(out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"secrets: {len(uniq)} hallazgo(s)")


def run_logic(target, out):
    findings = []

    # T2/T3: rate limit. Ráfaga CORTA (no destructiva) y observa si aparece 429.
    def one(_):
        return fetch(target, timeout=8)[0]
    with ThreadPoolExecutor(max_workers=10) as ex:
        codes = list(ex.map(one, range(20)))
    got_429 = any(c == 429 for c in codes if c)
    if codes and not got_429:
        findings.append({
            "category": "rate_limit", "title": "Posible ausencia de rate limit (sin 429 en ráfaga corta)",
            "cwe": "CWE-770", "cvss": 5.0, "priority": "P2",
            "location": target, "evidence": f"20 solicitudes, códigos: {sorted(set(c for c in codes if c))}",
            "recommendation": "Aplicar límite por IP/usuario/sesión y responder 429 con Retry-After.",
            "status": "nuevo",
        })

    # T5: enumeración. Compara respuesta a dos identificadores (válido-aparente vs control).
    # Solo marca si las respuestas difieren de forma observable. Requiere endpoint; se deja
    # como marcador cuando no hay endpoint de validación conocido.
    findings.append({
        "category": "logic", "title": "Enumeración de usuarios — requiere endpoint de validación del cliente",
        "cwe": "CWE-204", "cvss": 0.0, "priority": "P4",
        "location": target, "evidence": "Marcador: ejecutar diff de respuestas con IDs válido/inválido.",
        "recommendation": "Unificar respuestas para IDs válidos e inválidos.",
        "status": "informativo",
    })

    json.dump(findings, open(out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"logic: {len(findings)} entrada(s)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("op", choices=["secrets", "logic"])
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.op == "secrets":
        run_secrets(a.target, a.out)
    else:
        run_logic(a.target, a.out)


if __name__ == "__main__":
    sys.exit(main())
