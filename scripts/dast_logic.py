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
  python scripts/dast_logic.py logic   --target <url> [--login-path /rest/user/login] --out logic.json
"""
import argparse
import json
import re
import sys
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

UA = "AG-06-DAST/1.0 (+autorizado)"
TIMEOUT = 15

SECRET_PATTERNS = [
    ("api_key", re.compile(r"(?i)api[-_]?key[\"'=: ]+([A-Za-z0-9]{16,})")),
    ("subscription_key", re.compile(r"(?i)ocp-apim-subscription-key[\"'=: ]+([A-Za-z0-9]{16,})")),
    ("aws_key", re.compile(r"(AKIA|ASIA)[A-Z0-9]{16}")),
    ("bearer", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
]


def fetch(url, method="GET", headers=None, data=None, timeout=TIMEOUT):
    body_bytes = data.encode("utf-8") if isinstance(data, str) else data
    req = urllib.request.Request(url, method=method, data=body_bytes,
                                 headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(500000).decode("utf-8", "replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        # En login, un fallo de credenciales suele venir como 4xx CON cuerpo útil: lo leemos.
        try:
            ebody = e.read(500000).decode("utf-8", "replace")
        except Exception:
            ebody = ""
        return e.code, dict(e.headers or {}), ebody
    except Exception:
        return None, {}, ""


def mask(v):
    return (v[:6] + "****") if v and len(v) > 6 else "****"


def find_js(base, html):
    """Extrae los .js del HTML. v1.1: resuelve rutas RELATIVAS ("main.js", "./assets/x.js"),
    que es como Angular/Vite/Lovable cargan su bundle; v1.0 solo veía "http..." y "/...",
    por eso el run #11 dio 0 secretos en Juice Shop. Solo sigue JS del MISMO host (alcance G5)."""
    urls = []
    base_host = urllib.parse.urlparse(base).netloc
    for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html):
        full = urllib.parse.urljoin(base.rstrip("/") + "/", m.group(1))
        if urllib.parse.urlparse(full).netloc == base_host and full not in urls:
            urls.append(full)
    return urls[:25]


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


BAD_PW = "Zz!invalid-ag06-000000"  # password basura: nunca inicia sesión


def enum_probe(login_url, user, user_field="email", pass_field="password"):
    """Un intento de login NO destructivo: usuario dado + password inválido fijo.
    Nunca inicia sesión (la contraseña es basura) y es una sola solicitud por usuario.
    v1.1.6: nombres de campo configurables (user_field/pass_field) para apps que no usan
    email/password (p. ej. documento/cédula, usuario/clave). Prueba JSON; si el server no
    lo acepta, cae a form-urlencoded (incluye email+username por compatibilidad).
    Devuelve (status, longitud_cuerpo, nº_palabras, extracto) para comparar respuestas."""
    payload = json.dumps({user_field: user, pass_field: BAD_PW})
    status, _, body = fetch(login_url, method="POST", data=payload,
                            headers={"Content-Type": "application/json", "Accept": "application/json"})
    if status in (None, 404, 405, 415):  # endpoint no acepta JSON: intento form
        fields = {user_field: user, pass_field: BAD_PW}
        if user_field != "username":
            fields.setdefault("username", user)  # compat: algunos forms esperan 'username'
        form = urllib.parse.urlencode(fields)
        status, _, body = fetch(login_url, method="POST", data=form,
                                headers={"Content-Type": "application/x-www-form-urlencoded"})
    return status, len(body or ""), len((body or "").split()), (body or "")[:120]


def run_logic(target, out, login_path=None, user_field="email", pass_field="password",
              login_user=None):
    findings = []

    # T3: rate limit en la RAÍZ. Ráfaga CORTA (no destructiva) y observa si aparece 429.
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

    # T2/T5/T7: enumeración de usuarios. Compara la respuesta del login ante un usuario
    # plausible vs uno inexistente, SIEMPRE con password inválido (nunca inicia sesión).
    # Solo marca si la respuesta difiere de forma observable (código, longitud o mensaje).
    if login_path:
        login_url = target.rstrip("/") + "/" + login_path.lstrip("/")
        host = urllib.parse.urlparse(target).hostname or "example.com"
        likely = login_user or f"admin@{host}"          # usuario plausible (configurable)
        bogus = "no-existe-ag06-9f3a2b@" + host          # usuario casi seguro inexistente

        # T3 sobre el LOGIN (fuerza bruta / credential stuffing), endpoint que de verdad importa.
        # Ráfaga de POST con password inválido SIEMPRE contra el usuario inexistente, para no
        # arriesgar bloqueo de una cuenta real.
        # v1.1.7 (ADR-005): BASELINE ESTÁNDAR, igual para toda app (caja negra). No se calibra
        # al umbral interno del objetivo. AUTH_BURST=30 supera cualquier control razonable
        # (OWASP ASVS 2.2.1 anti-automatización; WSTG-ATHN-03): una app que cumple el estándar
        # frena la fuerza bruta (429 / lockout) mucho antes de 30 intentos rápidos. Si a los 30
        # no hay señal de freno, NO cumple el estándar.
        AUTH_BURST = 30
        def one_login(_):
            return enum_probe(login_url, bogus, user_field, pass_field)[0]
        with ThreadPoolExecutor(max_workers=10) as ex:
            lcodes = list(ex.map(one_login, range(AUTH_BURST)))
        if lcodes and not any(c == 429 for c in lcodes if c):
            findings.append({
                "category": "rate_limit",
                "title": "Login sin control anti-fuerza bruta (no cumple baseline OWASP)",
                "cwe": "CWE-307", "cvss": 6.5, "priority": "P2",
                "location": login_url,
                "evidence": (f"{AUTH_BURST} intentos de login sin 429/bloqueo; "
                             f"códigos: {sorted(set(c for c in lcodes if c))}"),
                "recommendation": ("Limitar intentos por IP/usuario y responder 429; añadir backoff "
                                   "y CAPTCHA/MFA. En borde: rate limit del WAF sobre la ruta de login."),
                "status": "nuevo",
            })

        r_likely = enum_probe(login_url, likely, user_field, pass_field)
        r_bogus = enum_probe(login_url, bogus, user_field, pass_field)
        if r_likely[0] is not None and r_bogus[0] is not None:
            diff_code = r_likely[0] != r_bogus[0]
            diff_len = abs(r_likely[1] - r_bogus[1]) > 16
            diff_words = abs(r_likely[2] - r_bogus[2]) > 4
            if diff_code or diff_len or diff_words:
                findings.append({
                    "category": "logic",
                    "title": "Posible enumeración de usuarios (respuestas de login divergentes)",
                    "cwe": "CWE-204", "cvss": 5.3, "priority": "P2",
                    "location": login_url,
                    "evidence": (f"válido-aparente: HTTP {r_likely[0]}, {r_likely[1]}B | "
                                 f"inexistente: HTTP {r_bogus[0]}, {r_bogus[1]}B"),
                    "recommendation": "Unificar respuesta, código y tiempo para usuarios válidos e inexistentes.",
                    "status": "confirmado",
                })
            else:
                findings.append({
                    "category": "logic",
                    "title": "Login no enumera usuarios por respuesta (respuestas equivalentes)",
                    "cwe": "CWE-204", "cvss": 0.0, "priority": "P4",
                    "location": login_url,
                    "evidence": f"Ambas respuestas equivalentes (~HTTP {r_likely[0]}, ~{r_likely[1]}B).",
                    "recommendation": "Mantener respuestas unificadas; revisar también diferencias de tiempo.",
                    "status": "informativo",
                })
    else:
        findings.append({
            "category": "logic", "title": "Enumeración de usuarios — no evaluada (sin login_path)",
            "cwe": "CWE-204", "cvss": 0.0, "priority": "P4",
            "location": target, "evidence": "Ejecutar con --login-path para evaluar T2/T5/T7.",
            "recommendation": "Unificar respuestas para IDs válidos e inválidos.",
            "status": "informativo",
        })

    json.dump(findings, open(out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"logic: {len(findings)} entrada(s)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("op", choices=["secrets", "logic"])
    ap.add_argument("--target", required=True)
    ap.add_argument("--login-path", dest="login_path", default=None,
                    help="Ruta de login para la prueba de enumeración (ej: /rest/user/login)")
    ap.add_argument("--login-user-field", dest="user_field", default="email",
                    help="Nombre del campo de usuario en el login (default: email; ej: documento, usuario)")
    ap.add_argument("--login-pass-field", dest="pass_field", default="password",
                    help="Nombre del campo de contraseña en el login (default: password; ej: clave)")
    ap.add_argument("--login-user", dest="login_user", default=None,
                    help="Valor de usuario plausible para la prueba de enumeración (ej: una cédula de prueba)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.op == "secrets":
        run_secrets(a.target, a.out)
    else:
        run_logic(a.target, a.out, login_path=a.login_path,
                  user_field=a.user_field, pass_field=a.pass_field, login_user=a.login_user)


if __name__ == "__main__":
    sys.exit(main())
