#!/usr/bin/env python3
"""AG-06 DAST — consolidador. Normaliza salidas de ZAP / Nuclei / testssl.sh /
scripts de lógica a findings.json con el mismo esquema que AG-01.

Uso:
  python scripts/dast_consolidar.py <dir_salidas> --target <url> --mode <lab|external>
         --out findings.json --summary informe-dast.md
"""
import argparse
import datetime as dt
import json
import os
import re
import sys

# Mapa de señales -> (CWE, CVSS aprox, prioridad). Alinea con los 14 casos Calidda.
RULES = {
    "trace": ("CWE-200", 3.5, "P4"),
    "x-frame-options": ("CWE-1021", 3.1, "P4"),
    "clickjack": ("CWE-1021", 3.1, "P4"),
    "frame-ancestors": ("CWE-1021", 3.1, "P4"),
    "cookie": ("CWE-614", 2.6, "P4"),
    "secure flag": ("CWE-614", 2.6, "P4"),
    "request smuggling": ("CWE-444", 3.1, "P4"),
    "cbc": ("CWE-326", 3.1, "P4"),
    "weak cipher": ("CWE-326", 3.1, "P4"),
    "caa": ("CWE-295", 0.0, "P4"),
    "certificate": ("CWE-295", 0.0, "P4"),
}

PRIO_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

# Hallazgos puramente informativos de ZAP que no aportan a un informe de cliente.
# Se descartan por título (coincidencia por substring, en minúsculas).
NOISE_TITLES = (
    "modern web application",
    "user agent fuzzer",
    "storable and cacheable content",
    "storable but non-cacheable content",
    "non-storable content",
    "re-examine cache-control directives",
    "information disclosure - suspicious comments",
    "charset mismatch",
    "retrieved from cache",
)


def is_noise(row):
    t = (row.get("title") or "").lower()
    return any(n in t for n in NOISE_TITLES)


def prio_from_cvss(cvss):
    if cvss >= 7.0:
        return "P1"
    if cvss >= 4.0:
        return "P2"
    if cvss >= 0.1:
        return "P3"
    return "P4"


def mask(text):
    """Enmascara posibles secretos/keys en evidencia (G8)."""
    if not text:
        return text
    text = re.sub(r"(AKIA|ASIA)[A-Z0-9]{8,}", r"\1****", text)
    text = re.sub(r"(?i)(api[-_ ]?key[\"'=: ]+)([A-Za-z0-9]{6})[A-Za-z0-9]+", r"\1\2****", text)
    text = re.sub(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}", "eyJ****<jwt>", text)
    return text[:400]


def classify(title, default_cwe="CWE-16", default_cvss=3.0):
    low = (title or "").lower()
    for key, (cwe, cvss, prio) in RULES.items():
        if key in low:
            return cwe, cvss, prio
    return default_cwe, default_cvss, prio_from_cvss(default_cvss)


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_jsonl(path):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return out


# ---------- parsers por herramienta ----------

def from_zap(data):
    rows = []
    if not data:
        return rows
    sites = data.get("site", []) if isinstance(data, dict) else []
    for site in sites:
        for alert in site.get("alerts", []):
            title = alert.get("alert") or alert.get("name") or "Hallazgo ZAP"
            cwe = f"CWE-{alert.get('cweid')}" if alert.get("cweid", "-1") not in ("-1", None) else None
            risk = (alert.get("riskdesc") or "").split(" ")[0].lower()
            cvss = {"high": 7.0, "medium": 5.0, "low": 3.0, "informational": 0.0}.get(risk, 3.0)
            inst = (alert.get("instances") or [{}])[0]
            c2, cv2, _ = classify(title, cwe or "CWE-16", cvss)
            rows.append({
                "source_tool": "zap", "category": "headers",
                "title": title, "cwe": cwe or c2, "cvss": cvss,
                "location": inst.get("uri", ""),
                "evidence": mask(inst.get("evidence", "")),
                "recommendation": mask(alert.get("solution", ""))[:300],
            })
    return rows


def from_nuclei(items):
    rows = []
    for it in items:
        info = it.get("info", {})
        title = info.get("name", "Hallazgo Nuclei")
        sev = (info.get("severity") or "info").lower()
        cvss = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}.get(sev, 3.0)
        cwe_list = (info.get("classification") or {}).get("cwe-id") or []
        cwe = cwe_list[0].upper() if cwe_list else None
        c2, cv2, _ = classify(title, cwe or "CWE-16", cvss)
        cat = "smuggling" if "smuggl" in title.lower() else ("tls" if "ssl" in title.lower() or "tls" in title.lower() else "headers")
        rows.append({
            "source_tool": "nuclei", "category": cat,
            "title": title, "cwe": cwe or c2, "cvss": cvss,
            "location": it.get("matched-at", it.get("host", "")),
            "evidence": mask(str(it.get("extracted-results", ""))),
            "recommendation": info.get("remediation", "")[:300],
        })
    return rows


def from_testssl(data):
    rows = []
    items = data if isinstance(data, list) else (data or {}).get("scanResult", [])
    for it in (items or []):
        fid = (it.get("id") or "").lower()
        sev = (it.get("severity") or "INFO").upper()
        if sev in ("OK", "INFO", "WARN") and "cbc" not in fid and "caa" not in fid:
            continue
        finding = it.get("finding", "")
        if "cbc" in fid or "cbc" in finding.lower():
            title = "Uso de cifrados CBC obsoletos"
        elif "caa" in fid:
            title = "Ausencia de registro DNS CAA"
        else:
            title = f"TLS: {it.get('id')}"
        cwe, cvss, _ = classify(title)
        rows.append({
            "source_tool": "testssl", "category": "tls",
            "title": title, "cwe": cwe, "cvss": cvss,
            "location": it.get("ip", ""), "evidence": mask(finding),
            "recommendation": "Deshabilitar suites CBC / definir CAA para el dominio.",
        })
    return rows


def from_generic(path, tool):
    """secrets.json y logic.json ya vienen en formato de filas listas."""
    data = load_json(path)
    rows = []
    for r in (data or []):
        r.setdefault("source_tool", tool)
        r["evidence"] = mask(r.get("evidence", ""))
        rows.append(r)
    return rows


def dedup(rows):
    seen, out = set(), []
    for r in rows:
        k = (r.get("cwe"), (r.get("title") or "").lower()[:40], r.get("location", "")[:60])
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--target", required=True)
    ap.add_argument("--mode", default="lab")
    ap.add_argument("--out", default="findings.json")
    ap.add_argument("--summary", default="informe-dast.md")
    a = ap.parse_args()

    rows = []
    rows += from_zap(load_json(os.path.join(a.outdir, "zap.json")))
    rows += from_nuclei(load_jsonl(os.path.join(a.outdir, "nuclei.jsonl")))
    rows += from_testssl(load_json(os.path.join(a.outdir, "testssl.json")))
    rows += from_generic(os.path.join(a.outdir, "secrets.json"), "secrets")
    rows += from_generic(os.path.join(a.outdir, "logic.json"), "logic")

    rows = dedup(rows)
    noise_n = sum(1 for r in rows if is_noise(r))
    rows = [r for r in rows if not is_noise(r)]
    run_id = "dast-" + dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d-%H%M")
    for i, r in enumerate(rows, 1):
        r["id"] = f"D-{i:04d}"
        r.setdefault("cvss", 3.0)
        r["priority"] = r.get("priority") or prio_from_cvss(r["cvss"])
        r.setdefault("status", "nuevo")
    rows.sort(key=lambda r: (PRIO_ORDER.get(r["priority"], 9), -r["cvss"]))

    doc = {
        "run_id": run_id, "target": a.target, "mode": a.mode,
        "verified": a.mode == "external" or a.mode == "lab",
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "count": len(rows), "noise_filtrado": noise_n, "findings": rows,
    }
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)

    by_p = {p: sum(1 for r in rows if r["priority"] == p) for p in ("P1", "P2", "P3", "P4")}
    lines = [
        f"# AG-06 DAST — `{run_id}`", "",
        f"Objetivo: `{a.target}` · Modo: {a.mode} · {len(rows)} hallazgos "
        f"(P1 {by_p['P1']} / P2 {by_p['P2']} / P3 {by_p['P3']} / P4 {by_p['P4']})", "",
        "| ID | Prioridad | CWE | Hallazgo | Herramienta | Ubicación |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        loc = (r.get("location", "") or "").replace("|", "/")[:50]
        lines.append(f"| {r['id']} | {r['priority']} | {r.get('cwe','')} | "
                     f"{(r.get('title','') or '').replace('|','/')[:50]} | {r['source_tool']} | {loc} |")
    if noise_n:
        lines += ["", f"_({noise_n} hallazgo(s) informativo(s) de ruido filtrados.)_"]
    lines += ["", "_AG-06 opera en perfil no destructivo y solo sobre objetivos verificados (G1–G9)._"]
    with open(a.summary, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
