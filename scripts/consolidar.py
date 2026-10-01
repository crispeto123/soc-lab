#!/usr/bin/env python3
"""AG-01 Orquestador (Lab costo cero) — consolida SARIF de AG-02 y AG-03.

Uso: python scripts/consolidar.py <carpeta_sarif> <salida_dir>
Genera findings.json (esquema de la ficha AG-01) y resumen.md en español.
Sin LLM: reglas deterministas. Enmascara secretos. Deduplica por regla+ubicación.
"""
import datetime as dt
import glob
import json
import os
import re
import sys

# Herramienta -> agente y categoría por defecto
TOOLS = {
    "semgrep": ("AG-02", "code"),
    "gitleaks": ("AG-02", "secret"),
    "codeql": ("AG-02", "code"),
    "trivy": ("AG-03", "dependency"),
    "osv-scanner": ("AG-03", "dependency"),
    "checkov": ("AG-03", "iac"),
}
LEVEL_CVSS = {"error": 7.5, "warning": 5.0, "note": 3.0, "none": 0.0}
VULN_RE = re.compile(r"CVE-\d{4}-\d+|GHSA(?:-[a-z0-9]{4}){3}")
PRIO = [(9.0, "P1"), (7.0, "P2"), (4.0, "P3"), (0.0, "P4")]
# Valor tras '=' o ':' (asignaciones) o tokens largos con letras y dígitos
ASSIGN_RE = re.compile(r"""(?i)((?:key|secret|token|pass(?:word)?|pwd|api[_-]?key)[\w-]*\s*[:=]\s*["']?)([^"'\s,;)]{4,})""")
TOKEN_RE = re.compile(r"\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])([A-Za-z0-9_\-]{3})[A-Za-z0-9_\-]{14,}([A-Za-z0-9_\-]{3})\b")


def mask(text: str) -> str:
    """Enmascara secretos en evidencias (guardrail G4)."""
    text = ASSIGN_RE.sub(lambda m: m.group(1) + m.group(2)[:2] + "****", text or "")
    return TOKEN_RE.sub(lambda m: f"{m.group(1)}****{m.group(2)}", text)


def tool_key(name: str) -> str:
    n = (name or "").lower()
    for k in TOOLS:
        if k in n:
            return k
    return n or "desconocido"


def rule_meta(run, rule_id, rule_index):
    rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
    rule = None
    if rule_index is not None and 0 <= rule_index < len(rules):
        rule = rules[rule_index]
    else:
        rule = next((r for r in rules if r.get("id") == rule_id), None)
    return rule or {}


def score(result, rule, tool_default=None):
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    for k in ("security-severity", "cvss", "cvssScore"):
        try:
            return float(props[k])
        except (KeyError, TypeError, ValueError):
            pass
    if tool_default is not None:
        return tool_default
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return LEVEL_CVSS.get(level, 5.0)


def tags_of(rule, result):
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    tags = " ".join(map(str, props.get("tags", [])))
    cwe = re.search(r"CWE-\d+", tags + " " + json.dumps(rule.get("help", {})))
    owasp = re.search(r"A\d{2}:20\d{2}", tags)
    return (cwe.group(0) if cwe else ""), (owasp.group(0) if owasp else "")


def category(tool, rule_id, base):
    rid = (rule_id or "").lower()
    if tool == "trivy":
        if rid.startswith(("avd-", "ds", "azu")) or "misconfig" in rid:
            return "iac"
        if "secret" in rid:
            return "secret"
    if "secret" in rid or "hardcoded" in rid or "credential" in rid:
        return "secret"
    return base


def parse(path):
    with open(path, encoding="utf-8") as f:
        sarif = json.load(f)
    for run in sarif.get("runs", []):
        tool = tool_key(run.get("tool", {}).get("driver", {}).get("name", ""))
        agent, base_cat = TOOLS.get(tool, ("AG-0?", "code"))
        for r in run.get("results", []) or []:
            rule_id = r.get("ruleId") or ""
            rule = rule_meta(run, rule_id, r.get("ruleIndex"))
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = re.sub(r"^(file://)?/(src|repo)/", "", loc.get("artifactLocation", {}).get("uri", ""))
            line = (loc.get("region") or {}).get("startLine", 0)
            snippet = ((loc.get("region") or {}).get("snippet") or {}).get("text", "")
            cvss = round(score(r, rule, 5.0 if tool == 'checkov' else None), 1)  # Checkov no trae severidad
            cwe, owasp = tags_of(rule, r)
            cat = category(tool, rule_id, base_cat)
            msg = (r.get("message") or {}).get("text", "")
            title = (rule.get("shortDescription") or {}).get("text") or msg.split("\n")[0][:120] or rule_id
            if cat == "secret":
                cvss = max(cvss, 9.0)  # G7: todo secreto expuesto es P1
            vid = VULN_RE.search(f"{title} {rule_id} {msg}")
            yield {
                "source_agent": agent,
                "tool": tool,
                "category": cat,
                "rule": rule_id,
                "vuln_id": vid.group(0) if vid else "",
                "title": title,
                "cwe": cwe,
                "owasp": owasp,
                "cvss": cvss,
                "location": f"{uri}:{line}" if line else uri,
                "evidence": mask(snippet.strip()[:200]),
                "recommendation": mask(((rule.get("help") or {}).get("text") or msg)[:300]),
            }


def main():
    src, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    run_id = os.environ.get("RUN_ID") or dt.datetime.utcnow().strftime("run-%Y%m%d-%H%M%S")
    repo = os.environ.get("GITHUB_REPOSITORY", "local")
    commit = (os.environ.get("GITHUB_SHA") or "local")[:7]

    seen, findings, errores = {}, [], []
    for path in sorted(glob.glob(os.path.join(src, "**", "*.sarif"), recursive=True)):
        try:
            for f in parse(path):
                # Dedup: misma ubicación + misma familia (CWE o regla)
                if f["category"] == "dependency" and f["vuln_id"]:
                    key = (f["location"].split(":")[0], f["vuln_id"])  # mismo CVE en el mismo manifiesto
                else:
                    key = (f["location"], f["cwe"] or f["rule"])
                if key in seen:
                    prev = seen[key]
                    prev["tools"] = sorted(set(prev["tools"]) | {f["tool"]})
                    prev["cvss"] = max(prev["cvss"], f["cvss"])
                    continue
                f["tools"] = [f["tool"]]
                seen[key] = f
                findings.append(f)
        except Exception as e:  # salida inválida: se descarta y se informa (paso 4)
            errores.append(f"{os.path.basename(path)}: {e}")

    findings.sort(key=lambda x: -x["cvss"])
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i:04d}"
        f["priority"] = next(p for t, p in PRIO if f["cvss"] >= t)
        f["auto_fixable"] = f["category"] in ("dependency", "iac")
        f["status"] = "nuevo"
        f.pop("tool", None)

    doc = {"run_id": run_id, "repo": repo, "commit": commit,
           "generated_at": dt.datetime.utcnow().isoformat() + "Z",
           "errors": errores, "findings": findings}
    with open(os.path.join(out, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)

    # Resumen en español
    cnt = lambda key, val: sum(1 for f in findings if f[key] == val)
    lines = [f"# Informe de seguridad — {repo} @ {commit}", "",
             f"Ejecución `{run_id}` · {len(findings)} hallazgos únicos", "",
             "| Prioridad | Hallazgos |", "|---|---|"]
    lines += [f"| {p} | {cnt('priority', p)} |" for p in ("P1", "P2", "P3", "P4")]
    lines += ["", "| Categoría | Hallazgos |", "|---|---|"]
    lines += [f"| {c} | {cnt('category', c)} |" for c in ("secret", "code", "dependency", "iac")]
    lines += ["", "## Top 15", "", "| ID | P | CVSS | Categoría | Título | Ubicación | Herramientas |",
              "|---|---|---|---|---|---|---|"]
    for f in findings[:15]:
        t = f["title"].replace("|", "/")[:80]
        lines.append(f"| {f['id']} | {f['priority']} | {f['cvss']} | {f['category']} | {t} | `{f['location']}` | {', '.join(f['tools'])} |")
    if errores:
        lines += ["", "## Salidas descartadas", ""] + [f"- {e}" for e in errores]
    escalar = [f for f in findings if f["priority"] == "P1" or f["category"] == "secret"]
    lines += ["", f"**Escalar a Cristian:** {len(escalar)} hallazgos (P1 o secretos).",
              "", "_Ningún cambio se ejecuta sin aprobación humana (guardrail G2)._"]
    with open(os.path.join(out, "resumen.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"{len(findings)} hallazgos únicos, {len(errores)} salidas descartadas")


if __name__ == "__main__":
    main()
