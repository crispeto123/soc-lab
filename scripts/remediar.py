#!/usr/bin/env python3
"""AG-04 Remediation — Lab costo cero (ADR-002), controles C1–C6 del ADR-001 v1.1.

Lee el plan por paquete de findings.json (AG-01) y abre un PR por paquete en ramas
soc/fix-*. Nunca escribe en main ni hace merge: la aprobación humana es el merge.

Uso:
  python scripts/remediar.py informe/findings.json [--max-open 5] [--stale-days 14] [--dry-run]
"""
import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys

PREFIX = "soc/fix-"
BOT = ("github-actions[bot]", "41898283+github-actions[bot]@users.noreply.github.com")
LABELS = {"soc-remediation": "1d76db", "P1": "b60205", "cambio-mayor": "fbca04"}


def sh(*cmd, cwd=None, check=True, dry=False):
    if dry and cmd[0] in ("git", "gh", "npm") and cmd[1] in ("push", "pr", "label", "commit", "install"):
        print("[dry-run]", " ".join(cmd))
        return ""
    r = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} → {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout.strip()


def vkey(v):
    return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v or "0")]


def slug(text):
    return re.sub(r"[^a-z0-9.]+", "-", text.lower()).strip("-")


def norm_py(name):
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------- edición de manifiestos (C1: solo en la rama soc/fix-*) ----------

def fix_npm(pkg_dir, package, version, dry):
    path = os.path.join(pkg_dir, "package.json")
    if not os.path.isfile(path):
        return False, "sin package.json", []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    for sec in ("dependencies", "devDependencies"):
        if package in data.get(sec, {}):
            data[sec][package] = version
            break
    else:
        return False, "dependencia transitiva (no está en package.json): revisar a mano", []
    files = [path]
    lock = os.path.join(pkg_dir, "package-lock.json")
    if not dry:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        if os.path.isfile(lock):
            sh("npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", cwd=pkg_dir)
            files.append(lock)
    return True, "", files


def fix_pip(req_path, package, version, dry):
    if not os.path.isfile(req_path):
        return False, "sin requirements.txt", []
    with open(req_path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    pat = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*==\s*[^\s;#]+(.*)$")
    hit = False
    for i, line in enumerate(lines):
        m = pat.match(line)
        if m and norm_py(m.group(1)) == norm_py(package):
            lines[i] = f"{m.group(1)}{m.group(2) or ''}=={version}{m.group(3)}"
            hit = True
    if not hit:
        return False, "no aparece fijado con == en requirements.txt: revisar a mano", []
    if not dry:
        with open(req_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    return True, "", [req_path]


def apply_fix(p, dry):
    manifest = p["manifest"]
    base = os.path.basename(manifest)
    if base in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
        return fix_npm(os.path.dirname(manifest) or ".", p["package"], p["fix_to"], dry)
    if base.startswith("requirements") and base.endswith(".txt"):
        return fix_pip(manifest, p["package"], p["fix_to"], dry)
    return False, f"manifiesto no soportado ({base})", []


# ---------- PRs ----------

def pr_body(p, run_id, major):
    cves = sorted(set(p["cves"]))
    lista = "\n".join(f"- `{c}`" for c in cves[:40]) + (f"\n- … y {len(cves) - 40} más" if len(cves) > 40 else "")
    aviso = ("\n> ⚠️ **Cambio de versión mayor** "
             f"({p['installed']} → {p['fix_to']}): puede romper compatibilidad. Probar antes del merge.\n") if major else ""
    escala = "\n> 🔴 **P1 — escalado a Cristian.** Revisar con prioridad.\n" if p["priority"] == "P1" else ""
    return f"""## AG-04 Remediation — actualización de dependencia

| Campo | Valor |
|---|---|
| Paquete | `{p['package']}` |
| Manifiesto | `{p['manifest']}` |
| Versión actual → propuesta | `{p['installed']}` → `{p['fix_to']}` |
| CVEs corregidos | {len(cves)} |
| CVSS máximo / Prioridad | {p['max_cvss']} / {p['priority']} |
| Ejecución origen (AG-01) | `{run_id}` |
{aviso}{escala}
### CVEs
{lista}

### Prueba esperada
1. Instalar dependencias y ejecutar la app / pruebas sin errores.
2. Volver a ejecutar **AG-01 Orquestador** tras el merge: estos CVEs deben desaparecer del informe.

---
_Abierto automáticamente por AG-04 (ADR-001 v1.1). AG-04 nunca hace merge: la aprobación es la revisión y el merge de este PR (control C2)._
_Si no se revisa en 14 días, se cierra automáticamente (control C6)._
"""


def open_soc_prs(dry):
    if dry and not os.environ.get("GH_TOKEN"):
        return []
    out = sh("gh", "pr", "list", "--state", "open", "--limit", "200",
             "--json", "number,headRefName,createdAt,title")
    return [p for p in json.loads(out or "[]") if p["headRefName"].startswith(PREFIX)]


def close_stale(prs, days, dry):
    """C6: cierra PRs soc/fix-* sin merge con más de `days` días."""
    now = dt.datetime.now(dt.timezone.utc)
    closed = []
    for p in prs:
        created = dt.datetime.fromisoformat(p["createdAt"].replace("Z", "+00:00"))
        if (now - created).days >= days:
            sh("gh", "pr", "close", str(p["number"]), "--comment",
               f"Cerrado automáticamente por AG-04: sin revisión en {days} días (control C6). "
               "Se volverá a proponer en la próxima ejecución si el CVE sigue abierto.", dry=dry)
            closed.append(p)
    return closed


def remote_branch_exists(branch):
    return bool(sh("git", "ls-remote", "--heads", "origin", branch, check=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--max-open", type=int, default=int(os.environ.get("MAX_OPEN_PRS", 5)))
    ap.add_argument("--stale-days", type=int, default=14)
    ap.add_argument("--base", default="main")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--summary", default="remediacion.md")
    a = ap.parse_args()
    dry = a.dry_run

    with open(a.findings, encoding="utf-8") as f:
        doc = json.load(f)
    run_id = doc.get("run_id", "?")
    packages = doc.get("packages", [])

    if not dry:
        sh("git", "config", "user.name", BOT[0])
        sh("git", "config", "user.email", BOT[1])
        for name, color in LABELS.items():
            sh("gh", "label", "create", name, "--color", color, "--force")

    prs = open_soc_prs(dry)
    closed = close_stale(prs, a.stale_days, dry)
    closed_n = {p["number"] for p in closed}
    prs = [p for p in prs if p["number"] not in closed_n]
    heads = {p["headRefName"] for p in prs}
    slots = max(a.max_open - len(prs), 0)

    rows = []  # (paquete, manifiesto, resultado)
    for p in packages:
        label = (p["package"], p["manifest"])
        if not p.get("fix_to"):
            rows.append((*label, "Sin versión corregida publicada — escalar"))
            continue
        if vkey(p["fix_to"]) <= vkey(p["installed"]):
            rows.append((*label, "La versión corregida no es mayor que la instalada — revisar"))
            continue
        app_dir = os.path.dirname(p["manifest"]) or "root"
        branch = f"{PREFIX}{slug(app_dir)}-{slug(p['package'])}-{slug(p['fix_to'])}"
        if branch in heads or (not dry and remote_branch_exists(branch)):
            rows.append((*label, f"Ya existe `{branch}`"))
            continue
        if slots == 0:
            rows.append((*label, f"En espera: límite de {a.max_open} PRs abiertos (C4)"))
            continue

        sh("git", "checkout", "-q", "-B", branch, f"origin/{a.base}" if not dry else "HEAD")
        try:
            ok, why, files = apply_fix(p, dry)
            if not ok:
                rows.append((*label, why))
                continue
            major = vkey(p["fix_to"])[0] != vkey(p["installed"])[0]
            title = f"[AG-04] {p['package']} {p['installed']} → {p['fix_to']} ({len(set(p['cves']))} CVEs, {p['priority']})"
            if not dry:
                sh("git", "add", "--", *files)   # solo los manifiestos tocados
                if not sh("git", "diff", "--cached", "--name-only"):
                    rows.append((*label, "Sin cambios tras aplicar el fix"))
                    continue
                sh("git", "commit", "-q", "-m", title + f"\n\nOrigen: {run_id}. Generado por AG-04 (ADR-001 v1.1).")
                sh("git", "push", "-q", "origin", branch)   # C1: solo ramas soc/fix-*
                labels = ["soc-remediation"] + (["P1"] if p["priority"] == "P1" else []) + (["cambio-mayor"] if major else [])
                url = sh("gh", "pr", "create", "--base", a.base, "--head", branch, "--title", title,
                         "--body", pr_body(p, run_id, major), *sum((["--label", l] for l in labels), []))
            else:
                url = "(dry-run)"
            slots -= 1
            rows.append((*label, f"PR abierto {url}" + (" · cambio mayor" if major else "")))
        except Exception as e:  # registra y continúa con el siguiente paquete
            rows.append((*label, f"Error: {e}"[:200]))
        finally:
            sh("git", "checkout", "-q", "-f", a.base if not dry else "-", check=False)

    abiertos = sum(1 for r in rows if r[2].startswith("PR abierto"))
    lines = [f"# AG-04 Remediation — `{run_id}`", "",
             f"{len(packages)} paquetes en el plan · {abiertos} PR(s) nuevos · "
             f"{len(prs)} ya abiertos · {len(closed)} cerrados por antigüedad (C6) · límite {a.max_open} (C4)", "",
             "| Paquete | Manifiesto | Resultado |", "|---|---|---|"]
    lines += [f"| {pk} | `{mf}` | {res.replace('|', '/')} |" for pk, mf, res in rows]
    lines += ["", "_AG-04 solo escribe en ramas `soc/fix-*` y nunca hace merge (C1). "
              "Secretos y hallazgos de código no se remedian automáticamente: se escalan (C5)._"]
    with open(a.summary, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
