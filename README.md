# SOC Lab — Agentes de seguridad para apps vibecoded (costo cero)

> ⚠️ Este repositorio contiene **código y configuración vulnerables a propósito**, con secretos **falsos**, para probar los agentes. No desplegar.

## Qué hace

| Agente | Workflow / job | Herramientas | Salida |
|---|---|---|---|
| AG-01 Orquestador | `ag01-orquestador.yml` → `ag01-consolidar` | `scripts/consolidar.py` (reglas, sin LLM) | `findings.json` + `resumen.md` (artefacto `informe-ag01` y resumen del job) |
| AG-02 Code Reviewer | job `ag02-code-reviewer` + `codeql.yml` | Semgrep, Gitleaks, CodeQL | SARIF |
| AG-03 Dependency & IaC Auditor | job `ag03-dependency-iac` | Trivy, OSV-Scanner, Checkov | SARIF |

Patrón (ADR-001): AG-02 y AG-03 en paralelo → AG-01 consolida, deduplica, prioriza (CVSS → P1–P4) y enmascara secretos.
Runtime temporal en GitHub Actions (ADR-002, Lab costo cero).

## Apps de prueba

| Ruta | Vulnerabilidades sembradas |
|---|---|
| `apps/api-node` | SQLi, command injection, XSS, prototype pollution, credenciales hardcodeadas, `.env` versionado, dependencias con CVE, Dockerfile como root |
| `apps/api-flask` | SQLi, command injection, `yaml.load` y `pickle` inseguros, debug activo, dependencias con CVE |
| `infra/main.bicep` | Storage público con HTTP/TLS 1.0, Key Vault sin soft delete, App Service sin HTTPS y con FTP |

## Cómo usar

1. Crear un repo **público** en GitHub (CodeQL y minutos de Actions gratis) y subir este contenido.
2. Ir a **Actions** → `AG-01 Orquestador` → **Run workflow** (también corre en cada push/PR y los lunes a las 06:00 Bogotá).
3. Ver el resumen en la ejecución y descargar el artefacto `informe-ag01`. CodeQL publica en **Security → Code scanning**.

## Guardrails

- Permisos mínimos (`contents: read`); solo el job de CodeQL tiene `security-events: write`.
- Ningún agente modifica código, hace merge ni despliega (AG-04 llegará después y solo abrirá PRs).
- Escanear únicamente repos propios o con autorización escrita del dueño.

## Pendiente de endurecimiento (antes de clientes)

- Fijar acciones y contenedores por SHA/digest (hoy usan `@v4` / `:latest`) y activar Dependabot.
- Migrar el runtime a Foundry Agent Service (revertir ADR-002).
