import json, sys
from pathlib import Path

REQUIRED = ["displayName", "description", "severity", "query", "queryFrequency",
            "queryPeriod", "tactics", "enabled"]
REQUIRED_MD_SECTIONS = ["## Descrição", "## Descrição técnica",
                        "## Blindspots e limitações", "## Considerações para o SOC"]
errors = []

def err(msg): errors.append(msg); print("ERRO:", msg)

# 1. Regras
for f in Path("detections/sentinel").rglob("*.json"):
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except Exception as e:
        err(f"{f}: JSON inválido ({e})"); continue
    res = data.get("resources", [])
    if len(res) != 1:
        err(f"{f}: deve ter exatamente 1 recurso"); continue
    props = res[0].get("properties", {})
    for k in REQUIRED:
        if k not in props or props[k] in ("", None, []):
            err(f"{f}: campo ausente/vazio '{k}'")
    if "TimeGenerated" not in props.get("query", "") and "ago(" not in props.get("query", ""):
        print(f"AVISO: {f}: query sem filtro de tempo explícito")
    md = f.with_suffix(".md")
    if not md.exists():
        err(f"{f}: falta o arquivo .md")
    else:
        text = md.read_text(encoding="utf-8")
        for s in REQUIRED_MD_SECTIONS:
            if s not in text:
                err(f"{md}: falta a seção '{s}'")

# 2. Packs
for p in Path("content-packs").glob("*.json"):
    pack = json.loads(p.read_text(encoding="utf-8"))
    for item in pack["content"]:
        if not Path(item + ".json").exists():
            err(f"{p}: regra inexistente '{item}'")

# 3. Ambientes
cust = json.loads(Path("customers.json").read_text())
for env in cust["environments"]:
    for pk in env["content-packs"]:
        if not Path(f"content-packs/{pk}.json").exists():
            err(f"customers.json: pack inexistente '{pk}' em {env['name']}")

sys.exit(1 if errors else 0)