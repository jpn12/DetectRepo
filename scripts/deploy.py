import json
import os
import subprocess
import sys
import tempfile
import uuid
import re
from pathlib import Path

import yaml  # pip install pyyaml

API_VERSION = "2025-07-01-preview"

OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
SUPPORTED_KINDS = ("Scheduled", "NRT")
 
REQUIRED_COMMON = ["name", "description", "severity", "query"]
REQUIRED_SCHEDULED = ["queryFrequency", "queryPeriod"]  # NRT não usa agendamento
 
# Mudanças nesses caminhos disparam deploy completo de todas as regras do cliente
FULL_DEPLOY_PREFIXES = ("content-packs/", "customers/", "scripts/", ".github/")
 
 
def mask(text: str, secrets: tuple) -> str:
    """Remove identificadores sensíveis de qualquer texto antes de imprimir."""
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text
 
 
def to_iso(d) -> str:
    """'5m' -> 'PT5M', '1h' -> 'PT1H', '1d' -> 'P1D'"""
    m = re.fullmatch(r"(\d+)([mhd])", str(d).strip())
    if not m:
        raise ValueError(f"duração inválida: {d}")
    n, u = m.groups()
    return f"P{n}D" if u == "d" else f"PT{n}{u.upper()}"
 
 
def changed_files():
    """Arquivos alterados no último commit. Retorna None se não for possível saber."""
    r = subprocess.run(["git", "diff", "--name-only", "HEAD~1", "HEAD"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return {line.strip() for line in r.stdout.splitlines() if line.strip()}
 
 
##def needs_full_deploy(changed) -> bool:
##    if os.environ.get("FORCE_FULL_DEPLOY") == "1":
##        return True
##    if changed is None:
##        return True
##    return any(p.startswith(FULL_DEPLOY_PREFIXES) for p in changed)
 
 
def find_rule_file(rule: str):
    """Resolve o caminho do pack para o .yaml real, ignorando maiúsculas/minúsculas."""
    target = Path(rule).with_suffix("").as_posix().lower()
    candidates = [p for p in Path("detections").rglob("*")
                  if p.suffix.lower() in (".yaml", ".yml")]
    for p in candidates:
        if p.with_suffix("").as_posix().lower() == target:
            return p
    # fallback: só pelo nome do arquivo (precisa ser único)
    stem = Path(rule).stem.lower()
    matches = [p for p in candidates if p.stem.lower() == stem]
    return matches[0] if len(matches) == 1 else None
 
 
def yaml_to_body(path: Path) -> dict:
    r = yaml.safe_load(path.read_text(encoding="utf-8"))
 
    kind = str(r.get("kind", "Scheduled")).strip()
    if kind not in SUPPORTED_KINDS:
        raise ValueError(f"kind inválido: '{kind}' (use {' ou '.join(SUPPORTED_KINDS)})")
 
    required = REQUIRED_COMMON + (REQUIRED_SCHEDULED if kind == "Scheduled" else [])
    missing = [k for k in required if not r.get(k)]
    if missing:
        raise ValueError(f"campos obrigatórios ausentes: {', '.join(missing)}")
 
    query = str(r["query"]).strip()
    if len(query) > 10000:
        raise ValueError(f"query com {len(query)} caracteres (limite ~10000)")
 
    # técnicas pai (T####) e sub-técnicas (T####.###) vão em campos separados
    all_techs = [str(t).strip() for t in r.get("relevantTechniques", [])]
    for t in all_techs:
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", t):
            raise ValueError(f"técnica inválida: '{t}'")
    techniques = sorted({t.split(".")[0] for t in all_techs})
    sub_techniques = [t for t in all_techs if "." in t]
 
    props = {
        "displayName": str(r["name"]).strip(),
        "description": str(r["description"]).strip(),
        "severity": r["severity"],
        "enabled": r.get("enabled", True),
        "query": query,
        "suppressionDuration": "PT5H",
        "suppressionEnabled": False,
        "tactics": r.get("tactics", []),
        "techniques": techniques,
        "subTechniques": sub_techniques,
        "entityMappings": r.get("entityMappings", []),
        "incidentConfiguration": {"createIncident": True},
        "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
    }
 
    if kind == "Scheduled":
        props.update({
            "queryFrequency": to_iso(r["queryFrequency"]),
            "queryPeriod": to_iso(r["queryPeriod"]),
            "triggerOperator": OPERATORS[r.get("triggerOperator", "gt")],
            "triggerThreshold": r.get("triggerThreshold", 0),
        })
 
    return {"kind": kind, "properties": props}
 
 
def list_existing(sub: str, rg: str, ws: str) -> dict:
    """Retorna {displayName em minúsculas: {"id": ..., "kind": ...}} do workspace."""
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
           f"/providers/Microsoft.SecurityInsights/alertRules?api-version={API_VERSION}")
    existing = {}
    while url:
        r = subprocess.run(["az", "rest", "--method", "get", "--url", url, "-o", "json"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            err = mask((r.stderr or r.stdout or ""), (sub, rg, ws))
            sys.exit(f"ERRO ao listar regras existentes:\n{err[:800]}")
        data = json.loads(r.stdout)
        for item in data.get("value", []):
            dn = item.get("properties", {}).get("displayName", "").strip().lower()
            if dn:
                if dn in existing:
                    print(f"AVISO: há mais de uma regra com o nome '{dn}' no workspace")
                existing[dn] = {"id": item["name"], "kind": item.get("kind")}
        url = data.get("nextLink")
    return existing
 
 
def main():
    if len(sys.argv) < 2:
        sys.exit("uso: python scripts/deploy.py <cliente>")
    customer = sys.argv[1]
 
    cfg_path = Path("customers") / f"{customer}.json"
    if not cfg_path.exists():
        sys.exit(f"ERRO: {cfg_path} não existe")
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    if "sentinel" not in cfg.get("platforms", {}):
        sys.exit(f"[{customer}] sem plataforma sentinel")
 
    sub = os.environ["AZURE_SUBSCRIPTION_ID"]
    rg = os.environ["RESOURCE_GROUP"]
    ws = os.environ["WORKSPACE"]
    secrets = (sub, rg, ws)
 
    # junta as regras de todos os packs do cliente
    rules = set()
    for pack_name in cfg["platforms"]["sentinel"]["content-packs"]:
        pack_path = Path("content-packs") / f"{pack_name}.json"
        if not pack_path.exists():
            sys.exit(f"ERRO: pack '{pack_name}' não existe")
        rules.update(json.loads(pack_path.read_text(encoding="utf-8"))["content"])
 
    # o que mudou neste commit? (define se é deploy completo ou só das regras alteradas)
    changed = changed_files()
    print(f"[{customer}] modo: {'APENAS ALTERADAS'}")
 
    # regras que já existem no workspace: {nome: {id, kind}}
    existing = list_existing(sub, rg, ws)
    seen_names = set()
 
    failed = []
    deployed = skipped = 0
    for rule in sorted(rules):
        f = find_rule_file(rule)
        if f is None:
            print(f"[{customer}] ERRO: yaml não encontrado para '{rule}'")
            failed.append(rule)
            continue
 
        if not full and f.as_posix() not in changed:
            print(f"[{customer}] SKIP   {f.name} (sem mudanças)")
            skipped += 1
            continue
 
        try:
            body = yaml_to_body(f)
        except Exception as e:
            print(f"[{customer}] ERRO em {f.name}: {e}")
            failed.append(f.name)
            continue
 
        key = body["properties"]["displayName"].strip().lower()
        kind = body["kind"]
 
        if key in seen_names:
            print(f"[{customer}] ERRO: nome duplicado '{key}' ({f.name})")
            failed.append(f.name)
            continue
        seen_names.add(key)
 
        # o tipo de uma regra existente não pode ser trocado (Scheduled <-> NRT)
        current = existing.get(key)
        if current and current["kind"] and current["kind"] != kind:
            print(f"[{customer}] ERRO: '{f.name}' é {kind}, mas no workspace a regra "
                  f"existente é {current['kind']}. Apague a antiga e rode de novo.")
            failed.append(f.name)
            continue
 
        # reaproveita o id da regra existente (mesmo nome); senão cria um novo
        rule_id = current["id"] if current else str(uuid.uuid4())
 
        url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
               f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
               f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
               f"?api-version={API_VERSION}")
 
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as tmp:
            json.dump(body, tmp)
            tmp_path = tmp.name
        try:
            r = subprocess.run(
                ["az", "rest", "--method", "put", "--url", url,
                 "--body", f"@{tmp_path}", "--only-show-errors", "-o", "none"],
                capture_output=True, text=True)
        finally:
            os.unlink(tmp_path)
 
        action = "UPDATE" if current else "CREATE"
        if r.returncode == 0:
            print(f"[{customer}] OK     {action} [{kind}] {f.name}")
            deployed += 1
        else:
            err = mask((r.stderr or r.stdout or "").strip(), secrets)
            print(f"[{customer}] FALHOU [{kind}] {f.name}\n{err[:1500]}")
            failed.append(f.name)
 
    print(f"[{customer}] resumo: {deployed} implantada(s), {skipped} ignorada(s), {len(failed)} com erro")
    if failed:
        sys.exit(f"[{customer}] {len(failed)} regra(s) com erro")
 
 
if __name__ == "__main__":
    main()