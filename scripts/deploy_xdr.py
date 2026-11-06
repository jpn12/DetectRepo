import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
 
import yaml
 
GRAPH_RESOURCE = "https://graph.microsoft.com"
BASE_URL = f"{GRAPH_RESOURCE}/security/rules/detectionRules"
PLATFORM = "defender-xdr"
RULES_DIR = Path("detections") / PLATFORM
 
REQUIRED = ["name", "description", "query", "schedule", "alert"]
REQUIRED_ALERT = ["title", "description", "severity"]
SEVERITIES = {"informational", "low", "medium", "high"}
SCHEDULES = {"1h": "PT1H", "3h": "PT3H", "12h": "PT12H", "24h": "PT24H"}
 
# namespace fixo para gerar ids estáveis a partir do nome (nunca mude depois de usar)
NAMESPACE = uuid.UUID("6f1c2f0e-5b7a-4c3d-9a2e-1d4b8c7e9a10")
 
FULL_DEPLOY_PREFIXES = ("content-packs/", "customers/", "scripts/", ".github/")
 
 
def mask(text: str, secrets) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text
 
 
def changed_files():
    r = subprocess.run(["git", "diff", "--name-only", "HEAD~1", "HEAD"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return {line.strip() for line in r.stdout.splitlines() if line.strip()}
 
 
def needs_full_deploy(changed) -> bool:
    if os.environ.get("FORCE_FULL_DEPLOY") == "1" or changed is None:
        return True
    return any(p.startswith(FULL_DEPLOY_PREFIXES) for p in changed)
 
 
def find_rule_file(rule: str):
    target = Path(rule).with_suffix("").as_posix().lower()
    candidates = [p for p in RULES_DIR.rglob("*") if p.suffix.lower() in (".yaml", ".yml")]
    for p in candidates:
        if p.with_suffix("").as_posix().lower() == target:
            return p
    stem = Path(rule).stem.lower()
    matches = [p for p in candidates if p.stem.lower() == stem]
    return matches[0] if len(matches) == 1 else None
 
 
def load_rule(path: Path) -> dict:
    r = yaml.safe_load(path.read_text(encoding="utf-8"))
    missing = [k for k in REQUIRED if not r.get(k)]
    if missing:
        raise ValueError(f"campos obrigatórios ausentes: {', '.join(missing)}")
    alert = r["alert"]
    missing = [k for k in REQUIRED_ALERT if not alert.get(k)]
    if missing:
        raise ValueError(f"campos obrigatórios ausentes em 'alert': {', '.join(missing)}")
    if str(alert["severity"]).lower() not in SEVERITIES:
        raise ValueError(f"severity inválida: {alert['severity']}")
    if str(r["schedule"]).lower() not in SCHEDULES:
        raise ValueError(f"schedule inválido: {r['schedule']} (use {', '.join(SCHEDULES)})")
    return r
 
 
def build_body(r: dict, rule_id: str) -> dict:
    alert = dict(r["alert"])
    alert["severity"] = str(alert["severity"]).lower()
    action = {"alertTemplate": alert}
    if r.get("automatedActions"):
        action["automatedActions"] = r["automatedActions"]
    if r.get("incidentConfiguration"):
        action["incidentConfiguration"] = r["incidentConfiguration"]
    return {
        "@odata.type": "#microsoft.graph.security.detectionRule",
        "id": rule_id,
        "displayName": str(r["name"]).strip(),
        "description": str(r["description"]).strip(),
        "status": "enabled" if r.get("enabled", True) else "disabled",
        "queryCondition": {"queryText": str(r["query"]).strip()},
        "schedule": {"frequency": SCHEDULES[str(r["schedule"]).lower()]},
        "detectionAction": action,
    }
 
 
def az_rest(method: str, url: str, body=None):
    cmd = ["az", "rest", "--method", method, "--url", url,
           "--resource", GRAPH_RESOURCE, "--only-show-errors", "-o", "json"]
    tmp_path = None
    if body is not None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as tmp:
            json.dump(body, tmp)
            tmp_path = tmp.name
        cmd += ["--body", f"@{tmp_path}"]
    try:
        return subprocess.run(cmd, capture_output=True, text=True)
    finally:
        if tmp_path:
            os.unlink(tmp_path)
 
 
def list_existing(secrets) -> dict:
    """Retorna {displayName em minúsculas: id} das regras do tenant."""
    url, existing = BASE_URL, {}
    while url:
        r = az_rest("get", url)
        if r.returncode != 0:
            err = mask((r.stderr or r.stdout or ""), secrets)
            sys.exit(f"ERRO ao listar regras existentes:\n{err[:800]}")
        data = json.loads(r.stdout)
        for item in data.get("value", []):
            dn = str(item.get("displayName", "")).strip().lower()
            if dn:
                if dn in existing:
                    print(f"AVISO: mais de uma regra com o nome '{dn}' no tenant")
                existing[dn] = item["id"]
        url = data.get("@odata.nextLink")
    return existing
 
 
def main():
    if len(sys.argv) < 2:
        sys.exit("uso: python scripts/deploy_xdr.py <cliente>")
    customer = sys.argv[1]
 
    cfg_path = Path("customers") / f"{customer}.json"
    if not cfg_path.exists():
        sys.exit(f"ERRO: {cfg_path} não existe")
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    platform_cfg = cfg.get("platforms", {}).get(PLATFORM)
    if not platform_cfg:
        print(f"[{customer}] sem plataforma {PLATFORM}, nada a fazer")
        return
 
    secrets = (os.environ.get("AZURE_TENANT_ID"),)
 
    rules = set()
    for pack_name in platform_cfg["content-packs"]:
        pack_path = Path("content-packs") / f"{pack_name}.json"
        if not pack_path.exists():
            sys.exit(f"ERRO: pack '{pack_name}' não existe")
        rules.update(json.loads(pack_path.read_text(encoding="utf-8"))["content"])
 
    changed = changed_files()
    full = needs_full_deploy(changed)
    print(f"[{customer}] XDR modo: {'DEPLOY COMPLETO' if full else 'APENAS ALTERADAS'}")
 
    existing = list_existing(secrets)
    seen_names, failed = set(), []
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
            r = load_rule(f)
        except Exception as e:
            print(f"[{customer}] ERRO em {f.name}: {e}")
            failed.append(f.name)
            continue
 
        key = str(r["name"]).strip().lower()
        if key in seen_names:
            print(f"[{customer}] ERRO: nome duplicado '{key}' ({f.name})")
            failed.append(f.name)
            continue
        seen_names.add(key)
 
        current_id = existing.get(key)
        rule_id = current_id or str(uuid.uuid5(NAMESPACE, f"xdr-rule:{key}"))
        body = build_body(r, rule_id)
 
        if current_id:
            body.pop("id")                      # id vai na URL, não no corpo do PATCH
            res = az_rest("patch", f"{BASE_URL}/{current_id}", body)
            action = "UPDATE"
        else:
            res = az_rest("post", BASE_URL, body)
            action = "CREATE"
 
        if res.returncode == 0:
            print(f"[{customer}] OK     {action} {f.name}")
            deployed += 1
        else:
            err = mask((res.stderr or res.stdout or "").strip(), secrets)
            print(f"[{customer}] FALHOU {action} {f.name}\n{err[:1500]}")
            failed.append(f.name)
 
    print(f"[{customer}] XDR resumo: {deployed} implantada(s), {skipped} ignorada(s), {len(failed)} com erro")
    if failed:
        sys.exit(f"[{customer}] {len(failed)} regra(s) XDR com erro")
 
 
if __name__ == "__main__":
    main()