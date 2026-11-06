import json
import os
import subprocess
import sys
import tempfile
import re
from pathlib import Path

import yaml  # pip install pyyaml

API_VERSION = "2025-07-01-preview"
OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}


def to_iso(d) -> str:
    """'5m' -> 'PT5M', '1h' -> 'PT1H', '1d' -> 'P1D'"""
    m = re.fullmatch(r"(\d+)([mhd])", str(d).strip())
    if not m:
        raise ValueError(f"duração inválida: {d}")
    n, u = m.groups()
    return f"P{n}D" if u == "d" else f"PT{n}{u.upper()}"


def find_rule_file(rule: str):
    """Resolve o caminho do pack para o .yaml real, ignorando maiúsculas/minúsculas."""
    target = Path(rule).with_suffix("").as_posix().lower()
    for p in Path("detections").rglob("*.y*ml"):
        if p.suffix.lower() in (".yaml", ".yml") and p.with_suffix("").as_posix().lower() == target:
            return p
    # fallback: só pelo nome do arquivo
    stem = Path(rule).stem.lower()
    matches = [p for p in Path("detections").rglob("*")
               if p.suffix.lower() in (".yaml", ".yml") and p.stem.lower() == stem]
    return matches[0] if len(matches) == 1 else None


def yaml_to_body(path: Path) -> tuple[str, dict]:
    r = yaml.safe_load(path.read_text(encoding="utf-8"))
    query = r["query"].strip()
    if len(query) > 10000:
        raise ValueError(f"query com {len(query)} caracteres (limite ~10000)")
    all_techs = [str(t).strip() for t in r.get("relevantTechniques", [])]
    techniques = sorted({t.split(".")[0] for t in all_techs})   # T1110.003 -> T1110
    sub_techniques = [t for t in all_techs if "." in t]  
    body = {
        "kind": "Scheduled",
        "properties": {
            "displayName": r["name"],
            "description": str(r["description"]).strip(),
            "severity": r["severity"],
            "enabled": r.get("enabled", True),
            "query": query,
            "queryFrequency": to_iso(r["queryFrequency"]),
            "queryPeriod": to_iso(r["queryPeriod"]),
            "triggerOperator": OPERATORS[r.get("triggerOperator", "gt")],
            "triggerThreshold": r.get("triggerThreshold", 0),
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "tactics": r.get("tactics", []),
            "techniques": techniques,
            "subTechniques": sub_techniques,
            "entityMappings": r.get("entityMappings", []),
            "incidentConfiguration": {"createIncident": True},
            "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
        },
    }
    return str(r["id"]), body


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

    rules = set()
    for pack_name in cfg["platforms"]["sentinel"]["content-packs"]:
        pack_path = Path("content-packs") / f"{pack_name}.json"
        if not pack_path.exists():
            sys.exit(f"ERRO: pack '{pack_name}' não existe")
        rules.update(json.loads(pack_path.read_text(encoding="utf-8"))["content"])

    failed = []
    for rule in sorted(rules):
        f = find_rule_file(rule)
        if f is None:
            print(f"[{customer}] ERRO: yaml não encontrado para '{rule}'")
            failed.append(rule)
            continue
        try:
            rule_id, body = yaml_to_body(f)
        except Exception as e:
            print(f"[{customer}] ERRO em {f.name}: {e}")
            failed.append(f.name)
            continue

        url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
               f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
               f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
               f"?api-version={API_VERSION}")

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(body, tmp)
            tmp_path = tmp.name
        try:
            r = subprocess.run(
                ["az", "rest", "--method", "put", "--url", url,
                 "--body", f"@{tmp_path}", "--only-show-errors", "-o", "none"],
                capture_output=True, text=True)
        finally:
            os.unlink(tmp_path)

        if r.returncode == 0:
            print(f"[{customer}] OK     {f.name}")
        else:
            err = (r.stderr or r.stdout or "").strip()
            # remove identificadores do texto antes de imprimir
            for secret in (sub, rg, ws):
                err = err.replace(secret, "***")
            print(f"[{customer}] FALHOU {f.name}\n{err[:1500]}")
            failed.append(f.name)

    if failed:
        sys.exit(f"[{customer}] {len(failed)} regra(s) com erro")


if __name__ == "__main__":
    main()