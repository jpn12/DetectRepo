import json, re
from pathlib import Path
import yaml  # pip install pyyaml

def to_iso(d: str) -> str:
    """'5m' -> 'PT5M', '1h' -> 'PT1H', '1d' -> 'P1D'"""
    m = re.fullmatch(r"(\d+)([mhd])", str(d).strip())
    if not m:
        raise ValueError(f"invalid duration: {d}")
    n, u = m.groups()
    return f"P{n}D" if u == "d" else f"PT{n}{u.upper()}"

OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}

def build(path: Path) -> dict:
    r = yaml.safe_load(path.read_text(encoding="utf-8"))
    query = r["query"].strip()
    if len(query) > 10000:
        raise ValueError(f"{path}: query has {len(query)} chars (limit ~10000)")
    props = {
        "displayName": r["name"],
        "description": r["description"].strip(),
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
        "techniques": r.get("relevantTechniques", []),
        "entityMappings": r.get("entityMappings", []),
        "incidentConfiguration": {"createIncident": True},
        "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
    }
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"workspace": {"type": "string"}},
        "resources": [{
            "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
            "apiVersion": "2023-02-01",
            "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{r['id']}')]",
            "kind": "Scheduled",
            "properties": props,
        }],
    }

if __name__ == "__main__":
    out = Path("build"); out.mkdir(exist_ok=True)
    for y in Path("detections/sentinel").rglob("*.yaml"):
        (out / f"{y.stem}.json").write_text(
            json.dumps(build(y), indent=2, ensure_ascii=False), encoding="utf-8")
        print("built", y.stem)