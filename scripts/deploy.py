import json
import os
import subprocess
import sys
from pathlib import Path

if len(sys.argv) < 2:
    sys.exit("uso: python scripts/deploy.py <nome-do-cliente>")

customer = sys.argv[1]
cfg_path = Path("customers") / f"{customer}.json"
if not cfg_path.exists():
    sys.exit(f"ERRO: {cfg_path} não existe")

cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
if "sentinel" not in cfg.get("platforms", {}):
    sys.exit(f"[{customer}] sem plataforma sentinel, nada a fazer")

resource_group = os.environ["RESOURCE_GROUP"]
workspace = os.environ["WORKSPACE"]

# junta as regras de todos os packs do cliente
rules = set()
for pack_name in cfg["platforms"]["sentinel"]["content-packs"]:
    pack_path = Path("content-packs") / f"{pack_name}.json"
    if not pack_path.exists():
        sys.exit(f"ERRO: pack '{pack_name}' não existe ({pack_path})")
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    rules.update(pack["content"])

failed = []
for rule in sorted(rules):
    name = Path(rule).name
    # prefere o ARM gerado em build/; senão usa o JSON original da regra
    template = Path("build") / f"{name}.json"
    if not template.exists():
        template = Path(rule + ".json")
    if not template.exists():
        print(f"[{customer}] ERRO: template não encontrado para '{rule}'")
        failed.append(name)
        continue

    r = subprocess.run([
        "az", "deployment", "group", "create",
        "--resource-group", resource_group,
        "--template-file", str(template),
        "--parameters", f"workspace={workspace}",
        "--only-show-errors", "-o", "none",
    ], capture_output=True, text=True)

    if r.returncode == 0:
        print(f"[{customer}] OK   {name}")
    else:
        print(f"[{customer}] FALHOU {name}")
        failed.append(name)

if failed:
    sys.exit(f"[{customer}] {len(failed)} regra(s) com erro")