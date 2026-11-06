import json, subprocess, sys
from pathlib import Path

target = sys.argv[1] if len(sys.argv) > 1 else None   # ex: lab ou prod
cust = json.loads(Path("customers.json").read_text())

for env in cust["environments"]:
    if target and env["name"] != target:
        continue
    rules = set()
    for pk in env["content-packs"]:
        pack = json.loads(Path(f"content-packs/{pk}.json").read_text())
        rules.update(pack["content"])
    for r in sorted(rules):
        print(f"[{env['name']}] deploy {r}")
        subprocess.run([
            "az", "deployment", "group", "create",
            "--resource-group", env["resource_group"],
            "--template-file", r + ".json",
            "--parameters", f"workspace={env['workspace']}",
        ], check=True)