import json, re, sys
from pathlib import Path

OUT = Path("detections/sentinel/misc")

def slug(name: str) -> str:
    return re.sub(r'[\\/:*?"<>|]', "", name).strip()

def main(files):
    OUT.mkdir(parents=True, exist_ok=True)
    for f in files:
        data = json.loads(Path(f).read_text(encoding="utf-8"))
        for res in data.get("resources", []):
            props = res.get("properties", {})
            name = props.get("displayName")
            if not name:
                continue
            single = {
                "$schema": data.get("$schema"),
                "contentVersion": data.get("contentVersion", "1.0.0.0"),
                "parameters": data.get("parameters", {}),
                "resources": [res],
            }
            path = OUT / f"{slug(name)}.json"
            path.write_text(json.dumps(single, indent=2, ensure_ascii=False), encoding="utf-8")
            md = path.with_suffix(".md")
            if not md.exists():
                md.write_text(
f"""# {name}

## Descrição
{props.get('description', '')}

## Descrição técnica
(Como a regra funciona, tabelas usadas, lógica)

## Blindspots e limitações
(O que a regra NÃO detecta)

## Considerações para o SOC
(Falsos positivos comuns, como triar)
""", encoding="utf-8")
            print("OK", path)

if __name__ == "__main__":
    main(sys.argv[1:])