"""Validação para Pull Requests. Não usa credenciais nem acessa nenhum ambiente.

uso: python scripts/validate.py

Verifica:
  - todas as regras (Sentinel e Defender XDR): campos, MITRE, duração, kind
  - nomes de regra únicos por plataforma
  - marcador "// DAC:exceptions" x "exception_fields"
  - packs e clientes apontando para regras/packs que existem
  - exceções de cada cliente: formato, campos permitidos, IPs, validade e tamanho da query
Os valores das exceções (IPs, usuários etc.) nunca são impressos.
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

import deploy


def main() -> int:
    errors, warnings = [], []

    def err(msg):
        errors.append(msg)
        print(f"ERRO:  {msg}")

    def warn(msg):
        warnings.append(msg)
        print(f"AVISO: {msg}")

    today = datetime.now(timezone.utc).date()
    rules = {p: {} for p in deploy.PLATFORM_NAMES}   # plataforma -> {nome minúsculo: Path}

    # ---------- 1. regras ----------
    for path in sorted(deploy.DETECTIONS_DIR.rglob("*")):
        if path.suffix.lower() not in (".yaml", ".yml"):
            continue
        plat = "defender-xdr" if deploy.XDR_DIR in path.parents else "sentinel"
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            err(f"{path.as_posix()}: YAML inválido")
            continue
        try:
            if plat == "sentinel":
                deploy.sentinel_body(path)
            else:
                deploy.xdr_load_rule(path)
        except Exception as e:
            err(f"{path.as_posix()}: {e}")
            continue

        key = str(raw["name"]).strip().lower()
        if key in rules[plat]:
            err(f"nome de regra duplicado em {plat}: '{key}' "
                f"({rules[plat][key].name} e {path.name})")
        rules[plat][key] = path

        has_marker = bool(deploy.EXC_MARKER.search(str(raw.get("query", ""))))
        fields = raw.get("exception_fields") or []
        if has_marker and not fields:
            err(f"{path.as_posix()}: tem o marcador '// DAC:exceptions' mas não declara 'exception_fields'")
        if fields and not has_marker:
            warn(f"{path.as_posix()}: declara 'exception_fields' mas não tem o marcador '// DAC:exceptions'")
        for fld in fields:
            if not deploy.FIELD_RE.fullmatch(str(fld)):
                err(f"{path.as_posix()}: exception_fields contém nome inválido: '{fld}'")

    # ---------- 2. packs ----------
    packs = {}
    for pack_path in sorted(Path("content-packs").glob("*.json")):
        try:
            pack = json.loads(pack_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            err(f"{pack_path.as_posix()}: JSON inválido")
            continue
        packs[pack_path.stem] = pack
        plat = pack.get("platform", "sentinel")
        if plat == "defender-xdr":
            base, excl = deploy.XDR_DIR, None
        else:
            base, excl = deploy.DETECTIONS_DIR, deploy.XDR_DIR
        for item in pack.get("content", []):
            if deploy.find_rule_file(item, base, excl) is None:
                err(f"{pack_path.as_posix()}: regra não encontrada: '{item}'")

    # ---------- 3. clientes ----------
    customers_dir = Path("customers")
    customer_names = set()
    for cpath in sorted(customers_dir.glob("*.json")):
        customer_names.add(cpath.stem)
        try:
            cfg = json.loads(cpath.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            err(f"{cpath.as_posix()}: JSON inválido")
            continue
        if cfg.get("customer") != cpath.stem:
            warn(f"{cpath.as_posix()}: o campo 'customer' deve ser igual ao nome do arquivo "
                 f"(e ao nome do Environment no GitHub)")
        for plat, pcfg in (cfg.get("platforms") or {}).items():
            for pk in pcfg.get("content-packs", []):
                if pk not in packs:
                    err(f"{cpath.as_posix()}: pack inexistente '{pk}' em {plat}")

    # ---------- 4. exceções por cliente ----------
    if customers_dir.is_dir():
        for d in sorted(p for p in customers_dir.iterdir() if p.is_dir()):
            customer = d.name
            if customer not in customer_names:
                warn(f"customers/{customer}/ existe, mas customers/{customer}.json não")
            for plat in deploy.PLATFORM_NAMES:
                try:
                    exc_map = deploy.load_customer_exceptions(customer, plat)
                except deploy.DeployError as e:
                    err(f"[{customer}] {e}")
                    continue
                for name, excs in exc_map.items():
                    rule_path = rules[plat].get(name)
                    if rule_path is None:
                        err(f"[{customer}] exceções para regra inexistente em {plat}: '{name}'")
                        continue
                    try:
                        if plat == "sentinel":
                            _, meta = deploy.sentinel_body(rule_path, {name: excs})
                        else:
                            _, meta = deploy.xdr_load_rule(rule_path, {name: excs})
                    except Exception as e:
                        err(f"[{customer}] {rule_path.name}: {e}")
                        continue
                    if meta["expired"]:
                        warn(f"[{customer}] {rule_path.name}: {meta['expired']} exceção(ões) vencida(s)")
                    for i, exc in enumerate(excs, 1):
                        try:
                            exp = deploy.parse_expires(exc["expires"])
                        except Exception:
                            continue
                        if exp - today > timedelta(days=deploy.MAX_EXPIRY_DAYS):
                            warn(f"[{customer}] {rule_path.name}: exceção #{i} vence em mais de "
                                 f"{deploy.MAX_EXPIRY_DAYS} dias")

    total = sum(len(v) for v in rules.values())
    print(f"\n{total} regra(s) verificada(s), {len(errors)} erro(s), {len(warnings)} aviso(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())