import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import yaml  # PyYAML (já vem instalado no runner do GitHub)

# =====================================================================================
# Configuração
# =====================================================================================

# Mudanças nesses caminhos fazem o script AVALIAR todas as regras do cliente
# (cada uma só é reenviada se estiver ausente ou diferente no ambiente).
FULL_DEPLOY_PREFIXES = ("content-packs/", "customers/", "scripts/", ".github/")

DETECTIONS_DIR = Path("detections")
XDR_DIR = DETECTIONS_DIR / "defender-xdr"

# --- Sentinel ---
SENTINEL_API_VERSION = "2024-03-01"  # subTechniques exige versão mais nova que 2023-02-01
OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
SENTINEL_KINDS = ("Scheduled", "NRT")
SENTINEL_REQUIRED = ["name", "description", "severity", "query"]
SENTINEL_REQUIRED_SCHEDULED = ["queryFrequency", "queryPeriod"]  # NRT não usa agendamento

# --- Defender XDR (Microsoft Graph, beta) ---
GRAPH_RESOURCE = "https://graph.microsoft.com"
XDR_URL = f"{GRAPH_RESOURCE}/beta/security/rules/detectionRules"
XDR_REQUIRED = ["name", "description", "query", "schedule", "alert"]
XDR_REQUIRED_ALERT = ["title", "description", "severity"]
XDR_SEVERITIES = {"informational", "low", "medium", "high"}
XDR_SCHEDULES = {"1h": "PT1H", "3h": "PT3H", "12h": "PT12H", "24h": "PT24H"}
# namespace fixo para gerar ids estáveis a partir do nome (nunca mude depois de usar)
XDR_NAMESPACE = uuid.UUID("6f1c2f0e-5b7a-4c3d-9a2e-1d4b8c7e9a10")

MITRE_ID = re.compile(r"T\d{4}(\.\d{3})?")

# --- Comparação ---
DURATION_KEYS = {"queryFrequency", "queryPeriod", "suppressionDuration",
                 "lookbackDuration", "frequency"}
CASEFOLD_KEYS = {"severity", "triggerOperator", "kind", "matchingMethod",
                 "aggregationKind", "status"}
_ISO_DURATION = re.compile(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?")


class DeployError(Exception):
    """Erro que interrompe a plataforma atual (as outras continuam)."""


class Scope:
    """O que será avaliado nesta execução."""

    def __init__(self):
        self.changed = changed_files()
        self.full = needs_full_deploy(self.changed)
        self.forced = os.environ.get("FORCE_REDEPLOY") == "1"

    def describe(self) -> str:
        base = "TODAS as regras do cliente" if self.full else "apenas YAMLs alterados"
        return base + (" | reenvio forçado" if self.forced else "")


# =====================================================================================
# Utilitários gerais
# =====================================================================================

def mask(text: str, secrets) -> str:
    """Remove identificadores sensíveis de qualquer texto antes de imprimir."""
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text


def changed_files():
    """Arquivos alterados no último commit. None se não for possível saber."""
    r = subprocess.run(["git", "diff", "--name-only", "HEAD~1", "HEAD"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return {line.strip() for line in r.stdout.splitlines() if line.strip()}


def needs_full_deploy(changed) -> bool:
    if os.environ.get("FORCE_FULL_DEPLOY") == "1" or changed is None:
        return True
    return any(p.startswith(FULL_DEPLOY_PREFIXES) for p in changed)


def to_iso(d) -> str:
    """'5m' -> 'PT5M', '1h' -> 'PT1H', '1d' -> 'P1D'"""
    m = re.fullmatch(r"(\d+)([mhd])", str(d).strip())
    if not m:
        raise ValueError(f"duração inválida: {d}")
    n, u = m.groups()
    return f"P{n}D" if u == "d" else f"PT{n}{u.upper()}"


def find_rule_file(rule: str, base: Path, exclude: Path = None):
    """Resolve o caminho do pack para o .yaml real, ignorando maiúsculas/minúsculas."""
    candidates = [p for p in base.rglob("*")
                  if p.suffix.lower() in (".yaml", ".yml")
                  and not (exclude and exclude in p.parents)]
    target = Path(rule).with_suffix("").as_posix().lower()
    for p in candidates:
        if p.with_suffix("").as_posix().lower() == target:
            return p
    stem = Path(rule).stem.lower()   # fallback: só pelo nome (precisa ser único)
    matches = [p for p in candidates if p.stem.lower() == stem]
    return matches[0] if len(matches) == 1 else None


def load_pack_rules(platform_cfg) -> set:
    rules = set()
    for pack_name in platform_cfg["content-packs"]:
        pack_path = Path("content-packs") / f"{pack_name}.json"
        if not pack_path.exists():
            raise DeployError(f"pack '{pack_name}' não existe")
        rules.update(json.loads(pack_path.read_text(encoding="utf-8"))["content"])
    return rules


# =====================================================================================
# Comparação: o que vamos enviar x o que já existe no ambiente
# =====================================================================================

def _duration_seconds(v: str):
    m = _ISO_DURATION.fullmatch(v.strip().upper())
    if not m or not any(m.groups()):
        return None
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + s


def _norm_str(key, v: str):
    if key in DURATION_KEYS:
        secs = _duration_seconds(v)
        if secs is not None:
            return secs
    v = v.replace("\r\n", "\n").strip()
    return v.casefold() if key in CASEFOLD_KEYS else v


def _is_empty(v) -> bool:
    return v is None or v == [] or v == {} or v == ""


def matches(sent, actual, key=None) -> bool:
    """True se tudo o que enviamos já está igual no ambiente.

    Campos que a API acrescenta por conta própria (valores padrão) são ignorados.
    """
    if isinstance(sent, dict):
        if not isinstance(actual, dict):
            return False
        for k, v in sent.items():
            if k not in actual or actual[k] is None:
                if _is_empty(v):
                    continue
                return False
            if not matches(v, actual[k], k):
                return False
        return True
    if isinstance(sent, list):
        if not isinstance(actual, list) or len(sent) != len(actual):
            return False
        if all(not isinstance(x, (dict, list)) for x in sent):
            return sorted(map(str, sent)) == sorted(map(str, actual))
        pool = list(actual)
        for item in sent:
            for i, cand in enumerate(pool):
                if matches(item, cand, key):
                    pool.pop(i)
                    break
            else:
                return False
        return True
    if isinstance(sent, str):
        return isinstance(actual, str) and _norm_str(key, sent) == _norm_str(key, actual)
    return sent == actual


def differing_keys(sent: dict, actual: dict) -> list:
    """Nomes (nunca valores) dos campos de primeiro nível que diferem."""
    out = []
    for k, v in sent.items():
        have = actual.get(k)
        if _is_empty(v) and _is_empty(have):
            continue
        if not matches(v, have, k):
            out.append(k)
    return out


# =====================================================================================
# Microsoft Sentinel
# =====================================================================================

def sentinel_body(path: Path) -> dict:
    r = yaml.safe_load(path.read_text(encoding="utf-8"))

    kind = str(r.get("kind", "Scheduled")).strip()
    if kind not in SENTINEL_KINDS:
        raise ValueError(f"kind inválido: '{kind}' (use {' ou '.join(SENTINEL_KINDS)})")

    required = SENTINEL_REQUIRED + (SENTINEL_REQUIRED_SCHEDULED if kind == "Scheduled" else [])
    missing = [k for k in required if not r.get(k)]
    if missing:
        raise ValueError(f"campos obrigatórios ausentes: {', '.join(missing)}")

    query = str(r["query"]).strip()
    if len(query) > 10000:
        raise ValueError(f"query com {len(query)} caracteres (limite ~10000)")

    # técnicas pai (T####) e sub-técnicas (T####.###) vão em campos separados
    all_techs = [str(t).strip() for t in r.get("relevantTechniques", []) or []]
    for t in all_techs:
        if not MITRE_ID.fullmatch(t):
            raise ValueError(f"técnica inválida: '{t}'")
    techniques = sorted({t.split(".")[0] for t in all_techs})
    sub_techniques = [t for t in all_techs if "." in t]

    props = {
        "displayName": str(r["name"]).strip(),
        "description": str(r["description"]).strip(),
        "severity": r["severity"],
        "enabled": r.get("enabled", True),
        "query": query,
        "suppressionDuration": r.get("suppressionDuration", "PT5H"),
        "suppressionEnabled": r.get("suppressionEnabled", False),
        "tactics": r.get("tactics", []) or [],
        "techniques": techniques,
        "subTechniques": sub_techniques,
        "incidentConfiguration": r.get("incidentConfiguration", {"createIncident": True}),
        "eventGroupingSettings": r.get("eventGroupingSettings",
                                       {"aggregationKind": "SingleAlert"}),
    }
    # opcionais: só vão se existirem (a API recusa entityMappings vazio)
    for opt in ("entityMappings", "alertDetailsOverride", "customDetails"):
        if r.get(opt):
            props[opt] = r[opt]

    if kind == "Scheduled":
        props.update({
            "queryFrequency": to_iso(r["queryFrequency"]),
            "queryPeriod": to_iso(r["queryPeriod"]),
            "triggerOperator": OPERATORS[r.get("triggerOperator", "gt")],
            "triggerThreshold": r.get("triggerThreshold", 0),
        })

    return {"kind": kind, "properties": props}


def sentinel_list_existing(sub: str, rg: str, ws: str) -> dict:
    """Retorna {displayName em minúsculas: {"id", "kind", "properties"}} do workspace."""
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
           f"/providers/Microsoft.SecurityInsights/alertRules"
           f"?api-version={SENTINEL_API_VERSION}")
    existing = {}
    while url:
        r = subprocess.run(["az", "rest", "--method", "get", "--url", url, "-o", "json"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            err = mask((r.stderr or r.stdout or ""), (sub, rg, ws))
            raise DeployError(f"erro ao listar regras existentes:\n{err[:800]}")
        data = json.loads(r.stdout)
        for item in data.get("value", []):
            props = item.get("properties", {})
            dn = str(props.get("displayName", "")).strip().lower()
            if dn:
                if dn in existing:
                    print(f"AVISO: há mais de uma regra com o nome '{dn}' no workspace")
                existing[dn] = {"id": item["name"], "kind": item.get("kind"),
                                "properties": props}
        url = data.get("nextLink")
    return existing


def deploy_sentinel(customer: str, cfg: dict, scope: Scope) -> int:
    """Retorna o número de regras com erro."""
    try:
        sub = os.environ["AZURE_SUBSCRIPTION_ID"]
        rg = os.environ["RESOURCE_GROUP"]
        ws = os.environ["WORKSPACE"]
    except KeyError as e:
        raise DeployError(f"variável de ambiente ausente: {e}")
    secrets = (sub, rg, ws)
    tag = f"[{customer}][sentinel]"

    rules = load_pack_rules(cfg)
    existing = sentinel_list_existing(sub, rg, ws)
    seen_names, failed = set(), []
    deployed = uptodate = skipped = 0

    for rule in sorted(rules):
        f = find_rule_file(rule, DETECTIONS_DIR, exclude=XDR_DIR)
        if f is None:
            print(f"{tag} ERRO: yaml não encontrado para '{rule}'")
            failed.append(rule)
            continue

        if not scope.full and f.as_posix() not in scope.changed:
            print(f"{tag} SKIP     {f.name} (arquivo não alterado)")
            skipped += 1
            continue

        try:
            body = sentinel_body(f)
        except Exception as e:
            print(f"{tag} ERRO em {f.name}: {e}")
            failed.append(f.name)
            continue

        key = body["properties"]["displayName"].strip().lower()
        kind = body["kind"]

        if key in seen_names:
            print(f"{tag} ERRO: nome duplicado '{key}' ({f.name})")
            failed.append(f.name)
            continue
        seen_names.add(key)

        current = existing.get(key)

        # o tipo de uma regra existente não pode ser trocado (Scheduled <-> NRT)
        if current and current["kind"] and current["kind"] != kind:
            print(f"{tag} ERRO: '{f.name}' é {kind}, mas no workspace a regra existente "
                  f"é {current['kind']}. Apague a antiga e rode de novo.")
            failed.append(f.name)
            continue

        # já implantada e idêntica? então não reenvia
        diff = []
        if current:
            diff = differing_keys(body["properties"], current["properties"])
            if not diff and not scope.forced:
                print(f"{tag} UPTODATE {f.name} (já implantada, sem alterações)")
                uptodate += 1
                continue

        rule_id = current["id"] if current else str(uuid.uuid4())
        url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
               f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
               f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}"
               f"?api-version={SENTINEL_API_VERSION}")

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
        detail = f" (campos: {', '.join(diff)})" if diff else ""
        if r.returncode == 0:
            print(f"{tag} OK       {action} [{kind}] {f.name}{detail}")
            deployed += 1
        else:
            err = mask((r.stderr or r.stdout or "").strip(), secrets)
            print(f"{tag} FALHOU   {action} [{kind}] {f.name}\n{err[:1500]}")
            failed.append(f.name)

    print(f"{tag} resumo: {deployed} implantada(s), {uptodate} já atualizada(s), "
          f"{skipped} ignorada(s), {len(failed)} com erro")
    return len(failed)


# =====================================================================================
# Microsoft Defender XDR (custom detection rules via Graph)
# =====================================================================================

def normalize_tactics(tactics):
    """A API só aceita a técnica PAI em 'technique'; sub-técnicas vão em 'subTechniques'.

    Aceita no YAML tanto T1059 quanto T1059.001 em 'technique' (ou em 'subTechniques')
    e converte para o formato que a API exige.
    """
    result = []
    for t in tactics or []:
        if not t.get("tactic"):
            raise ValueError("item de 'tactics' sem o campo 'tactic'")
        merged = {}
        for tech in t.get("techniques") or []:
            if isinstance(tech, str):
                tech = {"technique": tech}
            if not tech.get("technique"):
                raise ValueError(f"técnica sem o campo 'technique' na tática {t['tactic']}")
            ids = [str(tech["technique"]).strip()]
            ids += [str(x).strip() for x in tech.get("subTechniques") or []]
            for tid in ids:
                if not MITRE_ID.fullmatch(tid):
                    raise ValueError(f"técnica MITRE inválida: '{tid}'")
                subs = merged.setdefault(tid.split(".")[0], [])
                if "." in tid and tid not in subs:
                    subs.append(tid)
        techniques = []
        for parent, subs in merged.items():
            entry = {"technique": parent}
            if subs:
                entry["subTechniques"] = sorted(subs)
            techniques.append(entry)
        result.append({"tactic": t["tactic"], "techniques": techniques})
    return result


def xdr_load_rule(path: Path) -> dict:
    r = yaml.safe_load(path.read_text(encoding="utf-8"))
    missing = [k for k in XDR_REQUIRED if not r.get(k)]
    if missing:
        raise ValueError(f"campos obrigatórios ausentes: {', '.join(missing)}")
    alert = r["alert"]
    missing = [k for k in XDR_REQUIRED_ALERT if not alert.get(k)]
    if missing:
        raise ValueError(f"campos obrigatórios ausentes em 'alert': {', '.join(missing)}")
    if str(alert["severity"]).lower() not in XDR_SEVERITIES:
        raise ValueError(f"severity inválida: {alert['severity']}")
    if str(r["schedule"]).lower() not in XDR_SCHEDULES:
        raise ValueError(f"schedule inválido: {r['schedule']} (use {', '.join(XDR_SCHEDULES)})")
    if alert.get("tactics"):
        alert["tactics"] = normalize_tactics(alert["tactics"])
    return r


def xdr_body(r: dict, rule_id: str) -> dict:
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
        "schedule": {"frequency": XDR_SCHEDULES[str(r["schedule"]).lower()]},
        "detectionAction": action,
    }


def graph_rest(method: str, url: str, body=None):
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


def xdr_list_existing(secrets) -> dict:
    """Retorna {displayName em minúsculas: {"id", "item"}} das regras do tenant."""
    url, existing = XDR_URL, {}
    while url:
        r = graph_rest("get", url)
        if r.returncode != 0:
            err = mask((r.stderr or r.stdout or ""), secrets)
            raise DeployError(f"erro ao listar regras existentes:\n{err[:800]}")
        data = json.loads(r.stdout)
        for item in data.get("value", []):
            dn = str(item.get("displayName", "")).strip().lower()
            if dn:
                if dn in existing:
                    print(f"AVISO: mais de uma regra com o nome '{dn}' no tenant")
                existing[dn] = {"id": item["id"], "item": item}
        url = data.get("@odata.nextLink")
    return existing


def deploy_xdr(customer: str, cfg: dict, scope: Scope) -> int:
    """Retorna o número de regras com erro."""
    secrets = (os.environ.get("AZURE_TENANT_ID"),)
    tag = f"[{customer}][xdr]"

    rules = load_pack_rules(cfg)
    existing = xdr_list_existing(secrets)
    seen_names, failed = set(), []
    deployed = uptodate = skipped = 0

    for rule in sorted(rules):
        f = find_rule_file(rule, XDR_DIR)
        if f is None:
            print(f"{tag} ERRO: yaml não encontrado para '{rule}'")
            failed.append(rule)
            continue
        if not scope.full and f.as_posix() not in scope.changed:
            print(f"{tag} SKIP     {f.name} (arquivo não alterado)")
            skipped += 1
            continue

        try:
            r = xdr_load_rule(f)
        except Exception as e:
            print(f"{tag} ERRO em {f.name}: {e}")
            failed.append(f.name)
            continue

        key = str(r["name"]).strip().lower()
        if key in seen_names:
            print(f"{tag} ERRO: nome duplicado '{key}' ({f.name})")
            failed.append(f.name)
            continue
        seen_names.add(key)

        current = existing.get(key)
        rule_id = current["id"] if current else str(uuid.uuid5(XDR_NAMESPACE, f"xdr-rule:{key}"))
        body = xdr_body(r, rule_id)

        # já implantada e idêntica? então não reenvia
        diff = []
        if current:
            sent = {k: v for k, v in body.items() if k not in ("id", "@odata.type")}
            diff = differing_keys(sent, current["item"])
            if not diff and not scope.forced:
                print(f"{tag} UPTODATE {f.name} (já implantada, sem alterações)")
                uptodate += 1
                continue

        if current:
            body.pop("id")                      # id vai na URL, não no corpo do PATCH
            res = graph_rest("patch", f"{XDR_URL}/{current['id']}", body)
            action = "UPDATE"
        else:
            res = graph_rest("post", XDR_URL, body)
            action = "CREATE"

        detail = f" (campos: {', '.join(diff)})" if diff else ""
        if res.returncode == 0:
            print(f"{tag} OK       {action} {f.name}{detail}")
            deployed += 1
        else:
            err = mask((res.stderr or res.stdout or "").strip(), secrets)
            print(f"{tag} FALHOU   {action} {f.name}\n{err[:1500]}")
            failed.append(f.name)

    print(f"{tag} resumo: {deployed} implantada(s), {uptodate} já atualizada(s), "
          f"{skipped} ignorada(s), {len(failed)} com erro")
    return len(failed)


# =====================================================================================
# Roteador: uma função por plataforma
# =====================================================================================

PLATFORMS = {
    "sentinel": deploy_sentinel,
    "defender-xdr": deploy_xdr,
}


def main():
    if len(sys.argv) < 2:
        sys.exit("uso: python scripts/deploy.py <cliente> [sentinel|defender-xdr]")
    customer = sys.argv[1]
    only = sys.argv[2] if len(sys.argv) > 2 else None
    if only and only not in PLATFORMS:
        sys.exit(f"plataforma desconhecida: {only} (use {', '.join(PLATFORMS)})")

    cfg_path = Path("customers") / f"{customer}.json"
    if not cfg_path.exists():
        sys.exit(f"ERRO: {cfg_path} não existe")
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    platforms = cfg.get("platforms", {})

    scope = Scope()
    print(f"[{customer}] escopo: {scope.describe()}")

    total_failed, ran = 0, 0
    for name, fn in PLATFORMS.items():
        if only and name != only:
            continue
        if name not in platforms:
            continue
        ran += 1
        try:
            total_failed += fn(customer, platforms[name], scope)
        except DeployError as e:
            print(f"[{customer}][{name}] ERRO: {e}")
            total_failed += 1

    if ran == 0:
        print(f"[{customer}] nenhuma plataforma para implantar")
    if total_failed:
        sys.exit(f"[{customer}] {total_failed} erro(s)")


if __name__ == "__main__":
    main()