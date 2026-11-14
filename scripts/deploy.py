import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import date, datetime, timezone
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
PLATFORM_NAMES = ("sentinel", "defender-xdr")

# --- Sentinel ---
SENTINEL_API_VERSION = "2025-07-01-preview"  # subTechniques exige versão mais nova que 2023-02-01
OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}
SENTINEL_KINDS = ("Scheduled", "NRT")
SENTINEL_REQUIRED = ["name", "description", "severity", "query"]
SENTINEL_REQUIRED_SCHEDULED = ["queryFrequency", "queryPeriod"]  # NRT não usa agendamento
SENTINEL_MAX_QUERY = 10000

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

# --- Exceções por cliente ---
EXC_MARKER = re.compile(r"^[ \t]*//[ \t]*DAC:exceptions[ \t]*$", re.MULTILINE)
EXC_OPERATORS = ("equals", "contains", "startswith", "in", "in_range", "in_watchlist")
FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_LIST_VALUES = 500
WATCHLIST_ALIAS_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
WATCHLIST_REF_RE = re.compile(r"_GetWatchlist\(\s*['\"]([^'\"]+)['\"]\s*\)")
MAX_EXPIRY_DAYS = 365   # acima disso o validate.py apenas avisa
OVERRIDE_KEYS = {"rule", "platform", "enabled", "reason", "ticket", "expires"}

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
# Exceções por cliente: YAML declarativo -> KQL
#
# Regras de segurança: operadores de uma lista fixa, nomes de campo validados contra
# "exception_fields" da regra, valores sempre escapados e NUNCA impressos em log.
# =====================================================================================

def parse_expires(value) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise ValueError("'expires' deve ser uma data no formato AAAA-MM-DD")


def kql_str(v) -> str:
    """Literal de texto KQL com escape. Rejeita tipos que o YAML converte sem avisar."""
    if not isinstance(v, str):
        raise ValueError("valor deve ser texto (coloque entre aspas no YAML)")
    if v == "":
        raise ValueError("valor vazio")
    if CONTROL_RE.search(v):
        raise ValueError("valor contém caracteres de controle")
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_ip_range(raw, allow_broad: bool):
    """Aceita IP solto ou CIDR (IPv4/IPv6). Nunca inclui o valor na mensagem de erro."""
    if not isinstance(raw, str):
        raise ValueError("deve ser texto")
    s = raw.strip()
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=True)
        else:
            ip = ipaddress.ip_address(s)
            net = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}")
    except ValueError:
        raise ValueError("IP/CIDR inválido (CIDR com bits de host também é recusado)")
    if net.prefixlen == 0:
        raise ValueError("faixa 0.0.0.0/0 (ou ::/0) não é permitida")
    min_prefix = 16 if net.version == 4 else 32
    if net.prefixlen < min_prefix and not allow_broad:
        raise ValueError(f"faixa muito ampla (menor que /{min_prefix}); "
                         f"use allow_broad: true se for intencional")
    return net


def compile_condition(field: str, spec, allow_broad: bool, allow_watchlist: bool = True) -> str:
    # atalhos: valor simples = equals; lista = in
    if not isinstance(spec, dict):
        spec = {"in": spec} if isinstance(spec, list) else {"equals": spec}
    if len(spec) != 1:
        raise ValueError(f"campo '{field}': use exatamente um operador")
    (op, val), = spec.items()
    if op not in EXC_OPERATORS:
        raise ValueError(f"campo '{field}': operador inválido '{op}' "
                         f"(use {', '.join(EXC_OPERATORS)})")

    if op == "in_watchlist":
        if not allow_watchlist:
            raise ValueError(f"campo '{field}': 'in_watchlist' só é suportado no Sentinel")
        alias, column = val, "SearchKey"
        if isinstance(val, dict):
            if set(val) - {"alias", "column"}:
                raise ValueError(f"campo '{field}': in_watchlist aceita apenas 'alias' e 'column'")
            alias, column = val.get("alias"), val.get("column", "SearchKey")
        if not isinstance(alias, str) or not WATCHLIST_ALIAS_RE.fullmatch(alias):
            raise ValueError(f"campo '{field}': alias de watchlist inválido "
                             f"(use letras, números, '-' e '_', até 64 caracteres)")
        if not isinstance(column, str) or not FIELD_RE.fullmatch(column):
            raise ValueError(f"campo '{field}': nome de coluna da watchlist inválido")
        return f"coalesce({field} in ((_GetWatchlist('{alias}') | project {column})), false)"

    if op in ("equals", "contains", "startswith"):
        kop = {"equals": "=~", "contains": "contains", "startswith": "startswith"}[op]
        try:
            lit = kql_str(val)
        except ValueError as e:
            raise ValueError(f"campo '{field}': {e}")
        return f"coalesce({field} {kop} {lit}, false)"

    if not isinstance(val, list) or not val:
        raise ValueError(f"campo '{field}': '{op}' exige uma lista não vazia")
    if len(val) > MAX_LIST_VALUES:
        raise ValueError(f"campo '{field}': lista com mais de {MAX_LIST_VALUES} itens "
                         f"(para listas grandes use watchlist)")

    if op == "in":
        try:
            items = ", ".join(kql_str(x) for x in val)
        except ValueError as e:
            raise ValueError(f"campo '{field}': {e}")
        return f"coalesce({field} in~ ({items}), false)"

    # in_range: IPs soltos e CIDRs
    v4, v6 = [], []
    for i, raw in enumerate(val, 1):
        try:
            net = parse_ip_range(raw, allow_broad)
        except ValueError as e:
            raise ValueError(f"campo '{field}': in_range item {i}: {e}")
        (v4 if net.version == 4 else v6).append(str(net))
    parts = []
    if v4:
        parts.append(f"ipv4_is_in_any_range({field}, dynamic([{', '.join(json.dumps(x) for x in v4)}]))")
    if v6:
        parts.append(f"ipv6_is_in_any_range({field}, dynamic([{', '.join(json.dumps(x) for x in v6)}]))")
    # coalesce: valor que não é IP (ex.: nome de serviço da AWS) vira "não casa", em vez de
    # null, que faria o 'where not(...)' descartar o evento em silêncio
    return f"coalesce({' or '.join(parts)}, false)"


def compile_exception(exc, allowed_fields: set, today: date, allow_watchlist: bool = True):
    """Retorna a expressão KQL da exceção, ou None se estiver vencida."""
    if not isinstance(exc, dict):
        raise ValueError("cada exceção deve ser um mapa")
    for k in ("reason", "ticket", "expires", "when"):
        if not exc.get(k):
            raise ValueError(f"campo obrigatório ausente: '{k}'")
    expires = parse_expires(exc["expires"])
    if expires < today:
        return None
    when = exc["when"]
    if not isinstance(when, dict):
        raise ValueError("'when' deve ser um mapa campo -> condição")
    allow_broad = bool(exc.get("allow_broad", False))
    conds = []
    for field, spec in when.items():
        field = str(field)
        if not FIELD_RE.fullmatch(field):
            raise ValueError(f"nome de campo inválido: '{field}'")
        if field not in allowed_fields:
            raise ValueError(f"campo '{field}' não é permitido nesta regra (exception_fields)")
        conds.append(compile_condition(field, spec, allow_broad, allow_watchlist))
    return " and ".join(conds)


def render_query(r: dict, exceptions, today: date = None, allow_watchlist: bool = True):
    """Injeta as exceções do cliente na query. Retorna (query, ativas, vencidas)."""
    query = str(r["query"]).strip()
    if not exceptions:
        return query, 0, 0
    today = today or datetime.now(timezone.utc).date()
    if not EXC_MARKER.search(query):
        raise ValueError("há exceções para esta regra, mas ela não tem o marcador '// DAC:exceptions' "
                         "na query (nem 'exception_fields'), então não aceita exceções")
    allowed = {str(f) for f in (r.get("exception_fields") or [])}
    if not allowed:
        raise ValueError("a regra não declara 'exception_fields'")

    exprs, expired = [], 0
    for i, exc in enumerate(exceptions, 1):
        try:
            expr = compile_exception(exc, allowed, today, allow_watchlist)
        except ValueError as e:
            raise ValueError(f"exceção #{i}: {e}")
        if expr is None:
            expired += 1
        else:
            exprs.append(expr)
    if not exprs:
        return query, 0, expired

    block = "| where not(\n" + "\n    or\n".join(f"    ({e})" for e in exprs) + "\n  )"
    return EXC_MARKER.sub(lambda m: block, query, count=1), len(exprs), expired


def load_customer_exceptions(customer: str, platform: str) -> dict:
    """Lê customers/<cliente>/exceptions/*.yaml -> {nome da regra em minúsculas: [exceções]}."""
    out = {}
    d = Path("customers") / customer / "exceptions"
    if not d.is_dir():
        return out
    for f in sorted(d.rglob("*")):
        if f.suffix.lower() not in (".yaml", ".yml"):
            continue
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:   # a mensagem do PyYAML pode conter trechos do arquivo
            raise DeployError(f"YAML inválido em {f.as_posix()}")
        if not isinstance(data, dict):
            raise DeployError(f"{f.as_posix()}: formato inválido")
        plat = str(data.get("platform", "sentinel"))
        if plat not in PLATFORM_NAMES:
            raise DeployError(f"{f.as_posix()}: platform inválida (use {', '.join(PLATFORM_NAMES)})")
        if plat != platform:
            continue
        rule = str(data.get("rule", "")).strip()
        if not rule:
            raise DeployError(f"{f.as_posix()}: falta o campo 'rule'")
        excs = data.get("exceptions")
        if not isinstance(excs, list) or not excs:
            raise DeployError(f"{f.as_posix()}: 'exceptions' deve ser uma lista não vazia")
        out.setdefault(rule.lower(), []).extend(excs)
    return out


def load_customer_overrides(customer: str, platform: str) -> dict:
    """Lê customers/<cliente>/overrides/*.yaml -> {nome da regra em minúsculas: override}."""
    out = {}
    d = Path("customers") / customer / "overrides"
    if not d.is_dir():
        return out
    for f in sorted(d.rglob("*")):
        if f.suffix.lower() not in (".yaml", ".yml"):
            continue
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            raise DeployError(f"YAML inválido em {f.as_posix()}")
        items = data.get("overrides") if isinstance(data, dict) else None
        if not isinstance(items, list) or not items:
            raise DeployError(f"{f.as_posix()}: 'overrides' deve ser uma lista não vazia")
        for i, item in enumerate(items, 1):
            if not isinstance(item, dict):
                raise DeployError(f"{f.as_posix()}: override #{i} deve ser um mapa")
            unknown = sorted(set(map(str, item)) - OVERRIDE_KEYS)
            if unknown:
                raise DeployError(f"{f.as_posix()}: override #{i}: campo(s) não suportado(s): "
                                  f"{', '.join(unknown)} (aceitos: {', '.join(sorted(OVERRIDE_KEYS))})")
            plat = str(item.get("platform", "sentinel"))
            if plat not in PLATFORM_NAMES:
                raise DeployError(f"{f.as_posix()}: override #{i}: platform inválida")
            if plat != platform:
                continue
            rule = str(item.get("rule", "")).strip()
            if not rule:
                raise DeployError(f"{f.as_posix()}: override #{i}: falta o campo 'rule'")
            if rule.lower() in out:
                raise DeployError(f"mais de um override para a regra '{rule}' ({platform})")
            out[rule.lower()] = item
    return out


def override_state(item, today: date = None):
    """Retorna (desativada, vencida). Levanta ValueError se o override for inválido."""
    if not item:
        return False, False
    if item.get("enabled") is not False:
        raise ValueError("override: 'enabled' deve ser false (só é possível desativar)")
    for k in ("reason", "ticket", "expires"):
        if not item.get(k):
            raise ValueError(f"override: campo obrigatório ausente: '{k}'")
    today = today or datetime.now(timezone.utc).date()
    try:
        expires = parse_expires(item["expires"])
    except ValueError as e:
        raise ValueError(f"override: {e}")
    if expires < today:
        return False, True
    return True, False


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

def sentinel_body(path: Path, exceptions: dict = None, overrides: dict = None):
    """Monta o corpo da regra. Retorna (body, meta). 'exceptions' = {nome minúsculo: [...]}"""
    r = yaml.safe_load(path.read_text(encoding="utf-8"))

    kind = str(r.get("kind", "Scheduled")).strip()
    if kind not in SENTINEL_KINDS:
        raise ValueError(f"kind inválido: '{kind}' (use {' ou '.join(SENTINEL_KINDS)})")

    required = SENTINEL_REQUIRED + (SENTINEL_REQUIRED_SCHEDULED if kind == "Scheduled" else [])
    missing = [k for k in required if not r.get(k)]
    if missing:
        raise ValueError(f"campos obrigatórios ausentes: {', '.join(missing)}")

    name_key = str(r["name"]).strip().lower()
    query, active, expired = render_query(r, (exceptions or {}).get(name_key))
    disabled, override_expired = override_state((overrides or {}).get(name_key))
    if len(query) > SENTINEL_MAX_QUERY:
        raise ValueError(f"query com {len(query)} caracteres (limite ~{SENTINEL_MAX_QUERY})"
                         f"{' após aplicar exceções' if active else ''}")

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
        "enabled": False if disabled else r.get("enabled", True),
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

    return ({"kind": kind, "properties": props},
            {"active": active, "expired": expired,
             "disabled": disabled, "override_expired": override_expired})


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


def peek_rule_name(path: Path) -> str:
    """Nome da regra em minúsculas, sem validar o resto (usado para casar exceções)."""
    try:
        r = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return str(r.get("name", "")).strip().lower()
    except Exception:
        return ""


def referenced_watchlists(query: str) -> set:
    """Aliases citados em _GetWatchlist('...') na query já renderizada."""
    return set(WATCHLIST_REF_RE.findall(query))


def sentinel_list_watchlists(sub: str, rg: str, ws: str):
    """Aliases (minúsculos) das watchlists do workspace, ou None se não foi possível listar."""
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.OperationalInsights/workspaces/{ws}"
           f"/providers/Microsoft.SecurityInsights/watchlists"
           f"?api-version={SENTINEL_API_VERSION}")
    aliases = set()
    while url:
        r = subprocess.run(["az", "rest", "--method", "get", "--url", url, "-o", "json"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return None
        try:
            data = json.loads(r.stdout)
        except json.JSONDecodeError:
            return None
        for item in data.get("value", []):
            alias = (item.get("properties") or {}).get("watchlistAlias") or item.get("name")
            if alias:
                aliases.add(str(alias).lower())
        url = data.get("nextLink")
    return aliases


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
    exc_map = load_customer_exceptions(customer, "sentinel")
    ov_map = load_customer_overrides(customer, "sentinel")
    existing = sentinel_list_existing(sub, rg, ws)
    wl_cache = {}   # watchlists do workspace, carregadas só se alguma regra precisar
    seen_names, used_exc, used_ov, failed = set(), set(), set(), []
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

        peeked = peek_rule_name(f)
        if peeked in exc_map:
            used_exc.add(peeked)
        if peeked in ov_map:
            used_ov.add(peeked)

        try:
            body, meta = sentinel_body(f, exc_map, ov_map)
        except Exception as e:
            print(f"{tag} ERRO em {f.name}: {e}")
            failed.append(f.name)
            continue

        key = body["properties"]["displayName"].strip().lower()
        kind = body["kind"]
        if key in exc_map:
            used_exc.add(key)

        # regra que cita watchlist: a lista precisa existir no workspace deste cliente
        needed = referenced_watchlists(body["properties"]["query"])
        if needed:
            if "set" not in wl_cache:
                wl_cache["set"] = sentinel_list_watchlists(sub, rg, ws)
                if wl_cache["set"] is None:
                    print(f"{tag} AVISO: não foi possível listar as watchlists do workspace; "
                          f"a existência delas não será verificada")
            have = wl_cache["set"]
            if have is not None:
                missing_wl = sorted(a for a in needed if a.lower() not in have)
                if missing_wl:
                    print(f"{tag} ERRO em {f.name}: watchlist(s) inexistente(s) no workspace: "
                          f"{', '.join(missing_wl)}")
                    failed.append(f.name)
                    continue
        if meta["expired"]:
            print(f"{tag} AVISO    {f.name}: {meta['expired']} exceção(ões) vencida(s) ignorada(s)")
        if meta["override_expired"]:
            print(f"{tag} AVISO    {f.name}: override de desativação vencido; regra mantida ATIVA")
        extra = f" [exceções: {meta['active']}]" if meta["active"] else ""
        if meta["disabled"]:
            extra += " [DESATIVADA por override]"

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
                print(f"{tag} UPTODATE {f.name} (já implantada, sem alterações){extra}")
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
            print(f"{tag} OK       {action} [{kind}] {f.name}{detail}{extra}")
            deployed += 1
        else:
            err = mask((r.stderr or r.stdout or "").strip(), secrets)
            print(f"{tag} FALHOU   {action} [{kind}] {f.name}\n{err[:1500]}")
            failed.append(f.name)

    if scope.full:
        for name in sorted(set(exc_map) - used_exc):
            print(f"{tag} AVISO: há exceções para a regra '{name}', mas ela não está "
                  f"nos packs deste cliente (nome errado?)")
        for name in sorted(set(ov_map) - used_ov):
            print(f"{tag} AVISO: há override para a regra '{name}', mas ela não está "
                  f"nos packs deste cliente (nome errado?)")

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


def xdr_load_rule(path: Path, exceptions: dict = None, overrides: dict = None):
    """Lê e valida o YAML. Retorna (regra, meta); a query já vem com as exceções aplicadas."""
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

    name_key = str(r["name"]).strip().lower()
    query, active, expired = render_query(r, (exceptions or {}).get(name_key),
                                          allow_watchlist=False)
    r["query"] = query
    disabled, override_expired = override_state((overrides or {}).get(name_key))
    if disabled:
        r["enabled"] = False
    return r, {"active": active, "expired": expired,
               "disabled": disabled, "override_expired": override_expired}


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
    exc_map = load_customer_exceptions(customer, "defender-xdr")
    ov_map = load_customer_overrides(customer, "defender-xdr")
    existing = xdr_list_existing(secrets)
    seen_names, used_exc, used_ov, failed = set(), set(), set(), []
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

        peeked = peek_rule_name(f)
        if peeked in exc_map:
            used_exc.add(peeked)
        if peeked in ov_map:
            used_ov.add(peeked)

        try:
            r, meta = xdr_load_rule(f, exc_map, ov_map)
        except Exception as e:
            print(f"{tag} ERRO em {f.name}: {e}")
            failed.append(f.name)
            continue

        key = str(r["name"]).strip().lower()
        if key in exc_map:
            used_exc.add(key)
        if meta["expired"]:
            print(f"{tag} AVISO    {f.name}: {meta['expired']} exceção(ões) vencida(s) ignorada(s)")
        if meta["override_expired"]:
            print(f"{tag} AVISO    {f.name}: override de desativação vencido; regra mantida ATIVA")
        extra = f" [exceções: {meta['active']}]" if meta["active"] else ""
        if meta["disabled"]:
            extra += " [DESATIVADA por override]"

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
                print(f"{tag} UPTODATE {f.name} (já implantada, sem alterações){extra}")
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
            print(f"{tag} OK       {action} {f.name}{detail}{extra}")
            deployed += 1
        else:
            err = mask((res.stderr or res.stdout or "").strip(), secrets)
            print(f"{tag} FALHOU   {action} {f.name}\n{err[:1500]}")
            failed.append(f.name)

    if scope.full:
        for name in sorted(set(exc_map) - used_exc):
            print(f"{tag} AVISO: há exceções para a regra '{name}', mas ela não está "
                  f"nos packs deste cliente (nome errado?)")
        for name in sorted(set(ov_map) - used_ov):
            print(f"{tag} AVISO: há override para a regra '{name}', mas ela não está "
                  f"nos packs deste cliente (nome errado?)")

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