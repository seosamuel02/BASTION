from __future__ import annotations

import aiohttp
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set
from types import SimpleNamespace
from urllib.parse import urlparse

# --- Constants (필드명 고정) ---
TS_FIELD = "@timestamp"
MITRE_FIELD = "rule.mitre.id"
AGENT_NAME_FIELD = "agent.name"
OS_FIELD = "agent.os.platform"


# --- Helpers ---
def _to_utc(dt: Any) -> datetime:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(dt, (int, float)):
        return datetime.fromtimestamp(dt, tz=timezone.utc)
    if isinstance(dt, str):
        try:
            # ISO8601
            return datetime.fromisoformat(dt.replace('Z', '+00:00')).astimezone(timezone.utc)
        except Exception:
            # epoch string
            return datetime.fromtimestamp(float(dt), tz=timezone.utc)
    raise TypeError(f'Unsupported datetime type: {type(dt)}')


def _extract_operation_techniques(chain: Iterable[Dict[str, Any]]) -> Set[str]:
    techs: Set[str] = set()
    for link in chain or []:
        t = (
            link.get('technique_id')
            or (link.get('ability') or {}).get('technique_id')
            or (link.get('rule', {}).get('mitre') or {}).get('id')
        )
        # if id is list, extend
        if isinstance(t, list):
            techs.update(str(x) for x in t if x)
        elif t:
            techs.add(str(t))
    return techs


def _mitre_ids_from_source(source: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()

    # Nested dict paths
    data_mitre = (source.get('data') or {}).get('mitre') or {}
    rule_mitre = (source.get('rule') or {}).get('mitre') or {}

    for v in (data_mitre.get('id'), rule_mitre.get('id')):
        if isinstance(v, list):
            out.update(str(x) for x in v if x)
        elif v:
            out.add(str(v))

    # Flattened variants
    for k in ('data.mitre.id', 'rule.mitre.id', 'mitre.id'):
        v = source.get(k)
        if isinstance(v, list):
            out.update(str(x) for x in v if x)
        elif v:
            out.add(str(v))

    # Normalize: keep values that look like technique IDs (e.g., T1059 or T1078.003)
    norm = set()
    for tid in out:
        s = str(tid).strip()
        if s and s[0].upper() == 'T':
            norm.add(s.upper().replace('TECHNIQUE/', ''))
    return norm


async def fetch_alerts(
    indexer_url: str,
    username: str,
    password: str,
    *,
    index: str = 'wazuh-alerts-4.x-*',
    start: Any = None,
    end: Any = None,
    verify_ssl: bool = True,
    size: int = 1000
) -> List[Dict[str, Any]]:
    must_filters = []
    if start is not None and end is not None:
        must_filters.append({
            "range": {
                "@timestamp": {
                    "gte": _to_utc(start).isoformat(),
                    "lte": _to_utc(end).isoformat()
                }
            }
        })

    q = {
        "query": {"bool": {"filter": must_filters}},
        "size": int(size),
        "sort": [{ "@timestamp": {"order": "asc"} }],
        "_source": [
            "@timestamp", "rule.id", "rule.level", "rule.description",
            "rule.mitre.id", "rule.mitre.tactic",
            "agent.id", "agent.name", "agent.os.platform",
            "data", "rule", "mitre", "message"
        ]
    }
    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=verify_ssl)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        auth = aiohttp.BasicAuth(username, password)
        url = f"{indexer_url.rstrip('/')}/{index}/_search"
        async with session.post(url, auth=auth, json=q, headers={"Content-Type":"application/json"}) as resp:
            data = await resp.json()
            if resp.status != 200:
                raise RuntimeError(f"Indexer query failed: HTTP {resp.status} {data}")
            hits = (((data or {}).get('hits') or {}).get('hits') or [])
            return [h.get('_source', {}) for h in hits]


async def compute_coverage(operation: Dict[str, Any],
                           indexer: Dict[str, Any]) -> Dict[str, Any]:

    op_id = operation.get('id') or operation.get('operation_id')
    name = operation.get('name') or ''
    start, end = _to_utc(operation.get('start')), _to_utc(operation.get('end'))
    H = 3 
    now_utc = datetime.now(timezone.utc)
    if start:
        end = start + timedelta(hours=H)
    elif end:
        start = end - timedelta(hours=H)
    else:
        end = now_utc
        start = end - timedelta(hours=H)

    duration_seconds = int((end - start).total_seconds()) if end and start else None

    # -------------------------------
    # 1) IntegrationEngine 기반 link별 매칭 ( 탐지율)
    # -------------------------------
    engine_result = None
    attack_steps = 0
    detected_steps = 0
    total_matches = 0
    op_techniques: Set[str] = _extract_operation_techniques(operation.get('chain') or [])
    detected_tids: Set[str] = set()
    enriched_alerts: List[Dict[str, Any]] = []

    try:
        parsed = urlparse(indexer['url'])
        scheme = parsed.scheme or ('https' if indexer.get('verify_ssl', True) else 'http')
        host = parsed.hostname or 'localhost'
        port = parsed.port or (9200 if scheme == 'http' else 9200)

        try:
            from .integration_engine import IntegrationEngine
        except Exception:
            from importlib import import_module
            IntegrationEngine = import_module('integration_engine').IntegrationEngine

        engine = IntegrationEngine(overrides={
            'wazuh': {
                'scheme': scheme,
                'host': host,
                'port': port,
                'verify_ssl': bool(indexer.get('verify_ssl', True)),
                'username': indexer.get('username'),
                'password': indexer.get('password'),
                'index_pattern': indexer.get('index', 'wazuh-alerts-4.x-*'),
            },
            'match': {'time_window_sec': 180}
        })

        links_src = operation.get('chain') or []

        def _mk_link(d: Dict[str, Any]):
            # technique / name
            tech = d.get('technique_id') \
                   or (d.get('ability') or {}).get('technique_id')
            nm = (d.get('ability') or {}).get('name') or d.get('ability_name') or ''
            # time (finish > start > decide > executed_at)
            ts = d.get('finish') or d.get('start') or d.get('decide') or d.get('executed_at')
            ability = SimpleNamespace(technique_id=tech, name=nm)
            return SimpleNamespace(
                id=str(d.get('link_id') or d.get('id') or ''),
                ability=ability,
                finish=_to_utc(ts)
            )

        link_objs = [_mk_link(x) for x in links_src if isinstance(x, dict)]
        op_obj = SimpleNamespace(chain=link_objs)

        engine_result = await engine.correlate(op_obj)
        attack_steps = len(engine_result or [])
        detected_steps = sum(1 for r in (engine_result or []) if r.get('detected'))
        total_matches = sum(int(r.get('match_count') or 0) for r in (engine_result or []))

        # alerts(매칭건) 모으기 + 기법 집계
        for r in (engine_result or []):
            for m in (r.get('matches') or []):
                b = dict(m)
                # agent.name 정규화
                try:
                    agent = b.get('agent') or {}
                    if isinstance(agent, dict):
                        nm = (agent.get('name') or '').strip().lower()
                        if nm:
                            agent['name'] = nm
                            b['agent'] = agent
                except Exception:
                    pass
                tids = _mitre_ids_from_source(b)
                detected_tids.update(tids)
                b['technique_ids'] = sorted(tids) if tids else []
                enriched_alerts.append(b)
    except Exception:
        # 엔진 매칭 실패 시 enriched_alerts는 아래 fallback에서 채움
        engine_result = None

    # -------------------------------
    # 2) Fallback: 기간 내 경보에서 기법 추출 
    # -------------------------------
    if engine_result is None:
        alerts = await fetch_alerts(
            indexer_url=indexer['url'],
            username=indexer['username'],
            password=indexer['password'],
            index=indexer.get('index', 'wazuh-alerts-4.x-*'),
            start=start, end=end,
            verify_ssl=indexer.get('verify_ssl', True),
            size=2000
        )
        for a in alerts:
            tids = _mitre_ids_from_source(a)
            detected_tids.update(tids)
            b = dict(a)
            try:
                agent = b.get('agent') or {}
                if isinstance(agent, dict):
                    nm = (agent.get('name') or '').strip().lower()
                    if nm:
                        agent['name'] = nm
                        b['agent'] = agent
            except Exception:
                pass
            b['technique_ids'] = sorted(tids) if tids else []
            enriched_alerts.append(b)

    # -------------------------------
    # 3) 탐지율 계산
    # -------------------------------
    # A) 공격단계(links) 기준 탐지율 — 엔진 결과가 있을 때
    if attack_steps > 0:
        det_rate = round((detected_steps / attack_steps) * 100.0, 2)
    else:
        # B) 기법 기준 탐지율 — 엔진이 없거나 체인이 없을 때
        op_techniques = op_techniques or _extract_operation_techniques(operation.get('chain') or [])
        if op_techniques:
            matched = op_techniques & detected_tids
            undetected = op_techniques - matched
            det_rate = round((len(matched) / len(op_techniques) * 100.0), 2)
        else:
            matched = set()
            undetected = set()
            det_rate = 0.0

    return {
        'success': True,
        'operation_id': op_id, 'operation_name': name,
        'start_time': start.isoformat() if start else None,
        'end_time': end.isoformat() if end else None,
        'duration_seconds': duration_seconds,
        'attack_steps': int(attack_steps),
        'detected_steps': int(detected_steps),
        'total_alerts': len(enriched_alerts),
        'total_matches': int(total_matches),
        'correlation': {
            'detection_rate': det_rate,
            'total_techniques': len(op_techniques),
            'all_operation_techniques': sorted(op_techniques),
            'all_detected_techniques': sorted(detected_tids),
            **(lambda _m, _u: {
                'matched_techniques': sorted(_m),
                'undetected_techniques': len(_u),
                'undetected_techniques_list': sorted(_u)
            })(
                (op_techniques & detected_tids),
                (op_techniques - (op_techniques & detected_tids)) if op_techniques else set()
            ),
        },
        'alerts_matched': enriched_alerts,
    }
