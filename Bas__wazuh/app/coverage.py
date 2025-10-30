from __future__ import annotations

import aiohttp
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set
from types import SimpleNamespace
from urllib.parse import urlparse

# --- Helpers ---
def _to_utc(dt: Any) -> datetime:
    """Coerce naive/aware datetime or str(ISO/epoch) to timezone-aware UTC."""
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


def _maybe_to_utc(dt: Any) -> Optional[datetime]:
    """Return UTC datetime when value is provided, otherwise None."""
    if dt is None:
        return None
    return _to_utc(dt)


def _extract_operation_techniques(chain: Iterable[Dict[str, Any]]) -> Set[str]:
    """Collect technique_id from chain items when provided by operation logs."""
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
    index: str = 'wazuh-alerts-*',
    start: Any = None,
    end: Any = None,
    verify_ssl: bool = True,
    size: int = 1000
) -> List[Dict[str, Any]]:
    """Query Wazuh Indexer(OpenSearch/ES) for alerts within [start, end]."""
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
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": [
            "@timestamp", "rule.id", "rule.level", "rule.description",
            "agent.id", "agent.name",
            "data.mitre.technique", "data.mitre.id", "data.mitre.tactic",
            "data", "rule", "mitre", "message",
            "data.mitre.subtechnique"
        ]
    }
    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=verify_ssl)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        auth = aiohttp.BasicAuth(username, password)
        url = f"{indexer_url.rstrip('/')}/{index}/_search"
        async with session.get(url, auth=auth, json=q) as resp:
            data = await resp.json()
            if resp.status != 200:
                raise RuntimeError(f"Indexer query failed: HTTP {resp.status} {data}")
            hits = (((data or {}).get('hits') or {}).get('hits') or [])
            return [h.get('_source', {}) for h in hits]


async def compute_coverage(operation: Dict[str, Any],
                           indexer: Dict[str, Any]) -> Dict[str, Any]:

    op_id = operation.get('id') or operation.get('operation_id')
    name = operation.get('name') or ''
    start = _maybe_to_utc(operation.get('start'))
    end = _maybe_to_utc(operation.get('end'))
    default_window = timedelta(hours=3)
    now_utc = datetime.now(timezone.utc)
    if start and not end:
        end = start + default_window
    elif end and not start:
        start = end - default_window
    elif not start and not end:
        end = now_utc
        start = end - default_window

    duration_seconds = int((end - start).total_seconds()) if end and start else None

    # -------------------------------
    # 1) IntegrationEngine-based correlation
    # -------------------------------
    engine_result = None
    attack_steps = 0
    detected_steps = 0
    total_matches = 0
    op_techniques: Set[str] = _extract_operation_techniques(operation.get('chain') or [])
    detected_tids: Set[str] = set()
    representative_alerts: Dict[str, Dict[str, Any]] = {}

    def _prepare_alert(alert: Dict[str, Any],
                       fallback_tid: Optional[str] = None) -> tuple[Dict[str, Any], Set[str]]:
        """Normalise alert payload and extract mapped technique identifiers."""
        record = dict(alert or {})
        try:
            agent = record.get('agent') or {}
            if isinstance(agent, dict):
                nm = (agent.get('name') or '').strip().lower()
                if nm:
                    agent['name'] = nm
                    record['agent'] = agent
        except Exception:
            pass

        tids = _mitre_ids_from_source(record)
        if not tids and fallback_tid:
            tids = {str(fallback_tid)}

        record['technique_ids'] = sorted(tids) if tids else []
        return record, tids

    def _store_representative(alert: Dict[str, Any],
                              *,
                              key_hint: str = '',
                              fallback_tid: Optional[str] = None) -> None:
        """Keep the first alert per attack (link) for downstream reporting."""
        record, tids = _prepare_alert(alert, fallback_tid)
        detected_tids.update(tids)

        key = key_hint or ''
        if not key:
            if record['technique_ids']:
                joined = '|'.join(record['technique_ids'])
                key = f"tech:{joined}"
            else:
                key = f"alert:{len(representative_alerts)}"

        if key not in representative_alerts:
            representative_alerts[key] = record

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
                'index_pattern': indexer.get('index', 'wazuh-alerts-*'),
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

        # Analyse correlation output while keeping a single representative alert per link.
        for result in (engine_result or []):
            matches = result.get('matches') or []
            if not matches:
                continue

            link_id = str(result.get('link_id') or '')
            fallback_tid = result.get('technique_id')
            key_hint = f"link:{link_id}" if link_id else ''

            _store_representative(matches[0], key_hint=key_hint, fallback_tid=fallback_tid)

            for match in matches[1:]:
                _, tids = _prepare_alert(match, fallback_tid)
                detected_tids.update(tids)
    except Exception:
        # If correlation fails, fall back to raw alert queries
        engine_result = None

    # -------------------------------
    # 2) Fallback: derive technique coverage directly from alerts
    # -------------------------------
    if engine_result is None:
        match_windows: List[Any] = operation.get('_match_windows') or []
        if match_windows:
            for tech, center_dt, start_dt in match_windows:
                try:
                    center = center_dt if isinstance(center_dt, datetime) else _to_utc(center_dt)
                except Exception:
                    center = datetime.now(timezone.utc)
                window_half = timedelta(minutes=5)
                win_start = center - window_half
                win_end = center + window_half
                alerts = await fetch_alerts(
                    indexer_url=indexer['url'],
                    username=indexer['username'],
                    password=indexer['password'],
                    index=indexer.get('index', 'wazuh-alerts-*'),
                    start=win_start,
                    end=win_end,
                    verify_ssl=indexer.get('verify_ssl', True),
                    size=200,
                )
                for a in alerts:
                    _store_representative(
                        a,
                        fallback_tid=str(tech) if tech else None
                    )

        alerts = await fetch_alerts(
            indexer_url=indexer['url'],
            username=indexer['username'],
            password=indexer['password'],
            index=indexer.get('index', 'wazuh-alerts-*'),
            start=start, end=end,
            verify_ssl=indexer.get('verify_ssl', True),
            size=2000
        )
        for a in alerts:
            _store_representative(a)

    # -------------------------------
    # 3) 탐지율 계산
    # -------------------------------
    # A) 공격단계(links) 기준 탐지율 — 엔진 결과가 있을 때
    if attack_steps > 0:
        det_rate = round((detected_steps / attack_steps) * 100.0, 2)
    else:
        # B) 기법 기준 탐지율 — 엔진이 없거나 체인이 없을 때
        if not op_techniques:
            op_techniques = _extract_operation_techniques(operation.get('chain') or [])
        if op_techniques:
            matched = op_techniques & detected_tids
            undetected = op_techniques - matched
            det_rate = round((len(matched) / len(op_techniques) * 100.0), 2)
        else:
            matched = set()
            undetected = set()
            det_rate = 0.0

    # Ensure matched/undetected sets are always defined for the response.
    if attack_steps > 0:
        matched = op_techniques & detected_tids if op_techniques else set()
        undetected = (op_techniques - matched) if op_techniques else set()
    else:
        matched = matched if 'matched' in locals() else set()
        undetected = undetected if 'undetected' in locals() else set()

    enriched_alerts: List[Dict[str, Any]] = list(representative_alerts.values())

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
            'detected_techniques': len(matched),
            'all_operation_techniques': sorted(op_techniques),
            'all_detected_techniques': sorted(detected_tids),
            'matched_techniques': sorted(matched),
            'undetected_techniques': len(undetected),
            'undetected_techniques_list': sorted(undetected),
        },
        'alerts_matched': enriched_alerts,
    }
