from __future__ import annotations

import aiohttp
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

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

async def fetch_alerts(indexer_url: str, username: str, password: str, *, index: str = 'wazuh-alerts-*',
                       start: Any = None, end: Any = None, verify_ssl: bool = True, size: int = 1000) -> List[Dict[str, Any]]:
    """Query Wazuh Indexer(OpenSearch/ES) for alerts within [start, end]."""
    must_filters = []
    if start is not None and end is not None:
       must_filters.append({"range": {"@timestamp": {"gte": _to_utc(start).isoformat(), "lte": _to_utc(end).isoformat()}}})

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
    start, end = _to_utc(operation.get('start')), _to_utc(operation.get('end'))
    duration_seconds = int((end - start).total_seconds()) if end and start else None

    # Techniques intended by the operation (optional, not used for extraction if empty)
    op_techniques = _extract_operation_techniques(operation.get('chain') or [])

    # Pull alerts only from index (no rule->MITRE mapping fallback)
    alerts = await fetch_alerts(
        indexer_url=indexer['url'],
        username=indexer['username'],
        password=indexer['password'],
        index=indexer.get('index', 'wazuh-alerts-*'),
        start=start, end=end,
        verify_ssl=indexer.get('verify_ssl', True),
        size=2000
    )

    detected_tids: Set[str] = set()
    enriched_alerts: List[Dict[str, Any]] = []
    for a in alerts:
        tids = _mitre_ids_from_source(a)
        detected_tids.update(tids)
        b = dict(a)
        b['technique_ids'] = sorted(tids) if tids else []
        enriched_alerts.append(b)

    if op_techniques:
        matched = op_techniques & detected_tids
        undetected = op_techniques - matched
        det_rate = round((len(matched) / len(op_techniques) * 100.0), 2) if op_techniques else 0.0
    else:
        # If the operation didn't provide technique list, coverage is defined by detected set only
        matched = detected_tids
        undetected = set()
        det_rate = 100.0 if detected_tids else 0.0

    return {
        'success': True,
        'operation_id': op_id, 'operation_name': name,
        'start_time': start.isoformat() if start else None,
        'end_time': end.isoformat() if end else None,
        'duration_seconds': duration_seconds,
        'correlation': {
            'detection_rate': det_rate,
            'total_techniques': len(op_techniques),
            'detected_techniques': len(matched),
            'undetected_techniques': len(undetected),
            'matched_techniques': sorted(matched),
            'undetected_techniques_list': sorted(undetected),
            'all_operation_techniques': sorted(op_techniques),
            'all_detected_techniques': sorted(detected_tids),
        },
        'alerts_matched': enriched_alerts,
        'total_alerts': len(enriched_alerts),
    }