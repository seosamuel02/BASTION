import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

# IntegrationEngine 로딩
try:
    from .integration_engine import IntegrationEngine
except Exception:
    from importlib import import_module
    IntegrationEngine = import_module('integration_engine').IntegrationEngine


# -----------------------------
# Helpers
# -----------------------------
_ALLOWED_INDEX = re.compile(r'^wazuh-[\w\-\.\*]+$')  # 예: wazuh-*, wazuh-alerts-4.x-*, wazuh-alerts-4.5-2025.10.28

def _to_dt(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        s = value.strip()
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None

async def _run_in_executor(func, *args, **kwargs):
    """OpenSearch-py 동기 호출을 스레드 실행자로 보내 이벤트루프 블로킹 방지"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


def _kql_to_dsl(kql: str) -> Dict[str, Any]:
    if not kql or not kql.strip():
        return {"match_all": {}}

    expr = kql.strip()
    # 단순 분해 (따옴표 내 AND/OR은 미지원)
    if " AND " in expr:
        parts = [p.strip() for p in expr.split(" AND ")]
        conj = "AND"
    elif " OR " in expr:
        parts = [p.strip() for p in expr.split(" OR ")]
        conj = "OR"
    else:
        parts = [expr]
        conj = "AND"

    subs = []
    for p in parts:
        if p.startswith("exists:"):
            field = p.split("exists:", 1)[1].strip()
            subs.append({"exists": {"field": field}})
            continue

        if ">=" in p or "<=" in p:
            rng = {}
            field = None
            if ">=" in p:
                f, v = [x.strip() for x in p.split(">=")]
                field = f
                rng.setdefault(f, {})["gte"] = _try_num(v)
            if "<=" in p:
                f, v = [x.strip() for x in p.split("<=")]
                field = f
                rng.setdefault(f, {})["lte"] = _try_num(v)
            if field:
                subs.append({"range": rng})
            continue

        if ":" in p:
            f, v = [x.strip() for x in p.split(":", 1)]
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                subs.append({"match_phrase": {f: v[1:-1]}})
            else:
                subs.append({"term": {f + ".keyword": v}})
            continue

        # fallback
        subs.append({"query_string": {"query": p}})

    if conj == "AND":
        return {"bool": {"must": subs}} if subs else {"match_all": {}}
    else:
        return {"bool": {"should": subs, "minimum_should_match": 1}} if subs else {"match_all": {}}

def _try_num(v: str):
    try:
        if "." in v:
            return float(v)
        return int(v)
    except Exception:
        return v


# -----------------------------
# Public APIs
# -----------------------------
async def list_indices(pattern: str = "wazuh-*", *, config_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    OpenSearch _cat/indices를 사용해 인덱스 목록을 반환한다.
    """
    if not _ALLOWED_INDEX.match(pattern):
        return {"error": "pattern not allowed"}

    try:
        engine = IntegrationEngine(overrides=config_overrides or {})
    except Exception as e:
        return {"error": f"engine init failed: {e}"}

    client = engine.client
    try:
        data = await _run_in_executor(client.cat.indices, index=pattern, format='json', h='index')
        indices = sorted({row.get('index') for row in data if row.get('index')})
        return {"indices": indices}
    except Exception:
        try:
            resp = await _run_in_executor(
                client.transport.perform_request, 'GET', f'/_cat/indices/{pattern}',
                params={'format': 'json', 'h': 'index'}
            )
            indices = sorted({row.get('index') for row in resp if row.get('index')})
            return {"indices": indices}
        except Exception as e:
            return {"error": str(e)}


def discover_search(
    query: Optional[str] = None,
    *,
    # 추가 옵션
    kql: Optional[str] = None,
    index: Optional[str] = None,
    time_from: Optional[Union[str, int, float, datetime]] = None,
    time_to: Optional[Union[str, int, float, datetime]] = None,
    size: int = 100,
    sort: str = '@timestamp:desc',
    fields: Optional[List[str]] = None,
    filters: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None,
    time_field: str = "@timestamp",
    highlight: bool = False,
    track_total_hits: bool = True,
    config_overrides: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    try:
        engine = IntegrationEngine(overrides=config_overrides or {})
    except Exception as e:
        return {'took': 0, 'total': 0, 'hits': [], 'error': f'engine init failed: {e}', 'request': {}}

    client = engine.client
    index_pattern = index or engine.wazuh.get('index_pattern') or 'wazuh-alerts-4.x-*'
    if not _ALLOWED_INDEX.match(index_pattern):
        return {'took': 0, 'total': 0, 'hits': [], 'error': 'index not allowed', 'request': {}}

    tf = _to_dt(time_from)
    tt = _to_dt(time_to)

    # --- Query ---
    must: List[Dict[str, Any]] = []
    flt: List[Dict[str, Any]] = []

    if kql and kql.strip():
        kql_dsl = _kql_to_dsl(kql)
        if "bool" in kql_dsl:
            b = kql_dsl["bool"]
            if "must" in b: must.extend(b["must"])
            if "filter" in b: flt.extend(b["filter"])
            if "should" in b:
                must.append({"bool": {"should": b["should"], "minimum_should_match": b.get("minimum_should_match", 1)}})
        else:
            must.append(kql_dsl)
    elif query and str(query).strip():
        must.append({'query_string': {'query': query}})
    else:
        must.append({'match_all': {}})

    # dict 또는 Discover-style filters 배열 지원
    if isinstance(filters, dict):
        for k, v in filters.items():
            if v is None:
                continue
            if isinstance(v, (list, tuple, set)):
                flt.append({'terms': {k: list(v)}})
            else:
                flt.append({'term': {k: v}})
    elif isinstance(filters, list):
        for f in filters:
            if not isinstance(f, dict):
                continue
            meta = f.get("meta", {})
            if meta.get("disabled"):
                continue
            key = meta.get("key") or meta.get("field")
            t = meta.get("type")
            params = meta.get("params") or {}
            if t == "exists" and key:
                flt.append({"exists": {"field": key}})
                continue
            if t == "phrase" and key is not None:
                flt.append({"term": {f"{key}.keyword": params.get("query")}})
                continue
            if t == "range" and key is not None:
                r = {}
                if "gte" in params: r["gte"] = params["gte"]
                if "lte" in params: r["lte"] = params["lte"]
                if r:
                    flt.append({"range": {key: r}})
                continue
            q = f.get("query")
            if q:
                flt.append({"query_string": {"query": q}})

    # 시간 범위
    if tf or tt:
        rng = {}
        if tf: rng['gte'] = tf.isoformat()
        if tt: rng['lte'] = tt.isoformat()
        flt.append({'range': {time_field: rng}})

    body: Dict[str, Any] = {
        'size': max(1, min(int(size or 100), 10000)),
        'query': {'bool': {'must': must, 'filter': flt}},
        'track_total_hits': bool(track_total_hits),
        'stored_fields': ['*'],
        'docvalue_fields': [{ "field": time_field, "format": "date_time" }],
        '_source': fields or [
            time_field, "agent.name", "rule.id", "rule.level",
            "rule.description", "rule.mitre.id", "message", "full_log"
        ]
    }

    # 정렬
    if sort:
        try:
            f, o = (s.strip() for s in str(sort).split(':', 1))
            o = o.lower() if o else 'desc'
            body['sort'] = [{f: {'order': 'desc' if o not in ('asc', 'desc') else o}}]
        except Exception:
            body['sort'] = [{time_field: {'order': 'desc'}}]
    else:
        body['sort'] = [{time_field: {'order': 'desc'}}]

    # 하이라이트
    if highlight:
        body['highlight'] = {"fields": {"message": {}, "full_log": {}}}

    # 실행 (동기 호출)
    try:
        resp = client.search(index=index_pattern, body=body)
    except Exception as e:
        return {'took': 0, 'total': 0, 'hits': [], 'error': str(e), 'request': {'index': index_pattern, 'body': body}}

    hits = resp.get('hits', {}).get('hits', [])
    total_raw = resp.get('hits', {}).get('total', {})
    total = int(total_raw.get('value', 0)) if isinstance(total_raw, dict) else int(total_raw or 0)

    rows = []
    for h in hits:
        doc = h.get('_source', {}) or {}
        doc['_id'] = h.get('_id')
        doc['_index'] = h.get('_index')
        rows.append(doc)

    return {'took': resp.get('took', 0), 'total': total, 'hits': rows, 'request': {'index': index_pattern, 'body': body}}