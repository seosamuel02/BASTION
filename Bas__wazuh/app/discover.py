from datetime import datetime, timezone

try:
    from .integration_engine import IntegrationEngine
except Exception:
    from importlib import import_module
    IntegrationEngine = import_module('integration_engine').IntegrationEngine


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


def discover_search(query=None, *, index=None, time_from=None, time_to=None, size=100, sort='@timestamp:desc', fields=None, filters=None, config_overrides=None):
    engine = IntegrationEngine(overrides=config_overrides or {})
    client = engine.client
    index_pattern = index or engine.wazuh.get('index_pattern') or 'wazuh-alerts-4.x-*'

    tf = _to_dt(time_from)
    tt = _to_dt(time_to)

    must = []
    flt = []
    if query:
        must.append({'query_string': {'query': query}})
    else:
        must.append({'match_all': {}})

    if isinstance(filters, dict):
        for k, v in filters.items():
            if v is None:
                continue
            if isinstance(v, (list, tuple, set)):
                flt.append({'terms': {k: list(v)}})
            else:
                flt.append({'term': {k: v}})

    if tf or tt:
        rng = {}
        if tf:
            rng['gte'] = tf.isoformat()
        if tt:
            rng['lte'] = tt.isoformat()
        flt.append({'range': {'@timestamp': rng}})

    body = {
        'size': max(1, min(int(size or 100), 10000)),
        'query': {'bool': {'must': must, 'filter': flt}},
    }
    if fields:
        body['_source'] = list(fields)

    if sort:
        try:
            f, o = (s.strip() for s in str(sort).split(':', 1))
            o = o.lower() if o else 'desc'
            body['sort'] = [{f: {'order': 'desc' if o not in ('asc', 'desc') else o}}]
        except Exception:
            body['sort'] = [{'@timestamp': {'order': 'desc'}}]

    try:
        resp = client.search(index=index_pattern, body=body)
    except Exception as e:
        return {'took': 0, 'total': 0, 'hits': [], 'error': str(e), 'request': {'index': index_pattern, 'body': body}}

    hits = resp.get('hits', {}).get('hits', [])
    total_raw = resp.get('hits', {}).get('total', {})
    total = int(total_raw.get('value', 0)) if isinstance(total_raw, dict) else int(total_raw or 0)

    rows = []
    for h in hits:
        doc = h.get('_source', {})
        doc['_id'] = h.get('_id')
        doc['_index'] = h.get('_index')
        rows.append(doc)

    return {'took': resp.get('took', 0), 'total': total, 'hits': rows, 'request': {'index': index_pattern, 'body': body}}
