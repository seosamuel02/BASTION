from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Callable, Optional, List, Tuple

from aiohttp import web

from .coverage import compute_coverage

try:
    from .integration_engine import IntegrationEngine
except Exception:  # pragma: no cover - fallback for legacy packaging
    from importlib import import_module
    IntegrationEngine = import_module('integration_engine').IntegrationEngine


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_time_range(operation: Dict[str, Any],
                       default_minutes: int = 60) -> Dict[str, Any]:
    """
    Guarantee that start/end timestamps exist so coverage queries use a sane window.
    """
    op = dict(operation or {})
    has_start = bool(op.get("start"))
    has_end = bool(op.get("end"))
    if not (has_start and has_end):
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(minutes=default_minutes)
        if not has_start:
            op["start"] = start_dt.isoformat()
        if not has_end:
            op["end"] = end_dt.isoformat()
    return op


def _indexer_from_config(passed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Merge request overrides with IntegrationEngine defaults (setting.yml).
    """
    passed = passed or {}

    eng = IntegrationEngine()
    wz = eng.wazuh or {}

    scheme = (passed.get('scheme')
              or wz.get('scheme')
              or ('https' if wz.get('verify_ssl', True) else 'http')) or 'http'
    host = passed.get('host') or wz.get('host', 'localhost')
    port = int(passed.get('port') or wz.get('port', 9200))
    url = passed.get('url') or f"{scheme}://{host}:{port}"

    return {
        "url": url,
        "username": passed.get("username") or wz.get("username"),
        "password": passed.get("password") or wz.get("password"),
        "index": passed.get("index") or wz.get("index_pattern") or "wazuh-alerts-*",
        "verify_ssl": passed.get("verify_ssl", wz.get("verify_ssl", True)),
    }


async def _maybe_await(func: Callable, *args, **kwargs):
    """Allow health_getters to be sync or async."""
    try:
        res = func(*args, **kwargs)
        if asyncio.iscoroutine(res):
            return await res
        return res
    except Exception as e:  # pragma: no cover - defensive
        return f"error: {e}"


def _json_error(msg: str, status: int = 500) -> web.Response:
    return web.json_response({"success": False, "error": msg}, status=status)


def _to_iso(value: Any) -> Optional[str]:
    """Normalise assorted timestamp formats into ISO strings."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    return str(value)


async def _load_operation_chain(request: web.Request,
                                operation: Dict[str, Any]) -> Dict[str, Any]:
    """
    If the caller omitted operation.chain, pull it from Caldera so coverage can
    correlate attack links with Wazuh alerts.
    """
    if not isinstance(operation, dict):
        return {}

    if operation.get('chain'):
        return operation

    op_id = operation.get('id') or operation.get('operation_id')
    if not op_id:
        return operation

    services = request.app.get('bw_services') if request and request.app else None
    data_svc = services.get('data_svc') if isinstance(services, dict) else None
    if not data_svc:
        return operation

    caldera_op = None
    for key in ('operations', 'operation'):
        try:
            matches = await data_svc.locate(key, {'id': op_id})
            if matches:
                caldera_op = matches[0]
                break
        except Exception:
            continue

    if caldera_op is None:
        for key in ('operations', 'operation'):
            try:
                all_ops = await data_svc.locate(key, {})
            except Exception:
                continue
            for candidate in all_ops or []:
                if str(getattr(candidate, 'id', '')) == str(op_id):
                    caldera_op = candidate
                    break
            if caldera_op:
                break
        if caldera_op is None:
            return operation

    chain: List[Dict[str, Any]] = []
    windows: List[Tuple[str, datetime, datetime]] = []

    for link in getattr(caldera_op, 'chain', []) or []:
        ability_obj = getattr(link, 'ability', None)
        ability = {
            'technique_id': getattr(ability_obj, 'technique_id', None)
                            or getattr(link, 'technique_id', None),
            'name': getattr(ability_obj, 'name', None)
                    or getattr(link, 'ability_name', None) or ''
        }

        finish_dt = getattr(link, 'finish', None) or getattr(link, 'executed', None) \
            or getattr(link, 'executed_at', None)
        finish_iso = _to_iso(finish_dt)
        start_iso = _to_iso(getattr(link, 'start', None))

        entry = {
            'id': str(getattr(link, 'link_id', '')
                      or getattr(link, 'id', '') or ''),
            'link_id': str(getattr(link, 'link_id', '')
                           or getattr(link, 'id', '') or ''),
            'technique_id': ability.get('technique_id'),
            'ability': ability,
            'ability_name': ability.get('name') or '',
            'finish': finish_iso,
            'start': start_iso,
            'decide': _to_iso(getattr(link, 'decide', None)),
            'executed_at': _to_iso(getattr(link, 'executed_at', None)
                                   or getattr(link, 'executed', None)
                                   or getattr(link, 'finish', None)),
        }
        chain.append({k: v for k, v in entry.items() if v is not None})

        if ability.get('technique_id') and finish_iso:
            try:
                center_dt = datetime.fromisoformat(finish_iso.replace('Z', '+00:00'))
            except Exception:
                center_dt = datetime.now(timezone.utc)
            start_dt = None
            if start_iso:
                try:
                    start_dt = datetime.fromisoformat(start_iso.replace('Z', '+00:00'))
                except Exception:
                    start_dt = None
            windows.append((ability['technique_id'], center_dt, start_dt or center_dt))

    op = dict(operation)
    op['chain'] = chain

    if not op.get('start'):
        start_attr = getattr(caldera_op, 'start', None)
        op['start'] = _to_iso(start_attr) or (chain[0].get('executed_at') if chain else None)
    if not op.get('end'):
        end_attr = getattr(caldera_op, 'finish', None) or getattr(caldera_op, 'end', None)
        if end_attr:
            op['end'] = _to_iso(end_attr)
        elif chain:
            last = chain[-1].get('executed_at') or chain[-1].get('finish')
            if last:
                op['end'] = last

    if not op.get('name'):
        op['name'] = getattr(caldera_op, 'name', None)

    # Provide hint windows for coverage fallback queries
    if windows:
        op['_match_windows'] = windows

    return op


def create_router(*, health_getters: Dict[str, Callable] | None = None) -> web.RouteTableDef:
    routes = web.RouteTableDef()
    health_getters = health_getters or {}

    @routes.get('/api/health')
    async def health_check(request: web.Request) -> web.Response:
        status = {
            'plugin': 'healthy',
            'wazuh_manager': 'unknown',
            'wazuh_indexer': 'unknown',
            'authenticated': False,
            'timestamp': _utc_now_iso()
        }
        try:
            if 'wazuh_manager' in health_getters:
                status['wazuh_manager'] = await _maybe_await(health_getters['wazuh_manager'])
            if 'wazuh_indexer' in health_getters:
                status['wazuh_indexer'] = await _maybe_await(health_getters['wazuh_indexer'])
            if 'authenticated' in health_getters:
                status['authenticated'] = bool(await _maybe_await(health_getters['authenticated']))
        except Exception as e:
            status['error'] = str(e)
        return web.json_response(status)

    @routes.post('/api/correlate')
    async def correlate(request: web.Request) -> web.Response:
        try:
            payload = await request.json()
        except Exception:
            payload = {}

        operation = _ensure_time_range(payload.get('operation') or {})
        operation = await _load_operation_chain(request, operation)
        operation = _ensure_time_range(operation)

        indexer = _indexer_from_config(payload.get('indexer'))

        for k in ('url', 'username', 'password'):
            if not indexer.get(k):
                return _json_error(f"missing indexer.{k}", status=400)

        try:
            result = await compute_coverage(operation, indexer)
            return web.json_response(result)
        except Exception as e:
            return _json_error(f"compute_coverage failed: {e}", status=500)

    @routes.post('/api/dashboard/summary')
    async def dashboard_summary(request: web.Request) -> web.Response:
        try:
            payload = await request.json()
        except Exception:
            payload = {}

        operation = _ensure_time_range(payload.get('operation') or {})
        operation = await _load_operation_chain(request, operation)
        operation = _ensure_time_range(operation)

        indexer = _indexer_from_config(payload.get('indexer'))
        for k in ('url', 'username', 'password'):
            if not indexer.get(k):
                return _json_error(f"missing indexer.{k}", status=400)

        try:
            coverage = await compute_coverage(operation, indexer)
        except Exception as e:
            return _json_error(f"compute_coverage failed: {e}", status=500)

        corr = coverage.get('correlation') or {}
        kpi = {
            'operations': 1 if operation.get('id') else 0,
            'techniques_total': corr.get('total_techniques', 0),
            'techniques_detected': corr.get('detected_techniques', 0),
            'detection_rate': corr.get('detection_rate', 0.0),
            'alerts_total': coverage.get('total_alerts', 0),
            'attack_steps': coverage.get('attack_steps', 0),
        }

        return web.json_response({
            'success': True,
            'generated_at': _utc_now_iso(),
            'operation': {
                'id': coverage.get('operation_id') or operation.get('id'),
                'name': coverage.get('operation_name') or operation.get('name'),
                'start': coverage.get('start_time') or operation.get('start'),
                'end': coverage.get('end_time') or operation.get('end'),
            },
            'kpi': kpi,
            'coverage': coverage,
        })

    return routes
