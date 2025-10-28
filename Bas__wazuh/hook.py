name = 'BasWazuh'
description = 'BAS + Wazuh integration'
address = '/plugins/bas_wazuh'

import json
from datetime import datetime, timezone

from aiohttp import web
import aiohttp_jinja2
from app.service.auth_svc import check_authorization

# Robust import: support package, dotted, and flat module contexts
try:
    from .app.integration_engine import IntegrationEngine
except Exception:
    try:
        from bas_wazuh.integration_engine import IntegrationEngine
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


def _iso(value):
    dt = _to_dt(value)
    return dt.isoformat() if dt else None


async def _list_operations(data_svc):
    try:
        ops = await data_svc.locate('operations', {})
    except Exception:
        ops = await data_svc.locate('operation', {})
    normalized = []
    for o in ops:
        normalized.append({
            'id': str(getattr(o, 'id', '')),
            'name': getattr(o, 'name', '') or str(getattr(o, 'id', '')),
            'start': getattr(o, 'start', None)
        })
    normalized.sort(key=lambda x: x.get('start') or 0, reverse=True)
    return normalized


async def _get_operation_by_id(data_svc, op_id: str):
    for key in ('operations', 'operation'):
        try:
            matches = await data_svc.locate(key, {'id': op_id})
            if matches:
                return matches[0]
        except Exception:
            continue
    try:
        ops = await data_svc.locate('operations', {})
    except Exception:
        ops = await data_svc.locate('operation', {})
    for o in ops:
        if str(getattr(o, 'id', '')) == str(op_id):
            return o
    return None


# ----------------------
# Routes / Handlers
# ----------------------

@check_authorization
@aiohttp_jinja2.template('bas_wazuh.html')
async def gui(request: web.Request):
    services = request.app['bw_services']
    data_svc = services.get('data_svc')

    ops = await _list_operations(data_svc)
    op_id = request.query.get('op_id')
    window = request.query.get('window')

    selected_op = None
    results = None
    error = None
    time_window_sec = 60

    try:
        if not op_id and ops:
            op_id = ops[0]['id']  # latest
        if op_id:
            selected_op = await _get_operation_by_id(data_svc, op_id)
            if selected_op is None:
                error = f'Operation not found: {op_id}'
            else:
                overrides = {}
                if window:
                    try:
                        overrides['time_window_sec'] = int(window)
                    except Exception:
                        pass
                engine = IntegrationEngine(overrides=overrides)
                results = await engine.correlate(selected_op)
                time_window_sec = int(engine.match.get('time_window_sec', 60))
    except Exception as e:
        error = str(e)
        time_window_sec = 60

    return {
        'ops': ops,
        'selected_op_id': op_id,
        'results': results,
        'time_window_sec': time_window_sec,
        'error': error,
    }


@check_authorization
async def download(request: web.Request):
    services = request.app['bw_services']
    data_svc = services.get('data_svc')

    op_id = request.query.get('op_id')
    window = request.query.get('window')
    if not op_id:
        return web.json_response({'error': 'Missing op_id'}, status=400)

    overrides = {}
    if window:
        try:
            overrides['time_window_sec'] = int(window)
        except Exception:
            pass

    op = await _get_operation_by_id(data_svc, op_id)
    if not op:
        return web.json_response({'error': f'Operation not found: {op_id}'}, status=404)

    engine = IntegrationEngine(overrides=overrides)
    results = await engine.correlate(op)
    payload = {
        'operation_id': str(op_id),
        'generated_at': _iso(datetime.now(timezone.utc)),
        'time_window_sec': int(engine.match.get('time_window_sec', 60)),
        'results': results
    }
    return web.Response(
        text=json.dumps(payload, ensure_ascii=False, indent=2),
        content_type='application/json',
        headers={'Content-Disposition': f'attachment; filename="bw_results_{op_id}.json"'}
    )


async def _health(request: web.Request):
    return web.json_response({"status": "ok", "plugin": "bas_wazuh"}, status=200)


async def _ping(request: web.Request):
    return web.Response(text="bas_wazuh pong", content_type="text/plain")


# ----------------------
# API: /operations/start (POST) and /detections (GET)
# ----------------------

@check_authorization
async def start_operation(request: web.Request):
    services = request.app['bw_services']
    data_svc = services.get('data_svc')

    try:
        body = await request.json()
    except Exception:
        body = {}
    op_id = body.get('op_id') or request.query.get('op_id')
    if not op_id:
        return web.json_response({'error': 'Missing op_id'}, status=400)

    overrides = {}
    win = body.get('time_window_sec') or request.query.get('time_window_sec')
    if win:
        try:
            overrides['time_window_sec'] = int(win)
        except Exception:
            pass

    op = await _get_operation_by_id(data_svc, op_id)
    if not op:
        return web.json_response({'error': f'Operation not found: {op_id}'}, status=404)

    engine = IntegrationEngine(overrides=overrides)
    events = await engine.collect_operation_events(op)
    return web.json_response({
        'operation_id': str(op_id),
        'events': events,
        'time_window_sec': int(engine.match.get('time_window_sec', overrides.get('time_window_sec', 60)))
    })


@check_authorization
async def get_detections(request: web.Request):
    services = request.app['bw_services']
    data_svc = services.get('data_svc')

    op_id = request.query.get('op_id')
    if not op_id:
        return web.json_response({'error': 'Missing op_id'}, status=400)

    overrides = {}
    win = request.query.get('time_window_sec')
    if win:
        try:
            overrides['time_window_sec'] = int(win)
        except Exception:
            pass

    op = await _get_operation_by_id(data_svc, op_id)
    if not op:
        return web.json_response({'error': f'Operation not found: {op_id}'}, status=404)

    engine = IntegrationEngine(overrides=overrides)
    results = await engine.correlate(op)
    return web.json_response({
        'operation_id': str(op_id),
        'generated_at': _iso(datetime.now(timezone.utc)),
        'time_window_sec': int(engine.match.get('time_window_sec', overrides.get('time_window_sec', 60))),
        'results': results
    })


async def enable(services):
    app = services.get('app_svc').application
    app['bw_services'] = services

    print("[bas_wazuh] enable() called")

    # Primary iframe path
    app.router.add_route('GET', '/plugins/bas_wazuh', gui)

    # Backward-compatible aliases
    app.router.add_route('GET', '/plugin/bas_wazuh', gui)
    app.router.add_route('GET', '/plugin/bas_wazuh/gui', gui)
    app.router.add_route('GET', '/plugin/bas_wazuh/download', download)

    app.router.add_route('GET', '/plugin/bw/gui', gui)
    app.router.add_route('GET', '/plugin/bw/download', download)

    app.router.add_route('GET', '/plugin/bas_wazuh/health', _health)
    app.router.add_route('GET', '/bas_test', _ping)

    # API routes
    app.router.add_route('POST', '/operations/start', start_operation)
    app.router.add_route('GET', '/detections', get_detections)

    try:
        for r in app.router.routes():
            print("  [bas_wazuh] ROUTE:", r)
    except Exception as e:
        print("[bas_wazuh] route dump error:", e)

    print("[bas_wazuh] enable() finished")
    return True

