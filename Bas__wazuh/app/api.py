from __future__ import annotations
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Callable, Optional
from aiohttp import web

from .coverage import compute_coverage


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_time_range(operation: Dict[str, Any], default_minutes: int = 60) -> Dict[str, Any]:
    """
    coverage.py는 start/end를 기대하므로, 없으면 now-60m ~ now로 보정.
    (이미 값이 있으면 그대로 둔다)
    """
    op = dict(operation or {})
    has_start = bool(op.get("start"))
    has_end = bool(op.get("end"))
    if not (has_start and has_end):
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(minutes=default_minutes)
        if not has_start:
            op["start"] = end_dt.isoformat()  # 또는 start_dt, 필요에 따라 선택
            # 위 줄을 start_dt로 바꾸면 "시작~종료" 윈도우가 됨. 대시보드 요건에 따라 결정.
            op["start"] = start_dt.isoformat()
        if not has_end:
            op["end"] = end_dt.isoformat()
    return op


def _indexer_from_config(passed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    IntegrationEngine의 setting.yml(wazuh.*)을 기본으로 사용하고,
    클라이언트가 일부를 넘기면 덮어쓴다.
    """
    passed = passed or {}

    # IntegrationEngine 로드
    try:
        from .integration_engine import IntegrationEngine
    except Exception:
        from importlib import import_module
        IntegrationEngine = import_module('integration_engine').IntegrationEngine

    eng = IntegrationEngine()
    wz = eng.wazuh or {}

    # scheme/host/port → url
    scheme = (passed.get('scheme')
              or wz.get('scheme')
              or ('https' if wz.get('verify_ssl', True) else 'http')) or 'http'
    host = passed.get('host') or wz.get('host', 'localhost')
    port = int(passed.get('port') or wz.get('port', 9200))
    url = passed.get('url') or f"{scheme}://{host}:{port}"

    idx = {
        "url": url,
        "username": passed.get("username") or wz.get("username"),
        "password": passed.get("password") or wz.get("password"),
        "index": passed.get("index") or wz.get("index_pattern") or "wazuh-alerts-*",
        "verify_ssl": passed.get("verify_ssl", wz.get("verify_ssl", True)),
    }
    return idx


async def _maybe_await(func: Callable, *args, **kwargs):
    """health_getters가 sync/async 모두 가능하도록 래핑."""
    try:
        res = func(*args, **kwargs)
        if asyncio.iscoroutine(res):
            return await res
        return res
    except Exception as e:
        return f"error: {e}"


def _json_error(msg: str, status: int = 500) -> web.Response:
    return web.json_response({"success": False, "error": msg}, status=status)


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
        indexer = _indexer_from_config(payload.get('indexer'))

        # 필수값 점검
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

        # 1) operation 범위 보정
        operation = _ensure_time_range(payload.get('operation') or {})

        # 2) 인덱서 설정(setting.yml 기반) 자동 주입 + 덮어쓰기
        indexer = _indexer_from_config(payload.get('indexer'))

        # 3) 필수값 검증 (명확한 400)
        for k in ('url', 'username', 'password'):
            if not indexer.get(k):
                return _json_error(f"missing indexer.{k}", status=400)

        # 4) 커버리지 계산
        try:
            coverage = await compute_coverage(operation, indexer)
        except Exception as e:
            return _json_error(f"compute_coverage failed: {e}", status=500)

        # 5) KPI 구성
        corr = coverage.get('correlation') or {}
        kpi = {
            'operations': 1 if operation.get('id') else 0,
            'techniques_total': corr.get('total_techniques', 0),
            'techniques_detected': corr.get('detected_techniques', 0),
            'detection_rate': corr.get('detection_rate', 0.0),
            'alerts_total': coverage.get('total_alerts', 0),
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
