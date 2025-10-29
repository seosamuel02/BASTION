from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict
from aiohttp import web

from .coverage import compute_coverage

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def create_router(*, health_getters: Dict[str, callable] | None = None) -> web.RouteTableDef:
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
                status['wazuh_manager'] = await health_getters['wazuh_manager']()
            if 'wazuh_indexer' in health_getters:
                status['wazuh_indexer'] = await health_getters['wazuh_indexer']()
            if 'authenticated' in health_getters:
                status['authenticated'] = bool(await health_getters['authenticated']())
        except Exception as e:
            status['error'] = str(e)
        return web.json_response(status)

    @routes.post('/api/correlate')
    async def correlate(request: web.Request) -> web.Response:
        payload = await request.json()
        operation = payload.get('operation') or {}
        indexer = payload.get('indexer') or {}
        result = await compute_coverage(operation, indexer)
        return web.json_response(result)

    @routes.post('/api/dashboard/summary')
    async def dashboard_summary(request: web.Request) -> web.Response:
        payload = await request.json()
        operation = payload.get('operation') or {}
        indexer = payload.get('indexer') or {}

        coverage = await compute_coverage(operation, indexer)

        # Derive simple KPI for dashboard cards
        corr = coverage.get('correlation') or {}
        kpi = {
            'operations': 1,
            'techniques_total': corr.get('total_techniques', 0),
            'techniques_detected': corr.get('detected_techniques', 0),
            'detection_rate': corr.get('detection_rate', 0.0),
            'alerts_total': coverage.get('total_alerts', 0),
        }

        return web.json_response({
            'success': True,
            'generated_at': _utc_now_iso(),
            'operation': {
                'id': coverage.get('operation_id'),
                'name': coverage.get('operation_name'),
                'start': coverage.get('start_time'),
                'end': coverage.get('end_time'),
            },
            'kpi': kpi,
            'coverage': coverage,
        })

    return routes