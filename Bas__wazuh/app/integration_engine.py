import os
import yaml
import asyncio
from datetime import datetime, timedelta, timezone

try:
    from opensearchpy import OpenSearch
except Exception:
    OpenSearch = None

try:
    from elasticsearch import Elasticsearch
except Exception:
    Elasticsearch = None


CONFIG_CANDIDATES = [
    os.path.join(os.path.dirname(__file__), 'config', 'setting.yml'),
    os.path.join(os.getcwd(), 'config', 'setting.yml')
]


def _to_dt(value):
    """value(str/int/float/datetime) -> timezone-aware UTC datetime | None"""
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

def _iso(dt):
    if dt is None:
        return None
    if isinstance(dt, (int, float)):
        dt = datetime.fromtimestamp(dt, tz=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


class IntegrationEngine:
    def __init__(self, overrides: dict | None = None):
        self.config = self._load_settings()
        if overrides:
            # shallow override for top-level known keys
            self.config.update(overrides)

        self.wazuh = self.config.get('wazuh', {})
        self.match = self.config.get('match', {})
        self.client = self._build_client()

    # ------------------
    # Config / Client
    # ------------------
    def _load_settings(self) -> dict:
        for path in CONFIG_CANDIDATES:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
        return {}

    def _build_client(self):
        # support both nested (wazuh.*) and legacy flat keys
        host = self.wazuh.get('host') or self.config.get('host', 'localhost')
        port = int(self.wazuh.get('port') or self.config.get('port', 9200))
        scheme = (self.wazuh.get('scheme') or ('https' if self.config.get('ssl') else 'http') or 'http')
        verify = bool(self.wazuh.get('verify_ssl', self.config.get('verify_certs', True)))
        username = self.wazuh.get('username') or self.config.get('username')
        password = self.wazuh.get('password') or self.config.get('password')

        # 기본 kwargs
        kwargs = {
            'verify_certs': verify,
            'ssl_show_warn': False,
            'timeout': 30,
            'max_retries': 2,
            'retry_on_timeout': True,
        }

        # 호스트 정의: ES는 hosts에 scheme 포함이 안전, OS도 수용
        hosts = [{'host': host, 'port': port, 'scheme': scheme}]
        kwargs['hosts'] = hosts

        # SSL 관련 (자체서명 허용 시 경고/검증 완화)
        if scheme == 'https':
            kwargs['use_ssl'] = True
            if not verify:
                # 일부 버전에서 필요
                kwargs['ssl_assert_hostname'] = False
                kwargs['ssl_assert_fingerprint'] = None
        else:
            kwargs['use_ssl'] = False

    # 인증 (양쪽 클라 호환 위해 둘 다)
        if username:
            kwargs['http_auth'] = (username, password)
            kwargs['basic_auth'] = (username, password)

        if OpenSearch is not None:
            return OpenSearch(**kwargs)
        if Elasticsearch is not None:
            return Elasticsearch(**kwargs)
        raise RuntimeError('Neither opensearch-py nor elasticsearch client is installed')

    # ------------------
    # Operation Events
    # ------------------
    def _event_from_link(self, link) -> dict:
        ability = getattr(link, 'ability', None)
        technique_id = getattr(ability, 'technique_id', None) if ability else None
        ability_name = getattr(ability, 'name', '') if ability else ''
        ts_dt = getattr(link, 'finish', None) or getattr(link, 'start', None) or getattr(link, 'decide', None)
        command = getattr(link, 'command', None)
        pid = getattr(link, 'pid', None)

        return {
            'link_id': str(getattr(link, 'id', '')),
            'ability_name': ability_name,
            'technique_id': technique_id,
            'executed_at': _iso(ts_dt),
            'timestamp': ts_dt.timestamp() if hasattr(ts_dt, 'timestamp') else (float(ts_dt) if ts_dt else None),
            'command': command.decode('utf-8', errors='ignore') if isinstance(command, (bytes, bytearray)) else command,
            'pid': pid,
        }

    async def collect_operation_events(self, operation) -> list[dict]:
        events = []
        chain = getattr(operation, 'chain', [])
        for link in chain:
            events.append(self._event_from_link(link))
        return events

    # ------------------
    # Indexer Querying
    # ------------------
    def _build_query(self, technique_id: str, center_ts: float) -> dict:
        window_sec = int(self.match.get('time_window_sec', self.config.get('time_window_sec', 60)))
        center = datetime.fromtimestamp(center_ts, tz=timezone.utc)
        gte = (center - timedelta(seconds=window_sec)).isoformat()
        lte = (center + timedelta(seconds=window_sec)).isoformat()

        mitre_fields = self.match.get('mitre_fields') or ['rule.mitre.id', 'mitre.id']
        message_fields = self.match.get('message_fields') or []

        should = []
        for f in mitre_fields:
            should.append({'term': {f if not f.endswith('.keyword') else f: technique_id}})
            # also try keyword variants for analyzed fields
            if not f.endswith('.keyword'):
                should.append({'term': {f + '.keyword': technique_id}})
        for f in message_fields:
            should.append({'match_phrase': {f: technique_id}})

        return {
            'size': int(self.match.get('max_alerts', 200)),
            'query': {
                'bool': {
                    'filter': [
                        {'range': {'@timestamp': {'gte': gte, 'lte': lte}}}
                    ],
                    'should': should,
                    'minimum_should_match': 1
                }
            },
            'sort': [{'@timestamp': {'order': 'asc'}}]
        }

    def _summarize_hit(self, src: dict) -> dict:
        rule = src.get('rule') if isinstance(src.get('rule'), dict) else {}
        mitre = rule.get('mitre') if isinstance(rule.get('mitre'), dict) else {}
        agent = src.get('agent') if isinstance(src.get('agent'), dict) else {}

        return {
            '@timestamp': src.get('@timestamp'),
            'rule.id': rule.get('id', src.get('rule.id')),
            'level': rule.get('level', src.get('level')),
            'mitre.id': mitre.get('id', src.get('mitre.id') or src.get('rule.mitre.id')),
            'agent.id': agent.get('id'),
            'agent.name': agent.get('name'),
            'description': rule.get('description') or src.get('message'),
            'full.log' : src.get('full_log'),
        }

    def _search(self, technique_id: str, ts_epoch: float) -> list[dict]:
        if not technique_id or not ts_epoch:
            return []
        index = self.wazuh.get('index_pattern') or self.config.get('index', 'wazuh-alerts-4.x-*')
        body = self._build_query(technique_id, ts_epoch)
        try:
            resp = self.client.search(index=index, body=body)
        except Exception:
            return []
        hits = resp.get('hits', {}).get('hits', [])
        return [self._summarize_hit(h.get('_source', {})) for h in hits]

    async def correlate(self, operation) -> list[dict]:
        loop = asyncio.get_event_loop()
        results = []
        chain = getattr(operation, 'chain', [])
        for link in chain:
            ability = getattr(link, 'ability', None)
            technique_id = getattr(ability, 'technique_id', None) if ability else None
            ability_name = getattr(ability, 'name', '') if ability else ''

            ts_raw = getattr(link, 'finish', None) or getattr(link, 'start', None) or getattr(link, 'decide', None)
            ts_dt = _to_dt(ts_raw)
            ts_epoch = ts_dt.timestamp() if ts_dt else None

            matches = []
            if technique_id and ts_epoch:
                matches = await loop.run_in_executor(None, self._search, technique_id, ts_epoch)

            results.append({
                'link_id': str(getattr(link, 'id', '')),
                'ability_name': ability_name,
                'technique_id': technique_id,
                'executed_at': _iso(ts_dt) if ts_dt else None,
                'detected': len(matches) > 0,
                'match_count': len(matches),
                'matches': matches
            })
        return results
    

    