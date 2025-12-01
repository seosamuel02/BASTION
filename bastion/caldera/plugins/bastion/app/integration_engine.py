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
    os.path.join(os.path.dirname(__file__), 'conf', 'default.yml'),
    os.path.join(os.getcwd(), 'conf', 'default.yml')
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

    # UNIX timestamp면 datetime으로 변환
    if isinstance(dt, (int, float)):
        dt = datetime.fromtimestamp(dt, tz=timezone.utc)

    # naive datetime이면 UTC로 설정
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    # ISO8601 생성
    text = dt.isoformat()

    # "+00:00" → "Z"
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"

    return text


class IntegrationEngine:
    def __init__(self, overrides: dict | None = None, rule_mitre_mapping: dict | None = None):
        self.config = self._load_settings()
        if overrides:
            # shallow override for top-level known keys
            self.config.update(overrides)

        self.wazuh = self.config.get('wazuh', {})
        self.match = self.config.get('match', {})
        self.client = self._build_client()

        # 디버깅 모드 추가
        self.debug = self.config.get('debug', False)

        # Rule ID → MITRE Technique 매핑 (역매핑 생성)
        self.rule_mitre_mapping = rule_mitre_mapping or {}
        self.technique_to_rules = {}  # MITRE Technique → Rule IDs 역매핑
        if self.rule_mitre_mapping:
            for rule_id, technique_id in self.rule_mitre_mapping.items():
                if technique_id not in self.technique_to_rules:
                    self.technique_to_rules[technique_id] = []
                self.technique_to_rules[technique_id].append(str(rule_id))

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
    # Indexer Querying (개선됨)
    # ------------------
    def _build_query(self, technique_id: str, center_ts: float) -> dict:
        """개선된 쿼리 빌더 - 더 넓은 시간 윈도우와 다양한 필드 검색"""
        # 시간 윈도우 설정 (기본: 7200초 = 2시간)
        window_sec = int(self.match.get('time_window_sec', self.config.get('time_window_sec', 7200)))

        # Unix timestamp를 UTC datetime으로 변환
        center = datetime.fromtimestamp(center_ts, tz=timezone.utc)
        gte = (center - timedelta(seconds=window_sec)).isoformat()
        lte = (center + timedelta(seconds=window_sec)).isoformat()

        if self.debug:
            print(f"[DEBUG] Time window: {window_sec} seconds (±{window_sec/3600:.1f} hours)")
            print(f"[DEBUG] Center timestamp: {center_ts} → {center}")
            print(f"[DEBUG] Search range: {gte} to {lte}")

        # MITRE 필드들 - 더 많은 변형 추가
        mitre_fields = self.match.get('mitre_fields') or [
            'data.mitre.id',
            'rule.mitre.id', 
            'mitre.id',
            'rule.mitre.technique',
        ]
        
        message_fields = self.match.get('message_fields') or []

        # should 조건 구성
        should = []
        
        # 1. 각 MITRE 필드에 대해 term 쿼리 (정확한 매칭)
        for f in mitre_fields:
            # 원본 필드명으로 검색
            should.append({'term': {f: technique_id}})
            
            # .keyword 변형도 시도 (analyzed 필드 대응)
            if not f.endswith('.keyword'):
                should.append({'term': {f + '.keyword': technique_id}})
        
        # 2. 메시지 필드에서 구문 검색
        for f in message_fields:
            should.append({'match_phrase': {f: technique_id}})

        # 3. Rule ID 매핑을 사용한 검색 (MITRE 필드가 없는 알림 대응)
        if technique_id in self.technique_to_rules:
            rule_ids = self.technique_to_rules[technique_id]
            for rule_id in rule_ids:
                should.append({'term': {'rule.id': rule_id}})
                should.append({'term': {'rule.id.keyword': rule_id}})
            if self.debug:
                print(f"[DEBUG] Added rule.id filters for {technique_id}: {rule_ids}")

        # 4. 와일드카드로 부분 매칭도 추가 (T1xxx 형식 감지)
        should.append({'wildcard': {'data.mitre.id': f'*{technique_id}*'}})
        should.append({'wildcard': {'rule.mitre.id': f'*{technique_id}*'}})

        # timestamp와 @timestamp 둘 다 지원
        time_should = [
            {'range': {'@timestamp': {'gte': gte, 'lte': lte}}},
            {'range': {'timestamp': {'gte': gte, 'lte': lte}}}
        ]

        query = {
            'size': int(self.match.get('max_alerts', 200)),
            'query': {
                'bool': {
                    'filter': [
                        {
                            'bool': {
                                'should': time_should,
                                'minimum_should_match': 1
                            }
                        }
                    ],
                    'should': should,
                    'minimum_should_match': 1
                }
            },
            'sort': [
                {'@timestamp': {'order': 'asc', 'unmapped_type': 'date'}},
                {'timestamp': {'order': 'asc', 'unmapped_type': 'date'}}
            ]
        }
        
        # 디버그 모드일 때 쿼리 출력
        if self.debug:
            import json
            print(f"\n[DEBUG] Query for {technique_id} at {center}:")
            print(f"Time range: {gte} ~ {lte}")
            print(json.dumps(query, indent=2))
        
        return query

    def _extract_mitre_id(self, *values):
        """MITRE ID 추출 - 배열인 경우 첫 번째 요소 반환"""
        for val in values:
            if val:
                if isinstance(val, list) and len(val) > 0:
                    # 배열인 경우 첫 번째 요소 반환
                    return val[0] if val[0] else None
                elif isinstance(val, str):
                    # 문자열인 경우 그대로 반환
                    return val
        return None

    def _summarize_hit(self, hit: dict) -> dict:
        src = hit.get('_source', {}) or {}
        doc_id = hit.get('_id')
        rule = src.get('rule') if isinstance(src.get('rule'), dict) else {}
        
        # data.mitre 처리
        data_mitre = src.get('data', {}).get('mitre', {}) if isinstance(src.get('data'), dict) else {}
        
        # rule.mitre 처리 (list일 수 있음)
        raw_rule_mitre = rule.get('mitre')
        if isinstance(raw_rule_mitre, list) and raw_rule_mitre:
            rule_mitre = raw_rule_mitre[0] if isinstance(raw_rule_mitre[0], dict) else {}
        elif isinstance(raw_rule_mitre, dict):
            rule_mitre = raw_rule_mitre
        else:
            rule_mitre = {}

        agent = src.get('agent') if isinstance(src.get('agent'), dict) else {}

        # timestamp 우선순위: @timestamp > timestamp
        ts = src.get('@timestamp') or src.get('timestamp')

        return {
            'doc_id': doc_id,
            '@timestamp': ts,

            # 룰/레벨
            'rule.id': rule.get('id') or src.get('rule.id'),
            'level': rule.get('level') or src.get('rule.level') or src.get('level'),

            # MITRE - 여러 경로 시도 (배열인 경우 첫 번째 요소 추출)
            'mitre.id': self._extract_mitre_id(
                data_mitre.get('id'),
                rule_mitre.get('id'),
                src.get('mitre.id'),
                src.get('rule.mitre.id')
            ),
            'mitre.tactic': (
                data_mitre.get('tactic') or
                rule_mitre.get('tactic') or
                src.get('mitre.tactic') or
                src.get('rule.mitre.tactic')
            ),

            # 에이전트 정보
            'agent.id': agent.get('id') or src.get('agent.id'),
            'agent.name': agent.get('name') or src.get('agent.name'),

            # 기타
            'description': (
                rule.get('description') or
                src.get('rule.description') or
                src.get('message') or
                src.get('full_log')
            ),
            'data.audit.type': src.get('data', {}).get('audit', {}).get('type') if isinstance(src.get('data'), dict) else None,
            'data.audit.exe': src.get('data', {}).get('audit', {}).get('exe') if isinstance(src.get('data'), dict) else None,
        }

    def _search(self, technique_id: str, ts_epoch: float) -> list[dict]:
        """검색 수행 및 디버그 정보 출력"""
        if not technique_id or not ts_epoch:
            if self.debug:
                print(f"[DEBUG] Skipping search - technique_id: {technique_id}, ts_epoch: {ts_epoch}")
            return []
        
        index = self.wazuh.get('index_pattern') or self.config.get('index', 'wazuh-alerts-4.x-*')
        body = self._build_query(technique_id, ts_epoch)
        
        try:
            if self.debug:
                print(f"\n[DEBUG] Searching index: {index}")
                print(f"[DEBUG] Technique: {technique_id}")
                print(f"[DEBUG] Timestamp: {datetime.fromtimestamp(ts_epoch, tz=timezone.utc)}")
            
            resp = self.client.search(index=index, body=body)
            hits = resp.get('hits', {}).get('hits', [])
            
            if self.debug:
                print(f"[DEBUG] Found {len(hits)} hits")
                if hits:
                    print("[DEBUG] Sample hit:")
                    sample = hits[0].get('_source', {})
                    print(f"  - rule.id: {sample.get('rule', {}).get('id')}")
                    print(f"  - timestamp: {sample.get('@timestamp') or sample.get('timestamp')}")
                    print(f"  - data.mitre.id: {sample.get('data', {}).get('mitre', {}).get('id')}")
                    print(f"  - rule.mitre: {sample.get('rule', {}).get('mitre')}")
            
            return [self._summarize_hit(h) for h in hits]
            
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Search failed: {e}")
            import traceback
            traceback.print_exc()
            return []

    async def correlate(self, operation) -> list[dict]:
        """작업의 각 링크에 대해 Wazuh 알림과 상관분석"""
        loop = asyncio.get_event_loop()
        results = []
        chain = getattr(operation, 'chain', [])
        
        if self.debug:
            print(f"\n[DEBUG] ========== Correlation Start ==========")
            print(f"[DEBUG] Operation: {getattr(operation, 'name', 'Unknown')}")
            print(f"[DEBUG] Total links: {len(chain)}")
        
        for idx, link in enumerate(chain, 1):
            ability = getattr(link, 'ability', None)
            technique_id = getattr(ability, 'technique_id', None) if ability else None
            ability_name = getattr(ability, 'name', '') if ability else ''

            ts_raw = getattr(link, 'finish', None) or getattr(link, 'start', None) or getattr(link, 'decide', None)
            ts_dt = _to_dt(ts_raw)
            ts_epoch = ts_dt.timestamp() if ts_dt else None

            if self.debug:
                print(f"\n[DEBUG] --- Link {idx}/{len(chain)} ---")
                print(f"[DEBUG] Ability: {ability_name}")
                print(f"[DEBUG] Technique: {technique_id}")
                print(f"[DEBUG] Timestamp: {ts_dt} ({ts_epoch})")

            matches = []
            if technique_id and ts_epoch:
                matches = await loop.run_in_executor(None, self._search, technique_id, ts_epoch)
                
                if self.debug:
                    print(f"[DEBUG] Matches found: {len(matches)}")
            else:
                if self.debug:
                    print(f"[DEBUG] Skipped - missing technique_id or timestamp")

            results.append({
                'link_id': str(getattr(link, 'id', '')),
                'ability_name': ability_name,
                'technique_id': technique_id,
                'executed_at': _iso(ts_dt) if ts_dt else None,
                'detected': len(matches) > 0,
                'match_count': len(matches),
                'matches': matches
            })
        
        if self.debug:
            detected_count = sum(1 for r in results if r['detected'])
            print(f"\n[DEBUG] ========== Correlation End ==========")
            print(f"[DEBUG] Total: {len(results)}, Detected: {detected_count}")
        
        return results