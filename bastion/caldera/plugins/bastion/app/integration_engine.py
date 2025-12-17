import os
import yaml
import asyncio
from datetime import datetime, timedelta, timezone

try:
    from opensearchpy import OpenSearch
except Exception as e:
    import logging
    logging.getLogger('integration_engine').debug(f'[IntegrationEngine] OpenSearch import 실패: {e}')
    OpenSearch = None

try:
    from elasticsearch import Elasticsearch
except Exception as e:
    import logging
    logging.getLogger('integration_engine').debug(f'[IntegrationEngine] Elasticsearch import 실패: {e}')
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
        except Exception as e:
            # timestamp 변환 실패는 흔한 일이므로 디버그 레벨만 로깅
            import logging
            logging.getLogger('integration_engine').debug(f'[IntegrationEngine] datetime 변환 실패: {s}, error: {e}')
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
        """링크 정보를 이벤트 딕셔너리로 변환 (안전한 처리)"""
        try:
            ability = getattr(link, 'ability', None)
            technique_id = getattr(ability, 'technique_id', None) if ability else None
            ability_name = getattr(ability, 'name', '') if ability else ''
            ts_dt = getattr(link, 'finish', None) or getattr(link, 'start', None) or getattr(link, 'decide', None)
            command = getattr(link, 'command', None)
            pid = getattr(link, 'pid', None)

            # timestamp 안전하게 처리
            timestamp = None
            if ts_dt:
                try:
                    if hasattr(ts_dt, 'timestamp'):
                        timestamp = ts_dt.timestamp()
                    elif isinstance(ts_dt, (int, float)):
                        timestamp = float(ts_dt)
                except Exception as e:
                    import logging
                    logging.getLogger('integration_engine').debug(f'[IntegrationEngine] timestamp 변환 실패: {ts_dt}, error: {e}')
                    timestamp = None

            return {
                'link_id': str(getattr(link, 'id', '')),
                'ability_name': ability_name or '',
                'technique_id': technique_id or '',
                'executed_at': _iso(ts_dt),
                'timestamp': timestamp,
                'command': command.decode('utf-8', errors='ignore') if isinstance(command, (bytes, bytearray)) else (command or ''),
                'pid': pid,
            }
        except Exception as e:
            # 최소한의 정보라도 반환
            return {
                'link_id': str(getattr(link, 'id', '')) if link else '',
                'ability_name': '',
                'technique_id': '',
                'executed_at': None,
                'timestamp': None,
                'command': '',
                'pid': None,
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
        """개선된 쿼리 빌더 - 더 넓은 시간 윈도우와 다양한 필드 검색 (안전한 처리)"""
        try:
            # 시간 윈도우 설정 (기본: 7200초 = 2시간)
            window_sec = int(self.match.get('time_window_sec', self.config.get('time_window_sec', 7200)))

            # Unix timestamp를 UTC datetime으로 변환 (안전하게)
            try:
                center = datetime.fromtimestamp(center_ts, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                # timestamp가 유효하지 않으면 현재 시간 사용
                center = datetime.now(tz=timezone.utc)

            gte = (center - timedelta(seconds=window_sec)).isoformat()
            lte = (center + timedelta(seconds=window_sec)).isoformat()

            if self.debug:
                print(f"[DEBUG] Time window: {window_sec} seconds (±{window_sec/3600:.1f} hours)")
                print(f"[DEBUG] Center timestamp: {center_ts} → {center}")
                print(f"[DEBUG] Search range: {gte} to {lte}")
        except Exception as time_err:
            if self.debug:
                print(f"[DEBUG] Time window setup error: {time_err}")
            # fallback: 최근 2시간 검색
            gte = "now-2h"
            lte = "now+2h"

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

    def _extract_pid(self, data: dict) -> str | None:
        """Wazuh 알림에서 PID 추출 (Linux auditd / Windows Sysmon)"""
        if not isinstance(data, dict):
            return None

        # Linux auditd: data.audit.pid
        audit = data.get('audit')
        if isinstance(audit, dict):
            pid = audit.get('pid')
            if pid:
                return str(pid)

        # Windows Sysmon: data.win.eventdata.processId
        win = data.get('win')
        if isinstance(win, dict):
            eventdata = win.get('eventdata')
            if isinstance(eventdata, dict):
                pid = eventdata.get('processId') or eventdata.get('ProcessId')
                if pid:
                    return str(pid)

        return None

    def _extract_ppid(self, data: dict) -> str | None:
        """Wazuh 알림에서 PPID(Parent PID) 추출 (Linux auditd / Windows Sysmon)"""
        if not isinstance(data, dict):
            return None

        # Linux auditd: data.audit.ppid
        audit = data.get('audit')
        if isinstance(audit, dict):
            ppid = audit.get('ppid')
            if ppid:
                return str(ppid)

        # Windows Sysmon: data.win.eventdata.parentProcessId
        win = data.get('win')
        if isinstance(win, dict):
            eventdata = win.get('eventdata')
            if isinstance(eventdata, dict):
                ppid = eventdata.get('parentProcessId') or eventdata.get('ParentProcessId')
                if ppid:
                    return str(ppid)

        return None

    def _match_pid(self, link_pid, alert_pid: str | None, alert_ppid: str | None) -> tuple[bool, str | None]:
        """PID 매칭 확인 및 매칭 타입 반환

        Args:
            link_pid: Caldera 링크의 PID (int, str, or None)
            alert_pid: Wazuh 알림의 PID
            alert_ppid: Wazuh 알림의 PPID (Parent PID)

        Returns:
            (matched, match_type) - match_type: 'pid'|'ppid'|None
        """
        if link_pid is None:
            return (False, None)

        link_pid_str = str(link_pid)

        # 직접 PID 매칭 (우선순위 높음)
        if alert_pid and str(alert_pid) == link_pid_str:
            return (True, 'pid')

        # PPID 매칭 (자식 프로세스가 탐지된 경우)
        if alert_ppid and str(alert_ppid) == link_pid_str:
            return (True, 'ppid')

        return (False, None)

    def _calculate_confidence(self, matches: list[dict], link_pid) -> float:
        """탐지 신뢰도 점수 계산 (0.0 ~ 1.0)

        - MITRE + Time 매칭: 0.5 (기본)
        - PID 직접 매칭: +0.4
        - PPID 매칭: +0.3
        """
        if not matches:
            return 0.0

        base_score = 0.5  # MITRE + Time 매칭 기본 점수

        # PID 매칭 가산점
        pid_matches = [m for m in matches if m.get('pid_matched', False)]
        if pid_matches:
            # PID 직접 매칭 확인
            direct_pid = any(m.get('pid_match_type') == 'pid' for m in pid_matches)
            ppid_match = any(m.get('pid_match_type') == 'ppid' for m in pid_matches)

            if direct_pid:
                base_score += 0.4  # PID 직접 매칭
            elif ppid_match:
                base_score += 0.3  # PPID 매칭

        return min(base_score, 1.0)

    def _summarize_hit(self, hit: dict) -> dict:
        """Elasticsearch/OpenSearch hit를 요약 (안전한 처리)"""
        try:
            if not hit or not isinstance(hit, dict):
                return {}

            src = hit.get('_source', {}) or {}
            doc_id = hit.get('_id')

            # rule 처리
            rule = src.get('rule')
            if not isinstance(rule, dict):
                rule = {}

            # data.mitre 처리
            data = src.get('data')
            if isinstance(data, dict):
                data_mitre = data.get('mitre', {})
                if not isinstance(data_mitre, dict):
                    data_mitre = {}
            else:
                data_mitre = {}

            # rule.mitre 처리 (list일 수 있음)
            raw_rule_mitre = rule.get('mitre')
            if isinstance(raw_rule_mitre, list) and raw_rule_mitre:
                rule_mitre = raw_rule_mitre[0] if isinstance(raw_rule_mitre[0], dict) else {}
            elif isinstance(raw_rule_mitre, dict):
                rule_mitre = raw_rule_mitre
            else:
                rule_mitre = {}

            # agent 처리
            agent = src.get('agent')
            if not isinstance(agent, dict):
                agent = {}

            # timestamp 우선순위: @timestamp > timestamp
            ts = src.get('@timestamp') or src.get('timestamp')

            # MITRE ID 추출 (안전하게)
            mitre_id = None
            try:
                mitre_id = self._extract_mitre_id(
                    data_mitre.get('id'),
                    rule_mitre.get('id'),
                    src.get('mitre.id'),
                    src.get('rule.mitre.id')
                )
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] MITRE ID 추출 실패: {e}")
                mitre_id = None

            # MITRE tactic 추출
            mitre_tactic = (
                data_mitre.get('tactic') or
                rule_mitre.get('tactic') or
                src.get('mitre.tactic') or
                src.get('rule.mitre.tactic')
            )

            # description 추출
            description = (
                rule.get('description') or
                src.get('rule.description') or
                src.get('message') or
                src.get('full_log') or
                ''
            )

            return {
                'doc_id': doc_id,
                '@timestamp': ts,

                # 룰/레벨
                'rule.id': rule.get('id') or src.get('rule.id'),
                'level': rule.get('level') or src.get('rule.level') or src.get('level'),

                # MITRE - 여러 경로 시도
                'mitre.id': mitre_id,
                'mitre.tactic': mitre_tactic,

                # 에이전트 정보
                'agent.id': agent.get('id') or src.get('agent.id'),
                'agent.name': agent.get('name') or src.get('agent.name'),

                # 기타
                'description': description,
                'data.audit.type': data.get('audit', {}).get('type') if isinstance(data, dict) and isinstance(data.get('audit'), dict) else None,
                'data.audit.exe': data.get('audit', {}).get('exe') if isinstance(data, dict) and isinstance(data.get('audit'), dict) else None,

                # PID 필드 추출 (Linux auditd / Windows Sysmon)
                'pid': self._extract_pid(data),
                'ppid': self._extract_ppid(data),
            }
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] _summarize_hit failed: {e}")
            return {}

    def _search(self, technique_id: str, ts_epoch: float) -> list[dict]:
        """검색 수행 및 디버그 정보 출력 (안전한 처리)"""
        # 입력값 검증
        if not technique_id:
            if self.debug:
                print(f"[DEBUG] Skipping search - no technique_id")
            return []

        if not ts_epoch or not isinstance(ts_epoch, (int, float)):
            if self.debug:
                print(f"[DEBUG] Skipping search - invalid ts_epoch: {ts_epoch}")
            return []

        # 클라이언트 존재 확인
        if not self.client:
            if self.debug:
                print(f"[DEBUG] No client available")
            return []

        index = self.wazuh.get('index_pattern') or self.config.get('index', 'wazuh-alerts-4.x-*')

        try:
            body = self._build_query(technique_id, ts_epoch)
        except Exception as query_err:
            if self.debug:
                print(f"[DEBUG] Query build failed: {query_err}")
            return []

        try:
            if self.debug:
                print(f"\n[DEBUG] Searching index: {index}")
                print(f"[DEBUG] Technique: {technique_id}")
                try:
                    print(f"[DEBUG] Timestamp: {datetime.fromtimestamp(ts_epoch, tz=timezone.utc)}")
                except Exception as e:
                    print(f"[DEBUG] Timestamp: {ts_epoch} (raw, conversion failed: {e})")

            resp = self.client.search(index=index, body=body)

            if not resp:
                if self.debug:
                    print(f"[DEBUG] Empty response from search")
                return []

            hits = resp.get('hits', {}).get('hits', [])

            if self.debug:
                print(f"[DEBUG] Found {len(hits)} hits")
                if hits:
                    try:
                        print("[DEBUG] Sample hit:")
                        sample = hits[0].get('_source', {})
                        print(f"  - rule.id: {sample.get('rule', {}).get('id')}")
                        print(f"  - timestamp: {sample.get('@timestamp') or sample.get('timestamp')}")
                        print(f"  - data.mitre.id: {sample.get('data', {}).get('mitre', {}).get('id')}")
                        print(f"  - rule.mitre: {sample.get('rule', {}).get('mitre')}")
                        print(f"  - agent: {sample.get('agent')}")
                    except Exception as e:
                        print(f"[DEBUG] Sample hit 출력 실패: {e}")

            # 결과 처리 (안전하게)
            results = []
            for h in hits:
                try:
                    summarized = self._summarize_hit(h)
                    if summarized:
                        results.append(summarized)
                        if self.debug and len(results) == 1:
                            print(f"[DEBUG] First summarized result:")
                            print(f"  - rule.id: {summarized.get('rule.id')}")
                            print(f"  - agent.id: {summarized.get('agent.id')}")
                            print(f"  - agent.name: {summarized.get('agent.name')}")
                except Exception as sum_err:
                    if self.debug:
                        print(f"[DEBUG] Failed to summarize hit: {sum_err}")
                    continue

            return results

        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Search failed: {e}")
            import traceback
            traceback.print_exc()
            return []

    async def correlate(self, operation) -> list[dict]:
        """작업의 각 링크에 대해 Wazuh 알림과 상관분석 (안전한 처리)"""
        try:
            loop = asyncio.get_event_loop()
            results = []
            chain = getattr(operation, 'chain', [])

            if not chain:
                if self.debug:
                    print(f"[DEBUG] Operation {getattr(operation, 'name', 'Unknown')}: No chain links")
                return []

            if self.debug:
                print(f"\n[DEBUG] ========== Correlation Start ==========")
                print(f"[DEBUG] Operation: {getattr(operation, 'name', 'Unknown')}")
                print(f"[DEBUG] Total links: {len(chain)}")

            for idx, link in enumerate(chain, 1):
                try:
                    ability = getattr(link, 'ability', None)
                    technique_id = getattr(ability, 'technique_id', None) if ability else None
                    ability_name = getattr(ability, 'name', '') if ability else ''

                    ts_raw = getattr(link, 'finish', None) or getattr(link, 'start', None) or getattr(link, 'decide', None)
                    ts_dt = _to_dt(ts_raw)
                    ts_epoch = ts_dt.timestamp() if ts_dt else None

                    # PID 추출 (Caldera 공격 로그)
                    link_pid = getattr(link, 'pid', None)

                    if self.debug:
                        print(f"\n[DEBUG] --- Link {idx}/{len(chain)} ---")
                        print(f"[DEBUG] Ability: {ability_name}")
                        print(f"[DEBUG] Technique: {technique_id}")
                        print(f"[DEBUG] Timestamp: {ts_dt} ({ts_epoch})")
                        print(f"[DEBUG] PID: {link_pid}")

                    matches = []
                    if technique_id and ts_epoch:
                        try:
                            matches = await loop.run_in_executor(None, self._search, technique_id, ts_epoch)

                            # PID 매칭 적용
                            if matches and link_pid:
                                for match in matches:
                                    pid_matched, match_type = self._match_pid(
                                        link_pid,
                                        match.get('pid'),
                                        match.get('ppid')
                                    )
                                    match['pid_matched'] = pid_matched
                                    match['pid_match_type'] = match_type

                                # PID 매칭된 결과만 필터링 (PID가 있을 때)
                                # PID 매칭되지 않은 결과는 제거하여 정확도 향상
                                pid_filtered_matches = [m for m in matches if m.get('pid_matched', False)]

                                if pid_filtered_matches:
                                    # PID 매칭된 결과가 있으면 해당 결과만 사용
                                    matches = pid_filtered_matches
                                    if self.debug:
                                        print(f"[DEBUG] PID filtering applied: {len(matches)} matches with PID match")
                                else:
                                    # PID 매칭된 결과가 없으면 매칭 없음으로 처리
                                    # (PID가 있는데 일치하는 탐지가 없으면 정확한 매칭이 아님)
                                    matches = []
                                    if self.debug:
                                        print(f"[DEBUG] No PID matches found - clearing all matches (link.pid={link_pid} not found in any alert)")

                                # PID 직접 매칭 우선 정렬 (pid > ppid > timestamp)
                                matches.sort(key=lambda m: (
                                    m.get('pid_match_type') != 'pid',  # pid 매칭 우선
                                    m.get('pid_match_type') != 'ppid',  # ppid 매칭 그 다음
                                    m.get('@timestamp', '')
                                ))

                            if self.debug:
                                if matches:
                                    pid_match_count = sum(1 for m in matches if m.get('pid_matched', False))
                                    print(f"[DEBUG] ✓ Matches found: {len(matches)} (PID matched: {pid_match_count})")
                                    for m in matches[:3]:  # 처음 3개만 샘플 출력
                                        pid_info = f", pid_matched={m.get('pid_matched')}" if link_pid else ""
                                        print(f"  - rule.id={m.get('rule.id')}, ts={m.get('@timestamp')}{pid_info}")
                                else:
                                    print(f"[DEBUG] ✗ No matches found for technique={technique_id}")
                        except Exception as search_err:
                            if self.debug:
                                print(f"[DEBUG] ✗ Search error: {search_err}")
                            matches = []
                    else:
                        if self.debug:
                            reason = "no technique_id" if not technique_id else "no timestamp"
                            print(f"[DEBUG] ⊘ Skipped - {reason}")

                    # PID 매칭 통계 및 신뢰도 계산
                    pid_match_count = sum(1 for m in matches if m.get('pid_matched', False))
                    confidence = self._calculate_confidence(matches, link_pid)

                    results.append({
                        'link_id': str(getattr(link, 'id', '')),
                        'paw': str(getattr(link, 'paw', '')),
                        'ability_name': ability_name or '',
                        'technique_id': technique_id or '',
                        'executed_at': _iso(ts_dt) if ts_dt else None,
                        'detected': len(matches) > 0,
                        'match_count': len(matches),
                        'pid': link_pid,
                        'pid_match_count': pid_match_count,
                        'confidence': confidence,
                        'matches': matches
                    })
                except Exception as link_err:
                    if self.debug:
                        print(f"[DEBUG] Error processing link {idx}: {link_err}")
                    # 에러가 나도 최소한의 정보 추가
                    results.append({
                        'link_id': str(getattr(link, 'id', '')) if link else f'error_{idx}',
                        'paw': str(getattr(link, 'paw', '')) if link else '',
                        'ability_name': '',
                        'technique_id': '',
                        'executed_at': None,
                        'detected': False,
                        'match_count': 0,
                        'pid': None,
                        'pid_match_count': 0,
                        'confidence': 0.0,
                        'matches': []
                    })

            if self.debug:
                detected_count = sum(1 for r in results if r.get('detected', False))
                pid_matched_count = sum(1 for r in results if r.get('pid_match_count', 0) > 0)
                avg_confidence = sum(r.get('confidence', 0.0) for r in results) / len(results) if results else 0.0
                print(f"\n[DEBUG] ========== Correlation End ==========")
                print(f"[DEBUG] Total: {len(results)}, Detected: {detected_count}, PID Matched: {pid_matched_count}")
                print(f"[DEBUG] Average Confidence: {avg_confidence:.2f}")

            return results
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Critical error in correlate: {e}")
            import traceback
            traceback.print_exc()
            return []