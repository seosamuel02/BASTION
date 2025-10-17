"""
BASTION 서비스 - Caldera와 Wazuh 통합 핵심 로직
"""

import aiohttp
import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from aiohttp import web


class BASTIONService:
    """Caldera-Wazuh 통합 서비스"""

    # Wazuh Rule ID → MITRE ATT&CK Technique 매핑
    # Wazuh 기본 규칙에 MITRE 태그가 없으므로 수동 매핑
    RULE_MITRE_MAPPING = {
        # 인증 및 계정
        '5715': 'T1078',      # SSH authentication success → Valid Accounts
        '5501': 'T1078',      # PAM: Login session opened → Valid Accounts
        '5402': 'T1078.003',  # Successful sudo to ROOT → Valid Accounts: Local Accounts

        # 네트워크 탐지
        '533': 'T1049',       # netstat ports changed → System Network Connections Discovery

        # 시스템 탐지
        '510': 'T1082',       # rootcheck anomaly → System Information Discovery
        '502': 'T1082',       # Wazuh server started → System Information Discovery
        '503': 'T1082',       # Wazuh agent started → System Information Discovery

        # SCA (Security Configuration Assessment)
        '19005': 'T1082',     # SCA summary → System Information Discovery
        '19007': 'T1082',     # SCA high severity → System Information Discovery
        '19008': 'T1082',     # SCA medium severity → System Information Discovery
        '19009': 'T1082',     # SCA low severity → System Information Discovery

        # 파일 접근
        '550': 'T1083',       # Integrity checksum changed → File and Directory Discovery
        '554': 'T1083',       # File added to the system → File and Directory Discovery

        # 프로세스
        '592': 'T1059',       # Process creation → Command and Scripting Interpreter
        '594': 'T1059',       # Process execution → Command and Scripting Interpreter
    }

    def __init__(self, services: Dict[str, Any], config: Dict[str, Any]):
        """
        Args:
            services: Caldera 서비스 딕셔너리
            config: BASTION 설정
        """
        self.services = services
        self.data_svc = services.get('data_svc')
        self.rest_svc = services.get('rest_svc')
        self.app_svc = services.get('app_svc')
        self.log = self.app_svc.log if self.app_svc else logging.getLogger('bastion')

        # Wazuh 설정
        self.manager_url = config.get('wazuh_manager_url', 'https://localhost:55000')
        self.indexer_url = config.get('wazuh_indexer_url', 'https://localhost:9200')
        self.username = config.get('wazuh_username', 'wazuh')
        self.password = config.get('wazuh_password', 'wazuh')
        self.indexer_username = config.get('indexer_username', 'admin')
        self.indexer_password = config.get('indexer_password', 'SecretPassword')
        self.verify_ssl = config.get('verify_ssl', False)
        self.monitor_interval = config.get('alert_query_interval', 300)

        # 상태 관리
        self.token = None
        self.token_expiry = None
        self.last_alert_time = datetime.utcnow()
        self.is_authenticated = False

    async def authenticate(self):
        """Wazuh Manager API 인증"""
        try:
            auth = aiohttp.BasicAuth(self.username, self.password)
            url = f'{self.manager_url}/security/user/authenticate?raw=true'

            timeout = aiohttp.ClientTimeout(total=10)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.post(url, auth=auth) as resp:
                    if resp.status == 200:
                        self.token = await resp.text()
                        self.token_expiry = datetime.utcnow() + timedelta(minutes=15)
                        self.is_authenticated = True
                        self.log.info('[BASTION] Wazuh API 인증 성공')
                        return True
                    else:
                        error_text = await resp.text()
                        raise Exception(f'인증 실패 (HTTP {resp.status}): {error_text}')

        except aiohttp.ClientConnectorError as e:
            self.log.error(f'[BASTION] Wazuh Manager 연결 실패: {e}')
            self.log.error(f'[BASTION] {self.manager_url} 주소가 올바른지 확인하세요')
            raise
        except asyncio.TimeoutError:
            self.log.error('[BASTION] Wazuh API 연결 타임아웃 (10초)')
            raise
        except Exception as e:
            self.log.error(f'[BASTION] Wazuh 인증 오류: {e}')
            raise

    async def _ensure_authenticated(self):
        """토큰 유효성 확인 및 재인증"""
        if not self.token or not self.token_expiry:
            await self.authenticate()
        elif datetime.utcnow() >= self.token_expiry:
            self.log.info('[BASTION] 토큰 만료, 재인증 중...')
            await self.authenticate()

    async def get_recent_alerts(self, request: web.Request) -> web.Response:
        """
        최근 Wazuh 알림 조회

        Query Parameters:
            hours: 조회 시간 범위 (기본: 1시간)
            min_level: 최소 심각도 레벨 (기본: 7)
        """
        try:
            hours = int(request.query.get('hours', 1))
            min_level = int(request.query.get('min_level', 7))

            self.log.info(f'[BASTION] 알림 조회 요청: 최근 {hours}시간, 레벨 >= {min_level}')

            # OpenSearch 쿼리
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": min_level}}},
                            {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
                        ]
                    }
                },
                "size": 100,
                "sort": [{"timestamp": {"order": "desc"}}],
                "_source": [
                    "timestamp", "rule.id", "rule.level", "rule.description",
                    "agent.id", "agent.name", "data.mitre.technique", "data.mitre.id"
                ]
            }

            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                # Wazuh Indexer 인증
                auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                async with session.post(
                    f'{self.indexer_url}/wazuh-alerts-*/_search',
                    json=query,
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        alerts = data.get('hits', {}).get('hits', [])

                        # MITRE 기법 추출 및 각 alert에 technique_id 추가
                        techniques = set()
                        processed_alerts = []

                        for alert in alerts:
                            source = alert.get('_source', {})

                            # 1. 먼저 알림에서 직접 MITRE 데이터 확인
                            mitre_data = source.get('data', {}).get('mitre', {})
                            technique_id = None
                            if isinstance(mitre_data, dict) and 'id' in mitre_data:
                                technique_id = mitre_data['id']

                            # 2. MITRE 데이터가 없으면 규칙 ID 매핑 테이블 사용
                            if not technique_id:
                                rule_id = str(source.get('rule', {}).get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            if technique_id:
                                techniques.add(technique_id)

                            # 각 alert에 매핑된 technique_id 추가 (프론트엔드 표시용)
                            alert_data = source.copy()
                            alert_data['technique_id'] = technique_id
                            processed_alerts.append(alert_data)

                        result = {
                            'success': True,
                            'total': len(alerts),
                            'alerts': processed_alerts,
                            'detected_techniques': list(techniques),
                            'query_time': datetime.utcnow().isoformat()
                        }

                        self.log.info(f'[BASTION] 알림 {len(alerts)}건 조회 완료')
                        return web.json_response(result)
                    else:
                        error_text = await resp.text()
                        self.log.error(f'[BASTION] Indexer 쿼리 실패: {error_text}')
                        return web.json_response({
                            'success': False,
                            'error': f'Indexer query failed: HTTP {resp.status}'
                        }, status=500)

        except Exception as e:
            self.log.error(f'[BASTION] 알림 조회 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def correlate_operation(self, request: web.Request) -> web.Response:
        """
        Caldera 작전과 Wazuh 알림 상관관계 분석

        Body:
            operation_id: Caldera 작전 ID
        """
        try:
            data = await request.json()
            operation_id = data.get('operation_id')

            if not operation_id:
                return web.json_response({
                    'success': False,
                    'error': 'operation_id required'
                }, status=400)

            # Caldera 작전 조회
            operations = await self.data_svc.locate('operations', match={'id': operation_id})
            if not operations:
                return web.json_response({
                    'success': False,
                    'error': f'Operation {operation_id} not found'
                }, status=404)

            operation = operations[0]

            # 작전 실행 시간 범위 계산
            start_time = operation.start
            end_time = operation.finish if operation.finish else datetime.utcnow()

            # 1. 작전에서 실행된 MITRE 기법 추출
            operation_techniques = set()
            executed_abilities = []

            for link in operation.chain:
                # 각 링크는 실행된 ability를 나타냄
                ability = link.ability
                executed_abilities.append({
                    'ability_id': ability.ability_id,
                    'name': ability.name,
                    'tactic': ability.tactic,
                    'technique_id': ability.technique_id,
                    'technique_name': ability.technique_name
                })

                # MITRE 기법 ID 추출 (예: T1059)
                if ability.technique_id:
                    operation_techniques.add(ability.technique_id)

            self.log.info(f'[BASTION] 작전 실행 기법: {operation_techniques}')

            # 2. Wazuh 알림 조회 (작전 시간 범위)
            duration_seconds = int((end_time - start_time).total_seconds())
            duration_minutes = max(1, duration_seconds // 60)  # 최소 1분

            # OpenSearch 쿼리
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": 3}}},  # 낮은 레벨부터 조회
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": end_time.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": 500,
                "sort": [{"timestamp": {"order": "asc"}}],
                "_source": [
                    "timestamp", "rule.id", "rule.level", "rule.description",
                    "agent.id", "agent.name", "data.mitre.technique", "data.mitre.id",
                    "data.mitre.tactic"
                ]
            }

            # 3. Wazuh Indexer에서 알림 조회
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            detected_techniques = set()
            alerts_matched = []

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                async with session.post(
                    f'{self.indexer_url}/wazuh-alerts-*/_search',
                    json=query,
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        result_data = await resp.json()
                        alerts = result_data.get('hits', {}).get('hits', [])

                        # 알림에서 MITRE 기법 추출
                        for alert in alerts:
                            source = alert.get('_source', {})
                            mitre_data = source.get('data', {}).get('mitre', {})

                            # MITRE ID 추출 (다양한 형식 지원)
                            technique_id = None
                            if isinstance(mitre_data, dict):
                                technique_id = mitre_data.get('id')
                            elif isinstance(mitre_data, list):
                                for item in mitre_data:
                                    if isinstance(item, dict) and 'id' in item:
                                        technique_id = item.get('id')
                                        break

                            # MITRE 데이터가 없으면 규칙 ID 매핑 테이블 사용
                            if not technique_id:
                                rule_id = str(source.get('rule', {}).get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            if technique_id:
                                detected_techniques.add(technique_id)
                                alerts_matched.append({
                                    'timestamp': source.get('timestamp'),
                                    'rule_id': source.get('rule', {}).get('id'),
                                    'rule_level': source.get('rule', {}).get('level'),
                                    'description': source.get('rule', {}).get('description'),
                                    'agent_name': source.get('agent', {}).get('name'),
                                    'technique_id': technique_id
                                })

                    else:
                        error_text = await resp.text()
                        self.log.error(f'[BASTION] Indexer 쿼리 실패: {error_text}')

            # 4. 매칭 및 탐지율 계산
            matched_techniques = operation_techniques.intersection(detected_techniques)
            undetected_techniques = operation_techniques - detected_techniques

            detection_rate = 0.0
            if len(operation_techniques) > 0:
                detection_rate = len(matched_techniques) / len(operation_techniques)

            # 5. 상관관계 결과 생성
            correlation_result = {
                'success': True,
                'operation_id': operation_id,
                'operation_name': operation.name,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration_seconds,
                'correlation': {
                    'detection_rate': round(detection_rate, 2),
                    'total_techniques': len(operation_techniques),
                    'detected_techniques': len(matched_techniques),
                    'undetected_techniques': len(undetected_techniques),
                    'matched_techniques': list(matched_techniques),
                    'undetected_techniques_list': list(undetected_techniques),
                    'all_operation_techniques': list(operation_techniques),
                    'all_detected_techniques': list(detected_techniques)
                },
                'executed_abilities': executed_abilities,
                'alerts_matched': alerts_matched,
                'total_alerts': len(alerts_matched)
            }

            self.log.info(f'[BASTION] 상관관계 분석 완료: 탐지율 {detection_rate:.1%}')

            return web.json_response(correlation_result)

        except Exception as e:
            self.log.error(f'[BASTION] 상관관계 분석 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def generate_detection_report(self, request: web.Request) -> web.Response:
        """탐지 커버리지 리포트 생성"""
        try:
            # TODO: 구현 필요
            report = {
                'success': True,
                'message': 'Detection report generation not implemented yet',
                'total_operations': 0,
                'detection_rate': 0.0
            }

            return web.json_response(report)

        except Exception as e:
            self.log.error(f'[BASTION] 리포트 생성 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def create_adaptive_operation(self, request: web.Request) -> web.Response:
        """Wazuh 데이터 기반 적응형 작전 생성"""
        try:
            # TODO: 구현 필요
            return web.json_response({
                'success': True,
                'message': 'Adaptive operation not implemented yet'
            })

        except Exception as e:
            self.log.error(f'[BASTION] 적응형 작전 생성 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def get_agents_with_detections(self, request: web.Request) -> web.Response:
        """
        Caldera Agents 목록 + Wazuh Agent 매칭 + 최근 탐지 정보

        Query Parameters:
            hours: 조회 시간 범위 (기본: 1시간)
        """
        try:
            hours = int(request.query.get('hours', 1))
            self.log.info(f'[BASTION] Agents 조회 요청 (최근 {hours}시간 탐지)')

            # 1. Wazuh Agents 조회
            wazuh_agents = {}
            try:
                await self._ensure_authenticated()
                timeout = aiohttp.ClientTimeout(total=10)
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    headers = {'Authorization': f'Bearer {self.token}'}
                    async with session.get(f'{self.manager_url}/agents', headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for wazuh_agent in data.get('data', {}).get('affected_items', []):
                                agent_name = wazuh_agent.get('name', '')
                                wazuh_agents[agent_name] = {
                                    'id': wazuh_agent.get('id'),
                                    'name': agent_name,
                                    'ip': wazuh_agent.get('ip'),
                                    'status': wazuh_agent.get('status'),
                                    'version': wazuh_agent.get('version')
                                }
                            self.log.info(f'[BASTION] Wazuh Agents {len(wazuh_agents)}개 조회')
            except Exception as e:
                self.log.warning(f'[BASTION] Wazuh Agents 조회 실패: {e}')

            # 2. Caldera Agents 조회
            agents = await self.data_svc.locate('agents')

            agents_data = []
            for agent in agents:
                # Agent alive 상태 판단 (timezone 안전)
                alive = False
                if agent.last_seen:
                    try:
                        # timezone-aware datetime 처리
                        last_seen = agent.last_seen.replace(tzinfo=None) if agent.last_seen.tzinfo else agent.last_seen
                        alive = (datetime.utcnow() - last_seen).total_seconds() < 300  # 5분 이내
                    except Exception:
                        alive = False

                agent_info = {
                    'paw': agent.paw,
                    'host': agent.host,
                    'username': agent.username,
                    'platform': agent.platform,
                    'executors': agent.executors,
                    'privilege': agent.privilege,
                    'last_seen': agent.last_seen.isoformat() if agent.last_seen else None,
                    'sleep_min': agent.sleep_min,
                    'sleep_max': agent.sleep_max,
                    'group': agent.group,
                    'contact': agent.contact,
                    'alive': alive,
                    'recent_detections': []
                }

                # Wazuh Agent 매칭 (hostname 기반)
                wazuh_agent = wazuh_agents.get(agent.host)
                agent_info['wazuh_matched'] = wazuh_agent is not None
                if wazuh_agent:
                    agent_info['wazuh_agent'] = {
                        'id': wazuh_agent['id'],
                        'name': wazuh_agent['name'],
                        'ip': wazuh_agent['ip'],
                        'status': wazuh_agent['status'],
                        'version': wazuh_agent['version']
                    }
                else:
                    agent_info['wazuh_agent'] = None

                # 2. 각 Agent의 최근 Wazuh 탐지 조회
                # Agent hostname과 Wazuh agent.name 매칭
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {"rule.level": {"gte": 5}}},
                                {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
                                {
                                    "bool": {
                                        "should": [
                                            {"match": {"agent.name": agent.host}},
                                            {"match": {"agent.ip": agent.host}}
                                        ],
                                        "minimum_should_match": 1
                                    }
                                }
                            ]
                        }
                    },
                    "size": 10,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "_source": [
                        "timestamp", "rule.id", "rule.level", "rule.description",
                        "data.mitre.id", "data.mitre.tactic"
                    ]
                }

                try:
                    timeout = aiohttp.ClientTimeout(total=10)
                    connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

                    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                        auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                        async with session.post(
                            f'{self.indexer_url}/wazuh-alerts-*/_search',
                            json=query,
                            auth=auth
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                alerts = data.get('hits', {}).get('hits', [])

                                for alert in alerts:
                                    source = alert.get('_source', {})

                                    # 1. 먼저 알림에서 직접 MITRE 데이터 확인
                                    mitre_data = source.get('data', {}).get('mitre', {})
                                    technique_id = mitre_data.get('id') if isinstance(mitre_data, dict) else None

                                    # 2. MITRE 데이터가 없으면 규칙 ID 매핑 테이블 사용
                                    if not technique_id:
                                        rule_id = str(source.get('rule', {}).get('id', ''))
                                        technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                                    agent_info['recent_detections'].append({
                                        'timestamp': source.get('timestamp'),
                                        'rule_id': source.get('rule', {}).get('id'),
                                        'rule_level': source.get('rule', {}).get('level'),
                                        'description': source.get('rule', {}).get('description'),
                                        'technique_id': technique_id
                                    })

                except Exception as e:
                    self.log.warning(f'[BASTION] Agent {agent.host} 탐지 조회 실패: {e}')
                    # 에러가 나도 agent 정보는 반환

                agents_data.append(agent_info)

            result = {
                'success': True,
                'total_agents': len(agents_data),
                'agents': agents_data,
                'query_time': datetime.utcnow().isoformat()
            }

            self.log.info(f'[BASTION] Agents {len(agents_data)}개 조회 완료')
            return web.json_response(result)

        except Exception as e:
            self.log.error(f'[BASTION] Agents 조회 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def health_check(self, request: web.Request) -> web.Response:
        """플러그인 및 Wazuh 연결 상태 확인"""
        try:
            health = {
                'plugin': 'healthy',
                'wazuh_manager': 'unknown',
                'wazuh_indexer': 'unknown',
                'authenticated': self.is_authenticated,
                'timestamp': datetime.utcnow().isoformat()
            }

            # Wazuh Manager 상태 확인
            try:
                await self._ensure_authenticated()
                health['wazuh_manager'] = 'healthy'
            except Exception as e:
                health['wazuh_manager'] = f'unhealthy: {str(e)}'

            # Wazuh Indexer 상태 확인
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                    async with session.get(f'{self.indexer_url}/_cluster/health', auth=auth) as resp:
                        if resp.status == 200:
                            cluster_health = await resp.json()
                            health['wazuh_indexer'] = cluster_health.get('status', 'unknown')
            except Exception as e:
                health['wazuh_indexer'] = f'unhealthy: {str(e)}'

            return web.json_response(health)

        except Exception as e:
            self.log.error(f'[BASTION] 헬스체크 실패: {e}', exc_info=True)
            return web.json_response({
                'plugin': 'unhealthy',
                'error': str(e)
            }, status=500)

    async def get_dashboard_summary(self, request: web.Request) -> web.Response:
        """
        대시보드 통합 데이터 조회 (KPI, Operations, Tactic Coverage, Timeline)

        Query Parameters:
            hours: 조회 시간 범위 (기본: 24시간)
            min_level: 최소 심각도 레벨 (기본: 5)
        """
        try:
            hours = int(request.query.get('hours', 24))
            min_level = int(request.query.get('min_level', 5))

            self.log.info(f'[BASTION] 대시보드 요약 조회: 최근 {hours}시간')

            # 1. Operations 목록 조회 (Caldera)
            all_operations = await self.data_svc.locate('operations')

            # 최근 N시간 내 작전 필터링
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            operations_data = []
            total_attack_steps = 0
            operation_techniques = set()  # 전체 작전에서 실행된 기법

            for op in all_operations:
                # 최근 N시간 내 시작된 작전만 포함 (timezone 안전 비교)
                if op.start:
                    op_start = op.start.replace(tzinfo=None) if op.start.tzinfo else op.start
                    if op_start >= cutoff_time:
                        # 작전 실행 단계 추출
                        attack_steps = []
                        op_techniques = set()

                        for link in op.chain:
                            ability = link.ability
                            attack_steps.append({
                                'ability_id': ability.ability_id,
                                'name': ability.name,
                                'tactic': ability.tactic,
                                'technique_id': ability.technique_id,
                                'technique_name': ability.technique_name,
                                'timestamp': link.finish.isoformat() if link.finish else None
                            })

                            if ability.technique_id:
                                op_techniques.add(ability.technique_id)
                                operation_techniques.add(ability.technique_id)

                        total_attack_steps += len(attack_steps)

                        operations_data.append({
                            'id': op.id,
                            'name': op.name,
                            'state': op.state,
                            'started': op.start.isoformat() if op.start else None,
                            'finished': op.finish.isoformat() if op.finish else None,
                            'attack_steps': attack_steps,
                            'techniques': list(op_techniques),
                            'agent_count': len(op.agents)
                        })

            # 2. Wazuh 탐지 이벤트 조회
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"rule.level": {"gte": min_level}}},
                            {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
                        ]
                    }
                },
                "size": 1000,
                "sort": [{"timestamp": {"order": "asc"}}],
                "_source": [
                    "timestamp", "rule.id", "rule.level", "rule.description",
                    "agent.id", "agent.name", "data.mitre.id", "data.mitre.tactic"
                ]
            }

            detected_techniques = set()
            tactic_stats = {}  # Tactic별 탐지 통계
            timeline_data = {}  # 시간대별 이벤트
            detection_events = []

            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)

            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                auth = aiohttp.BasicAuth(self.indexer_username, self.indexer_password)
                async with session.post(
                    f'{self.indexer_url}/wazuh-alerts-*/_search',
                    json=query,
                    auth=auth
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        alerts = data.get('hits', {}).get('hits', [])

                        for alert in alerts:
                            source = alert.get('_source', {})

                            # MITRE 기법 추출
                            mitre_data = source.get('data', {}).get('mitre', {})
                            technique_id = None
                            tactic = None

                            if isinstance(mitre_data, dict):
                                technique_id = mitre_data.get('id')
                                tactic = mitre_data.get('tactic', [])
                                if isinstance(tactic, list) and tactic:
                                    tactic = tactic[0]

                            # 규칙 ID 매핑 테이블 사용
                            if not technique_id:
                                rule_id = str(source.get('rule', {}).get('id', ''))
                                technique_id = self.RULE_MITRE_MAPPING.get(rule_id)

                            if technique_id:
                                detected_techniques.add(technique_id)

                            # Tactic 통계
                            if tactic:
                                if tactic not in tactic_stats:
                                    tactic_stats[tactic] = {'detected': 0, 'executed': 0}
                                tactic_stats[tactic]['detected'] += 1

                            # Timeline 데이터 (분 단위 버킷)
                            timestamp = source.get('timestamp')
                            if timestamp:
                                bucket = timestamp[:16]  # YYYY-MM-DDTHH:MM
                                if bucket not in timeline_data:
                                    timeline_data[bucket] = {'attacks': 0, 'detections': 0}
                                timeline_data[bucket]['detections'] += 1

                            detection_events.append({
                                'timestamp': timestamp,
                                'rule_id': source.get('rule', {}).get('id'),
                                'rule_level': source.get('rule', {}).get('level'),
                                'description': source.get('rule', {}).get('description'),
                                'agent_name': source.get('agent', {}).get('name'),
                                'technique_id': technique_id,
                                'tactic': tactic
                            })

            # 3. Tactic별 실행 통계 계산
            for op_data in operations_data:
                for step in op_data['attack_steps']:
                    tactic = step.get('tactic')
                    if tactic:
                        if tactic not in tactic_stats:
                            tactic_stats[tactic] = {'detected': 0, 'executed': 0}
                        tactic_stats[tactic]['executed'] += 1

                    # Timeline 데이터에 공격 추가
                    timestamp = step.get('timestamp')
                    if timestamp:
                        bucket = timestamp[:16]  # YYYY-MM-DDTHH:MM
                        if bucket not in timeline_data:
                            timeline_data[bucket] = {'attacks': 0, 'detections': 0}
                        timeline_data[bucket]['attacks'] += 1

            # 4. KPI 계산
            matched_techniques = operation_techniques.intersection(detected_techniques)
            coverage = len(matched_techniques) / len(operation_techniques) if operation_techniques else 0.0

            # Agents 수 (간단한 조회)
            agents = await self.data_svc.locate('agents')
            total_agents = len(agents)

            # 5. Timeline 데이터 정렬
            timeline_list = [
                {'time': k, 'attacks': v['attacks'], 'detections': v['detections']}
                for k, v in sorted(timeline_data.items())
            ]

            # 6. Tactic Coverage 데이터 (ATT&CK 순서대로)
            tactic_order = [
                "Initial Access", "Execution", "Persistence", "Privilege Escalation",
                "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                "Collection", "Exfiltration", "Command and Control"
            ]

            tactic_coverage = []
            for tactic in tactic_order:
                stats = tactic_stats.get(tactic, {'executed': 0, 'detected': 0})
                cov = stats['detected'] / stats['executed'] if stats['executed'] > 0 else 0.0
                tactic_coverage.append({
                    'tactic': tactic,
                    'executed': stats['executed'],
                    'detected': stats['detected'],
                    'coverage': round(cov, 2)
                })

            # 7. 최종 응답
            result = {
                'success': True,
                'kpi': {
                    'total_operations': len(operations_data),
                    'total_agents': total_agents,
                    'total_attack_steps': total_attack_steps,
                    'total_detections': len(detection_events),
                    'coverage': round(coverage, 2),
                    'last_seen': detection_events[0]['timestamp'] if detection_events else None
                },
                'operations': operations_data,
                'tactic_coverage': tactic_coverage,
                'timeline': timeline_list,
                'detection_events': detection_events[:400],  # 최근 400건만
                'query_time': datetime.utcnow().isoformat()
            }

            self.log.info(f'[BASTION] 대시보드 요약 생성 완료 (작전: {len(operations_data)}, 탐지: {len(detection_events)})')
            return web.json_response(result)

        except Exception as e:
            self.log.error(f'[BASTION] 대시보드 요약 실패: {e}', exc_info=True)
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)

    async def continuous_monitoring(self):
        """지속적인 Wazuh 알림 모니터링 (백그라운드 태스크)"""
        self.log.info(f'[BASTION] 지속 모니터링 시작 (간격: {self.monitor_interval}초)')

        while True:
            try:
                await asyncio.sleep(self.monitor_interval)

                # TODO: 알림 모니터링 및 자동 대응 로직
                self.log.debug('[BASTION] 모니터링 주기 실행')

            except asyncio.CancelledError:
                self.log.info('[BASTION] 지속 모니터링 중지됨')
                break
            except Exception as e:
                self.log.error(f'[BASTION] 모니터링 오류: {e}')
                await asyncio.sleep(60)
