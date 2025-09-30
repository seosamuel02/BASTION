# BASTION
<img width="1920" height="1816" alt="Untitled diagram _ Mermaid Chart-2025-09-30-003730" src="https://github.com/user-attachments/assets/540f1f5b-8f9c-433b-b584-f8202b042f4a" />

1. SOAR 셔플 → 칼데라 : SOAR 셔플이 칼데라 API를 호출하여 TTP 공격을 지시하고 컨텍스트를 기록
   
2. Wazuh → ELK Stack  : Wazuh Agent가 로그를 수집하고 Manager가 생성한 Alert JSON을 Elasticsearch에 저장
   
3. 셔플 → Elastic API : 셔플이 Elasticsearch API를 호출하여 공격 컨텍스트에 해당하는 Alert가 있는지 조회. Alert가 없다면 미탐(FN) 확정
   
4. 셔플 → Wazuh API : FN이 확정 시 SOAR가 Wazuh API를 호출하여 새로운 XML 룰 코드를 전송하고 룰셋을 자동 재로드 하도록 명령
   
5. 셔플 → 칼데라 : 룰 수정 완료 후, SOAR가 칼데라에게 동일 공격을 재실행 하여 개선 효과를 자율적으로 검증하게 하여 폐쇄 루프 구조를 이룸.

<환경 분리>

SOAR(Shuffle) → 로컬PC/ 클라우드 환경이 아닌 로컬PC에 서버를 두는 이유는 SOAR는 FN/FP 진단 로직, ML 모델 호출, 복잡한 API 오케스트레이션 등 CPU와 RAM을 집중적으로 사용하는 중앙 두뇌 역할을 수행합니다. AWS 무료 티어의 자원 제약 t2.micro에서 벗어나 개발 및 테스트 속도를 극대화하기 위함

Victim VM → 클라우드/ BAS 공격의 재현성과 격리된 환경을 보장해야하며 Ansible로 Agent를 자동으로 설치하고 테스트 후 인프라를 쉽게 폐기하는 Iac 호름 검증을 위함.

BAS/SIEM Core(Caldera, Wazuh Manager, ELK Stack) → 클라우드/ 안정적인 공인 IP와 가용성을 확보, 칼데라의 TTP 실행 로그를 안정적으로 수집/저장 해야함.

#테라폼으로 클라우드 자원을 프로비저닝 하고 앤서블로 그 위에 애플리케이션을 구성하는 표준 자동화 방식 진행

Terraform으로 VM 2개 생성

   1. Caldera와 Wazuh Stack이 구동될 클라우드 VM
   
      1a. AWS EC2에 VM 정의 및 배포 

      1b. 네트워크 설정을 해야함 VPC를 생성했을 때 Caldera C2 서버 포트, Wazuh Agent 통신 포트 등을 허용하는 보안 그룹을 구성해야함.

   2. BAS 공격을 받을 피해자 VM ← 어택 테스트 시뮬레이션용

   2a. 테라폼으로 만든 VM 위에서 실하게 되는데 VM에 필요한 소프트웨어 설치, Agent 배포, 서비스 간의 IP 주소 설정 → 도커 컴포즈 실행/ 에이전트 배포 자동화/ 초기 SOAR 설정 등 3가지 생각됨
