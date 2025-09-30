# BASTION
<img width="3840" height="3632" alt="Untitled diagram _ Mermaid Chart-2025-09-30-003730" src="https://github.com/user-attachments/assets/540f1f5b-8f9c-433b-b584-f8202b042f4a" />

<환경 분리>
SOAR(Shuffle) → 로컬PC/ 클라우드 환경이 아닌 로컬PC에 서버를 두는 이유는 SOAR는 FN/FP 진단 로직, ML 모델 호출, 복잡한 API 오케스트레이션 등 CPU와 RAM을 집중적으로 사용하는 중앙 두뇌 역할을 수행합니다. AWS 무료 티어의 자원 제약 t2.micro에서 벗어나 개발 및 테스트 속도를 극대화하기 위함

Victim VM → 클라우드/ BAS 공격의 재현성과 격리된 환경을 보장해야하며 Ansible로 Agent를 자동으로 설치하고 테스트 후 인프라를 쉽게 폐기하는 Iac 호름 검증을 위함.

BAS/SIEM Core(Caldera, Wazuh Manager, ELK Stack) → 클라우드/ 안정적인 공인 IP와 가용성을 확보, 칼데라의 TTP 실행 로그를 안정적으로 수집/저장 해야함.
