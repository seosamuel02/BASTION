#!/bin/bash
# run.sh

echo "Terraform 적용 중..."
cd terraform
terraform init -upgrade
terraform apply -auto-approve

echo "Ansible 인벤토리 생성 중..."
cd ../ansible
chmod +x generate_inventory.sh
./generate_inventory.sh

echo "Ansible 실행 중..."
ansible-playbook -i inventory.ini wazuh-setup.yml

echo "완료! Wazuh → Shuffle 연동 성공!"