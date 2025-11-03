#!/bin/bash
# generate_inventory.sh

cat > inventory.ini << EOF
[wazuh]
wazuh-server ansible_host=$(terraform output -raw wazuh_server_sg_id) ansible_user=ec2-user ansible_ssh_private_key_file=~/.ssh/wazuh-key.pem

[caldera]
${caldera_instance_ip:-172.31.37.123} ansible_user=ec2-user ansible_ssh_private_key_file=~/.ssh/caldera-key.pem

[shuffle]
shuffle-server ansible_host=localhost ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/shuffle-key.pem

[all:vars]
ansible_python_interpreter=/usr/bin/python3
EOF

echo "Ansible inventory 생성 완료: inventory.ini"