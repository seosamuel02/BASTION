# main.tf
provider "aws" {
  region = "ap-northeast-2"  # 필요시 변경
}

# 변수 정의
variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "caldera_instance_ip" {
  description = "Caldera 인스턴스의 사설 IP"
  type        = string
  default     = "172.31.37.123"  # 정확히 업데이트됨
}

# 보안 그룹 정의
resource "aws_security_group" "wazuh_server" {
  name        = "wazuh-server-sg"
  description = "Wazuh Server + Caldera + Shuffle Integration"
  vpc_id      = var.vpc_id

  tags = {
    Name = "Wazuh-Server-SG"
  }
}

# === 인바운드 규칙 ===
resource "aws_security_group_rule" "ingress_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]  # 보안상 사무실 IP로 변경 추천
  security_group_id = aws_security_group.wazuh_server.id
  description       = "SSH Access"
}

resource "aws_security_group_rule" "ingress_agent_log_tcp" {
  type                     = "ingress"
  from_port                = 1514
  to_port                  = 1514
  protocol                 = "tcp"
  source_security_group_id = "sg-0c409b21f0ff892a"  # AGENT SG
  security_group_id        = aws_security_group.wazuh_server.id
  description              = "Wazuh Agent Log (TCP)"
}

resource "aws_security_group_rule" "ingress_agent_log_udp" {
  type                     = "ingress"
  from_port                = 1514
  to_port                  = 1514
  protocol                 = "udp"
  source_security_group_id = "sg-0c409b21f0ff892a"  # AGENT SG
  security_group_id        = aws_security_group.wazuh_server.id
  description              = "Wazuh Agent Log (UDP)"
}

# Caldera OpenSearch 포트 (IP 정확히 변경됨)
resource "aws_security_group_rule" "ingress_caldera_opensearch" {
  type              = "ingress"
  from_port         = 9200
  to_port           = 9200
  protocol          = "tcp"
  cidr_blocks       = ["${var.caldera_instance_ip}/32"]  # 172.31.37.123/32
  security_group_id = aws_security_group.wazuh_server.id
  description       = "Caldera OpenSearch"
}

resource "aws_security_group_rule" "ingress_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.wazuh_server.id
  description       = "HTTPS Web Access"
}

resource "aws_security_group_rule" "ingress_agent_add" {
  type                     = "ingress"
  from_port                = 1515
  to_port                  = 1515
  protocol                 = "tcp"
  source_security_group_id = "sg-0c409b21f0ff892a"  # AGENT SG
  security_group_id        = aws_security_group.wazuh_server.id
  description              = "Wazuh Agent Registration"
}

resource "aws_security_group_rule" "ingress_wazuh_api" {
  type                     = "ingress"
  from_port                = 55000
  to_port                  = 55000
  protocol                 = "tcp"
  source_security_group_id = "sg-0d69cbd6b52528fbf"  # BAS SG
  security_group_id        = aws_security_group.wazuh_server.id
  description              = "Wazuh API"
}

resource "aws_security_group_rule" "ingress_wazuh_dashboard" {
  type              = "ingress"
  from_port         = 5601
  to_port           = 5601
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.wazuh_server.id
  description       = "Wazuh Dashboard (Kibana)"
}

# === 아웃바운드 규칙 (모두 허용) ===
resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.wazuh_server.id
  description       = "Allow all outbound"
}

# 출력
output "wazuh_server_sg_id" {
  value       = aws_security_group.wazuh_server.id
  description = "Wazuh Server Security Group ID"
}