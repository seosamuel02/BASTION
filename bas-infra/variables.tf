# -----------------------------------------------------------
# 사용자 설정 변수 정의 (variables.tf)
# -----------------------------------------------------------

# 1. 사용할 AWS 리전
variable "aws_region" {
  description = "AWS Region to deploy resources"
  type        = string
  default     = "ap-northeast-2"
}

# 2. SSH 접속 키 쌍 이름
variable "key_name" {
  description = "The name of the SSH keypair registered in AWS"
  type        = string
  default     = "your-ssh-key-name" 
}

# 3. BAS/SIEM 서버용 AMI 
# BAS와 Wazuh를 설치할 서버
variable "bas_ami" {
  description = "AMI for the BAS/SIEM Core (Ubuntu 22.04 or similar)"
  type        = string
  default     = "ami-0797825b4269e84b7" # 실제 사용 AMI ID로 변경 필요
}

# 4. 피해자 서버용 AMI 
# CALDERA 공격을 받을 타겟 서버
variable "victim_ami" {
  description = "AMI for the Victim/Target Server (e.g., Windows or Linux)"
  type        = string
  default     = "ami-071a93887c2bde268" # 예시 AMI ID
}

# 5. VM 인스턴스 타입 
variable "instance_type" {
  description = "Instance type for the Core and Victim servers"
  type        = string
  default     = "t3.medium" 
}