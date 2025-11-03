# variables.tf
variable "region" {
  type    = string
  default = "ap-northeast-2"
}

variable "vpc_id" {
  type = string
}

variable "agent_sg_id" {
  type    = string
  default = "sg-0c409b21f0ff892a"
}

variable "bas_sg_id" {
  type    = string
  default = "sg-0d69cbd6b52528fbf"
}

variable "caldera_instance_ip" {
  type    = string
  default = "172.31.37.123"
}