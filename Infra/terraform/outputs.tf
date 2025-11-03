# outputs.tf
output "wazuh_server_ip" {
  value       = aws_instance.wazuh_server.private_ip
  description = "Wazuh 서버 사설 IP"
}

output "caldera_ip" {
  value       = "172.31.37.123"
  description = "Caldera 인스턴스 IP"
}

output "shuffle_ip" {
  value       = aws_instance.shuffle_server.private_ip
  description = "Shuffle 서버 IP"
}