# ==============================================================================
# Outputs de Infraestructura - Valores y Recursos Aprovisionados
# ==============================================================================

output "vpc_id" {
  description = "Identificador de la VPC aprovisionada."
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "Bloque CIDR de la VPC."
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "Lista de identificadores de las subredes públicas."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Lista de identificadores de las subredes privadas."
  value       = aws_subnet.private[*].id
}

output "nat_gateway_ip" {
  description = "Dirección IP elástica pública asignada al NAT Gateway."
  value       = aws_eip.nat.public_ip
}

output "bastion_public_ip" {
  description = "Dirección IP pública del host Bastion (si fue habilitado)."
  value       = try(aws_instance.bastion[0].public_ip, "N/A (Bastion deshabilitado)")
}

output "workload_private_ip" {
  description = "Dirección IP privada de la instancia de carga de trabajo protegida."
  value       = aws_instance.workload.private_ip
}

output "workload_instance_id" {
  description = "ID de la instancia EC2 asegurada."
  value       = aws_instance.workload.id
}

output "kms_cmk_arn" {
  description = "ARN de la clave KMS administrada por el cliente para cifrado de almacenamiento."
  value       = aws_kms_key.ebs.arn
}

output "kms_cmk_alias" {
  description = "Alias de la clave KMS CMK."
  value       = aws_kms_alias.ebs.name
}

output "secure_s3_bucket_name" {
  description = "Nombre del bucket S3 protegido y cifrado con KMS."
  value       = aws_s3_bucket.secure_storage.id
}

output "secure_s3_bucket_arn" {
  description = "ARN del bucket S3 protegido."
  value       = aws_s3_bucket.secure_storage.arn
}

output "sns_alerts_topic_arn" {
  description = "ARN del tópico SNS de alertas de seguridad."
  value       = aws_sns_topic.security_alerts.arn
}

output "threat_detector_log_group" {
  description = "Nombre del grupo de CloudWatch Logs para eventos del agente de seguridad."
  value       = aws_cloudwatch_log_group.threat_detector.name
}

output "vpc_flow_logs_group" {
  description = "Nombre del grupo de CloudWatch Logs para VPC Flow Logs."
  value       = aws_cloudwatch_log_group.vpc_flow_logs.name
}
