# ==============================================================================
# Computo Seguro - Instancia EC2, Bastionado Automatizado y KMS CMK
# CIS AWS Foundations Benchmark & CIS Linux Benchmark
# ==============================================================================

# 1. Clave Administrada por el Cliente (KMS CMK) con Rotación Anual Automática
# CIS AWS Benchmark: Cifrado en reposo para volúmenes EBS, S3, SNS y CloudWatch
resource "aws_kms_key" "ebs" {
  description             = "KMS CMK para cifrado de almacenamiento EBS, S3 y logs en ${var.project_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Control total de administración delegado a la cuenta raíz
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      # Permisos para CloudWatch Logs
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
      },
      # Permisos para el servicio SNS
      {
        Sid    = "AllowSNSService"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-kms-cmk"
    KeyType     = "CustomerManagedKey"
    Compliance  = "CIS-AWS-Benchmark"
  }
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${var.project_name}-cmk"
  target_key_id = aws_kms_key.ebs.key_id
}

# 2. Búsqueda de AMI Oficial de Ubuntu 22.04 LTS (Jammy Jellyfish)
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# 3. Host Bastion (Opcional - Perímetro Público)
resource "aws_instance" "bastion" {
  count                       = var.enable_bastion ? 1 : 0
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  key_name                    = var.ssh_key_name != "" ? var.ssh_key_name : null
  associate_public_ip_address = true

  # Cifrado de volumen raíz obligatorio con KMS CMK
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    kms_key_id            = aws_kms_key.ebs.arn
    delete_on_termination = true
  }

  # Forzar IMDSv2 (CIS AWS Benchmark 5.6: Mitigación de SSRF)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "${var.project_name}-bastion-host"
    Role = "Bastion-JumpHost"
  }
}

# 4. Instancia EC2 de Carga de Trabajo Privada (Workload Protegida)
resource "aws_instance" "workload" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.private[0].id
  vpc_security_group_ids = [aws_security_group.workload.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_workload.name
  key_name             = var.ssh_key_name != "" ? var.ssh_key_name : null

  # Cifrado de volumen raíz obligatorio con KMS CMK
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    kms_key_id            = aws_kms_key.ebs.arn
    delete_on_termination = true
  }

  # Forzar IMDSv2 (CIS AWS Benchmark 5.6: Mitigación de SSRF)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # User Data: Despliegue seguro codificado en Base64, hardening CIS e inicio del Daemon
  user_data = <<-EOF
              #!/bin/bash
              set -euo pipefail

              echo "=== INICIANDO DESPLIEGUE Y HARDENING EN NODO SEGURO ==="

              # 1. Crear directorios operacionales
              mkdir -p /opt/threat-detector
              mkdir -p /etc/threat-detector

              # 2. Configurar variables de entorno del detector
              cat <<ENV_EOF > /etc/threat-detector/env
              AWS_REGION=${var.aws_region}
              CW_LOG_GROUP=${aws_cloudwatch_log_group.threat_detector.name}
              CW_LOG_STREAM=instance-\$(hostname)
              SNS_TOPIC_ARN=${aws_sns_topic.security_alerts.arn}
              BRUTE_FORCE_THRESHOLD=${var.brute_force_threshold}
              BRUTE_FORCE_WINDOW_SECONDS=${var.brute_force_window_seconds}
              AUTH_LOG_PATH=/var/log/auth.log
              THREAT_LOG_PATH=/var/log/threat_detection.log
              ENV_EOF
              chmod 0600 /etc/threat-detector/env

              # 3. Decodificar e inyectar script de bastionado Linux (CIS Benchmarks)
              echo "${base64encode(file("${path.module}/../scripts/harden_linux.sh"))}" | base64 -d > /opt/threat-detector/harden_linux.sh
              chmod 0700 /opt/threat-detector/harden_linux.sh

              # 4. Decodificar e inyectar script de detección de amenazas en Python
              echo "${base64encode(file("${path.module}/../scripts/threat_detector.py"))}" | base64 -d > /opt/threat-detector/threat_detector.py
              chmod 0755 /opt/threat-detector/threat_detector.py

              # 5. Decodificar e inyectar unidad systemd
              echo "${base64encode(file("${path.module}/../systemd/threat-detector.service"))}" | base64 -d > /etc/systemd/system/threat-detector.service
              chmod 0644 /etc/systemd/system/threat-detector.service

              # 6. Instalar dependencias del sistema y cliente AWS
              export DEBIAN_FRONTEND=noninteractive
              apt-get update -qq
              apt-get install -y -qq python3 python3-pip iptables iptables-persistent netfilter-persistent
              pip3 install --quiet boto3 || true

              # 7. Ejecutar bastionado de Linux
              bash /opt/threat-detector/harden_linux.sh

              # 8. Habilitar e iniciar servicio de detección activa
              systemctl daemon-reload
              systemctl enable threat-detector.service
              systemctl start threat-detector.service

              echo "=== DESPLIEGUE DE SEGURIDAD COMPLETADO EXITOSAMENTE ==="
              EOF

  tags = {
    Name        = "${var.project_name}-hardened-workload"
    Security    = "Hardened-CIS"
    ThreatAgent = "Active"
  }
}
