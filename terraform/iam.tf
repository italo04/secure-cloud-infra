# ==============================================================================
# Gestión de Identidades y Acceso (IAM) - Principio de Mínimo Privilegio
# Cero Credenciales Estáticas, Cero AdministratorAccess, Cero Wildcards (*)
# ==============================================================================

# 1. Bucket S3 Protegido para Almacenamiento Seguro de la Carga de Trabajo
resource "aws_s3_bucket" "secure_storage" {
  bucket_prefix = "${var.project_name}-data-"
  force_destroy = false

  tags = {
    Name        = "${var.project_name}-secure-data-bucket"
    DataPrivacy = "Confidential"
  }
}

# Control de Versiones S3
resource "aws_s3_bucket_versioning" "secure_storage" {
  bucket = aws_s3_bucket.secure_storage.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Bloqueo Integral de Acceso Público S3 (CIS Benchmark)
resource "aws_s3_bucket_public_access_block" "secure_storage" {
  bucket = aws_s3_bucket.secure_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Cifrado en Reposo con Clave KMS CMK
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_storage" {
  bucket = aws_s3_bucket.secure_storage.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.ebs.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Política de Bucket: Denegar cualquier conexión sin TLS 1.2+ (Cifrado en Tránsito)
resource "aws_s3_bucket_policy" "enforce_tls" {
  bucket = aws_s3_bucket.secure_storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.secure_storage.arn,
          "${aws_s3_bucket.secure_storage.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
          NumericLessThan = {
            "s3:TlsVersion" = "1.2"
          }
        }
      }
    ]
  })
}

# 2. Tópico de Notificaciones SNS para Alertas de Seguridad
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_name}-security-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.ebs.arn

  tags = {
    Name = "${var.project_name}-security-alerts-topic"
  }
}

# Política de SNS para exigir conexiones cifradas HTTPS
resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceSecureTransportSNS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alerts.arn
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# 3. Log Group en CloudWatch para el Agente Threat Detector
resource "aws_cloudwatch_log_group" "threat_detector" {
  name              = "/aws/ec2/threat-detector"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.ebs.arn

  tags = {
    Name = "${var.project_name}-threat-detector-logs"
  }
}

# 4. IAM Role para Instancia EC2 (Sin credenciales de larga duración)
resource "aws_iam_role" "ec2_workload" {
  name = "${var.project_name}-ec2-workload-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2AssumeRolePolicy"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ec2-workload-role"
  }
}

# 5. Política de Mínimo Privilegio (Zero Wildcards, Zero AdministratorAccess)
resource "aws_iam_policy" "ec2_workload_least_privilege" {
  name        = "${var.project_name}-ec2-least-privilege-policy"
  description = "Permisos estrictamente acotados a lectura de S3, envio de logs y alertas SNS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Acceso de solo lectura al Bucket S3 específico del proyecto
      {
        Sid    = "StrictS3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.secure_storage.arn,
          "${aws_s3_bucket.secure_storage.arn}/*"
        ]
      },
      # Envío de logs hacia el Log Group exclusivo de CloudWatch
      {
        Sid    = "CloudWatchLogsPublishEvents"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.threat_detector.arn}:*"
        ]
      },
      # Publicación de alertas exclusivamente en el tópico SNS de seguridad
      {
        Sid    = "SNSSecurityAlertsPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.security_alerts.arn
        ]
      },
      # Permisos criptográficos KMS acotados a la clave CMK asignada
      {
        Sid    = "KMSDecryptionAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_kms_key.ebs.arn
        ]
      }
    ]
  })
}

# Adjuntar política al Rol
resource "aws_iam_role_policy_attachment" "ec2_workload" {
  role       = aws_iam_role.ec2_workload.name
  policy_arn = aws_iam_policy.ec2_workload_least_privilege.arn
}

# Soporte opcional para AWS Systems Manager (SSM) Session Manager (acceso seguro sin SSH abierto)
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_workload.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Instance Profile para asociar a la instancia EC2
resource "aws_iam_instance_profile" "ec2_workload" {
  name = "${var.project_name}-ec2-workload-instance-profile"
  role = aws_iam_role.ec2_workload.name

  tags = {
    Name = "${var.project_name}-ec2-instance-profile"
  }
}
