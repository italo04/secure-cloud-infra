# ==============================================================================
# Seguridad de Red - Security Groups de Mínimo Privilegio y Default Deny
# CIS AWS Foundations Benchmark (Recomendación 5.4 y Control de Tráfico Estricto)
# ==============================================================================

# 1. Default Security Group Sellado
# CIS AWS Benchmark 5.4: El default security group de la VPC no debe permitir
# ningún tipo de tráfico entrante ni saliente (Aislamiento Total).
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  # Cero reglas de ingress y egress
  ingress = []
  egress  = []

  tags = {
    Name        = "${var.project_name}-default-sg-isolated"
    Compliance  = "CIS-AWS-Benchmark-5.4"
    Description = "Default SG completamente sellado sin reglas permitidas"
  }
}

# 2. Security Group para el Host Bastion (Perímetro Público Controlado)
resource "aws_security_group" "bastion" {
  name        = "${var.project_name}-bastion-sg"
  description = "Control de acceso perimetral para el host Bastion (SSH restringido)"
  vpc_id      = aws_vpc.main.id

  # Egress HTTPS para parches y dependencias del sistema operativo
  egress {
    description = "Salida HTTPS para actualizaciones del sistema"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-bastion-sg"
    Tier = "Public-Perimeter"
  }
}

# Regla de Ingress SSH al Bastion (Condicional: sólo si se especifican CIDRs autorizados)
resource "aws_security_group_rule" "bastion_ingress_ssh" {
  count             = length(var.allowed_admin_cidrs) > 0 ? 1 : 0
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = var.allowed_admin_cidrs
  security_group_id = aws_security_group.bastion.id
  description       = "Acceso SSH administrativo autorizado desde IPs/VPN especificas"
}

# 3. Security Group para la Carga de Trabajo Privada (Workload EC2)
resource "aws_security_group" "workload" {
  name        = "${var.project_name}-workload-sg"
  description = "Security Group de maximo aislamiento para la instancia privada"
  vpc_id      = aws_vpc.main.id

  # Egress Restrictivo: Solo HTTPS (443) para consumir APIs de AWS (CloudWatch, SNS, S3)
  # y descargar paquetes del sistema operativo mediante el NAT Gateway.
  egress {
    description = "Salida HTTPS controlada para APIs de AWS y paquetes seguros"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-workload-sg"
    Tier = "Private-Workload"
  }
}

# 4. Reglas Desacopladas de Conexión entre Bastion y Workload (Evita Dependencias Cíclicas)
resource "aws_security_group_rule" "bastion_to_workload_ssh" {
  type                     = "egress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.workload.id
  security_group_id        = aws_security_group.bastion.id
  description              = "Salto SSH exclusivo hacia las instancias de la subred privada"
}

resource "aws_security_group_rule" "workload_from_bastion_ssh" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion.id
  security_group_id        = aws_security_group.workload.id
  description              = "Acceso SSH restringido exclusivamente desde el Bastion SG"
}
