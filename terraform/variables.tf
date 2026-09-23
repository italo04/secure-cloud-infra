# ==============================================================================
# Variables de Entrada - Proyecto de Infraestructura Segura (AWS & Terraform)
# ==============================================================================

variable "aws_region" {
  type        = string
  description = "Región de AWS para el despliegue de infraestructura."
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Ambiente de despliegue (production, staging, dev)."
  default     = "production"

  validation {
    condition     = contains(["production", "staging", "dev"], var.environment)
    error_message = "El ambiente debe ser uno de: production, staging, dev."
  }
}

variable "project_name" {
  type        = string
  description = "Nombre base del proyecto para etiquetado y nomenclatura de recursos."
  default     = "secure-cloud-infra"
}

variable "vpc_cidr" {
  type        = string
  description = "Bloque CIDR principal para la Virtual Private Cloud (VPC)."
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "El valor de vpc_cidr debe ser un bloque CIDR IPv4 válido."
  }
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "Lista de bloques CIDR para las subredes públicas (mínimo 2 en distintas AZs)."
  default     = ["10.0.1.0/24", "10.0.2.0/24"]

  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "Debe proporcionar al menos 2 subredes públicas para alta disponibilidad."
  }
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "Lista de bloques CIDR para las subredes privadas (mínimo 2 en distintas AZs)."
  default     = ["10.0.10.0/24", "10.0.11.0/24"]

  validation {
    condition     = length(var.private_subnet_cidrs) >= 2
    error_message = "Debe proporcionar al menos 2 subredes privadas para alta disponibilidad."
  }
}

variable "availability_zones" {
  type        = list(string)
  description = "Zonas de disponibilidad (AZs) a utilizar dentro de la región seleccionada."
  default     = ["us-east-1a", "us-east-1b"]
}

variable "allowed_admin_cidrs" {
  type        = list(string)
  description = "Lista de CIDRs autorizados para acceso administrativo SSH (Principio de Mínimo Privilegio). Ej: ['203.0.113.50/32']."
  default     = []
}

variable "enable_bastion" {
  type        = bool
  description = "Indica si se aprovisiona un host Bastion en la subred pública para acceso SSH seguro hacia la instancia privada."
  default     = true
}

variable "instance_type" {
  type        = string
  description = "Tipo de instancia EC2 para las cargas de trabajo."
  default     = "t3.micro"
}

variable "ssh_key_name" {
  type        = string
  description = "Nombre del Key Pair de AWS para asociar a las instancias EC2 (opcional)."
  default     = ""
}

variable "brute_force_threshold" {
  type        = number
  description = "Número máximo de intentos fallidos antes de aplicar bloqueo automático en iptables."
  default     = 5
}

variable "brute_force_window_seconds" {
  type        = number
  description = "Ventana deslizante de tiempo en segundos para acumular intentos fallidos."
  default     = 60
}

variable "log_retention_days" {
  type        = number
  description = "Días de retención para los grupos de logs en AWS CloudWatch."
  default     = 90
}
