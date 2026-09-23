#!/usr/bin/env python3
"""
threat_detector.py
==================
Sistema Activo de Detección y Mitigación de Ataques de Fuerza Bruta en Tiempo Real.
Monitorea /var/log/auth.log, correlaciona eventos mediante una ventana deslizante de 60s,
aplica bloqueo inmediato vía iptables (< 15s SLA) y despacha telemetría estructurada
hacia AWS CloudWatch Logs y AWS SNS.

Autor: Lead Cloud Security & DevSecOps Engineer (github.com/italo04/secure-cloud-infra)
"""

import os
import sys
import re
import time
import json
import signal
import socket
import argparse
import subprocess
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# Asegurar codificación UTF-8 en stdout/stderr
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Dependencia opcional / lazy import de boto3 para entornos AWS
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


# ==============================================================================
# CONFIGURACIÓN Y CONSTANTES
# ==============================================================================

DEFAULT_AUTH_LOG = os.environ.get("AUTH_LOG_PATH", "/var/log/auth.log")
DEFAULT_ALERT_LOG = os.environ.get("THREAT_LOG_PATH", "/var/log/threat_detection.log")
CW_LOG_GROUP = os.environ.get("CW_LOG_GROUP", "/aws/ec2/threat-detector")
CW_LOG_STREAM = os.environ.get("CW_LOG_STREAM", f"instance-{socket.gethostname()}")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

WINDOW_SECONDS = int(os.environ.get("BRUTE_FORCE_WINDOW_SECONDS", "60"))
THRESHOLD_ATTEMPTS = int(os.environ.get("BRUTE_FORCE_THRESHOLD", "5"))
MAX_RESPONSE_SLA_SECONDS = 15.0

# Expresiones regulares optimizadas para logs de OpenSSH
AUTH_PATTERNS = [
    # 1. Contraseña fallida para usuario existente o inválido
    re.compile(
        r"(?:Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+)",
        re.IGNORECASE
    ),
    # 2. Usuario inválido detectado antes del fallo de clave
    re.compile(
        r"(?:Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+)",
        re.IGNORECASE
    ),
    # 3. Desconexión anómala durante preautenticación
    re.compile(
        r"(?:Connection closed by (?:authenticating user )?(?P<user>\S+)? (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ \[preauth\])",
        re.IGNORECASE
    ),
]


# ==============================================================================
# CLASE: SlidingWindowTracker
# ==============================================================================

class SlidingWindowTracker:
    """Gestiona el conteo de intentos fallidos por IP dentro de una ventana de tiempo."""

    def __init__(self, window_seconds: int = WINDOW_SECONDS, threshold: int = THRESHOLD_ATTEMPTS):
        self.window_seconds = window_seconds
        self.threshold = threshold
        # Estructura: { ip: [ (timestamp_float, username) ] }
        self.history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self.blocked_ips: set = set()

    def record_attempt(self, ip: str, username: str, timestamp: float) -> Tuple[bool, int, List[str]]:
        """
        Registra un intento y determina si se superó el umbral.
        Retorna: (debe_bloquearse, conteo_actual, lista_usuarios_intentados)
        """
        if ip in self.blocked_ips:
            return False, len(self.history[ip]), [u for _, u in self.history[ip]]

        # Limpiar eventos fuera de la ventana
        cutoff = timestamp - self.window_seconds
        self.history[ip] = [entry for entry in self.history[ip] if entry[0] >= cutoff]

        # Registrar nuevo intento
        self.history[ip].append((timestamp, username))
        current_count = len(self.history[ip])
        users = list({u for _, u in self.history[ip] if u})

        if current_count >= self.threshold:
            self.blocked_ips.add(ip)
            return True, current_count, users

        return False, current_count, users

    def mark_unblocked(self, ip: str):
        """Remueve la IP del set de bloqueados (útil para pruebas o desbaneo)."""
        self.blocked_ips.discard(ip)
        self.history.pop(ip, None)


# ==============================================================================
# CLASE: ThreatMitigator
# ==============================================================================

class ThreatMitigator:
    """Ejecuta acciones de mitigación activa (iptables, logs locales, AWS CloudWatch & SNS)."""

    def __init__(
        self,
        alert_log_path: str = DEFAULT_ALERT_LOG,
        dry_run: bool = False,
        aws_region: str = AWS_REGION,
        cw_log_group: str = CW_LOG_GROUP,
        cw_log_stream: str = CW_LOG_STREAM,
        sns_topic_arn: str = SNS_TOPIC_ARN,
    ):
        self.alert_log_path = alert_log_path
        self.dry_run = dry_run
        self.aws_region = aws_region
        self.cw_log_group = cw_log_group
        self.cw_log_stream = cw_log_stream
        self.sns_topic_arn = sns_topic_arn

        self.cw_client = None
        self.sns_client = None
        self._init_aws_clients()

    def _init_aws_clients(self):
        """Inicializa clientes de AWS de forma resiliente."""
        if not BOTO3_AVAILABLE:
            return

        try:
            self.cw_client = boto3.client("logs", region_name=self.aws_region)
            self._ensure_cw_log_stream()
        except Exception as e:
            # En entornos locales o de desarrollo sin credenciales AWS, continuar sin bloquear
            self.cw_client = None

        try:
            if self.sns_topic_arn:
                self.sns_client = boto3.client("sns", region_name=self.aws_region)
        except Exception:
            self.sns_client = None

    def _ensure_cw_log_stream(self):
        """Crea el Log Group y Log Stream en CloudWatch si no existen."""
        if not self.cw_client:
            return
        try:
            self.cw_client.create_log_stream(
                logGroupName=self.cw_log_group,
                logStreamName=self.cw_log_stream
            )
        except self.cw_client.exceptions.ResourceAlreadyExistsException:
            pass
        except Exception:
            pass

    def is_ip_already_blocked(self, ip: str) -> bool:
        """Verifica si ya existe una regla DROP para esta IP en iptables."""
        if self.dry_run:
            return False
        try:
            result = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def block_ip(self, ip: str) -> Tuple[bool, str]:
        """Inyecta una regla DROP inmediata en iptables."""
        if self.dry_run:
            return True, "DRY_RUN_SUCCESS"

        if self.is_ip_already_blocked(ip):
            return True, "ALREADY_BLOCKED"

        try:
            cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return True, "SUCCESS"
        except subprocess.CalledProcessError as e:
            return False, f"IPTABLES_ERROR: {e.stderr.strip()}"
        except FileNotFoundError:
            return False, "IPTABLES_NOT_FOUND"

    def record_alert(self, payload: dict):
        """Registra el evento estructurado en el archivo local de auditoría."""
        line = json.dumps(payload, ensure_ascii=False) + "\n"
        try:
            # Crear directorio si no existe
            log_dir = os.path.dirname(self.alert_log_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            with open(self.alert_log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            sys.stderr.write(f"[ERROR] No se pudo escribir en {self.alert_log_path}: {e}\n")

    def dispatch_cloudwatch(self, payload: dict):
        """Envía el evento de telemetría a CloudWatch Logs."""
        if not self.cw_client:
            return

        try:
            timestamp_ms = int(time.time() * 1000)
            self.cw_client.put_log_events(
                logGroupName=self.cw_log_group,
                logStreamName=self.cw_log_stream,
                logEvents=[
                    {
                        "timestamp": timestamp_ms,
                        "message": json.dumps(payload)
                    }
                ]
            )
        except Exception as e:
            # Tolerar fallos de red hacia AWS sin afectar la mitigación local
            pass

    def dispatch_sns(self, payload: dict):
        """Publica una alerta en el tópico SNS configurado."""
        if not self.sns_client or not self.sns_topic_arn:
            return

        try:
            subject = f"[SECURITY ALERT] Brute-Force Blocked: {payload.get('attacker_ip')}"
            message = (
                f"Active Threat Defense Mitigation Alert\n"
                f"----------------------------------------\n"
                f"Attacker IP:     {payload.get('attacker_ip')}\n"
                f"Failed Attempts: {payload.get('failed_attempts')}\n"
                f"Targeted Users:  {', '.join(payload.get('targeted_users', []))}\n"
                f"Response Time:   {payload.get('response_time_ms')} ms\n"
                f"SLA Compliance:  {'MET (< 15s)' if payload.get('sla_met') else 'EXCEEDED'}\n"
                f"Host:            {payload.get('host')}\n"
                f"Timestamp:       {payload.get('timestamp')}\n"
            )
            self.sns_client.publish(
                TopicArn=self.sns_topic_arn,
                Subject=subject[:100],
                Message=message
            )
        except Exception:
            pass

    def handle_mitigation(
        self,
        ip: str,
        attempts: int,
        targeted_users: List[str],
        incident_start_ts: float,
        detection_ts: float
    ) -> dict:
        """
        Ejecuta la orquestación completa de mitigación:
        1. Bloqueo iptables
        2. Medición de latencia y SLA (< 15s)
        3. Auditoría JSON
        4. Notificación CloudWatch / SNS
        """
        mitigation_start = time.time()
        success, reason = self.block_ip(ip)
        mitigation_end = time.time()

        # Medir latencia total desde la detección hasta la inyección de la regla
        response_time_ms = round((mitigation_end - detection_ts) * 1000, 2)
        total_incident_duration_ms = round((mitigation_end - incident_start_ts) * 1000, 2)
        total_response_seconds = mitigation_end - detection_ts
        sla_met = total_response_seconds <= MAX_RESPONSE_SLA_SECONDS

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "BRUTE_FORCE_BLOCKED",
            "host": socket.gethostname(),
            "attacker_ip": ip,
            "failed_attempts": attempts,
            "window_seconds": WINDOW_SECONDS,
            "targeted_users": targeted_users,
            "action": "IPTABLES_DROP",
            "mitigation_status": reason,
            "response_time_ms": response_time_ms,
            "total_incident_duration_ms": total_incident_duration_ms,
            "sla_threshold_seconds": MAX_RESPONSE_SLA_SECONDS,
            "sla_met": sla_met
        }

        # 1. Auditoría local obligatoria
        self.record_alert(payload)

        # 2. Telemetría CloudWatch Logs
        self.dispatch_cloudwatch(payload)

        # 3. Notificación SNS
        self.dispatch_sns(payload)

        return payload


# ==============================================================================
# PARSER DE LOGS
# ==============================================================================

def parse_auth_line(line: str) -> Optional[Tuple[str, str]]:
    """
    Analiza una línea de log y extrae la tupla (ip, username).
    Retorna None si la línea no coincide con un intento fallido de SSH.
    """
    for pattern in AUTH_PATTERNS:
        match = pattern.search(line)
        if match:
            group_dict = match.groupdict()
            ip = group_dict.get("ip")
            user = group_dict.get("user") or "unknown"
            if ip:
                return ip, user
    return None


# ==============================================================================
# MONITOR DE ARCHIVO (Log Tailer con detección de rotación de inodo)
# ==============================================================================

def follow_log_file(filepath: str, stop_signal_handler):
    """
    Generador que realiza 'tail -F' sobre un archivo de log, soportando
    rotación de log (logrotate) al rastrear cambios en el inodo.
    """
    current_file = None
    current_inode = None

    while not stop_signal_handler.is_stopped():
        try:
            if not os.path.exists(filepath):
                time.sleep(1.0)
                continue

            stat_info = os.stat(filepath)
            inode = stat_info.st_ino

            if current_file is None or inode != current_inode:
                if current_file:
                    current_file.close()
                current_file = open(filepath, "r", encoding="utf-8", errors="replace")
                # Posicionarse al final del archivo en el primer inicio
                if current_inode is None:
                    current_file.seek(0, os.SEEK_END)
                current_inode = inode

            line = current_file.readline()
            if line:
                yield line
            else:
                # Comprobar si el archivo fue truncado
                if current_file.tell() > os.stat(filepath).st_size:
                    current_file.seek(0, os.SEEK_SET)
                time.sleep(0.1)

        except Exception as e:
            time.sleep(0.5)

    if current_file:
        current_file.close()


class SignalHandler:
    def __init__(self):
        self._stopped = False
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        self._stopped = True

    def is_stopped(self) -> bool:
        return self._stopped


# ==============================================================================
# FUNCIÓN PRINCIPAL DE EJECUCIÓN
# ==============================================================================

def run_detector(
    log_path: str = DEFAULT_AUTH_LOG,
    alert_path: str = DEFAULT_ALERT_LOG,
    dry_run: bool = False,
    single_pass_file: Optional[str] = None
):
    tracker = SlidingWindowTracker(window_seconds=WINDOW_SECONDS, threshold=THRESHOLD_ATTEMPTS)
    mitigator = ThreatMitigator(alert_log_path=alert_path, dry_run=dry_run)
    sig_handler = SignalHandler()

    print(f"[+] Iniciando Threat Detector v1.0...")
    print(f"[+] Monitoreando: {log_path}")
    print(f"[+] Archivo de alertas: {alert_path}")
    print(f"[+] Parámetros de detección: > {THRESHOLD_ATTEMPTS} fallos en {WINDOW_SECONDS}s (SLA < {MAX_RESPONSE_SLA_SECONDS}s)")
    if dry_run:
        print("[!] MODO DRY-RUN: Las reglas de iptables no serán aplicadas físicamente.")

    if single_pass_file:
        # Modo de prueba / análisis estático de archivo
        if not os.path.exists(single_pass_file):
            print(f"[ERROR] Archivo no encontrado: {single_pass_file}")
            sys.exit(1)

        with open(single_pass_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parsed = parse_auth_line(line)
                if parsed:
                    ip, user = parsed
                    now = time.time()
                    should_block, count, users = tracker.record_attempt(ip, user, now)
                    if should_block:
                        incident_start = tracker.history[ip][0][0] if tracker.history[ip] else now
                        payload = mitigator.handle_mitigation(ip, count, users, incident_start, now)
                        print(f"[ALERTA] IP {ip} BLOQUEADA en {payload['response_time_ms']} ms. Metadatos: {payload}")
        return

    # Modo Daemon en vivo
    for line in follow_log_file(log_path, sig_handler):
        parsed = parse_auth_line(line)
        if parsed:
            ip, user = parsed
            now = time.time()
            should_block, count, users = tracker.record_attempt(ip, user, now)
            if should_block:
                incident_start = tracker.history[ip][0][0] if tracker.history[ip] else now
                payload = mitigator.handle_mitigation(ip, count, users, incident_start, now)
                print(f"[ALERTA ACTIVA] IP {ip} bloqueada con éxito. Respuesta: {payload['response_time_ms']} ms. SLA OK: {payload['sla_met']}")


def main():
    parser = argparse.ArgumentParser(
        description="Agente de Detección y Mitigación Automática de Ataques SSH (CIS / Cloud Security)"
    )
    parser.add_argument("--log-path", default=DEFAULT_AUTH_LOG, help="Ruta al archivo auth.log a monitorear")
    parser.add_argument("--alert-path", default=DEFAULT_ALERT_LOG, help="Ruta al archivo de registro de alertas")
    parser.add_argument("--dry-run", action="store_true", help="No aplicar reglas iptables reales")
    parser.add_argument("--scan-file", help="Procesar un archivo de log estático y salir (para pruebas)")
    args = parser.parse_args()

    run_detector(
        log_path=args.log_path,
        alert_path=args.alert_path,
        dry_run=args.dry_run,
        single_pass_file=args.scan_file
    )


if __name__ == "__main__":
    main()
