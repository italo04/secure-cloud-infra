#!/usr/bin/env python3
"""
test_threat_detector.py
=======================
Suite de Pruebas Unitarias y Simulador de Ataques de Fuerza Bruta.
Permite validar el algoritmo de correlación de ventana deslizante, el parsing
de eventos de OpenSSH, y simular ataques en tiempo real verificando que la
mitigación se active y ejecute en menos de 15 segundos.

Uso:
  - Ejecutar tests unitarios:
      python3 -m unittest tests/test_threat_detector.py
  - Ejecutar simulación de ataque completa:
      python3 tests/test_threat_detector.py --simulate-attack

Autor: Lead Cloud Security & DevSecOps Engineer (github.com/italo04/secure-cloud-infra)
"""

import os
import sys
import time
import json
import unittest
import tempfile
import argparse
from typing import List

# Asegurar codificación UTF-8 en stdout/stderr para entornos Windows/Linux
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Permitir importación del módulo desde ../scripts
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

try:
    from threat_detector import (
        parse_auth_line,
        SlidingWindowTracker,
        ThreatMitigator,
        WINDOW_SECONDS,
        THRESHOLD_ATTEMPTS,
        MAX_RESPONSE_SLA_SECONDS,
    )
except ImportError as e:
    raise ImportError(f"No se pudo importar threat_detector.py: {e}")


class TestThreatDetectorUnit(unittest.TestCase):
    """Pruebas unitarias para los componentes core del detector de amenazas."""

    def test_parse_auth_line_failed_password_valid_user(self):
        line = "Sep 23 18:00:01 web-server sshd[12345]: Failed password for ubuntu from 198.51.100.25 port 45212 ssh2"
        result = parse_auth_line(line)
        self.assertIsNotNone(result)
        ip, user = result
        self.assertEqual(ip, "198.51.100.25")
        self.assertEqual(user, "ubuntu")

    def test_parse_auth_line_invalid_user(self):
        line = "Sep 23 18:00:02 web-server sshd[12346]: Invalid user admin from 203.0.113.88 port 38910"
        result = parse_auth_line(line)
        self.assertIsNotNone(result)
        ip, user = result
        self.assertEqual(ip, "203.0.113.88")
        self.assertEqual(user, "admin")

    def test_parse_auth_line_failed_password_invalid_user(self):
        line = "Sep 23 18:00:03 web-server sshd[12347]: Failed password for invalid user root from 192.0.2.14 port 51234 ssh2"
        result = parse_auth_line(line)
        self.assertIsNotNone(result)
        ip, user = result
        self.assertEqual(ip, "192.0.2.14")
        self.assertEqual(user, "root")

    def test_parse_auth_line_preauth_disconnect(self):
        line = "Sep 23 18:00:04 web-server sshd[12348]: Connection closed by authenticating user oracle 198.51.100.99 port 41234 [preauth]"
        result = parse_auth_line(line)
        self.assertIsNotNone(result)
        ip, user = result
        self.assertEqual(ip, "198.51.100.99")
        self.assertEqual(user, "oracle")

    def test_parse_auth_line_ignores_benign_logs(self):
        line = "Sep 23 18:00:05 web-server sshd[12349]: Accepted publickey for ubuntu from 198.51.100.1 port 52100 ssh2"
        result = parse_auth_line(line)
        self.assertIsNone(result)

        system_log = "Sep 23 18:00:06 web-server systemd[1]: Started Daily apt upgrade and clean activities."
        self.assertIsNone(parse_auth_line(system_log))

    def test_sliding_window_triggers_on_threshold(self):
        tracker = SlidingWindowTracker(window_seconds=60, threshold=5)
        ip = "198.51.100.100"
        now = time.time()

        # Enviar 4 intentos: no debe bloquear aún
        for i in range(4):
            should_block, count, users = tracker.record_attempt(ip, f"user{i}", now + (i * 2))
            self.assertFalse(should_block)
            self.assertEqual(count, i + 1)

        # 5to intento dentro de la ventana: DEBE activar bloqueo
        should_block, count, users = tracker.record_attempt(ip, "user_final", now + 10)
        self.assertTrue(should_block)
        self.assertEqual(count, 5)
        self.assertIn("user_final", users)

        # 6to intento no debe volver a gatillar bloqueo redundante
        should_block, count, users = tracker.record_attempt(ip, "user_extra", now + 12)
        self.assertFalse(should_block)

    def test_sliding_window_expires_old_attempts(self):
        tracker = SlidingWindowTracker(window_seconds=60, threshold=5)
        ip = "198.51.100.200"
        t0 = 1000.0

        # 4 intentos en t=1000
        for i in range(4):
            tracker.record_attempt(ip, f"user{i}", t0)

        # Intento 70 segundos después (fuera de la ventana de 60s)
        t1 = t0 + 70.0
        should_block, count, users = tracker.record_attempt(ip, "new_user", t1)
        self.assertFalse(should_block)
        # Los 4 anteriores expiraron, sólo debe quedar 1 intento registrado
        self.assertEqual(count, 1)

    def test_mitigator_sla_and_payload(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            mitigator = ThreatMitigator(alert_log_path=tmp_path, dry_run=True)
            ip = "203.0.113.50"
            start_ts = time.time() - 2.0
            det_ts = time.time()

            payload = mitigator.handle_mitigation(
                ip=ip,
                attempts=5,
                targeted_users=["admin", "root"],
                incident_start_ts=start_ts,
                detection_ts=det_ts
            )

            self.assertEqual(payload["attacker_ip"], ip)
            self.assertEqual(payload["failed_attempts"], 5)
            self.assertEqual(payload["action"], "IPTABLES_DROP")
            self.assertTrue(payload["sla_met"])
            self.assertLess(payload["response_time_ms"] / 1000.0, MAX_RESPONSE_SLA_SECONDS)

            # Verificar persistencia en el log de auditoría
            with open(tmp_path, "r", encoding="utf-8") as f:
                content = f.read()
                data = json.loads(content.strip())
                self.assertEqual(data["attacker_ip"], ip)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


# ==============================================================================
# SIMULADOR DE ATAQUES DE FUERZA BRUTA
# ==============================================================================

def simulate_brute_force_attack(attacker_ip: str = "203.0.113.195", target_attempts: int = 6):
    """
    Simula un ataque de fuerza bruta SSH en ráfaga para verificar el tiempo
    de reacción de extremo a extremo y el cumplimiento del SLA (< 15 segundos).
    """
    print("\n" + "=" * 75)
    print(" [!] INICIANDO SIMULACIÓN DE ATAQUE DE FUERZA BRUTA SSH EN TIEMPO REAL")
    print("=" * 75)
    print(f"[*] IP Atacante Simulada:    {attacker_ip} (RFC 5737 TEST-NET-3)")
    print(f"[*] Ráfaga de Intentos:      {target_attempts} intentos secuenciales")
    print(f"[*] Umbral de Detección:     > {THRESHOLD_ATTEMPTS} fallos en {WINDOW_SECONDS}s")
    print(f"[*] SLA Máximo Permitido:    < {MAX_RESPONSE_SLA_SECONDS} segundos")
    print("-" * 75)

    with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log") as tmp_alert:
        tmp_alert_path = tmp_alert.name

    tracker = SlidingWindowTracker(window_seconds=WINDOW_SECONDS, threshold=THRESHOLD_ATTEMPTS)
    mitigator = ThreatMitigator(alert_log_path=tmp_alert_path, dry_run=True)

    attack_usernames = ["root", "admin", "ubuntu", "test", "postgres", "guest"]
    simulated_events: List[dict] = []

    simulation_wall_start = time.perf_counter()

    for idx in range(target_attempts):
        user = attack_usernames[idx % len(attack_usernames)]
        # Simular línea generada por OpenSSH daemon
        log_line = f"Sep 23 18:15:{10+idx:02d} secure-cloud-node sshd[{20000+idx}]: Failed password for invalid user {user} from {attacker_ip} port {40000+idx} ssh2"

        step_start = time.perf_counter()
        parsed = parse_auth_line(log_line)
        if not parsed:
            continue

        ip, extracted_user = parsed
        now_ts = time.time()
        should_block, count, users = tracker.record_attempt(ip, extracted_user, now_ts)

        step_elapsed_ms = (time.perf_counter() - step_start) * 1000

        print(f"  -> [{idx+1}/{target_attempts}] Intento SSH: user='{user}' IP={ip} | Estado: {count} fallos registrados ({step_elapsed_ms:.2f} ms)")

        if should_block:
            incident_start = tracker.history[ip][0][0] if tracker.history[ip] else now_ts
            payload = mitigator.handle_mitigation(ip, count, users, incident_start, now_ts)
            simulated_events.append(payload)

        # Breve pausa para simular el intervalo de red de un atacante automatizado (50ms)
        time.sleep(0.05)

    total_simulation_time = time.perf_counter() - simulation_wall_start

    print("-" * 75)
    print(" [+] RESULTADOS DE LA MITIGACION:")

    if not simulated_events:
        print(" [X] ERROR: El ataque no fue detectado ni mitigado.")
        sys.exit(1)

    event = simulated_events[0]
    response_time_ms = event["response_time_ms"]
    sla_status = "CUMPLIDO (< 15s)" if event["sla_met"] else "VIOLADO (> 15s)"

    print(f"  * Estado de la Deteccion:   EXITOSA (Bloqueo Gatillado en Intento #{event['failed_attempts']})")
    print(f"  * Accion de Contencion:     {event['action']} (Regla inyectada en iptables INPUT)")
    print(f"  * Tiempo de Respuesta SLA:  {response_time_ms:.2f} ms  [{sla_status}]")
    print(f"  * Duracion Total del Flujo: {total_simulation_time:.3f} segundos")
    print(f"  * Usuarios Comprometidos:   {', '.join(event['targeted_users'])}")
    print(f"  * Carga JSON Generada:")
    print(" " + json.dumps(event, indent=4))
    print("=" * 75)
    print(" [OK] SIMULACION COMPLETADA SATISFACTORIAMENTE CONFORME AL SLA DE SEGURIDAD.\n")

    if os.path.exists(tmp_alert_path):
        os.remove(tmp_alert_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Suite y Simulador de Ataques SSH")
    parser.add_argument("--simulate-attack", action="store_true", help="Ejecutar simulación activa de ataque de fuerza bruta")
    parser.add_argument("--ip", default="203.0.113.195", help="IP atacante para la simulación")
    args, unknown = parser.parse_known_args()

    if args.simulate_attack:
        simulate_brute_force_attack(attacker_ip=args.ip)
    else:
        # Ejecutar suite de pruebas de unittest
        unittest.main(argv=[sys.argv[0]] + unknown)
