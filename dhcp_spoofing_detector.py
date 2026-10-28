from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sniff, Scapy_Exception
from datetime import datetime, timezone

import json
import argparse
import logging
import sys
import time

JSON_FILE = "./trust_file.json"
data = {} 
hosts_en_revision = {}  # Ahora guardará {ip: set(mac1, mac2, ...)}

def load_json(file_dir):
    try:
        with open(file_dir, "r", encoding="UTF-8") as f:
            raw_data = json.load(f)
            return {ip: mac.lower() for ip, mac in raw_data.items()}
            
    except FileNotFoundError:
        print(f"Error: El archivo '{file_dir}' no existe.")
        return None
    except json.JSONDecodeError:
        print(f"Error: El archivo '{file_dir}' contiene un JSON corrupto o inválido.")
        return None

def validate_args():
    p = argparse.ArgumentParser(description="DHCP Spoofing Detector")
    p.add_argument("-i", "--iface", required=True, help="Interfaz de red a escuchar (ej: eth0, wlan0)")
    p.add_argument("-c", "--count", type=int, default=0, help="Límite de paquetes a capturar (0 = infinito)")
    return p.parse_args()



# =========================================================================
# 1. SISTEMA DE LOGGING
# =========================================================================

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage()
        }

        if hasattr(record, "alert_meta") and record.alert_meta:
            log_obj.update(record.alert_meta)

        return json.dumps(log_obj, ensure_ascii=False)

def configure_logger(name="dhcp_detector", silent=False):
    logger = logging.getLogger(name)

    if not logger.hasHandlers():
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(console_handler)

        file_handler = logging.FileHandler("dhcp_spoof_alert.jsonl")
        file_handler.setLevel(logging.WARNING)
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)

        logger.propagate = False

    if silent:
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.INFO)

    return logger

logger = configure_logger()


# =========================================================================
# 2. DETECTOR DE DHCP SPOOFING
# =========================================================================
ALERT_COOLDOWN = 5 
atacante = {} # (server_ip, server_mac) -> time

def alert(tipo, ip_rogue, mac_rogue, now, **kwargs):
    clave = (ip_rogue, mac_rogue)
    
    if clave in atacante and (now - atacante[clave] <= ALERT_COOLDOWN):
        return
        
    atacante[clave] = now

    meta = {
        "tipo": tipo,
    }
    meta.update(kwargs)
    
    if tipo == "dhcp spoofing":
        msg = f"[{tipo}] Datos del rogue: {ip_rogue} --- {mac_rogue}"
    else:
        msg = f"[{tipo}] msj sin categoria"

    logger.warning(msg, extra={"alert_meta": meta})


def spoof_detector(packet):

    if DHCP not in packet:
        return
    
    dhcp_data = packet[DHCP].options
    dhcp_dict = {}
    for opt in dhcp_data:
        if isinstance(opt, tuple):
            dhcp_dict[opt[0]] = opt[1]

    
    dhcp_tipo = dhcp_dict.get("message-type", None)

    if dhcp_tipo is None:
        return
    
    if dhcp_tipo in (2,5):
        # posible sospechoso

        ip_emisor = packet[IP].src
        mac_emisor = packet[Ether].src.lower()
        server_id_emisor = dhcp_dict.get("server_id", None)

        #pruebas del MITM

        gateway_dado = dhcp_dict.get("router", None) 
        dns_dado = dhcp_dict.get("name_server", None)

        # chequeo

        mac_valida=data.get(ip_emisor, None)

        if mac_valida is None or mac_valida != mac_emisor:
            alert("dhcp spoofing", ip_emisor, mac_emisor, time.time(), gateway_dado=gateway_dado, dns_dado=dns_dado, server_id_dado=server_id_emisor)


def sniff_network(iface, count):
    try:
        sniff(
            filter="udp and (port 67 or port 68)",
            prn=spoof_detector,
            store=False,
            iface=iface,
            count=count
        )
    except PermissionError:
        print("Error: Permisos insuficientes. Ejecutá el script con sudo.")
    except Scapy_Exception as e:
        print(f"Error de Scapy: {e}")
    except OSError as e:
        print(f"Error de red: {e}")

def main():
    global data 
    
    args = validate_args()
    
    data = load_json(JSON_FILE)
    if data is None:
        return
    
    print(f"Iniciando detector DHCP spoofing en la interfaz {args.iface}...")
    sniff_network(args.iface, args.count) 

if __name__ == "__main__":
    main()