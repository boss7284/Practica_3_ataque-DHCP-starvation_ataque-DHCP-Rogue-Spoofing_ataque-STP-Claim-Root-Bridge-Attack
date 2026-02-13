# Practica_3_ataque-DHCP-starvation_ataque-DHCP-Rogue-Spoofing_ataque-STP-Claim-Root-Bridge-Attack

# Practica-3-DHCP-Starvation-DHCP-Rogue-STP-Root-Bridge-Attack-gns3-y-scapy

**Asignatura:** Seguridad en Redes 

**Estudiante:** Roberto de Jesus

**Matrícula:** 2023-0348 

**Profesor:** Jonathan Esteban Rondón 

**Fecha:** Febrero 2026

**Link del video**: https://youtu.be/zQ0hL_5hpos 

---

# Herramientas de Auditoría de Seguridad en Redes - Ataques Layer 2

## Tabla de Contenidos
- [Descripción General](#-descripción-general)
- [Topología del Laboratorio](#-topología-del-laboratorio)
- [Script 1: DHCP Starvation Attack](#-script-1-dhcp-starvation-attack)
- [Script 2: DHCP Rogue Server Attack](#-script-2-dhcp-rogue-server-attack)
- [Script 3: STP Claim Root Bridge Attack](#-script-3-stp-claim-root-bridge-attack)
- [Requisitos del Sistema](#-requisitos-del-sistema)
- [Medidas de Mitigación](#-medidas-de-mitigación)

---

##  Descripción General

Este proyecto contiene tres scripts de prueba de seguridad desarrollados con Scapy para demostrar vulnerabilidades comunes en redes de capa 2 (Layer 2).

### Scripts Incluidos
- **DHCP Starvation Attack**  
  Ataque de denegación de servicio mediante agotamiento del pool de direcciones IP del servidor DHCP.
  
- **DHCP Rogue/Spoofing Server**  
  Servidor DHCP malicioso que proporciona configuraciones falsas (gateway, DNS) a los clientes.
  
- **STP Claim Root Bridge Attack**  
  Ataque al protocolo **Spanning Tree Protocol (STP)** para reclamar el rol de Root Bridge y redirigir tráfico.

>  **ADVERTENCIA**  
> Estas herramientas están diseñadas **EXCLUSIVAMENTE** para fines educativos en laboratorios como **GNS3 o PNETLAB**.  
> Este código es original. En caso de plagio, habrá retaliación legal.

---

##  Topología del Laboratorio

### Diagrama de Red

![image alt](https://github.com/boss7284/d.u.m.p2/blob/0febd2957c0c35be74dc9476fd039456b7783bc9/Screenshot%202026-02-06%20023647.png)

### Configuración de Red

#### Router R1
- **IP**: `192.168.10.1/24`
- **Función**: Gateway principal
- **DHCP Server**: `192.168.10.2` (configurado en R1)
- **Dominio**: `laboratorio.local`
- **DNS**: `8.8.8.8`

#### Switch SW1
- **Modelo**: Cisco IOSv
- **VLAN**: 10 (Datos)
- **STP**: Habilitado (PVST+)
- **Prioridad STP**: 32768 (default)

#### Dispositivos Finales

| Dispositivo | IP | MAC | Gateway | DHCP Server |
|------------|-----|-----|---------|-------------|
| PC1 (VPCS) | 192.168.10.21/24 | 00:50:79:66:68:00 | 192.168.10.1 | 192.168.10.2 |
| PC2 (VPCS) | 192.168.10.22/24 | 00:50:79:66:68:01 | 192.168.10.1 | 192.168.10.2 |
| Kali Linux | 192.168.10.11/24 | 00:0c:29:e6:e2:1b | 192.168.10.1 | - |

---

## Script 1: DHCP Starvation Attack

### Objetivo
Demostrar la vulnerabilidad del protocolo **DHCP** ante ataques de **agotamiento del pool de direcciones IP** mediante el envío masivo de solicitudes DHCP DISCOVER con direcciones MAC aleatorias.

### Funcionamiento
1. Genera direcciones MAC aleatorias
2. Envía paquetes DHCP DISCOVER por cada MAC
3. El servidor DHCP reserva una IP para cada solicitud
4. El pool de IPs se agota rápidamente
5. Los clientes legítimos no pueden obtener direcciones IP

### Impacto Esperado
-  Agotamiento del pool de direcciones IP disponibles
-  Nuevos clientes no pueden conectarse a la red
-  Denegación de servicio (DoS) para servicios de red
-  Preparación para ataque DHCP Rogue

### Parámetros Principales
```python
INTERFACE = "eth0"           # Interfaz de red
COUNT = 100                  # Número de solicitudes
DELAY = 0.1                  # Retardo entre solicitudes
```

### Ejecución
```bash
# Ataque básico 
sudo python3 dhcp_starvation.py 

# Ataque agresivo con 200 solicitudes
sudo python3 dhcp_starvation.py -i eth0 -c 200 -d 0.05
```

### Verificación en R1
```cisco
show ip dhcp binding
show ip dhcp pool
show ip dhcp server statistics
```

**Salida Esperada**:
```
DHCP pool exhausted
Available addresses: 0
```

---

## Script 2: DHCP Rogue Server Attack

### Objetivo
Demostrar cómo un atacante puede actuar como **servidor DHCP malicioso**, proporcionando configuraciones falsas (gateway, DNS) para interceptar tráfico de red.

### Funcionamiento
1. El script escucha solicitudes DHCP DISCOVER
2. Responde con DHCP OFFER antes que el servidor legítimo
3. Proporciona configuración maliciosa:
   - Gateway falso (el atacante)
   - DNS falso (el atacante)
   - IP del pool del atacante
4. El cliente acepta la configuración maliciosa
5. Todo el tráfico pasa por el atacante (MitM)

### Capacidades del Ataque
-  Interceptar todo el tráfico de la víctima
-  Redirección de DNS (DNS Spoofing)
-  Man-in-the-Middle (MitM)
-  Captura de credenciales (HTTP, FTP, Telnet)
-  Modificación de tráfico en tránsito
-  Secuestro de sesiones

### Parámetros del Script
```python
INTERFACE = "eth0"
SERVER_IP = "192.168.10.100"    # IP del servidor rogue
GATEWAY = "192.168.10.100"       # Gateway falso (atacante)
DNS = "192.168.10.100"           # DNS falso (atacante)
SUBNET_MASK = "255.255.255.0"
```

### Ejecución
```bash
# Servidor DHCP rogue básico
sudo python3 dhcp_rogue.py -i eth0 -s 192.168.10.100

# Servidor con gateway y DNS personalizados
sudo python3 dhcp_rogue.py -i eth0 -s 192.168.10.50 -g 192.168.10.50 -d 8.8.8.8
```

### Combinación con DHCP Starvation
```bash
# Terminal 1: Agotar el servidor legítimo
sudo python3 dhcp_starvation.py -i eth0 -c 150

# Terminal 2: Iniciar servidor rogue
sudo python3 dhcp_rogue.py -i eth0 -s 192.168.10.100 -g 192.168.10.100 -d 192.168.10.100

# Terminal 3: Habilitar IP forwarding para MitM
sudo sysctl -w net.ipv4.ip_forward=1
```

### Verificación en PC1
```bash
# En VPCS
dhcp
show ip

# Debería mostrar:
# DHCP Server: 192.168.10.100 (atacante)
# Gateway: 192.168.10.100 (atacante)
```

---

## Script 3: STP Claim Root Bridge Attack

### Objetivo
Demostrar la vulnerabilidad del protocolo **Spanning Tree Protocol (STP)** ante la inyección de **BPDUs falsas** para reclamar el rol de **Root Bridge** y redirigir todo el tráfico de la red a través del atacante.

### Funcionamiento
1. El atacante envía BPDUs con prioridad 0 (la más alta)
2. Los switches recalculan la topología STP
3. El atacante se convierte en el nuevo Root Bridge
4. Todo el tráfico se redirige a través del atacante
5. El atacante puede interceptar, modificar o bloquear tráfico

### Impacto Esperado
-  Reconvergencia de la topología STP
-  El atacante se convierte en Root Bridge
-  Todo el tráfico pasa por el atacante (MitM)
-  Posibles loops de red si no se maneja correctamente
-  Tormentas de broadcast
-  Caída de switches por sobrecarga

### Parámetros Principales
```python
INTERFACE = "eth0"
PRIORITY = 0                # Prioridad más alta
INTERVAL = 2                # Intervalo entre BPDUs (segundos)
MAC_ADDRESS = "00:0c:29:e6:e2:1b"
```

### Ejecución
```bash
# Ataque continuo (infinito)
sudo python3 stp_root_attack.py -i eth0 -p 0

# Enviar 50 BPDUs y detenerse
sudo python3 stp_root_attack.py -i eth0 -p 0 -c 50

# Burst de 20 BPDUs
sudo python3 stp_root_attack.py -i eth0 -p 0 -b --burst-count 20

# Ataque con intervalo personalizado
sudo python3 stp_root_attack.py -i eth0 -p 0 -t 1
```

### Verificación en SW1
```cisco
show spanning-tree
show spanning-tree root
show spanning-tree detail
```

**Salida Esperada**:
```
Root ID    Priority    0
           Address     00:0c:29:e6:e2:1b  (Kali)
           This bridge is the root
```

### Mitigación en Tiempo Real
```cisco
# Habilitar BPDU Guard en puertos de acceso
interface range GigabitEthernet0/1-3
 spanning-tree bpduguard enable
```

---

##  Requisitos del Sistema

### Software Necesario
- **Kali Linux** (2024.x o superior)
- **Python 3.8+**
- **Scapy** (2.5.0+)
- **GNS3** (2.2.x) o **PNETLab**
- **Cisco IOSv** (Switch Layer 2)

### Instalación de Dependencias

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Scapy
sudo apt install python3-scapy -y

# O instalar con pip
pip install scapy --break-system-packages

# Verificar instalación
python3 -c "from scapy.all import *; print('Scapy OK')"
```

### Configuración de Red en Kali

```bash
# Configurar IP estática en eth0
sudo ip addr add 192.168.10.11/24 dev eth0
sudo ip link set eth0 up

# Configurar gateway
sudo ip route add default via 192.168.10.1

# Verificar conectividad
ping -c 3 192.168.10.1
```

---

##  Medidas de Mitigación

Las siguientes medidas reducen o eliminan la efectividad de ataques **DHCP** y **STP** en redes Cisco.

---

###  Protección DHCP

#### DHCP Snooping
Valida los mensajes DHCP y crea una base de datos de bindings legítimos.

```cisco
! Habilitar DHCP Snooping globalmente
ip dhcp snooping
ip dhcp snooping vlan 10

! Configurar puerto confiable (hacia el servidor DHCP legítimo)
interface GigabitEthernet0/0
 description "Uplink to R1 (DHCP Server)"
 ip dhcp snooping trust

! Puertos no confiables (hacia clientes)
interface range GigabitEthernet0/1-3
 description "Access Ports"
 ip dhcp snooping limit rate 10
```

#### Dynamic ARP Inspection (DAI)
Previene ARP Spoofing validando contra la base de DHCP Snooping.

```cisco
ip arp inspection vlan 10

interface GigabitEthernet0/0
 ip arp inspection trust

interface range GigabitEthernet0/1-3
 ip arp inspection limit rate 15
```

#### IP Source Guard
Previene suplantación de direcciones IP.

```cisco
interface range GigabitEthernet0/1-3
 ip verify source
```

#### Port Security
Limita el número de direcciones MAC por puerto.

```cisco
interface GigabitEthernet0/3
 switchport mode access
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
```

---

###  Protección STP

#### BPDU Guard
Deshabilita puertos que reciben BPDUs no autorizadas.

```cisco
! Habilitar globalmente en puertos PortFast
spanning-tree portfast bpduguard default

! O por interfaz
interface range GigabitEthernet0/1-3
 spanning-tree bpduguard enable
```

#### Root Guard
Previene que un puerto se convierta en Root Port.

```cisco
interface GigabitEthernet0/0
 spanning-tree guard root
```

#### BPDU Filter
Suprime el envío/recepción de BPDUs.

```cisco
interface range GigabitEthernet0/1-3
 spanning-tree bpdufilter enable
```

#### PortFast
Acelera la convergencia en puertos de acceso (solo si no hay switches conectados).

```cisco
interface range GigabitEthernet0/1-3
 spanning-tree portfast
```

#### Configurar Prioridad STP Manualmente
```cisco
! Asegurar que SW1 sea el Root Bridge legítimo
spanning-tree vlan 10 priority 4096
```

---

###  Configuración Completa Recomendada

```cisco
! ===== CONFIGURACIÓN SEGURA COMPLETA EN SW1 =====

! DHCP Snooping
ip dhcp snooping
ip dhcp snooping vlan 10

! DAI
ip arp inspection vlan 10
ip arp inspection validate src-mac dst-mac ip

! STP Security
spanning-tree mode rapid-pvst
spanning-tree vlan 10 priority 4096
spanning-tree portfast bpduguard default

! Puerto Uplink (hacia R1)
interface GigabitEthernet0/0
 description "Uplink to R1"
 switchport mode trunk
 ip dhcp snooping trust
 ip arp inspection trust
 spanning-tree guard root

! Puertos de Acceso (hacia PCs y Kali)
interface range GigabitEthernet0/1-3
 description "Access Ports"
 switchport mode access
 switchport access vlan 10
 
 ! DHCP Security
 ip dhcp snooping limit rate 10
 ip verify source
 
 ! ARP Security
 ip arp inspection limit rate 15
 
 ! STP Security
 spanning-tree portfast
 spanning-tree bpduguard enable
 
 ! Port Security
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky

! Logging
logging buffered 51200 informational
logging console informational
```

---

##  Detección y Monitoreo

### Logs en el Switch

```cisco
! Ver eventos DHCP Snooping
show ip dhcp snooping statistics
show ip dhcp snooping binding

! Ver eventos STP
show spanning-tree inconsistentports
show spanning-tree detail

! Ver logs
show logging | include DHCP|STP|BPDU
```

---

##  Referencias

- [RFC 2131 - DHCP Protocol](https://www.rfc-editor.org/rfc/rfc2131)
- [IEEE 802.1D - Spanning Tree Protocol](https://standards.ieee.org/standard/802_1D-2004.html)
- [Cisco DHCP Snooping Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750/software/release/15-0_2_se/configuration/guide/scg3750/swdhcp82.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---


> **Nota Final**  
> Este código es **100% original**. Cualquier plagio será reportado y perseguido legalmente.  
> Si encuentras útil este proyecto, por favor da una ⭐ en GitHub.

---

**Última actualización**: Febrero 2026  
**Versión**: 1.0.0
