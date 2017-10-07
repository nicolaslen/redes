#!/usr/bin/env python
# encoding: utf-8

from sys import argv, exit
import math
import matplotlib.pyplot as plt
from matplotlib import pylab
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy .all import *

def plot_bars(simbolos,entropia):
    
    info_set  = set()
    filtered_simbolos = {}
    if (len(simbolos) > 10):
        for host in simbolos:
            info_host = simbolos[host]
            if info_host not in info_set:
                info_set.add(info_host)
                filtered_simbolos[host] = simbolos[host]
    else:
        filtered_simbolos = simbolos

    fig, ax = plt.subplots()
    #Dibujo de los graficos
    entrop_line = ax.axvline(entropia, color='blue', linewidth=2,alpha = 0.7)
    maxEntrop_line = ax.axvline(math.log((len(simbolos)),2), color='red', linewidth=2,alpha = 0.7)
    bars = ax.barh(range(len(filtered_simbolos)), filtered_simbolos.values(), align='center', alpha=0.4, color='green')
    plt.yticks(range(len(filtered_simbolos)), filtered_simbolos.keys())

    #Rotulos y titulos
    ax.legend((bars[0], entrop_line, maxEntrop_line), ('IP\'s', 'H(S)', 'HMAX(S)'))
    pylab.xlabel("INFORMACION")
    pylab.ylabel("IP")
    pylab.title("INFORMACION SIMBOLOS")

    #Lo muestra y te da la opcion para guardarlo
    plt.show()    


PROTOCOL_MAPPINGS = {
    '0x800': "Internet Protocol version 4 (IPv4)",
    '0x806': "Address Resolution Protocol (ARP)",
    '0x842': "Wake-on-LAN",
    '0x22f3': "IETF TRILL Protocol",
    '0x6003': "DECnet Phase IV",
    '0x8035': "Reverse Address Resolution Protocol",
    '0x809b': "AppleTalk (Ethertalk)",
    '0x80f3': "AppleTalk Address Resolution Protocol (AARP)",
    '0x8100': "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq",
    '0x8137': "IPX",
    '0x8204': "QNX Qnet",
    '0x86dd': "Internet Protocol Version 6 (IPv6)",
    '0x8808': "Ethernet flow control",
    '0x8819': "CobraNet",
    '0x8847': "MPLS unicast",
    '0x8848': "MPLS multicast",
    '0x8863': "PPPoE Discovery Stage",
    '0x8864': "PPPoE Session Stage",
    '0x8870': "Jumbo Frames (proposed)",
    '0x887b': "HomePlug 1.0 MME",
    '0x888e': "EAP over LAN (IEEE 802.1X)",
    '0x8892': "PROFINET Protocol",
    '0x889a': "HyperSCSI (SCSI over Ethernet)",
    '0x88a2': "ATA over Ethernet",
    '0x88a4': "EtherCAT Protocol",
    '0x88a8': "Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq",
    '0x88ab': "Ethernet Powerlink[citation needed]",
    '0x88cc': "Link Layer Discovery Protocol (LLDP)",
    '0x88cd': "SERCOS III",
    '0x88e1': "HomePlug AV MME[citation needed]",
    '0x88e3': "Media Redundancy Protocol (IEC62439-2)",
    '0x88e5': "MAC security (IEEE 802.1AE)",
    '0x88e7': "Provider Backbone Bridges (PBB) (IEEE 802.1ah)",
    '0x88f7': "Precision Time Protocol (PTP) over Ethernet (IEEE 1588)",
    '0x8902': "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)",
    '0x8906': "Fibre Channel over Ethernet (FCoE)",
    '0x8914': "FCoE Initialization Protocol",
    '0x8915': "RDMA over Converged Ethernet (RoCE)",
    '0x891d': "TTEthernet Protocol Control Frame (TTE)",
    '0x892f': "High-availability Seamless Redundancy (HSR)",
    '0x9000': "Ethernet Configuration Testing Protocol",
}

SHORT_NAME = {
    '0x800': "IPv4",
    '0x806': "ARP",
    '0x842': "Wake-on-LAN",
    '0x8035': "RARP",
    '0x809b': "AppleTalk",
    '0x80f3': "AARP",
    '0x8137': "IPX",
    '0x8204': "QNX Qnet",
    '0x86dd': "IPv6",
    '0x8808': "Ethernet flow control",
    '0x8819': "CobraNet",
    '0x8847': "MPLS unicast",
    '0x8848': "MPLS multicast",
    '0x8863': "PPPoE Discovery Stage",
    '0x8864': "PPPoE Session Stage",
    '0x888e': "EAP over LAN",
    '0x8892': "PROFINET Protocol",
    '0x889a': "HyperSCSI (SCSI over Ethernet)",
    '0x88a2': "ATA over Ethernet",
    '0x88a4': "EtherCAT Protocol",
}

PACKET_COUNT    =   10
DECIMALES       =   3

def buscar_protocolo(tipo, short=False):
    try:
        if short:
            return SHORT_NAME[tipo]
        return PROTOCOL_MAPPINGS[tipo]
    except KeyError:
        return tipo

def mostrarTabla(titulos, tabla):
    row_format ="{:>15}" * len(titulos)
    print(row_format.format(*titulos))
    for row in tabla:
        print(row_format.format(*row))
    print("\n")

def generarItemDeTablaS1(simbolo, s_prob, s_info, cant):
    return (simbolo[0], simbolo[1], round(s_prob, DECIMALES), round(s_info, DECIMALES), cant)

def generarItemDeTablaS2(simbolo, s_prob, s_info, cant):
    return (simbolo, round(s_prob, DECIMALES), round(s_info, DECIMALES), cant)

def obtenerSimboloS1(paquete):
    dst = paquete.dst == "ff:ff:ff:ff:ff:ff"
    return (("Broadcast" if dst else "Unicast"), buscar_protocolo(hex(paquete.type), True))

def condicionS1(paquete):
    return True

def obtenerSimboloS2(paquete):
    return paquete[ARP].pdst

def condicionS2(paquete):
    return ARP in paquete and paquete.op == 1 and paquete[ARP].psrc != paquete[ARP].pdst

def imprimirHerramienta(tabla, tablaTitulos, entropia, entropiaMax):
    mostrarTabla(tablaTitulos, tabla)
    print("Entropía: {0}").format(entropia)
    print("Entropía Máxima: {0}").format(entropiaMax)

def herramienta(fnObtenerSimbolo, fnCondicion, fnGenerarItemDeTabla):
    simbolos = set()
    cantidadPorSimbolo = dict()
    infoPorSimbolos = dict()
    cantidadTotal = 0

    for paquete in pkts:
        if fnCondicion(paquete):
            simbolo = fnObtenerSimbolo(paquete)
            simbolos.add(simbolo)
            if simbolo in cantidadPorSimbolo:
                cantidadPorSimbolo[simbolo] += 1
            else:
                cantidadPorSimbolo[simbolo] = 1
            cantidadTotal += 1

    tabla = set()
    entropia = 0
    entropiaMax = 0

    for simbolo in simbolos:
        s_prob = float(cantidadPorSimbolo[simbolo]) / cantidadTotal
        s_info = math.log(float(1) / s_prob, 2)
        tabla.add(fnGenerarItemDeTabla(simbolo, s_prob, s_info, cantidadPorSimbolo[simbolo]))
        entropia += (s_prob * s_info)
        infoPorSimbolos[simbolo] = s_info

    tabla = sorted(tabla, key=lambda x: x[len(next(iter(tabla)))-2])

    entropiaMax = math.log(len(simbolos), 2)
    
    return (simbolos, cantidadPorSimbolo, tabla, cantidadTotal, int(round(entropia)), int(round(entropiaMax)), infoPorSimbolos)

#*********************************

if __name__ ==  '__main__':

    #Leer una captura desde el archivo de entrada
    if len(argv) == 2:
        pkts = rdpcap(argv[1])
    else:
        print("Invalid Parameters")
        print("python file.py file.pcap")
        exit()

    (s1_simbolos, s1_cantidadPorSimbolo, s1_tabla, s1_cantTotal, s1_entropia, s1_entropiaMax, s1_infoPorSimbolos) = herramienta(obtenerSimboloS1, condicionS1, generarItemDeTablaS1)
    (s2_simbolos, s2_cantidadPorSimbolo, s2_tabla, s2_cantTotal, s2_entropia, s2_entropiaMax, s2_infoPorSimbolos) = herramienta(obtenerSimboloS2, condicionS2, generarItemDeTablaS2)

    s1_tablaTitulos = ["TIPO", "PROTOCOLO", "PROBABILIDAD", "INFORMACIÓN", "APARICIONES"]
    print("\n-- FUENTE S1 --\n")
    imprimirHerramienta(s1_tabla, s1_tablaTitulos, s1_entropia, s1_entropiaMax)

    cantBroadcast = 0
    for simbolo in s1_simbolos:
        if simbolo[0] == "Broadcast":
            cantBroadcast += s1_cantidadPorSimbolo[simbolo]
    porcBroadcast = float(cantBroadcast * 100) / s1_cantTotal
    porcUnicast = 100 - float(cantBroadcast * 100) / s1_cantTotal
    print("Broadcast: {0} %").format(round(porcBroadcast, DECIMALES))
    print("Unicast: {0} %").format(round(porcUnicast, DECIMALES))

    s2_tablaTitulos = ["IP", "PROBABILIDAD", "INFORMACIÓN", "APARICIONES"]
    print("\n-- FUENTE S2 --\n")
    imprimirHerramienta(s2_tabla, s2_tablaTitulos, s2_entropia, s2_entropiaMax)

    plot_bars(s1_infoPorSimbolos, s1_entropia)
    plot_bars(s2_infoPorSimbolos, s2_entropia)