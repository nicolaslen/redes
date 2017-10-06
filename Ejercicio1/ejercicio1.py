
#*********************************
#!   / u s r / b i n / env   p y t h o n
from sys import argv, exit
import math
import matplotlib.pyplot as plt
from matplotlib import pylab
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy .all import *

#def monitor_callback(pkt):
#    print(pkt.show()

def plot_bars(simbolos,entropia,total, toal_arp):
    
    info_set = set()
    
    fig, ax = plt.subplots()
    #Dibujo de los graficos
    entrop_line = ax.axvline(entropia, color='blue', linewidth=2,alpha = 0.7)
    maxEntrop_line = ax.axvline(math.log((len(s1_simbolos)),2), color='red', linewidth=2,alpha = 0.7)
    bars = ax.barh(range(len(s1_simbolos)), s1_simbolos.values(), align='center', alpha=0.4, color='green')
    bars[1].set_linewidth(2)

    plt.yticks(range(len(simbolos)),simbolos.keys())


    #Rotulos y titulos
    ax.legend((bars[0], entrop_line, maxEntrop_line), ('simbolos', 'Entropia','Entropia maxima'))
    pylab.xlabel("Informacion")
    pylab.ylabel("Ip Hosts")
    pylab.title("Informacion ssimbolos")
        # Data to plot
    labels = 'ARP', 'Otros'
    sizes = [total_arp,total]
    colors = ['gold', 'yellowgreen']
    
 
    # Plot
    fig, ad = plt.subplots()
    ad.pie(sizes, labels=labels, colors=colors,
        autopct='%1.1f%%', shadow=True, startangle=140)
 
    plt.axis('equal')

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

def generarItemDeTablaS1(simbolo, s_prob, s_info, cant):
    return (("Broadcast" if simbolo[0] else "Unicast"), buscar_protocolo(simbolo[1], True), round(s_prob, DECIMALES), round(s_info, DECIMALES), cant)

def generarItemDeTablaS2(simbolo, s_prob, s_info, cant):
    return (simbolo, round(s_prob, DECIMALES), round(s_info, DECIMALES), cant)

def obtenerSimboloS1(paquete):
    dst = paquete.dst == "ff:ff:ff:ff:ff:ff"
    return (dst, hex(paquete.type))

def condicionS1(paquete):
    return True

def obtenerSimboloS2(paquete):
    return paquete[ARP].pdst

def condicionS2(paquete):
    return ARP in paquete and paquete.op == 1 and paquete[ARP].psrc != paquete[ARP].pdst

def imprimirHerramienta(tabla, tablaTitulos, entropia, entropiaMax):
    print("\nTabla:")
    mostrarTabla(tablaTitulos, tabla)
    print("\nEntropia: {0}").format(entropia)
    print("\nEntropia Maxima: {0}").format(entropiaMax)

def herramienta(fnObtenerSimbolo, fnCondicion, fnGenerarItemDeTabla):
    simbolos = set()
    cantidadPorSimbolo = dict()
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

    tabla = sorted(tabla, key=lambda x: x[len(next(iter(tabla)))-2])

    entropiaMax = math.log(len(simbolos), 2)
    
    return (simbolos, cantidadPorSimbolo, tabla, cantidadTotal, int(round(entropia)), int(round(entropiaMax)))

#*********************************

if __name__ ==  '__main__':

    if len(argv) >= 3:
        print("Parametros invalidos")
        print("Uso: ejercicio1.py archivo_entrada")
        exit()
    elif len(argv) == 2:
        #Leer una captura desde el archivo de entrada
        pkts = rdpcap(argv[1])
    else:
        #Capturar paquetes en vivo
        pkts = sniff(prn = lambda x:x.show(), count = PACKET_COUNT)
        #Escribo los paqutes en el archivo(Sobreescribe!)
        wrpcap("temp.pcap", pkts)

    (s1_simbolos, s1_cantidadPorSimbolo, s1_tabla, s1_cantTotal, s1_entropia, s1_entropiaMax) = herramienta(obtenerSimboloS1, condicionS1, generarItemDeTablaS1)
    (s2_simbolos, s2_cantidadPorSimbolo, s2_tabla, s2_cantTotal, s2_entropia, s2_entropiaMax) = herramienta(obtenerSimboloS2, condicionS2, generarItemDeTablaS2)

    s1_tablaTitulos = ["TIPO DESTINO", "PROTOCOLO", "PROBABILIDAD", "INFORMACION", "APARICIONES"]
    imprimirHerramienta(s1_tabla, s1_tablaTitulos, s1_entropia, s1_entropiaMax)


    cantBroadcast = 0
    for simbolo in s1_simbolos:
        if simbolo[0]:
            cantBroadcast += s1_cantidadPorSimbolo[simbolo]
    porcBroadcast = float(cantBroadcast * 100) / s1_cantTotal
    print("Porc Broadcast: {0}").format(round(porcBroadcast, DECIMALES))


    s2_tablaTitulos = ["DIR IP", "PROBABILIDAD", "INFORMACION", "APARICIONES"]
    imprimirHerramienta(s2_tabla, s2_tablaTitulos, s2_entropia, s2_entropiaMax)


    '''
    print("s1_simbolos posibles =")
    print(s1_simbolos)
    print("\n")
    print("s1_simbolos=")
    print(cantidadPorSimbolo)
    print("\n")
    '''


    '''
    s_broadcast = 0
    s_unicast   = 0
    total = 0
    total_arp = 0
    '''

    #Calculo de la frecuencia relativa e informacion para cada simbolo
    '''
    for paquete in pkts:
        print("-------------\n")

        if paquete.type == 2054:
            print(paquete[ARP].fields)
        elif paquete.type == 2048:
            print(paquete[IP].fields)
            if UDP in paquete:
                print(paquete[UDP].fields)
            if TCP in paquete:
                print(paquete[TCP].fields)
            if ICMP in paquete:
                print(paquete[ICMP].fields)
        else:
            conjunto.add(paquete.type)
            print(paquete.type)

        if ARP in paquete:
            total_arp += 1
        if paquete.dst == "ff:ff:ff:ff:ff:ff":
            s_broadcast+=1
        else:
            s_unicast+=1
        total += 1
    print(conjunto)



    exit
    #Verifica haber escuchado al menos un paquete broadcast        
    assert(s_broadcast != 0)
    assert(s_unicast != 0)


    #Calculo de probabilidades, informacion y entropia
    s_broadcastProba = float(s_broadcast)/total
    s_unicastProba      = float(s_unicast)/total
    s_broadcastInfo = math.log(1/s_broadcastProba,2)
    s_unicastInfo   = math.log(1/s_unicastProba,2)
    s_entropia = s_broadcastProba*s_broadcastInfo + s_unicastProba*s_unicastInfo
    print("Paquetes escuchados: %d, de los cuales %d son ARP" %(total,total_arp))
    print("Entropia: %f, broadcastProba: %f, unicastProba: %f ,Info(broadcast): %f, Info(unicast) : %f" % (s_entropia,s_broadcastProba,s_unicastProba,s_broadcastInfo,s_unicastInfo))    

    simbolos = {}
    simbolos["broadcast"] = s_broadcastInfo
    simbolos["unicast"] = s_unicastInfo
    plot_bars(simbolos,s_entropia,total, total_arp)
    '''