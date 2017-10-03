
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
    
    info_set  = set()
    
    fig, ax = plt.subplots()
    #Dibujo de los graficos
    entrop_line = ax.axvline(entropia, color='blue', linewidth=2,alpha = 0.7)
    maxEntrop_line = ax.axvline(math.log((len(simbolos)),2), color='red', linewidth=2,alpha = 0.7)
    bars = ax.barh(range(len(simbolos)), simbolos.values(), align='center', alpha=0.4, color='green')
    bars[1].set_linewidth(2)

    plt.yticks(range(len(simbolos)),simbolos.keys())


    #Rotulos y titulos
    ax.legend((bars[0], entrop_line, maxEntrop_line), ('simbolos', 'Entropia','Entropia maxima'))
    pylab.xlabel("Informacion")
    pylab.ylabel("Ip Hosts")
    pylab.title("Informacion simbolos")
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

#No encontre una forma mas copada para hacer que termine y despues poder escribir el resultado del sniff
#Estaria bueno que sea por tiempo

PACKET_COUNT    =   10

#*********************************

if __name__ ==  '__main__':

    if len(argv) >= 3:
        print("Parametros invalidos")
        print("Uso:")
        print("sniffer archivo_entrada")
        exit()
    elif len(argv) == 2:
        #Leer una captura desde el archivo de entrada
        pkts = rdpcap(argv[1])
    else:
        #Capturar paquetes en vivo
        pkts = sniff(prn = lambda x:x.show(),count = PACKET_COUNT)
        #Escribo los paqutes en el archivo(Sobreescribe!)
        wrpcap("temp.pcap",pkts)

    s_broadcast = 0
    s_unicast   = 0
    total = 0
    total_arp = 0

    conjunto = set()


    for paquete in pkts:
        dst = paquete.dst == "ff:ff:ff:ff:ff:ff"
        conjunto.add((dst, paquete.type))

    simbolos = dict.fromkeys(conjunto, 0)

    for paquete in pkts:
        dst = paquete.dst == "ff:ff:ff:ff:ff:ff"
        conjunto.add((dst, paquete.type))
        simbolos[(dst, paquete.type)] += 1

    print("simbolos posibles =")
    print(conjunto)
    print("\n")
    print("simbolos=")
    print(simbolos)
    print("\n")

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
    print(conjunto



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