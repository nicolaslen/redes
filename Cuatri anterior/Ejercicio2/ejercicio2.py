
#*********************************
#!   / u s r / b i n / env   p y t h o n
from sys import argv, exit
import math
import matplotlib.pyplot as plt
from matplotlib import pylab

from scapy .all import *
def monitor_callback(pkt):
	print pkt .show()

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
	ax.legend((bars[0], entrop_line, maxEntrop_line), ('Ip\'s', 'Entropia','Entropia maxima'))
	pylab.xlabel("Informacion")
	pylab.ylabel("Ip Hosts")
	pylab.title("Informacion simbolos")

	#Lo muestra y te da la opcion para guardarlo
	plt.show()	


#No encontre una forma mas copada para hacer que termine y despues poder escribir el resultado del sniff
#Estaria bueno que sea por tiempo

PACKET_COUNT    =   5
WHO_HAS = 1
CANT_DESTACADOS = 5

#*********************************

if __name__ ==  '__main__':

	if len(argv) >= 3:
    	 print ("Parametros invalidos")
         print ("Uso:")
         print ("sniffer archivo_entrada")
         exit()
	elif len(argv) == 2:
		#Leer una captura desde el archivo de entrada
		pkts = rdpcap(argv[1])
		pkts.show()
	else:
		 #Capturar paquetes en vivo
		 pkts = sniff(filter = "arp", prn = lambda x:x.summary(),count = PACKET_COUNT)
		 #Escribo los paqutes en el archivo(Sobreescribe!)
		 wrpcap("temp.pcap",pkts)
 	
 	#Este diccionario guarda como clave a las ips, y como definicion almacena las ocurrencias
 	#Una vez calculadas las ocurrencias, luego se redefinen con la informacion de la ip
 	simbolos = {}

 	#Cuento las ocurrencias de cada simbolo(ip's) segun aparezcan en los mensajes de who-has
 	
 	cant_who = 0
 	cant_arp = 0
	for paquete in pkts:
		#Verifico si es un paquete ARP
		if ARP in paquete: 
			cant_arp += 1
			if paquete.op == WHO_HAS and paquete.psrc != paquete.pdst:
				#Cuento a la ip dst y verifico si no estaba definida
				cant_who += 1
				if simbolos.get(paquete.pdst) != None:
					simbolos[paquete.pdst] += 1
				else:
					simbolos[paquete.pdst] = 1

	assert(cant_who > 0)

	#Calculo de probabilidades, informacion y entropia
	
	print("\n------------------------------Fin de la captura--------------------------------------\n")
	print("\n------------------------------Datos obtenidos--------------------------------------\n")

	entropia = 0
	minInfo = 100000000000000000 	#Esto es una cota gigante 
	maxInfo = 0
	host_minInfo = ""
	print("Se encontraron %d hosts" %(len(simbolos)))

	for host in simbolos:
		proba = simbolos[host] / float(cant_who)
		info = math.log(1/proba,2)
		entropia += (info*proba)

		#Ahora actualizo el diccionario con la informacion de cada ip en vez de sus ocurrencias
		simbolos[host] = info

		if info < minInfo:
			minInfo = info
			host_minInfo = host
		print("Host:%s, Probabilidad:%f, Informacion:%f " %(host,proba,info))

	print("\n--------------------------------------------------------------------\n")
	#Ordeno (creciente) a las ips segun su info para despues poder mostrar arbitrariamente los primeros k	
	hosts_destacados = sorted(simbolos, key=simbolos.__getitem__)[0:CANT_DESTACADOS]

	print("Entropia:%f, Entropia maxima teorica:%f \n"%(entropia,math.log((len(simbolos)),2)))
	print("--------------------------------------------------------------------\n")

	#Un host destacado es aquel con la menor informacion(mayor probabilidad)
	print("Hosts destacados:\n")
	for host in hosts_destacados:
		print("IP:%s, Informacion:%f"%(host,simbolos[host]))

	#Muestro el grafico de barras(falta hacer el grafo de los hosts)
	plot_bars(simbolos,entropia)
