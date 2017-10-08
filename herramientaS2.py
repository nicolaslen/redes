#!/usr/bin/env python
# encoding: utf-8

from sys import argv, exit
import math
import matplotlib.pyplot as plt

from matplotlib import pylab
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy .all import *

import graphviz as gv
import functools

DECIMALES = 3

def PlotBars(simbolos, entropia, entropiaMax):
    
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

    #Dibuja
    entrop_line = ax.axvline(entropia, color='blue', linewidth=2,alpha = 0.7)
    maxEntrop_line = ax.axvline(entropiaMax, color='red', linewidth=2,alpha = 0.7)
    bars = ax.barh(range(len(filtered_simbolos)), filtered_simbolos.values(), align='center', alpha=0.4, color='green')
    plt.yticks(range(len(filtered_simbolos)), filtered_simbolos.keys(), fontsize=7, rotation=45)

    #Rótulos y títulos
    ax.legend((bars[0], entrop_line, maxEntrop_line), ('I(S(i))', 'H(S)', 'HMAX(S)'))
    pylab.xlabel("INFORMACION")
    pylab.ylabel("S(i)")
    pylab.title("Cantidad de INFORMACION por SIMBOLO")

    #Lo muestra
    plt.show()    

def PrintTable(titulos, tabla):
    row_format ="{:>20}" * len(titulos)
    print(row_format.format(*titulos))
    for row in tabla:
        print(row_format.format(*row))
    print("\n")

def CreateRow(simbolo, s_prob, s_info, cant):
    return (simbolo, round(s_prob, DECIMALES), round(s_info, DECIMALES), cant)

def GetSymbolFromFrame(paquete):
    return paquete[ARP].pdst

def Condition(paquete):
    if ARP in paquete and paquete.op == 1 and paquete[ARP].psrc != paquete[ARP].pdst:
        nodos.add(paquete[ARP].psrc)
        nodos.add(paquete[ARP].pdst)
        aristas.add((paquete[ARP].psrc,paquete[ARP].pdst))
        return True
    else:
        return False

def PrintResults(tabla, tablaTitulos, entropia, entropiaMax):
    PrintTable(tablaTitulos, tabla)
    print("Entropía: {0} ({1:.2f})").format(int(math.ceil(entropia)), entropia)
    print("Entropía Máxima: {0} ({1:.2f})\n").format(int(math.ceil(entropiaMax)), entropiaMax)

def AddNodes(graph, nodes):
    for n in nodes:
        if isinstance(n, tuple):
            graph.node(n[0], **n[1])
        else:
            graph.node(n)
    return graph

def AddEdges(graph, edges):
    for e in edges:
        if isinstance(e[0], tuple):
            graph.edge(*e[0], **e[1])
        else:
            graph.edge(*e)
    return graph

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
    
    return (simbolos, cantidadPorSimbolo, tabla, cantidadTotal, entropia, entropiaMax, infoPorSimbolos)

if __name__ ==  '__main__':

    #Leer una captura desde el archivo de entrada
    if len(argv) == 2:
        pkts = rdpcap(argv[1])
    else:
        print("Invalid Parameters")
        print("python file.py file.pcap")
        exit()
        
    #Creamos la lista de nodos y aristas para el grafo de la red
    nodos = set()
    aristas = set()

    #Para los paquetes de la captura, correr la herramienta 
    (S2, apariciones, tabla, cantidad, entropia, entropiaMax, informacion) = herramienta(GetSymbolFromFrame, Condition, CreateRow)

    #Imprimir la tabla para S2
    PrintResults(tabla, ["IP", "PROBABILIDAD", "INFORMACIÓN", "APARICIONES"], entropia, entropiaMax)

    #Gráfico de barras para S2
    PlotBars(informacion, int(math.ceil(entropia)), entropiaMax)
    
    #Grafo de la red
    digraph = functools.partial(gv.Digraph, format='png')
    graph = digraph()
    AddEdges(AddNodes(graph, nodos),aristas).render('network')
