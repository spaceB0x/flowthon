#!/usr/bin/env python
from scapy.all import *
import sys
import time
import re
import netaddr
import argparse
parser = argparse.ArugumentParser()

#Globals
XFFreg=re.compile('X\-Forwarded\-For\:\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
UDPreg=re.compile('\{\|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\}')
list=[]
addresses=netaddr.IPNetwork("172.16.0.0/12")
localaddr=netaddr.IPNetwork("127.0.0.1/32")

#define callback
def packet_decider(packet):

    p=packet
    if(packet.haslayer(IP)):
        if (packet[IP].proto == 6) :
            TCPsend(p)
        elif (packet[IP].proto == 17):
            UDPsend(p)
        else:
            print packet.show()

    else:
        print "[*][*] Not an IP based packet."


def TCPsend(p):

    epoch=getEpoch()
    sip=p[IP].src
    dip=p[IP].dst
    sport=p[TCP].sport
    dport=p[TCP].dport

    lus=lookup(sip,sport)
    lud=lookup(dip,dport)
    if((lus is None) and (lud is None)):
        if (p.haslayer(Raw)):
            raw=str(p[Raw])
            xff=XFFreg.search(raw)
            if (xff is None):
	        print "Not a match"

            else:
                newsrc= (xff.group(0)).strip('X-Forwarded-For: ')
	        addToList(sip,sport,newsrc)
                sip=str(newsrc)

        else:
            print "No TCP Raw"
    elif(lus is not None):
	sip=str(lus)
    else:
        dip=str(lud)

    try:
        send(IP(dst="10.209.104.214")/UDP(dport=18001)/NetflowV5Header(sysUptime=5, unixSecs=epoch, unixNanoSeconds=3) \
                /NetflowV5Record(src=str(sip), dst=str(dip), srcport=sport, dstport=dport, prot=6))
        print "[*] TCP netflow send successful"
	print sip
    except:
        print "[*][*] TCP Netflow not sent"

def UDPsend(p):

    epoch=getEpoch()
    sip=p[IP].src
    dip=p[IP].dst
    sport=p[UDP].sport
    dport=p[UDP].dport
    lu=lookup(sip,sport)
    if(lu is None): #If not in list, then add to list and try and strip headerinfo
        if (p.haslayer(Raw)):
            raw=str(p[Raw])
	    ureg=UDPreg.search(raw)
            if (ureg is None):
 	        print "Not a match"
	    else:
                newsrc= (ureg.group(0)).strip('{|').strip('}')
                addToList(sip,sport,newsrc)
		sip=str(newsrc)

        else:
            print "No UDP Raw"
    else: sip=str(lu)

    try:
        send(IP(dst="10.209.104.214")/UDP(dport=18001)/NetflowV5Header(sysUptime=5, unixSecs=epoch, unixNanoSeconds=3) \
                /NetflowV5Record(src=str(sip), dst=str(dip), srcport=sport, dstport=dport, prot=17))
        print "[*] UDP netflow send successful"
        print sip
    except:
        print "[*][*] UDP Netflow not sent"



def getEpoch():
    a= int(time.time())
    return a

def lookup(sip,sport):
    for x in list:
        if (x[0]==sip and x[1]==sport):
	    return x[2]
	else: return None

def addToList(sip,sport,newsrc):
    if((sip not in addresses)and (newsrc not in localaddr)):
        listitem=[sip,sport,newsrc]
        list.append(listitem)
        print list
def main():
    sniff(iface="docker0",prn=packet_decider, store=0)

main()
