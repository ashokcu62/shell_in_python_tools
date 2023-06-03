import scapy.all as scapy
import re
from optparse import OptionParser



def get_options():
    parser = OptionParser()
    parser.add_option("-i", "--ip", dest="ip",
                      help="enter ip or ip with range", metavar="FILE")
    
    (options, args) = parser.parse_args()
    if not options.ip :
        parser.error("[-] please specify an interface , --help for more info")
    return options.ip

def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request
    # print(arp_request_broadcast.summary())
    answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    

    client_list=[]

    for element in answered_list:
        client_dic={"ip":element[1].psrc,"mac":element[1].hwsrc}
        client_list.append(client_dic)
    print("scanning completed")    
    return  client_list

def show(client_list):
    print("IP\t\t\tMAC Adress\n","-"*70)
    for client in client_list:
        print(client["ip"]+"\t\t"+client["mac"])
        print("-"*70)

# ------------------SCANNER-------------------------------
def scanner():
    ip=get_options()
    clients=scan(ip)
    show(clients)

scanner()