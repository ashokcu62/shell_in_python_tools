import scapy.all as scapy
import re
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


a=scan("192.168.199.0/24")
show(a)