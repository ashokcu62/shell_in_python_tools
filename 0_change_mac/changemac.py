import subprocess
import optparse
import re

def get_options():
    parser=optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="add interface")
    parser.add_option("-m","--mac",dest="new_mac",help="add newmac")
    (options,args)= parser.parse_args()

    if not options.interface :
        parser.error("[-] please specify an interface , --help for more info")
    if not options.new_mac :
        parser.error("[-] please specify mac adress , --help for more info")

    return options

def changemac(interface,new_mac):
    subprocess.call(["ifconfig",interface,"down"])
    print(f"[+] changing mac adress to {interface} >{new_mac}")
    subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
    subprocess.call(["ifconfig",interface,"up"])

def get_current_mac(interface):
    ifconfig_output=str(subprocess.check_output(["ifconfig",interface]))
    expression_res=re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_output)
    if expression_res:
        return expression_res.group(0)
    else:
        print("[-] could not read mac adress")

options=get_options()
current_mac=get_current_mac(options.interface)

print("current mac >",current_mac)

changemac(options.interface,options.new_mac)

current_mac=get_current_mac(options.interface)

if current_mac == options.new_mac :
    print("[+] mac address successfully get changed ")
else:
    print("[-] mac adress not get changed")




    


