#Write network sniffer tool(It must take input from command line)

#!/usr/bin/python3
print("Use Sudo")

from datetime import datetime 
import sys
import subprocess 
from scapy.all import *

print(sys.argv)

net_iface = sys.argv[1] # taking interface name as command line argument
print(net_iface)

subprocess.call(["ifconfig",net_iface,"promisc"]) 
num_of_pkt = int(sys.argv[2]) # taking no_of_packet as command line
print(num_of_pkt)


time_sec = int(sys.argv[3]) # taking time from command line
print(time_sec)


proto = sys.argv[4] # taking protocol from command line(like all | icmp | arp)
print(proto)

def logs(packet):
	packet.show()
	print(f"SRC_MAC: {str(packet[0].src)} DEST_MAC: {str(packet[0].dst)}")


if proto == "all":
	sniff(iface = net_iface ,count = num_of_pkt, timeout = time_sec, prn=logs ) 
elif proto == "arp":
	sniff(iface = net_iface, count = num_of_pkt,timout = time_sec , prn = logs , filter = proto) 
elif proto == "icmp":
	sniff(iface = net_iface, count = num_of_pkt,timout = time_sec , prn = logs , filter = proto)
else:
	print("Wrong protocol")
"""
-------------------------------------------output-----------------------------------------
sudo python3 packet_sniffer.py ens33 1 1 all
[sudo] password for sachin: 
Use Sudo
['network_sniffer_commandline.py', 'wlp7s0', '1', '1', 'all']
wlp7s0
1
1
all
"""
