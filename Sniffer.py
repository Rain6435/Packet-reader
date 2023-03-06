import socket
from scapy import all as scapy
from scapy.all import wrpcap

def sniffing():
    s = scapy.sniff(iface='Software Loopback Interface 1',count = 30,store=True,filter="icmp")
    wrpcap("foo.pcap", s)
    print(s)
sniffing()
