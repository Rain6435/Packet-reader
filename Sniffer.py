# Import necessary libraries
import socket  # Standard Python library providing socket operations
from scapy import all as scapy  # Import all functionalities from scapy library
from scapy.all import wrpcap  # Import wrpcap method from scapy library


# Define a function for packet sniffing
def sniffing():
    # Sniff packets using scapy library
    s = scapy.sniff(
        iface="Software Loopback Interface 1", count=30, store=True, filter="icmp"
    )

    # Write the sniffed packets to a .pcap file named 'foo.pcap'
    wrpcap("foo.pcap", s)

    # Print the captured packets
    print(s)


# Call the sniffing function to start packet sniffing
sniffing()
