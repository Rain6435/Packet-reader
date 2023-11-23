Sniffer.py: Script to sniff packets using scappy.
Documentation for this file:

scapy.sniff(iface, count, store, filter): Sniffs network packets based on specified parameters.
iface: Network interface name to sniff packets from.
count: Number of packets to capture.
store: Boolean indicating whether to store packets in memory.
filter: Protocol or filter to apply while sniffing (e.g., "icmp").
wrpcap():

wrpcap(file_name, packets): Writes captured packets to a .pcap file.
file_name: Name of the .pcap file to write the packets to.
packets: Sniffed packets to be written to the file.

Additional Notes:
The code captures ICMP packets on the specified network interface and stores them in the file foo.pcap.
Make sure the scapy library is correctly installed to use its functionalities for packet manipulation and capturing.
Please note that the code may require appropriate permissions and administrative privileges to access the network interface for packet sniffing.

The wrpcap method lets you save the sniffed content in a file.
