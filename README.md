This project is a packet reader that serves the purpoe of detecting which protocols are used in a certain packet. It allows you detect which IP adresses are interacting with each other and what are they sending to each other.
It uses different types of reading of bit level data. It implements an understanding of the headers of communication protocols.

main.py:
The structure of the project is in the form of a script that can accept parsed parameters for different needs.
A description for the possible parameters is in the code.
This is possible using the optparse library. We are also using pcap to manage our packets.
The DgDict object defines a dictionary where every sniffed parameter will be stored to be displayed.
The DgEngine object takes a pcap file as an input. It reads the pcap file as a byte array then applies the necessary transformation to call the methods propietary to the layers and protocols present in the pcap file.

The different classes of protocols are where the bit manipulation is done.
