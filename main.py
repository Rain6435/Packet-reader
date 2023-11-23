from optparse import OptionParser  # For parsing command-line options
import json
from pypcap import *
from datetime import datetime

# Create an OptionParser object for parsing command-line options
parser = OptionParser()

# Add options to the parser
parser.add_option(
    "-n", type="int", dest="num_pkts", default=5, help="number of packets to process"
)

parser.add_option(
    "-f",
    "--file",
    dest="filename",
    default="f2200.pcap",
    help="read file",
    metavar="FILE",
)

parser.add_option(
    "-a", "--filter", dest="filter", default="None", help="filter the wanted class"
)

parser.add_option(
    "-t",
    "--timestamp",
    action="store_true",
    dest="time_stamps",
    default=False,
    help="Print timestamps",
)

(options, args) = parser.parse_args()


def bytes2ip(a):
    """
    Converts bytes to an IP address string.

    Args:
    - a: List of bytes representing an IP address.

    Returns:
    - IP address string converted from the bytes.
    """
    val = [str(i) for i in a]
    s = "."
    return s.join(val)


def get_decimal_from_bytes(datag):
    """
    Converts bytes to a decimal value.

    Args:
    - datag: Represents the byte data to be converted to a decimal value.

    Returns:
    - decimal: Decimal value converted from the byte data.
    """
    hexa = bytes(datag).hex()
    decimal = int(hexa, base=16)
    return decimal


class DgDict:
    """
    Class to store and manage a dictionary.

    Methods:
    - __init__: Initializes a DgDict object.
    - update: Updates the dictionary with a new key-value pair.
    - __str__: String representation of the dictionary.
    """

    def __init__(self, dg=None):
        """
        Initializes a DgDict object.

        Args:
        - dg: Represents the initial dictionary. Defaults to an empty dictionary if None.
        """
        if dg is None:
            self.dg = {}

    def update(self, key, data):
        """
        Updates the dictionary with a new key-value pair.

        Args:
        - key: Represents the key to be added or updated in the dictionary.
        - data: Represents the corresponding value associated with the key.
        """
        self.dg[key] = data

    def __str__(self):
        """String representation of the dictionary."""
        return str(self.dg)


class DgEngine(pcap):
    """
    Class for packet processing.

    Inherits from:
    - pcap: Represents packet capture functionality.

    Attributes:
    - dgdict: Instance of DgDict for storing packet data.

    Methods:
    - __init__: Initializes the DgEngine object with packet capture parameters.
    - read_1_pkt: Reads one packet from the packet capture object.
    - print_datag: Prints the contents of the datagram.
    - print_time_stamps: Prints the timestamp of the datagram.
    - print_json_datag: Prints the datagram in JSON format.
    """

    dgdict = DgDict()

    def __init__(self, stream, mode):
        """
        Initializes the DgEngine object with packet capture parameters.

        Args:
        - stream: Represents the packet stream to process.
        - mode: Represents the mode of packet processing.
        """
        self.p = pcap(stream, mode)
        assert (self.p.version, self.p.thiszone, self.p.sigfigs) == ((2, 4), 0, 0)
        self.datagram = None

    def read_1_pkt(self):
        """Reads one packet from the packet capture object."""
        self.dgdict.dg.clear()
        self.datagram = self.p.read()
        return self.datagram

    def print_datag(self):
        """Prints the contents of the datagram."""
        print(self.datagram)

    def print_time_stamps(self):
        """Prints the timestamp of the datagram."""
        x = self.datagram
        timestamp = x[0][0] + x[0][1] / 1e6
        d = datetime.fromtimestamp(timestamp)
        print("Date:", d)

    def print_json_datag(self, n):
        """
        Prints the datagram in JSON format.

        Args:
        - n: Represents the datagram number.
        """
        if options.filter != "None":
            if options.filter in self.dgdict.dg:
                print("-" * 10, "Datagram No.", n, "-" * 10)
                print(json.dumps(self.dgdict.dg, indent=4, sort_keys=False))
        else:
            print("-" * 10, "Datagram No.", n, "-" * 10)
            print(json.dumps(self.dgdict.dg, indent=4, sort_keys=False))


class DgEngine(pcap):
    """
    Class for processing packets.

    Inherits from:
    - pcap: Represents packet capture functionality.

    Methods:
    - process: Processes the packet and decodes the various protocol layers.
    """

    def process(self):
        """
        Processes the packet and decodes the various protocol layers.

        The method decodes the packet and identifies its protocol layers
        (Ethernet, ARP, IPv4, IPv6, UDP, TCP, ICMP) by utilizing the
        access_protocol, network_protocol, and transport_protocol classes.
        It extracts different segments of the packet and decodes them
        based on the identified layers.

        Returns:
        - layer: Indicates the identified top-level protocol layer of the packet.
                 Returns 'None' if the protocol layer is not identified.
        """
        frame = bytearray(self.datagram[1][:])
        framed = access_protocol(Eth(frame))
        layer = framed.access_proto_decode()

        pkt = frame[14:]
        if layer == "ARP":
            networked = network_protocol(Arp(pkt))
            layer = networked.network_proto_decode()
        if layer == "IPV4":
            networked = network_protocol(IpV4(pkt))
            layer = networked.network_proto_decode()
        elif layer == "IPV6":
            networked = network_protocol(IpV6(pkt))
            layer = networked.network_proto_decode()
        else:
            return "None"

        seg = pkt[20:]
        if layer == "UDP":
            transported = transport_protocol(UDP(seg))
            layer = transported.transport_proto_decode()
        if layer == "ICMP":
            transported = transport_protocol(ICMP(seg))
            layer = transported.transport_proto_decode()
        if layer == "TCP":
            transported = transport_protocol(TCP(seg))
            layer = transported.transport_proto_decode()
        else:
            return "None"


class access_protocol:
    """
    Class for accessing protocols.

    Attributes:
    - ap_selector: Represents the selected access protocol.
    """

    def __init__(self, ap_selector):
        """
        Initialize access protocol instance.

        Args:
        - ap_selector: Represents the selected access protocol.
        """
        self.selector = ap_selector

    def access_proto_decode(self):
        """
        Decodes the selected access protocol.

        Returns:
        - decoded_data: Decoded information of the access protocol.
        """
        return self.selector.decode()


class network_protocol:
    """
    Class for network protocols.

    Attributes:
    - net_selector: Represents the selected network protocol.
    """

    def __init__(self, net_selector):
        """
        Initialize network protocol instance.

        Args:
        - net_selector: Represents the selected network protocol.
        """
        self.selector = net_selector

    def network_proto_decode(self):
        """
        Decodes the selected network protocol.

        Returns:
        - decoded_data: Decoded information of the network protocol.
        """
        return self.selector.decode()


class transport_protocol:
    """
    Class for transport protocols.

    Attributes:
    - transport_selector: Represents the selected transport protocol.
    """

    def __init__(self, transport_selector):
        """
        Initialize transport protocol instance.

        Args:
        - transport_selector: Represents the selected transport protocol.
        """
        self.selector = transport_selector

    def transport_proto_decode(self):
        """
        Decodes the selected transport protocol.

        Returns:
        - decoded_data: Decoded information of the transport protocol.
        """
        return self.selector.decode()


class Eth:
    """
    Class for Ethernet protocol decoding.

    Attributes:
    - frame: Represents the Ethernet frame.
    """

    def __init__(self, frame):
        """
        Initialize Ethernet frame instance.

        Args:
        - frame: Represents the Ethernet frame.
        """
        self.a = frame

    def decode(self):
        """
        Decodes the Ethernet frame and extracts relevant information.

        Returns:
        - eth_type: Ethernet frame type.
        """
        a = self.a

        dict_data = {
            "pkt_Lenght": len(a[:]),
            "mac dest": a[0:6].hex(":"),
            "mac src": a[6:12].hex(":"),
            "Type": TYPES.get(a[12:14].hex(), a[12:14].hex()),
        }

        DgEngine.dgdict.update("eth", dict_data)

        eth_type = DgEngine.dgdict.dg["eth"]["Type"]
        return eth_type


class Arp:
    """
    Class for decoding ARP packets.

    Attributes:
    - pkt: Represents the ARP packet data.
    """

    def __init__(self, pkt):
        """
        Initialize ARP packet instance.

        Args:
        - pkt: Represents the ARP packet data.
        """
        self.a = pkt

    def decode(self):
        """
        Decodes ARP packet and extracts relevant information.

        Returns:
        - dict_data: A dictionary containing decoded ARP packet information.
        """
        a = self.a

        hwt = a[0:2].hex()
        pt = a[2:4].hex()
        phlen = a[4:5].hex()
        loglen = a[5:6].hex()
        oper = OPER.get(a[6:8].hex())
        sender_mac = a[8:14].hex(":")
        sender_ip = bytes2ip(a[14:18])
        target_mac = a[18:24].hex(":")
        target_ip = bytes2ip(a[24:28])

        dict_data = {
            "hwt": hwt,
            "pt": pt,
            "phlen": phlen,
            "loglen": loglen,
            "oper": oper,
            "sender mac (SHA)": sender_mac,
            "sender ip (SPA)": sender_ip,
            "target mac (THA)": target_mac,
            "target ip (TPA)": target_ip,
        }
        DgEngine.dgdict.update("arp", dict_data)
        return dict_data


class IpV4:
    """
    Class for decoding IPv4 packets.

    Attributes:
    - pkt: Represents the IPv4 packet data.
    """

    def __init__(self, pkt):
        """
        Initialize IPv4 packet instance.

        Args:
        - pkt: Represents the IPv4 packet data.
        """
        self.a = pkt

    def decode(self):
        """
        Decodes IPv4 packet and extracts relevant information.

        Returns:
        - dict_data: A dictionary containing decoded IPv4 packet information.
        """
        a = self.a
        s = bytes2ip(a)

        ipsrc = (str(a[12]), str(a[13]), str(a[14]), str(a[15]))
        ipdst = (str(a[16]), str(a[17]), str(a[18]), str(a[19]))
        version = "{:02X}".format(((a[0] & 0xF0)) >> 4) + " (en hex)"
        LEntete = str(((a[0] & 0x0F) * 4))
        TOSDSCP = "{:02X}".format(((a[1] & 0xFC)) >> 2)
        LTotale = get_decimal_from_bytes(a[2:4])
        ECN = "{:02X}".format(((a[1] & 0x3)) >> 4)
        id = a[4:6].hex()
        flag = FLAGSIP.get(int((a[6] & 0xE0) >> 5))
        TTL = get_decimal_from_bytes(a[8:9])
        Protocol = PROTO.get(a[9:10].hex())
        CheckSum = get_decimal_from_bytes(a[10:12])

        dict_data = {
            "ip_source": ".".join(ipsrc),
            "ip_dest": ".".join(ipdst),
            "version": version,
            "header length": LEntete + " octets",
            "TOS/DSCP": TOSDSCP + " (en hex)",
            "total length": LTotale,
            "ECN": ECN,
            "Identification": id + " en (hex)",
            "FLAGS": flag,
            "TTL": TTL,
            "Protocol": Protocol,
            "CheckSum": CheckSum,
        }
        DgEngine.dgdict.update("ip", dict_data)  #
        return dict_data


class IpV6:
    """
    Class for decoding IPv6 packets.

    Attributes:
    - pkt6: Represents the IPv6 packet data.
    """

    def __init__(self, pkt6):
        """
        Initialize IPv6 packet instance.

        Args:
        - pkt6: Represents the IPv6 packet data.
        """
        self.a = pkt6

    def decode(self):
        """
        Decodes IPv6 packet and performs required operations.

        Returns:
        - dict_data: A dictionary containing IPv6 related information.
        """
        a = self.a
        dict_data = {"IPV6": "NA"}
        DgEngine.dgdict.update("ipv6", dict_data)
        return dict_data


class UDP:
    """
    Class for decoding UDP packets.

    Attributes:
    - seg: Represents the segment of the UDP packet.
    """

    def __init__(self, seg):
        """
        Initialize UDP packet instance.

        Args:
        - seg: Represents the segment of the UDP packet.
        """
        self.a = seg

    def decode(self):
        """
        Decodes UDP packet and extracts relevant information.

        Returns:
        - dict_data: A dictionary containing decoded UDP packet information.
        """
        a = self.a
        port_src = get_decimal_from_bytes(a[0:2])
        port_des = get_decimal_from_bytes(a[2:4])
        length = get_decimal_from_bytes(a[4:6])
        checksum = a[6:8].hex()

        dict_data = {
            "src port": port_src,
            "dst port": port_des,
            "length": length,
            "checksum": checksum,
        }
        DgEngine.dgdict.update("udp", dict_data)
        return dict_data


class TCP:
    """
    Class for decoding TCP packets.

    Attributes:
    - seg: Represents the segment of the TCP packet.
    """

    def __init__(self, seg):
        """
        Initialize TCP packet instance.

        Args:
        - seg: Represents the segment of the TCP packet.
        """
        self.a = seg

    def decode(self):
        """
        Decodes TCP packet and extracts relevant information.

        Returns:
        - dict_data: A dictionary containing decoded TCP packet information.
        """
        a = self.a
        srcPort = get_decimal_from_bytes(a[0:2])
        srcDest = get_decimal_from_bytes(a[2:4])
        seqNum = get_decimal_from_bytes(a[4:8])
        ackNum = get_decimal_from_bytes(a[8:12])
        forthLayerDRF = a[12:14]
        dataOffset = forthLayerDRF[0:4].hex()
        reserved = forthLayerDRF[4:7].hex()
        flags = str(a[13:14])
        windowSize = get_decimal_from_bytes(a[14:16])
        checkSum = get_decimal_from_bytes(a[16:18])
        urgentPointer = get_decimal_from_bytes(a[18:20])
        # restOfHeader = str(a[20:])

        dict_data = {
            "srcPort": srcPort,
            "srcDest": srcDest,
            "seqNum": seqNum,
            "ackNum": ackNum,
            "dataOffset": dataOffset,
            "reserved": reserved,
            "flags": flags,
            "windowSize": windowSize,
            "checkSum": checkSum,
            "urgentPointer": urgentPointer,
            # "restOfHeader": restOfHeader
        }
        DgEngine.dgdict.update("tcp", dict_data)
        return dict_data


class ICMP:
    """
    Class for decoding ICMP packets.

    Attributes:
    - seg: Represents the segment of the ICMP packet.
    """

    def __init__(self, seg):
        """
        Initialize ICMP packet instance.

        Args:
        - seg: Represents the segment of the ICMP packet.
        """
        self.a = seg

    def decode(self):
        """
        Decodes ICMP packet and extracts relevant information.

        Returns:
        - dict_data: A dictionary containing decoded ICMP packet information.
        """
        a = self.a
        type = get_decimal_from_bytes(a[0:1])
        code = get_decimal_from_bytes(a[1:2])
        checksum = get_decimal_from_bytes(a[2:4])
        rest_of_header = a[4:].hex()

        dict_data = {
            "type": type,
            "code": code,
            "checksum": checksum,
            "rest of header": rest_of_header,
        }
        global n
        n += 1
        DgEngine.dgdict.update("icmp", dict_data)
        return dict_data


a = DgEngine(options.filename, "rb")

while n < 100:
    a.read_1_pkt()  # Reads one packet from the file
    a.process()  # Processes the packet data

    # Checks if printing timestamps is enabled
    if options.time_stamps:
        a.print_time_stamps()  # Prints the timestamp of the packet

    a.print_json_datag(n)  # Prints the packet information in JSON format
    n += 1  # Increment packet counter
