from optparse import OptionParser
import struct
import json
import sys
from pypcap import *
from datetime import datetime
import time

parser = OptionParser()
parser.add_option("-n",
                  type="int",
                  dest="num_pkts",
                  default=5,
                  help="number of packets to process")

parser.add_option("-f",
                  "--file",
                  dest="filename",
                  default="f2200.pcap",
                  help="read file",
                  metavar="FILE")

parser.add_option("-a",
                  "--filter",
                  dest="filter",
                  default="None",
                  help="filter the wanted class")

parser.add_option("-t",
                  "--timestamp",
                  action="store_true",
                  dest="time_stamps",
                  default=False,
                  help="Print timestamps")

(options, args) = parser.parse_args()


def bytes2ip(a):
  val = [str(i) for i in a]
  s = "."
  return s.join(val)


def get_decimal_from_bytes(datag):
  hexa = bytes(datag).hex()
  decimal = int(hexa, base=16)
  return decimal

n = 0

FLAGSIP = {
  0: "None",
  1: "F",
  2: "DF",
  3: "F+DF",
  4: "RES",
  5: "RES+DF",
  6: "RES+F",
  7: "RES+F+DF"
}

TYPES = {"0806": "ARP", "0800": "IPV4", "86dd": "IPV6", "8100": "DOT1Q"}
PROTO = {"11": "UDP", "06": "TCP", "01": "ICMP", "29": "IPV6", "2f": "GRE"}
OPER = {"0001": "ARP Request", "0002": "ARP Reply"}


class DgDict:

  def __init__(self, dg=None):
    if dg == None:
      self.dg = {}

  def update(
    self, key, data
  ):
    self.dg[key] = data

  def __str__(self):
    return self.dg


class DgEngine(
    pcap):

  dgdict = DgDict()

  def __init__(self, stream, mode):
    self.p = pcap(stream, mode)
    assert ((self.p.version, self.p.thiszone, self.p.sigfigs) == ((2, 4), 0, 0))
    self.datagram = None

  def read_1_pkt(self):
    self.dgdict.dg.clear()
    self.datagram = self.p.read()
    return self.datagram

  def print_datag(
      self):
    print(self.datagram)

  def print_time_stamps(self):
    x = self.datagram
    timestamp = x[0][0] + x[0][1] / 1e6
    d = datetime.fromtimestamp(timestamp)
    print("Date:", d)

  def print_json_datag(
      self, n):
    if options.filter != "None":
      if options.filter in self.dgdict.dg:
        print("-" * 10, "Datagram No.", n, "-" * 10)
        print(json.dumps(self.dgdict.dg, indent=4, sort_keys=False))
    else:
      print("-" * 10, "Datagram No.", n, "-" * 10)
      print(json.dumps(self.dgdict.dg, indent=4, sort_keys=False))

  def process(self):
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
      return ("None")

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
      return ("None")

class access_protocol(
):

  def __init__(self, ap_selector):
    self.selector = ap_selector

  def access_proto_decode(self):
    return self.selector.decode(
    )


class network_protocol():

  def __init__(self, net_selector):
    self.selector = net_selector

  def network_proto_decode(self):
    return self.selector.decode()


class transport_protocol():

  def __init__(self, transport_selector):
    self.selector = transport_selector

  def transport_proto_decode(self):
    return self.selector.decode()


class Eth():

  def __init__(
      self,
      frame):
    self.a = frame

  def decode(self):
    a = self.a

    dict_data = {
      "pkt_Lenght ": len(a[:]),
      "mac dest": a[0:6].hex(':'),
      "mac src": a[6:12].hex(':'),
      "Type": TYPES.get(a[12:14].hex(), a[12:14].hex())
    }

    DgEngine.dgdict.update("eth", dict_data)

    return DgEngine.dgdict.dg["eth"]["Type"]



class Arp():

  def __init__(
      self,
      pkt):
    self.a = pkt

  def decode(self):
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
      "target ip (TPA)": target_ip
    }
    DgEngine.dgdict.update("arp", dict_data)
class IpV4():

  def __init__(
      self,
      pkt):
    self.a = pkt

  def decode(self):
    a = self.a
    s = bytes2ip(a)

    # à modifier ici
    ipsrc = (str(a[12]), str(a[13]), str(a[14]), str(a[15]))
    ipdst = (str(a[16]), str(a[17]), str(a[18]), str(a[19]))
    version = "{:02X}".format(((a[0] & 0xF0)) >> 4) + " (en hex)"
    LEntete = str(((a[0] & 0x0F) * 4))
    TOSDSCP = "{:02X}".format(((a[1] & 0xFC)) >> 2)
    LTotale = get_decimal_from_bytes(a[2:4])
    ECN = "{:02X}".format(((a[1] & 0x3)) >> 4)
    id = a[4:6].hex()
    flag = FLAGSIP.get(int((a[6] & 0XE0) >> 5))
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
      "CheckSum": CheckSum
    }
    DgEngine.dgdict.update("ip", dict_data)  #

    return Protocol
class IpV6():

  def __init__(self, pkt6):
    self.a = pkt6

  def decode(self):
    a = self.a
    dict_data = {"IPV6": "NA"}
    DgEngine.dgdict.update("ipv6", dict_data)  #
class UDP():

  def __init__(
      self,
      seg):
    self.a = seg

  def decode(self):
    a = self.a
    port_src = get_decimal_from_bytes(a[0:2])
    port_des = get_decimal_from_bytes(a[2:4])
    length = get_decimal_from_bytes(a[4:6])
    checksum = a[6:8].hex()

    dict_data = {
      "port_source": port_src,
      "port_dest": port_des,
      "length": length,
      "checksum": checksum
    }
    DgEngine.dgdict.update("udp", dict_data)  #
class TCP():
    def __init__(
            self,
            seg):  # passe juste le pkt à décoder, et non le datagram au complet
        self.a = seg

    def decode(self):
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
class ICMP():
  def __init__(
      self,
      seg):
    self.a = seg

  def decode(self):
    a = self.a
    type=get_decimal_from_bytes(a[0:1])
    code = get_decimal_from_bytes(a[1:2])
    checksum = get_decimal_from_bytes(a[2:4])
    rest_of_header = a[4:].hex()

    dict_data = {
      "type": type,
      "code":code,
      "checksum":checksum,
      "rest of header":rest_of_header
    }
    global n
    n +=1
    DgEngine.dgdict.update("icmp", dict_data)

a = DgEngine(options.filename,'rb')

while n < 100:
  a.read_1_pkt()
  a.process()
  if options.time_stamps: a.print_time_stamps()
  a.print_json_datag(n)
  n+=1
