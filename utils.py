from scapy.all import *

def rdpcap_and_close(filename, count=-1):
    pcap_reader = PcapReader(filename)
    packets = pcap_reader.read_all(count=count)
    pcap_reader.close()
    return packets

def bytes_str_hex(bytes):
    bytes = bytes_hex(bytes)
    bytes = bytes.__str__().strip("b").strip("'")
    return bytes

def hex_str_to_int(str):
    return int(str, 16)

def format_hex_adress(adress):
    adress = bytes_str_hex(adress)
    tmp_str = ""
    for i in range(0, len(adress), 2):
        splice_str = adress[i:(i+2)]
        tmp_str += splice_str
        tmp_str += ":"
    tmp_str = tmp_str.strip(":")
    return tmp_str

def format_dec_adress(adress):
    adress = bytes_str_hex(adress)
    tmp_str = ""
    for i in range(0, len(adress), 2):
        splice_str = adress[i:(i+2)]
        int_addr = int(splice_str, 16)
        tmp_str += str(int_addr)
        tmp_str += "."
    tmp_str = tmp_str.strip(".")
    return tmp_str

def is_fin_true(flags):
    if flags & 0b00000001:
        return True
    else:
        return False

def is_ack_true(flags):
    if flags & 0b00010000:
        return True
    else:
        return False
def is_syn_true(flags):
    if flags & 0b00000010:
        return True
    else:
        return False
def is_rst_true(flags):
    if flags & 0b00000100:
        return True
    else:
        return False

#load type dictionaries for ethernet II, LLC
ether_types_dict = {}
ieee_types_dict = {}
ipv4_types_dict = {}
tcp_types_dict = {}
udp_types_dict = {}
ipv6_types_dict = {}
icmp_types_dict = {}
with open('ethernet_II_types.txt') as file:
    for line in file:
        line = line.strip()
        key = line[0:4]
        value = line[5:len(line)]
        ether_types_dict[key] = value
with open('LLC_ssaps.txt') as file:
    for line in file:
        line = line.strip()
        key = line[0:2]
        value = line[3:len(line)]
        ieee_types_dict[key] = value
with open('ipv4_types.txt') as file:
    for line in file:
        line = line.strip().split()
        key = int(line[0])
        value = line[1]
        ipv4_types_dict[key] = value
with open('tcp_types.txt') as file:
    for line in file:
        line = line.strip().split()
        key = int(line[0])
        value = line[1]
        tcp_types_dict[key] = value
with open('udp_types.txt') as file:
    for line in file:
        line = line.strip().split()
        key = int(line[0])
        value = line[1]
        udp_types_dict[key] = value
with open('ipv6_types.txt') as file:
    for line in file:
        line = line.strip().split()
        key = int(line[0])
        value = line[1]
        ipv6_types_dict[key] = value
with open('icmp_types.txt') as file:
    for line in file:
        line = line.strip()
        line_split = line.split()
        key = int(line_split[0])
        line_split.pop(0)
        line_end = " ".join(line_split)
        value = line_end
        icmp_types_dict[key] = value


