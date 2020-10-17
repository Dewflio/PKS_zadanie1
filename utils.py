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

#load type dictionaries for ethernet II, LLC
ether_types_dict = {}
ieee_types_dict = {}
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
