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

def format_hex_adress(adress):
    tmp_str = ""
    for i in range(0, len(adress), 2):
        splice_str = adress[i:(i+2)]
        tmp_str += splice_str
        tmp_str += ":"
    tmp_str = tmp_str.strip(":")
    return tmp_str

def frame_get_len_medium(frame):
    l = len(frame)
    if l < 60:
        l = 64
    else:
        l += 4
    return l

def get_dst_mac(packet):
    dst_mac = packet[0:6]
    return dst_mac

def get_src_mac(packet):
    src_mac = packet[6:12]
    return src_mac

def get_eth_type_or_len(packet):
    ret_val = packet[12:14]
    return ret_val

def get_ieee_type(packet, ieee_types):
    ieee_3B = packet[14:17]
    str_ieee_3B = bytes_str_hex(ieee_3B)
    Byte_1 = str_ieee_3B[0:2]
    Byte_2 = str_ieee_3B[2:4]
    Byte_3 = str_ieee_3B[4:6]

    type = ieee_types[Byte_1]

    if Byte_1 == "ff" and Byte_2 == "ff":
        type = "IEEE 802.3 Raw - " + type
    elif Byte_1 == "aa" and Byte_2 == "aa":
        type = "IEEE 802.3 LLC, SNAP - " + type
    else:
        type = "IEE 802.3 LLC - " + type

    return type

def print_formated_packet(packet):
    count = 0
    print_str = ""
    str_packet = bytes_str_hex(packet)
    for i in range(0, len(str_packet), 2):
        print_str += str_packet[i] + str_packet[i+1]
        count += 1
        if count % 16 == 0:
            print_str += "\n"
        else:
            print_str += " "
            if count % 8 == 0:
                print_str += " "

    print(print_str)


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

print(ether_types_dict)
print(ieee_types_dict)

working_dir = "vzorky_pcap_na_analyzu/"
pcap_file = input("Enter the name of the file to be analysed: ")
packets = rdpcap_and_close(working_dir + pcap_file)
packets_arr = []
for i in range(len(packets)):
    packets_arr.append(bytes(packets[i]))


for i in range(len(packets_arr)):
    dst_mac = get_dst_mac(packets_arr[i])
    src_mac = get_src_mac(packets_arr[i])
    len_type = get_eth_type_or_len(packets_arr[i])

    str_dst_mac = bytes_str_hex(dst_mac)
    str_src_mac = bytes_str_hex(src_mac)
    str_len_type = bytes_str_hex(len_type)

    int_len_type = int(str_len_type, 16)
    frame_type = ""
    if (int_len_type >= 1500):
        frame_type = "Ethernet II - " + ether_types_dict[str_len_type]
    else:
        frame_type = get_ieee_type(packets_arr[i], ieee_types_dict)

    print("Frame Number: " + str(i + 1))
    print("Length: " + str(len(packets_arr[i])))
    print("Length on Medium: " + str(frame_get_len_medium(packets_arr[i])))
    print("Frame Type: " + frame_type)
    print("Dst MAC adress: " + format_hex_adress(str_dst_mac))
    print("Src MAC adress: " + format_hex_adress(str_src_mac))
    print_formated_packet(packets_arr[i])
    print("")




