from scapy.all import *
from utils import *
from protocols import *

class Frame:
    def __init__(self, num, bytes):
        # int
        self.num = num
        # bytes - all bytes of the frame
        self.bytes = bytes

        # bytes converted to hex string (2 characters = 1 byte)
        self.bytes_str = bytes_str_hex(self.bytes)
        # int - length of frame in bytes
        self.len = len(self.bytes)
        # int - lenght of frame on medium
        self.len_on_medium = self.get_len_medium()

        # bytes
        self.dst_mac = self.get_dst_mac()
        # bytes
        self.src_mac = self.get_src_mac()

        # bytes
        self.len_type = self.get_len_type()
        # int - len_type converted to int
        self.inside_len = hex_str_to_int(bytes_str_hex(self.len_type))
        # string - type of the frame
        self.frame_type = self.get_frame_type()
        self.frame_sub_type = self.get_frame_sub_type()

    def get_dst_mac(self):
        return self.bytes[0:6]
    def get_src_mac(self):
        return self.bytes[6:12]
    def get_len_type(self):
        return self.bytes[12:14]
    def get_frame_type(self):
        if self.inside_len >= 512:
            return "Ethernet II"
        else:
            ieee_3B = self.bytes[14:17]
            str_ieee_3B = bytes_str_hex(ieee_3B)
            Byte_1 = str_ieee_3B[0:2]
            Byte_2 = str_ieee_3B[2:4]
            Byte_3 = str_ieee_3B[4:6]
            type = ""

            if Byte_1 == "ff" and Byte_2 == "ff":
                type = "IEEE 802.3 Raw"
            elif Byte_1 == "aa" and Byte_2 == "aa":
                type = "IEEE 802.3 LLC, SNAP"
            else:
                type = "IEE 802.3 LLC"
            return type
    def get_frame_sub_type(self):
        if self.inside_len >= 512:
            str_type = bytes_str_hex(self.len_type)
            return ether_types_dict[str_type]
        else:
            ieee_3B = self.bytes[14:17]
            ieee_3B_str = bytes_str_hex(ieee_3B)
            Byte_1 = ieee_3B_str[0:2]
            Byte_2 = ieee_3B_str[2:4]
            return ieee_types_dict[Byte_2]
    def get_ether2_byte2(self):
        ieee_3B = self.bytes[14:17]
        ieee_3B_str = bytes_str_hex(ieee_3B)
        Byte_2 = ieee_3B_str[2:4]
        return Byte_2


    def get_len_medium(self):
        l = self.len
        if l < 60:
            l = 64
        else:
            l += 4
        return l

class Printer:
    def __init__(self):
        pass
    def print_formatted_packet(self, frame):
        count = 0
        print_str = ""
        str_packet = frame.bytes_str
        for i in range(0, len(str_packet), 2):
            print_str += str_packet[i] + str_packet[i + 1]
            count += 1
            if count % 16 == 0:
                print_str += "\n"
            else:
                print_str += " "
                if count % 8 == 0:
                    print_str += " "
        print(print_str)
    def print_formatted_dst_mac(self, frame):
        formatted_dst_mac = format_hex_adress(frame.dst_mac)
        print("Dst MAC: " + formatted_dst_mac)
    def print_formatted_src_mac(self, frame):
        formatted_src_mac = format_hex_adress(frame.src_mac)
        print("Src MAC: " + formatted_src_mac)
    def print_frame_number(self, frame):
        print("Frame #: " + str(frame.num))
    def print_frame_length(self, frame):
        print("Length: " + str(frame.len))
    def print_frame_length_medium(self, frame):
        print("Length on Medium: " + str(frame.len_on_medium))
    def print_frame_type(self, frame):
        print("Frame Type: " + frame.frame_type)
    def print_frame_sub_type(self,frame):
        if frame.inside_len < 512:
            print("Frame (Sub) Type: " + frame.frame_sub_type)
        else:
            print("Embedded protocol: " + frame.frame_sub_type)
    def print_frame_payload_len(self, frame):
        if frame.inside_len < 512:
            print("Length of Payload: " + str(frame.inside_len))
    def print_point_3(self, dict):
        print("IPv4 destination addresses:")
        most = 0
        max_address = None
        for i in dict.keys():
            print("\t" + format_dec_adress(i))
            if dict[i] > most:
                most = dict[i]
                max_address = i
        print("IPv4 address that received the most packets:")
        print("\t" + format_dec_adress(max_address) + " received " + str(dict[max_address]) + " packets")



class Communications:
    def __init__(self):
        self.IPv4_packets = []
        self.IPv6_packets = []
        self.ARP_packets = []
        self.HTTP_packets = []



working_dir = "vzorky_pcap_na_analyzu/"
pcap_file = input("Enter the name of the file to be analysed: ")
packets = rdpcap_and_close(working_dir + pcap_file)
frames = []
printer = Printer()
comms = Communications()

for i in range(len(packets)):
    frames.append(Frame((i+1), bytes(packets[i])))
    printer.print_frame_number(frames[-1])
    printer.print_frame_type(frames[-1])
    printer.print_frame_sub_type(frames[-1])
    printer.print_frame_payload_len(frames[-1])
    printer.print_frame_length(frames[-1])
    printer.print_frame_length_medium(frames[-1])
    printer.print_formatted_dst_mac(frames[-1])
    printer.print_formatted_src_mac(frames[-1])
    printer.print_formatted_packet(frames[-1])
    print("")

    if frames[-1].inside_len >= 512:
        type = frames[-1].len_type
        type = bytes_str_hex(type)

        if type == "0800":
            # IPv4
            new_head = IPv4(frames[-1], 14)
            comms.IPv4_packets.append(new_head)
        elif type == "86dd":
            # IPv6
            new_head = IPv6(frames[-1], 14)
            comms.IPv6_packets.append(new_head)
        elif type == "0806":
            # ARP
            new_head = ARP(frames[-1], 14)
            comms.ARP_packets.append(new_head)

#bod 3 - pocet primacich ipv4 adries
ipv4_recievers = {}
for i in comms.IPv4_packets:
    if i.dst not in ipv4_recievers.keys():
        ipv4_recievers[i.dst] = 1
    else:
        ipv4_recievers[i.dst] += 1
printer.print_point_3(ipv4_recievers)

#bod 3 - prejde vsetky ipv4 packety, zisti ake maju embeddnute protokoly a prida ich do comms
for i in comms.IPv4_packets:
    ipv4_emb_type = i.embedded_protocol
    ipv4_emb_type = hex_str_to_int(bytes_str_hex(ipv4_emb_type))
    print(ipv4_types_dict[ipv4_emb_type])


