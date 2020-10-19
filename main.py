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

        self.is_in_IPv4 = False
        self.is_in_IPv6 = False
        self.is_in_ARP = False
        self.is_in_TCP = False
        self.is_in_UDP = False
        self.is_in_ICMP = False
        self.is_in_HTTP = False
        self.is_in_FTP_DATA = False
        self.is_in_FTP_CONTROL = False
        self.is_in_SSH = False
        self.is_in_TELNET = False
        self.is_in_HTTPS = False
        self.is_in_TFTP = False

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
            print("Embedded Protocol: " + frame.frame_sub_type)
    def print_frame_payload_len(self, frame):
        if frame.inside_len < 512:
            print("Payload Len: " + str(frame.inside_len))
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
        print("")
    def print_frame_all(self, frame, print_data = True):
        self.print_frame_number(frame)
        self.print_frame_type(frame)
        self.print_frame_length(frame)
        self.print_frame_length_medium(frame)
        self.print_frame_payload_len(frame)
        self.print_formatted_dst_mac(frame)
        self.print_formatted_src_mac(frame)
        self.print_frame_sub_type(frame)

        if frame.is_in_IPv4:
            ipv4_src = frame.is_in_IPv4.src
            ipv4_dst = frame.is_in_IPv4.dst
            ipv4_src = format_dec_adress(ipv4_src)
            ipv4_dst = format_dec_adress(ipv4_dst)
            print("IPv4 src: " + ipv4_src)
            print("IPv4 dst: " + ipv4_dst)
            emb = frame.is_in_IPv4.get_int_embedded_protocol()
            if emb in ipv4_types_dict.keys():
                print("Embedded Protocol: " + ipv4_types_dict[emb])

        if frame.is_in_TCP:
            tcp_src_port = frame.is_in_TCP.get_int_src_port()
            tcp_dst_port = frame.is_in_TCP.get_int_dst_port()
            print("TCP src port: " + str(tcp_src_port))
            print("TCP dst port: " + str(tcp_dst_port))
            emb = frame.is_in_TCP.get_embedded_protocol()
            if emb != None:
                print("Embedded Protocol: " + tcp_types_dict[emb])
        elif frame.is_in_UDP:
            udp_src_port = frame.is_in_UDP.get_int_src_port()
            udp_dst_port = frame.is_in_UDP.get_int_dst_port()
            print("UDP src port: " + str(udp_src_port))
            print("UDP dst port: " + str(udp_dst_port))
            emb = frame.is_in_UDP.get_embedded_protocol()
            if emb != None:
                print("Embedded Protocol: " + udp_types_dict[emb])
        elif frame.is_in_ARP:
            arp_op = frame.is_in_ARP.get_int_operation()
            op_string = ""
            if arp_op == 1:
                op_string = "request"
            elif arp_op == 2:
                op_string = "reply"
            print("Opcode: " + op_string + " (" + str(arp_op) + ")")

            print("Src MAC: " + format_hex_adress(frame.is_in_ARP.source_hardware_address))
            print("Src IP:  " + format_dec_adress(frame.is_in_ARP.source_protocol_address))

            print("Target MAC: " + format_hex_adress(frame.is_in_ARP.target_hardware_address))
            print("Target IP:  " + format_dec_adress(frame.is_in_ARP.target_protocol_address))
        if frame.is_in_ICMP:
            icmp_type = frame.is_in_ICMP.get_int_type()
            str_type = ""
            if icmp_type in icmp_types_dict.keys():
                str_type = icmp_types_dict[icmp_type] + " "
            print("Type: " + str_type + "(" + str(icmp_type) + ")")



        if print_data == True:
            self.print_formatted_packet(frame)
        print("")

class ARP_tuple:
    def __init__(self, packet1):
        self.packet1 = packet1
        self.packet2 = None
    def set_packet2(self, packet):
        self.packet2 = packet
    def is_packet2_set(self):
        if self.packet2 == None:
            return False
        else:
            return True


class Comm:
    def __init__(self, ip1, ip2):
        self.ip1 = ip1
        self.ip2 = ip2
        self.packets = []
        self.is_finished = False
        self.last_fin_packet = None
        self.last_fin_packet_type = 0

    def do_ips_match(self, ip1, ip2):
        if (self.ip1 == ip1 and self.ip2 == ip2) or (self.ip1 == ip2 and self.ip2 == ip1):
            return True
        else:
            return False
    def is_frame_in_packets(self, frame):
        for i in self.packets:
            if i.frame == frame:
                return True
        return False


class Communications:
    def __init__(self):
        self.IPv4_packets = []
        self.IPv6_packets = []
        self.ARP_packets = []

        #protocols in IPv4 headers
        self.TCP_packets = []
        self.UDP_packets = []
        self.ICMP_packets = []

        #protocols in TCP headers
        self.HTTP_packets = []
        self.FTP_DATA_packets = []
        self.FTP_CONTROL_packets = []
        self.SSH_packets = []
        self.TELNET_packets = []
        self.HTTPS_packets = []

        #protocols in UDP headers
        self.TFTP_packets = []

        self.COMs = []

        self.complete_COMs = []
        self.incomplete_COMs = []
    def separate_comms(self):
        for i in self.COMs:
            if i.is_finished:
                self.complete_COMs.append(i)
            else:
                self.incomplete_COMs.append(i)

    def analyse_tcps(self):
        for i in self.TCP_packets:
            src_ip = i.parent.src
            dst_ip = i.parent.dst
            is_added = False
            flags = i.get_int_flags()
            for c in self.COMs:
                if c.do_ips_match(src_ip, dst_ip) and c.is_finished == False:
                    c.packets.append(i)
                    is_added = True
                    if is_rst_true(flags):
                        c.last_fin_packet = i
                        c.last_fin_packet_type = 4
                        c.is_finished = True
                    elif is_fin_true(flags) and c.last_fin_packet == None:
                        c.last_fin_packet = i
                        c.last_fin_packet_type = 1
                    elif is_fin_true(flags) and c.last_fin_packet_type == 1:
                        last_src = c.last_fin_packet.parent.src
                        last_dst = c.last_fin_packet.parent.dst
                        if is_ack_true(flags) and last_dst == src_ip and last_src == dst_ip:
                            c.last_fin_packet = i
                            c.last_fin_packet_type = 2
                    elif is_ack_true(flags) and c.last_fin_packet_type == 2:
                        last_src = c.last_fin_packet.parent.src
                        last_dst = c.last_fin_packet.parent.dst
                        if last_dst == src_ip and last_src == dst_ip:
                            c.last_fin_packet = i
                            c.last_fin_packet_type = 3
                            c.is_finished = True



            if is_added == False:
                new_c = Comm(src_ip, dst_ip)
                self.COMs.append(new_c)






working_dir = "vzorky_pcap_na_analyzu/"
pcap_file = input("Enter the name of the file to be analysed: ")
packets = rdpcap_and_close(working_dir + pcap_file)
frames = []
printer = Printer()
comms = Communications()

for i in range(len(packets)):
    frames.append(Frame((i+1), bytes(packets[i])))
    if frames[-1].inside_len >= 512:
        type = frames[-1].len_type
        type = bytes_str_hex(type)
        if type == "0800":
            # IPv4
            new_head = IPv4(frames[-1], 14)
            frames[-1].is_in_IPv4 = new_head
            comms.IPv4_packets.append(new_head)
        elif type == "86dd":
            # IPv6
            new_head = IPv6(frames[-1], 14)
            frames[-1].is_in_IPv6 = new_head
            comms.IPv6_packets.append(new_head)
        elif type == "0806":
            # ARP
            new_head = ARP(frames[-1], 14)
            frames[-1].is_in_ARP = new_head
            comms.ARP_packets.append(new_head)


#bod 3 - prejde vsetky ipv4 packety, zisti ake maju embeddnute protokoly a prida ich do comms
for i in comms.IPv4_packets:
    ipv4_emb_type = i.embedded_protocol_type
    ipv4_emb_type = hex_str_to_int(bytes_str_hex(ipv4_emb_type))
    if ipv4_emb_type == 6:
        new_head = TCP(i.frame, i.offset + i.header_len, i)
        i.frame.is_in_TCP = new_head
        comms.TCP_packets.append(new_head)
    elif ipv4_emb_type == 17:
        new_head = UDP(i.frame, i.offset + i.header_len, i)
        i.frame.is_in_UDP = new_head
        comms.UDP_packets.append(new_head)
    elif ipv4_emb_type == 1:
        new_head = ICMP(i.frame, i.offset + i.header_len)
        i.frame.is_in_ICMP = new_head
        comms.ICMP_packets.append(new_head)

for i in comms.TCP_packets:
    TCP_emb_type = i.get_embedded_protocol()
    if (i.tcp_payload_len >  0):
        if TCP_emb_type == 20:
            new_head = FTP_DATA(i.frame, i.offset + i.header_len)
            i.frame.is_in_FTP_DATA = new_head
            comms.FTP_DATA_packets.append(new_head)
            print("AHA")
        elif TCP_emb_type == 21:
            new_head = FTP_CONTROL(i.frame, i.offset + i.header_len)
            i.frame.is_in_FTP_CONTROL = new_head
            comms.FTP_CONTROL_packets.append(new_head)
        elif TCP_emb_type == 22:
            new_head = SSH(i.frame, i.offset + i.header_len)
            i.frame.is_in_SSH = new_head
            comms.SSH_packets.append(new_head)
        elif TCP_emb_type == 23:
            new_head = TELNET(i.frame, i.offset + i.header_len)
            i.frame.is_in_TELNET = new_head
            comms.TELNET_packets.append(new_head)
        elif TCP_emb_type == 80:
            new_head = HTTP(i.frame, i.offset + i.header_len)
            i.frame.is_in_HTTP = new_head
            comms.HTTP_packets.append(new_head)
        elif TCP_emb_type == 443:
            new_head = HTTPS(i.frame, i.offset + i.header_len)
            i.frame.is_in_HTTPS = new_head
            comms.HTTPS_packets.append(new_head)

TFTP_server_IP = False
TFTP_server_port = False
TFTP_my_port = False
for i in comms.UDP_packets:
    UDP_emb_type = i.get_embedded_protocol()
    if (i.get_int_length() - i.get_int_header_len() > 0):
        if UDP_emb_type == 69:
            new_head = TFTP(i.frame, i.offset + i.get_int_header_len())
            i.frame.is_in_TFTP = new_head
            comms.TFTP_packets.append(new_head)
            TFTP_server_IP = bytes_str_hex(i.parent.dst)
            TFTP_my_port = i.get_int_src_port()

        elif (TFTP_server_IP != False) and (bytes_str_hex(i.parent.src) == TFTP_server_IP) and (i.get_int_dst_port() == TFTP_my_port):
            new_head = TFTP(i.frame, i.offset + i.get_int_header_len())
            i.frame.is_in_TFTP = new_head
            comms.TFTP_packets.append(new_head)
            TFTP_server_port = i.get_int_src_port()
        elif (TFTP_server_port == i.get_int_src_port() and TFTP_my_port == i.get_int_dst_port()) or (TFTP_server_port == i.get_int_dst_port() and TFTP_my_port == i.get_int_src_port()):
            new_head = TFTP(i.frame, i.offset + i.get_int_header_len())
            i.frame.is_in_TFTP = new_head
            comms.TFTP_packets.append(new_head)


for frame in frames:
    printer.print_frame_all(frame)


#bod 3 - pocet primacich ipv4 adries
ipv4_recievers = {}
for i in comms.IPv4_packets:
    if i.dst not in ipv4_recievers.keys():
        ipv4_recievers[i.dst] = 1
    else:
        ipv4_recievers[i.dst] += 1
printer.print_point_3(ipv4_recievers)


comms.analyse_tcps()
comms.separate_comms()
print("Complete Communications: " + str(len(comms.complete_COMs)) + " Incomplete Communications: " + str(len(comms.incomplete_COMs)))

while 1==1:
    print("Protocols to choose from: HTTP, HTTPS, TELNET, SSH, FTP_CONTROL, FTP_DATA, TFTP, ICMP, ARP")
    which_comm_to_display = input("Enter the name of the protocol to display: ")

    while 1 == 1:
        x = input("Do you want the packet data to be displayed? (y/n)")
        if x == 'y' or x == 'n' or x == 'Y' or x == 'N':
            break

    print_data_bool = False
    if x == 'y' or x == 'Y':
        print_data_bool = True

    numbers = []
    if which_comm_to_display == "HTTP":
        for i in comms.HTTP_packets:
            printer.print_frame_all(i.frame, print_data = print_data_bool)
            numbers.append(i.frame.num)

    elif which_comm_to_display == "HTTPS":
        for i in comms.HTTPS_packets:
            printer.print_frame_all(i.frame, print_data = print_data_bool)
            numbers.append(i.frame.num)
    elif which_comm_to_display == "TELNET":
        for i in comms.TELNET_packets:
            printer.print_frame_all(i.frame, print_data = print_data_bool)
            numbers.append(i.frame.num)
    elif which_comm_to_display == "SSH":
        for i in comms.SSH_packets:
            printer.print_frame_all(i.frame, print_data = print_data_bool)
            numbers.append(i.frame.num)
    elif which_comm_to_display == "FTP_CONTROL":
        for i in comms.FTP_CONTROL_packets:
            printer.print_frame_all(i.frame, print_data = print_data_bool)
            numbers.append(i.frame.num)
    elif which_comm_to_display == "FTP_DATA":
        for i in comms.FTP_DATA_packets:
            printer.print_frame_all(i.frame, print_data = print_data_bool)
            numbers.append(i.frame.num)

    elif which_comm_to_display == "TFTP":
        for i in comms.TFTP_packets:
            printer.print_frame_all(i.frame, print_data = print_data_bool)
            numbers.append(i.frame.num)
    elif which_comm_to_display == "ICMP":
        for i in comms.ICMP_packets:
            printer.print_frame_all(i.frame, print_data = print_data_bool)
            numbers.append(i.frame.num)
    elif which_comm_to_display == "ARP":
        arp_tuples = []
        for i in comms.ARP_packets:
            printer.print_frame_all(i.frame, print_data = print_data_bool)
            numbers.append(i.frame.num)

            if i.get_int_operation() == 2:
                added = False
                for u in range(len(arp_tuples) -1 , -1 , -1):
                    if arp_tuples[u].is_packet2_set() == False:
                        src_hw = i.source_hardware_address
                        src_pr = i.source_protocol_address
                        dst_hw = i.target_hardware_address
                        dst_pr = i.target_protocol_address
                        if arp_tuples[u].packet1.source_hardware_address == dst_hw:
                            added = True
                            arp_tuples[u].set_packet2(i)
                            break

            elif i.get_int_operation() == 1:
                arp_tuples.append(ARP_tuple(i))

        print("ARP PAIRS (frame numbers):")
        for i in arp_tuples:
            if i.is_packet2_set():
                print(i.packet1.frame.num, i.packet2.frame.num)



    print("Number of packets: " + str(len(numbers)))
    print("Numbers of frames with the corresponding protocol: ")
    print(numbers)
    print("")


