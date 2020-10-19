from utils import *

class IPv4:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.header_len = self.frame.bytes[self.offset : self.offset + 1]
        self.header_len = (bytes_str_hex(self.header_len))[1]
        self.header_len = int(self.header_len, 16) * 4

        self.total_len = self.frame.bytes[(offset+ 2) : (offset + 4)]

        self.header = self.frame.bytes[self.offset : (self.offset + self.header_len)]
        self.src = self.header[12:16]
        self.dst = self.header[16:20]

        self.embedded_protocol_type = self.frame.bytes[self.offset + 9 : self.offset + 10]
        #print("EMBEDDED PROTOCOL: "+ str(hex_str_to_int(bytes_str_hex(self.embedded_protocol))))
    def get_int_total_len(self):
        return hex_str_to_int(bytes_str_hex(self.total_len))
    def get_int_header_len(self):
        return self.header_len
    def get_int_embedded_protocol(self):
        return hex_str_to_int(bytes_str_hex(self.embedded_protocol_type))

class IPv6:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.next_header = frame.bytes[(offset + 6) : (offset + 7)]
        self.hop_limit = frame.bytes[(offset + 7): (offset + 8)]
        self.src = frame.bytes[(offset + 8) : (offset + 24)]
        self.dst = frame.bytes[(offset + 24) : (offset + 40)]
        self.header_len = 40

class ARP:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.hardware_address_type = frame.bytes[(offset) : (offset + 2)]
        self.protocol_address_type = frame.bytes[(offset + 2) : (offset + 4)]
        self.hw_addr_len = frame.bytes[(offset + 4) : (offset + 5)]
        self.prot_addr_len = frame.bytes[(offset + 5): (offset + 6)]
        self.operation = frame.bytes[(offset + 6) : (offset + 8)]

        self.hw_addr_len = hex_str_to_int(bytes_str_hex(self.hw_addr_len))
        self.prot_addr_len = hex_str_to_int(bytes_str_hex(self.prot_addr_len))

        self.source_hardware_address = frame.bytes[(offset + 8) : (offset + 8 + self.hw_addr_len)]
        self.source_protocol_address = frame.bytes[(offset + 14) : (offset + 14 + self.prot_addr_len)]

        self.target_hardware_address = frame.bytes[(offset + 18) : (offset + 18 + self.hw_addr_len)]
        self.target_protocol_address = frame.bytes[(offset + 24) : (offset + 24 + self.prot_addr_len)]

    def get_int_operation(self):
        return hex_str_to_int(bytes_str_hex(self.operation))

class TCP:
    def __init__(self, frame, offset, parent):
        self.frame = frame
        self.offset = offset
        self.parent = parent


        self.src_port = frame.bytes[offset : (offset + 2)]
        self.dst_port = frame.bytes[(offset + 2) : (offset + 4)]
        self.sequence_number = frame.bytes[(offset + 4) : (offset + 8)]
        self.acknowledgement_number = frame.bytes[(offset + 8) : (offset + 12)]

        self.flags = frame.bytes[(offset + 13) : (offset + 14)]

        self.header_len = frame.bytes[(offset + 12) : (offset + 13)]
        self.header_len = (bytes_str_hex(self.header_len))[0]
        self.header_len = int(self.header_len, 16) * 4

        self.tcp_payload_len = self.parent.get_int_total_len() - self.parent.get_int_header_len() - self.header_len
    def get_int_flags(self):
        return hex_str_to_int(bytes_str_hex(self.flags))
    def get_int_header_len(self):
        return self.header_len
    def get_int_src_port(self):
        return hex_str_to_int(bytes_str_hex(self.src_port))
    def get_int_dst_port(self):
        return hex_str_to_int(bytes_str_hex(self.dst_port))
    def get_int_sequence_number(self):
        return hex_str_to_int(bytes_str_hex(self.sequence_number))
    def get_int_acknowledgement_number(self):
        return hex_str_to_int(bytes_str_hex(self.acknowledgement_number))
    def get_embedded_protocol(self):
        if self.get_int_dst_port() in tcp_types_dict.keys():
            return self.get_int_dst_port()
        elif self.get_int_src_port() in tcp_types_dict.keys():
            return self.get_int_src_port()
        else:
            return None



class UDP:
    def __init__(self, frame, offset, parent):
        self.frame = frame
        self.offset = offset
        self.parent = parent

        self.src_port = frame.bytes[offset: (offset + 2)]
        self.dst_port = frame.bytes[(offset + 2): (offset + 4)]
        self.length = frame.bytes[(offset + 4): (offset + 8)]
        self.checksum = frame.bytes[(offset + 8): (offset + 12)]
        self.header_len = 8
    def get_int_src_port(self):
        return hex_str_to_int(bytes_str_hex(self.src_port))
    def get_int_dst_port(self):
        return hex_str_to_int(bytes_str_hex(self.dst_port))
    def get_int_length(self):
        return hex_str_to_int(bytes_str_hex(self.length))
    def get_int_header_len(self):
        return self.header_len
    def get_int_checksum(self):
        return hex_str_to_int(bytes_str_hex(self.checksum))
    def get_embedded_protocol(self):
        if self.get_int_src_port() in udp_types_dict.keys():
            return self.get_int_src_port()
        elif self.get_int_dst_port() in udp_types_dict.keys():
            return self.get_int_dst_port()
        else:
            return None


class HTTP:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.src = None
        self.dst = None

class HTTPS:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.src = None
        self.dst = None

class TELNET:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.src = None
        self.dst = None

class SSH:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.src = None
        self.dst = None

class FTP_DATA:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.src = None
        self.dst = None

class FTP_CONTROL:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.src = None
        self.dst = None


class TFTP:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.src = None
        self.dst = None

class ICMP:
    def __init__(self, frame, offset):
        self.frame = frame
        self.offset = offset

        self.type = frame.bytes[(offset) : (offset + 1)]
        self.code = frame.bytes[(offset + 1) : (offset + 2)]
        self.checksum = frame.bytes[(offset + 2) : (offset + 4)]
        self.other = frame.bytes[(offset + 4) : (offset + 8)]

        self.header_len = 8
    def get_int_type(self):
        return hex_str_to_int(bytes_str_hex(self.type))
    def get_int_checksum(self):
        return hex_str_to_int(bytes_str_hex(self.checksum))
    def get_int_code(self):
        return hex_str_to_int(bytes_str_hex(self.code))