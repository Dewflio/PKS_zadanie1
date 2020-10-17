from utils import *

class IPv4:
    def __init__(self, frame, offset):
        self.frame = frame
        self.beginning_offset = offset

        self.header_len = self.frame.bytes[self.beginning_offset : self.beginning_offset + 1]
        self.header_len = (bytes_str_hex(self.header_len))[1]
        self.header_len = int(self.header_len, 16) * 4

        self.header = self.frame.bytes[self.beginning_offset : (self.beginning_offset + self.header_len)]
        self.src = self.header[12:16]
        self.dst = self.header[16:20]

        self.embedded_protocol = self.frame.bytes[self.beginning_offset + 9 : self.beginning_offset + 10]
        #print("EMBEDDED PROTOCOL: "+ str(hex_str_to_int(bytes_str_hex(self.embedded_protocol))))

class IPv6:
    def __init__(self, frame, offset):
        self.frame = frame
        self.src = None
        self.dst = None

class ARP:
    def __init__(self, frame, offset):
        self.frame = frame
        self.src = None
        self.dst = None
        self.type = None

class TCP:
    def __init__(self, frame):
        self.frame = frame
        self.src = None
        self.dst = None

class UDP:
    def __init__(self, frame):
        self.frame = frame
        self.src = None
        self.dst = None

class HTTP:
    def __init__(self, frame):
        self.frame = frame
        self.src = None
        self.dst = None

class HTTPS:
    def __init__(self, frame):
        self.frame = frame
        self.src = None
        self.dst = None

class TELNET:
    def __init__(self, frame):
        self.frame = frame
        self.src = None
        self.dst = None

class SSH:
    def __init__(self, frame):
        self.frame = frame
        self.src = None
        self.dst = None

class FTP:
    def __init__(self, frame):
        self.frame = frame
        self.src = None
        self.dst = None

class TFTP:
    def __init__(self, frame):
        self.frame = frame
        self.src = None
        self.dst = None

class ICMP:
    def __init__(self, frame):
        self.frame = frame
        self.src = None
        self.dst = None