import struct
import socket
from src.utility import Utility

    
class Unpack(Utility):
    def __init__(self):
        pass
    
    '''
    Unpack ethernet first 14bytes of frame 
    Returns destination and source mac, protocol and payload
    '''
    def ethernet_frame(self, dataFrame):
        dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", dataFrame[:14])
        
        return super().format_mac_addr(dest_mac), super().format_mac_addr(src_mac), socket.htons(proto), dataFrame[14:] 
    
    '''
    Unpacks ipv4 packet
    Returns Version, HeaderLen, TTL, Protocol, Source & Dest Address and payload
    '''
    def ipv4_packet(self, data):
        version_HeaderLen = data[0]
        
        # Bitshift 4 towards right
        version = version_HeaderLen >> 4
        headerLen = (version_HeaderLen & 15) * 4
        
        ttl, protocol, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
        
        return version, headerLen, ttl, protocol, super().format_ip(src), super().format_ip(target), data[headerLen:] 
    
    '''
    Unpacks ICMP packet
    Returns ICMP Type, Code, Checksum and payload
    '''
    def icmp_segment(self, data):
        icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
        
        return icmp_type, code, checksum, data[4:]
    
    '''
    Unpacks TCP Packet
    Returns Source & Dest Port, Sequence, Acknowledgment, Offset, Reserved, Flags and payload
    '''
    def tcp_segment(self, data):
        src_port, dest_port, seq, ack, offsetResFlag = struct.unpack("! H H L L H", data[:14])
        
        # Bitshift to right by 12
        offset = (offsetResFlag >> 12) * 4
        
        flag_urg = (offsetResFlag & 32) >> 5
        flag_ack = (offsetResFlag & 16) >> 4
        flag_psh = (offsetResFlag & 8) >> 3
        flag_rst = (offsetResFlag & 4) >> 2
        flag_syn = (offsetResFlag & 2) >> 1
        flag_fin = offsetResFlag & 1
        
        return src_port, dest_port, seq, ack, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    
    '''
    Unpacks UDP Packet
    Returns Source & Dest Port, size and payload
    '''
    def udp_segment(self, data):
        src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
        
        return src_port, dest_port, size, data[8:]