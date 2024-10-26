import socket
from time import sleep
from datetime import datetime
from src.unpack import Unpack
from src.utility import Utility
    
# Tab spaces
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t'
DATA_TAB_2 = '\t\t'
DATA_TAB_3 = '\t\t\t'
DATA_TAB_4 = '\t\t\t\t'
    
class Sniffer(Unpack, Utility):
    def __init__(self, keep_alive, write_log):
        '''
        True --> will show keep alive packets
        False --> wont show keep alive packets
        '''
        self.isKeepAlive = keep_alive
        self.writeLog = write_log
        
    def main(self):
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        if self.writeLog:
            fileHandle = open(f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt", "+a")
        
        if not(self.isKeepAlive):
            print("Capturing keep-alive packets turned off by default. Use --keep-alive to turn it on")
            sleep(1)
        
        try:
            while True:
                raw_data, addr = conn.recvfrom(65536)
                dest_mac, src_mac, protocol, data = super().ethernet_frame(raw_data)
                
                # Filtering the keep alive packets
                if dest_mac  == "00:00:00:00:00:00" and src_mac == "00:00:00:00:00:00":
                    if not(self.isKeepAlive):
                        continue
                
                print("\nEthernet Frame: ")
                print(f"{TAB_1}Destination: {dest_mac} \n{TAB_1}Source: {src_mac} \n{TAB_1}Protocol: {protocol}")
                
                # 8 for IPv4
                if protocol == 8:
                    version, headerLen, ttl, proto, src, target, data = super().ipv4_packet(data)
                    print(f"Protocol: {proto}")
                    
                    print(TAB_1 + "Ipv4 Packet: ")
                    print(TAB_2 + f"Version: {version}, Header Lenght: {headerLen}, TTL: {ttl}")
                    print(TAB_2 + f"Protocol: {proto}, Source: {src}, Target: {target}")
                    
                    if self.writeLog:
                        fileHandle.write(f"Ethernet Frame: \n Dest:{dest_mac} Src:{src_mac} Protocol:{protocol}\n")
                        fileHandle.write(f" Ipv4 Packet: \n\tVersion:{version} HeaderLen:{headerLen} TTL:{ttl} \n\tProtocol:{proto} Source:{src} Target:{target}\n")
                    
                    # 1 for ICMP
                    if proto == 1:
                        icmp_type, code, checksum, data = super().icmp_segment(data)
                        
                        print(TAB_1 + "ICMP Packet: ")
                        print(TAB_2 + f"Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                        print(TAB_2 + "Data: ")
                        ascii_output = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data)
                        print(super().format_multi_line(DATA_TAB_3, ascii_output))
                        
                        if self.writeLog:
                            fileHandle.write(f"ICMP Packet: \n\tType:{icmp_type} Code:{code} Checksum:{checksum}")
                            fileHandle.write(f"\tData: {ascii_output}\n\n")
                        
                    # 6 for TCP
                    elif proto == 6:
                        src_port, dest_port, seq, ack, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = super().tcp_segment(data)
                        
                        print(TAB_1 + "TCP Segment: ")
                        print(TAB_2 + f"Source Port: {src_port}, Destination Port: {dest_port}")
                        print(TAB_2 + f"Sequence: {seq}, Acknowledgment: {ack}")
                        print(TAB_2 + "Flags: ")
                        print(TAB_3 + f"URG:{flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}")
                        print(TAB_2 + "Data: ")
                        ascii_output = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data)
                        print(super().format_multi_line(DATA_TAB_3, ascii_output))
                        
                        if self.writeLog:
                            fileHandle.write(f" TCP Segment: \n\tSrc_Port:{src_port} Dest_Port:{dest_port} Seq:{seq} ACK:{ack}\n")
                            fileHandle.write(f"\tFlags: URG:{flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}")
                            fileHandle.write(f"\n\t Data: {ascii_output}\n\n")
                    
                    # 17 for UDP
                    elif proto == 17:
                        src_port, dest_port, size, data = super().udp_segment(data)
                        
                        print(TAB_1 + "UDP Segment: ")
                        print(TAB_2 + f"Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}")
                        ascii_output = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data)
                        print(super().format_multi_line(DATA_TAB_3, ascii_output))
                        
                        if self.writeLog:
                            fileHandle.write(f" UDP Segment: \n\tSrc_Port:{src_port} Dest_Port:{dest_port} Length:{size}")
                            fileHandle.write(f"\n\tData: {ascii_output}\n\n")
                    
                    # Other    
                    else:
                        print(TAB_1 + "Data: ")
                        ascii_output = ''.join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)
                        print(super().format_multi_line(DATA_TAB_2, ascii_output))
                        
                        if self.writeLog:
                            fileHandle.write(f"\tData: {ascii_output}\n\n")
        except KeyboardInterrupt:
            if self.writeLog:
                fileHandle.close()