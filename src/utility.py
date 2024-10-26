import textwrap

class Utility:
    def __init__(self):
        pass    
    
    '''
    Return formated IP address (i.e 127.0.0.1)
    '''
    def format_ip(self, ipAddr):
        return ".".join(map(str, ipAddr))
    
    '''
    Return formatted MAC address (i.e AA:BB:CC:DD:EE:FF)
    '''
    def format_mac_addr(self, byteAddr):
        byteStr = map("{:02x}".format, byteAddr)
        mac_addr = ":".join(byteStr).upper()
        
        return mac_addr
    
    def format_multi_line(self, prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = "".join(r"\x{:02x}".format(byte) for byte in string)
            if size%2:
                size -= 1
                
        return "\n".join([prefix + line for line in textwrap.wrap(string, size)])