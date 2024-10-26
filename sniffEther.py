from src.main import Sniffer
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Ethernet packet sniffer.")
    
    parser.add_argument("--keep-alive", default=False, action="store_true", help="Shows keep-alive packets")
    parser.add_argument("--write-log", default=False, action="store_true", help="Writes the captured packets in txt file")
    
    args = parser.parse_args()
    
    sniffer = Sniffer(args.keep_alive, args.write_log)
    sniffer.main()