from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.rip import RIP, RIPEntry, RIPAuth
import argparse
import logging

def create_logger(name=__name__):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        formater = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formater)
        logger.addHandler(console_handler)
        return logger

class Sniffer:
    def __init__(self, interface, logger = None | logging.Logger):
        self.interface = interface
        self.logger = logger if logger else create_logger(self.__class__.__name__)

    def start(self):
        sniff(iface=self.interface, filter="udp port 520", prn=self.process_packet)

    def process_packet(self, packet):
        rip_packet = packet[RIP]
        self.logger.info(packet.summary())
        self.logger.info(rip_packet.show())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple packet sniffer using Scapy")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", default="eth0")

    args = parser.parse_args()

    print(f"Starting sniffer on interface: {args.interface}")

    sniffer = Sniffer(args.interface)
    sniffer.start()

