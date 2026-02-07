from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.rip import RIP, RIPEntry, RIPAuth
from utils.utils import create_logger
import argparse
import logging

class Sniffer:
    def __init__(self, interface, logger: logging.Logger | None = None):
        self.interface = interface
        self.logger = logger if logger else create_logger(self.__class__.__name__)

    def start(self):
        sniff(iface=self.interface, filter="udp port 520", prn=self.process_packet)

    def process_packet(self, packet):
        rip_packet = packet[RIP]
        self.logger.info(packet.summary())
        self.logger.debug(rip_packet.show())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple packet sniffer using Scapy")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", default="eth0")

    args = parser.parse_args()

    print(f"Starting sniffer on interface: {args.interface}")

    sniffer = Sniffer(args.interface)
    sniffer.start()

