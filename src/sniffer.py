from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.rip import RIP, RIPEntry, RIPAuth
from utils.utils import create_logger
import argparse
import logging

class Sniffer:
    def __init__(self, interface: str, logger: logging.Logger | None = None):
        self.interface = interface
        self.logger = logger if logger else create_logger(self.__class__.__name__, level=logging.DEBUG)

    def start(self):
        sniff(iface=self.interface, filter="udp port 520", prn=self.process_packet)

    def process_packet(self, packet: Packet):
        rip_packet: RIP = packet[RIP]
        self.logger.info(packet.summary())
        self.logger.debug(f"RIP packet:\n{rip_packet.show(dump=True)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple packet sniffer using Scapy")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", default="eth0")

    args = parser.parse_args()

    print(f"Starting sniffer on interface: {args.interface}")

    sniffer = Sniffer(args.interface)
    sniffer.start()

