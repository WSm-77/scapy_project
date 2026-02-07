from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.rip import RIP, RIPEntry, RIPAuth
import argparse

class Sniffer:
    def __init__(self, interface):
        self.interface = interface

    def start(self):
        # sniff(iface=self.interface, filter="icmp or icmp6 or rip", prn=self.process_packet)
        sniff(iface=self.interface, filter="udp port 520", prn=self.process_packet)
        # sniff(iface=self.interface, prn=self.process_packet)

    def process_packet(self, packet):
        # print(packet.show())
        print(packet.summary())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple packet sniffer using Scapy")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", default="eth0")

    args = parser.parse_args()

    print(f"Starting sniffer on interface: {args.interface}")

    sniffer = Sniffer(args.interface)
    sniffer.start()

