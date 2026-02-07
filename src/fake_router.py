from scapy.all import *
from threading import Thread
from maliciouse_rip.maliciouse_rip_sender import MalliciousRIPSender
from utils.utils import create_logger

class FakeRouter:
    def __init__(self):
        super().__init__()
        self.logger = create_logger(self.__class__.__name__)

    def start(self):
        self.logger.info("Starting fake router...")
        rip_sender = MalliciousRIPSender(configuration_path="path/to/config")
        rip_sender.start()
        rip_sender.join()

if __name__ == "__main__":
    fake_router = FakeRouter()
    fake_router.start()
