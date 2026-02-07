from scapy.all import *
from threading import Thread
from maliciouse_rip.maliciouse_rip_sender import MalliciousRIPSender
from utils.utils import create_logger
import os

class FakeRouter:
    def __init__(self):
        super().__init__()
        self.logger = create_logger(self.__class__.__name__, level=logging.DEBUG)

    def start(self):
        self.logger.info("Starting fake router...")
        configuration_path = os.path.join(os.path.dirname(__file__), "conf", "rip_update.yaml")
        rip_sender = MalliciousRIPSender(configuration_path=configuration_path, logger=self.logger)
        rip_sender.start()
        rip_sender.join()

if __name__ == "__main__":
    fake_router = FakeRouter()
    fake_router.start()
