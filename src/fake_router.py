from scapy.all import *
from threading import Thread
from maliciouse_rip.maliciouse_rip_sender import MalliciousRIPSender
from utils.utils import create_logger
import argparse, os

class FakeRouter:
    def __init__(self):
        super().__init__()
        self.logger = create_logger(self.__class__.__name__, level=logging.DEBUG)

    def start(self, configuration_path: str):
        self.logger.info("Starting fake router...")
        rip_sender = MalliciousRIPSender(configuration_path=configuration_path, logger=self.logger)
        rip_sender.start()
        rip_sender.join()

if __name__ == "__main__":
    arg_parse = argparse.ArgumentParser(description="Fake router that sends malicious RIP updates")
    arg_parse.add_argument(
        "--config",
        type=str,
        default=os.path.join(os.path.dirname(__file__), "conf", "rip_update.yaml"),
        help="Path to the configuration file for the fake router"
    )
    args = arg_parse.parse_args()

    fake_router = FakeRouter()
    fake_router.start(args.config)
