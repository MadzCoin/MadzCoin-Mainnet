import threading

from src.core import rgbPrint
from src.web import runNode

rgbPrint("Starting Node...", "green")

if __name__ == "__main__":
    t1 = threading.Thread(target=runNode)
    t1.start()