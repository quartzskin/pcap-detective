import logging

__version__ = "0.1.0"

# scapy logs about missing libpcap on import; we only read files
logging.getLogger("scapy").setLevel(logging.ERROR)
