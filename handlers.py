import threading
import queue
import time
from scapy.all import wrpcap

from sniffer import ftp_queue, ftp_data_queue, other_queue

def ftp_handler():
    packets = []
    while True:
        packet = ftp_queue.get()
        packets.append(packet)
        if len(packets) >= 10:
            wrpcap("ftp.pcap", packets)
            packets = []

def ftp_data_handler():
    packets = []
    while True:
        packet = ftp_data_queue.get()
        packets.append(packet)
        if len(packets) >= 10:
            wrpcap("ftp_data.pcap", packets)
            packets = []

def other_handler():
    packets = []
    while True:
        packet = other_queue.get()
        packets.append(packet)
        if len(packets) >= 10:
            wrpcap("other.pcap", packets)
            packets = []

def start_handlers():
    threading.Thread(target=ftp_handler, daemon=True).start()
    threading.Thread(target=ftp_data_handler, daemon=True).start()
    threading.Thread(target=other_handler, daemon=True).start()