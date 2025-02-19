from scapy.all import sniff, TCP, UDP, Raw, wrpcap
import threading
import queue
import time

ftp_queue = queue.Queue()
ftp_data_queue = queue.Queue()
other_queue = queue.Queue()

def packet_handler(paket):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load/decode(errors="ignore")

        ftp_commands = ["USER", "PASS", "RETR", "STOR", "LIST"]
        if any(cmd in payload for cmd in ftp_commands):
            ftp_queue.put(packet)
            return
        if packet[TCP].sport == 21 or packet[TCP].dport ==21:
            ftp_data_queue.put(packet)
            return
    if packet.haslayer(UDP):
        if 20000 <= packet[UDP].sport <=25000:
            print(f"Обработчик 3: {time.strftime('%H:%M:%S')} пакет UDP {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport} игнорируется")
            return

    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        print(f"Обработчик 3: {time.strftime('%H:%M:%S')} пакет TCP {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport} инициирует соединение")
        other_queue.put(packet)

def start_sniffer(interface):
    print(f"Сниффер запущен на интерфейсе {interface}")
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Использование: python sniffer.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]

    threading.Thread(target=start_sniffer, args=(interface,), daemon=True).start()

    from handlers import start_handlers
    start_handlers()