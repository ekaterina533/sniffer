import scapy.all as scapy
import threading
import queue
import time
import sys

# Очереди для передачи пакетов между сниффером и обработчиками
queue1 = queue.Queue()
queue2 = queue.Queue()
queue3 = queue.Queue()

# Функция для обработчика 1 (FTP-управление)
def handler1():
    while True:
        packet = queue1.get()
        if packet:
            scapy.wrpcap("ftp.pcap", packet, append=True)

# Функция для обработчика 2 (FTP-данные)
def handler2():
    while True:
        packet = queue2.get()
        if packet:
            scapy.wrpcap("ftp_data.pcap", packet, append=True)

# Функция для обработчика 3 (остальные пакеты)
def handler3():
    while True:
        packet = queue3.get()
        if packet:
            if packet.haslayer(scapy.UDP) and packet[scapy.UDP].sport in range(20000, 25001):
                print(f"Обработчик 3: {time.ctime()} пакет UDP {packet[scapy.IP].src}:{packet[scapy.UDP].sport} -> {packet[scapy.IP].dst}:{packet[scapy.UDP].dport} игнорируется")
            elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
                print(f"Обработчик 3: {time.ctime()} пакет TCP {packet[scapy.IP].src}:{packet[scapy.TCP].sport} -> {packet[scapy.IP].dst}:{packet[scapy.TCP].dport} инициирует соединение")
            else:
                scapy.wrpcap("other.pcap", packet, append=True)

# Функция для захвата пакетов
def packet_callback(packet):
    if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
        if packet[scapy.TCP].dport == 21 or packet[scapy.TCP].sport == 21:  # FTP-управление
            queue1.put(packet)
        elif packet[scapy.TCP].dport == 20 or packet[scapy.TCP].sport == 20:  # FTP-данные
            queue2.put(packet)
        else:
            queue3.put(packet)
    else:
        queue3.put(packet)

# Запуск обработчиков в отдельных потоках
threading.Thread(target=handler1, daemon=True).start()
threading.Thread(target=handler2, daemon=True).start()
threading.Thread(target=handler3, daemon=True).start()

# Запуск сниффера
def start_sniffing(interface):
    print(f"Запуск сниффера на интерфейсе {interface}...")
    scapy.sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python sniffer.py <интерфейс>")
        sys.exit(1)
    start_sniffing(sys.argv[1])