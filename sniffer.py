import scapy.all as scapy
import threading
import queue
import time
import sys

# Очереди для передачи данных между сниффером и обработчиками
queue1 = queue.Queue()
queue2 = queue.Queue()
queue3 = queue.Queue()

# Функция для обработчика 1 (FTP control traffic)
def handler1():
    with open("ftp.pcap", "wb") as f:
        while True:
            packet = queue1.get()
            if packet is None:
                break
            scapy.wrpcap(f, packet, append=True)

# Функция для обработчика 2 (FTP data traffic)
def handler2():
    with open("ftp_data.pcap", "wb") as f:
        while True:
            packet = queue2.get()
            if packet is None:
                break
            scapy.wrpcap(f, packet, append=True)

# Функция для обработчика 3 (Other traffic)
def handler3():
    with open("other.pcap", "wb") as f:
        while True:
            packet = queue3.get()
            if packet is None:
                break
            # Дополнительное задание: обработка UDP и TCP SYN пакетов
            if packet.haslayer(scapy.UDP) and packet[scapy.UDP].sport in range(20000, 25001):
                print(f"Обработчик 3: {time.ctime()} пакет UDP {packet[scapy.IP].src}:{packet[scapy.UDP].sport} -> {packet[scapy.IP].dst}:{packet[scapy.UDP].dport} игнорируется")
            elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
                print(f"Обработчик 3: {time.ctime()} пакет TCP {packet[scapy.IP].src}:{packet[scapy.TCP].sport} -> {packet[scapy.IP].dst}:{packet[scapy.TCP].dport} инициирует соединение")
            else:
                scapy.wrpcap(f, packet, append=True)

# Функция для сниффера
def packet_sniffer(interface):
    def packet_callback(packet):
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            # Проверяем, является ли пакет частью FTP control соединения
            if packet[scapy.TCP].dport == 21 or packet[scapy.TCP].sport == 21:
                queue1.put(packet)
            # Проверяем, является ли пакет частью FTP data соединения
            elif packet[scapy.TCP].dport == 20 or packet[scapy.TCP].sport == 20:
                queue2.put(packet)
            else:
                queue3.put(packet)
        else:
            queue3.put(packet)

    scapy.sniff(iface=interface, prn=packet_callback, store=False)

# Запуск обработчиков в отдельных потоках
threading.Thread(target=handler1, daemon=True).start()
threading.Thread(target=handler2, daemon=True).start()
threading.Thread(target=handler3, daemon=True).start()

# Запуск сниффера
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python sniffer.py <интерфейс>")
        sys.exit(1)
    
    interface = sys.argv[1]
    packet_sniffer(interface)