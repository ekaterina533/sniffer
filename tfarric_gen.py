import subprocess
import sys

def generate_traffic(traffic_type, sessions, port=None):
    if traffic_type == "TCP":
        for _ in range(sessions):
            subprocess.run(["iperf3", "-c", "127.0.0.1", "-p", str(port) if port else "5201"])
    elif traffic_type == "UDP":
        for _ in range(sessions):
            subprocess.run(["iperf3", "-c", "127.0.0.1", "-u", "-p", str(port) if port else "5201"])
    elif traffic_type == "FTP":
        subprocess.run(["wget", "ftp://127.0.0.1"])
    else:
        print("Неверный тип трафика. Используйте TCP, UDP или FTP.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Использование: python traffic_generator.py <тип трафика> <количество сессий> [порт]")
        sys.exit(1)
    traffic_type = sys.argv[1]
    sessions = int(sys.argv[2])
    port = sys.argv[3] if len(sys.argv) > 3 else None
    generate_traffic(traffic_type, sessions, port)
