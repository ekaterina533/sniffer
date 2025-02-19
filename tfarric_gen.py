import subprocess
import sys

def generate_traffic(protocol, sessions):
    if protocol.upper() == "UDP":
        cmd = f"iperf3 -c 127.0.0.1 -u -b 1M -t {sessions}"
    elif protocol.upper() == "TCP":
        cmd = f"iperf3 -c 127.0.0.1 -t {sessions}"
    elif protocol.upper() == "FTP":
        cmd = f"wget ftp://127.0.0.1/file"
    else:
        print("Неизвестный протокол")
        return
    subprocess.run(cmd, shell=True)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Использование: python traffic_gen.py <TCP/UDP/FTP> <количество сессий>")
        sys.exit(1)

    protocol = sys.argv[1]
    sessions = int(sys.argv[2])
    generate_traffic(protocol, sessions)
