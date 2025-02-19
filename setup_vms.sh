#!/bin/bash

echo "Настройка сети..."
echo "1" > /proc/sys/net/ipv4/ip_forward

# Поднятие интерфейсов
ip link set dev eth1 up
ip addr add 192.168.1.1/24 dev eth1

# Установка FTP-сервера
apt update && apt install -y vsftpd
systemctl start vsftpd
