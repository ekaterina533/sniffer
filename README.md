# sniffer
# Сниффер и распределитель данных

## Описание
Программа «Сниффер и распределитель данных» предназначена для перехвата сетевого трафика и его распределения по различным обработчикам в зависимости от типа трафика (FTP, TCP, UDP). Программа записывает перехваченные пакеты в соответствующие файлы:
- `ftp.pcap` — пакеты FTP control трафика.
- `ftp_data.pcap` — пакеты FTP data трафика.
- `other.pcap` — остальные пакеты.

## Требования
- Python 3.6 или выше.

## Тестовая среда
Программа тестировалась на двух виртуальных машинах (ВМ), развернутых в VMware:
- **Gen (Генератор трафика)**: Используется для генерации TCP, UDP и FTP трафика.
- **Obj (Объект тестирования)**: На этой машине запускается сниффер для анализа трафика.
- Ссылка на диск с виртуальными машинами: https://drive.google.com/drive/folders/1MwJ-4uOZ_QUNVvMgAXoVR0RS39pOz0vP?usp=sharing 

**Важно**:
- Файлы для запуска программы находятся в директории `/home/sniffer`.
- Пароль суперпользователя (root) на обеих виртуальных машинах: `Pa$$w0rd`.
