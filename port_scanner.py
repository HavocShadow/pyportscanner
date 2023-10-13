from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
ip = input("[+] Masukkan IP Anda : ")
target_ip = input("[+] Masukkan IP target : ")
while True:
    try:
        target_port = int(input("[+] Masukkan port : "))
        break
    except ValueError:
        print("Port harus berupa angka. Coba lagi.")

protocol_choice = input("[+] Pilih protokol (TCP/UDP/ICMP): ").upper()

if protocol_choice not in ['TCP', 'UDP', 'ICMP']:
    print('Protokol tidak valid. Pilih antara TCP, UDP, atau ICMP.')
    exit()

if protocol_choice == 'TCP':
    response = sr1(IP(dst=target_ip)/TCP(dport=target_port, flags="S"), timeout=1, verbose=0)
elif protocol_choice == 'UDP':
    response = sr1(IP(dst=target_ip)/UDP(dport=target_port), timeout=1, verbose=0)
elif protocol_choice == 'ICMP':
    response = sr1(IP(dst=target_ip)/ICMP(), timeout=1, verbose=0)

if response:
    if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        print(f'[+] Port {target_port} is opened')
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
        print(f'[+] Port {target_port} is closed')
else:
    print(f'[+] Port Unknown')

# Gunakan IP sebagai protokol default jika tidak ada pilihan lain
if protocol_choice == 'UDP':
    packets = IP(src=ip, dst=target_ip)/UDP(dport=target_port)
elif protocol_choice == 'ICMP':
    packets = IP(src=ip, dst=target_ip)/ICMP()
else:  # Default to TCP
    packets = IP(src=ip, dst=target_ip)/TCP(dport=target_port)

reply = sr1(packets, timeout=1, verbose=False)

if reply:
    print('[+] Packet successfully sent')
    reply.show()
else:
    print('[+] Packet failed to send')
