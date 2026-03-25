from scapy.all import ARP, DNSRR, Raw
from storage import alerts

arp_table = {}

def detect(packet):
    # ARP Spoof
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_table and arp_table[ip] != mac:
            alerts.append(f"ARP Spoofing detected for {ip}")
        else:
            arp_table[ip] = mac

    # Credential Leak
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if "username" in payload or "password" in payload:
            alerts.append("Credential leak detected")

    # DNS Monitoring
    if packet.haslayer(DNSRR):
        dns = packet[DNSRR]
        alerts.append(f"DNS: {dns.rrname} -> {dns.rdata}")