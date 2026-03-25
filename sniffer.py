from scapy.all import sniff
from state import is_running
from storage import packets
from detector import detect
from classifier import classify_packet

def process_packet(packet):
    category = classify_packet(packet)

    data = {
        "summary": packet.summary(),
        "category": category
    }

    packets.append(data)

    detect(packet)

def start_sniffing():
    global is_running
    is_running = True

    def stop_filter(x):
        return not is_running

    sniff(prn=process_packet, store=False, stop_filter=stop_filter)