def classify_packet(packet):
    if packet.haslayer("TCP"):
        dport = packet["TCP"].dport

        # Video (YouTube, streaming)
        if dport in [443, 1935]:
            return "video"

        # Call (VoIP)
        if dport in [5060, 5061]:
            return "call"

        # Music (Spotify etc.)
        if dport in [80, 8080]:
            return "music"

    return "normal"