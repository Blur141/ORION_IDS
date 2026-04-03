# ============================================================
# classifier.py — Traffic Category Classifier
# ============================================================
# Looks at a packet and decides: is this video, music, or
# normal browsing? Uses port numbers as clues.
#
# HOW PORT CLASSIFICATION WORKS:
#   Every network service runs on a "port" — a numbered door.
#   Example: web traffic uses port 80 or 443.
#   Video streams use specific ports too.
#   We use these port numbers as hints to classify traffic.
# ============================================================

# -----------------------------------------------------------
# Port-to-category mappings
# -----------------------------------------------------------

# Common ports used by video streaming services
VIDEO_PORTS = {
    1935,   # RTMP (live streaming protocol used by YouTube, Twitch)
    554,    # RTSP (real-time streaming protocol)
    8554,   # RTSP alternate
    8080,   # HTTP alternate (some video CDNs)
    1755,   # MMS (Microsoft Media Server)
}

# Common ports used by music/audio streaming
MUSIC_PORTS = {
    4070,   # Spotify
    57621,  # Spotify local discovery
    8883,   # MQTT (used by some audio apps)
}

# Common DNS/HTTP/HTTPS ports — regular browsing
BROWSING_PORTS = {
    80,     # HTTP
    443,    # HTTPS
    53,     # DNS lookup
    8443,   # HTTPS alternate
}


# -----------------------------------------------------------
# Main classify function
# -----------------------------------------------------------
def classify_packet(src_port: int, dst_port: int) -> str:
    """
    Given source and destination port numbers,
    return one of: 'video', 'music', 'normal_browsing', 'other'

    We check both src_port and dst_port because:
    - When you REQUEST a video: your port is random, server port is 1935
    - When server SENDS you video: server port is 1935, your port is random
    So we must check BOTH directions.
    """

    # Combine both ports into one set for easy checking
    ports = {src_port, dst_port}

    # Check video ports first (most specific)
    if ports & VIDEO_PORTS:        # & means "intersection" — any match?
        return "video"

    # Check music ports
    if ports & MUSIC_PORTS:
        return "music"

    # Check browsing ports
    if ports & BROWSING_PORTS:
        return "normal_browsing"

    # Nothing matched — unknown traffic
    return "other"
