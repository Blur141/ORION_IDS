# ============================================================
# classifier.py — Traffic Category Classifier (FIXED)
# ============================================================
#
# WHY THE OLD VERSION FAILED:
# ─────────────────────────────────────────────────────────────
# The old classifier only looked at PORT NUMBERS.
# It expected YouTube to use port 1935 (RTMP) or 554 (RTSP).
# But that's OLD technology from the early 2000s.
#
# Modern reality in 2024:
#   YouTube  → HTTPS on port 443  (encrypted)
#   Spotify  → HTTPS on port 443  (encrypted)
#   Netflix  → HTTPS on port 443  (encrypted)
#   Twitch   → HTTPS on port 443  (encrypted)
#
# So EVERY streaming service now uses port 443 — the same port
# as online banking, email, and any normal website.
# That's why EVERYTHING was classified as "normal_browsing".
# Port numbers alone can no longer tell services apart.
#
# HOW THE NEW VERSION WORKS:
# ─────────────────────────────────────────────────────────────
# We now use a TWO-LAYER approach:
#
#   LAYER 1 — DNS Snooping (the smart layer)
#     When your browser connects to YouTube, it first asks:
#     "What is the IP address of youtube.com?"
#     That question travels as a DNS packet — unencrypted!
#     We read those DNS queries and record which IP addresses
#     belong to which service (YouTube, Spotify, etc.)
#     This builds a live "IP → category" lookup table.
#
#   LAYER 2 — Port Fallback (the safety net)
#     If we haven't seen a DNS query for an IP yet, we fall
#     back to port-based guessing — same as before, but now
#     it's only used as a backup, not the primary method.
#
# RESULT:
#   YouTube traffic on port 443 → IP was seen in a DNS query
#   for googlevideo.com → classified as "video" ✅
# ============================================================

# ─────────────────────────────────────────────────────────────
# LAYER 1 — DNS Domain → Category mappings
# ─────────────────────────────────────────────────────────────
#
# These are the domain name patterns we look for in DNS queries.
# When a DNS packet contains a domain that matches any of these,
# we record the resolved IP as belonging to that category.
#
# How to read this: "if a DNS query contains 'googlevideo.com',
# the IP that comes back is video traffic."

VIDEO_DOMAINS = [
    # YouTube & Google Video
    "youtube.com",
    "youtu.be",
    "googlevideo.com",      # YouTube's video delivery CDN
    "ytimg.com",            # YouTube image/thumbnail CDN
    "yt3.ggpht.com",        # YouTube avatar CDN

    # Twitch
    "twitch.tv",
    "twitchsvc.net",
    "jtvnw.net",            # Twitch's video delivery network

    # Netflix
    "netflix.com",
    "nflxvideo.net",        # Netflix video CDN
    "nflximg.net",

    # Disney+, Hulu, Prime Video
    "disneyplus.com",
    "hulu.com",
    "hulustream.com",
    "amazon.com",
    "amazonaws.com",        # AWS — used by Prime Video
    "aiv-cdn.net",          # Amazon Instant Video CDN

    # Other streaming
    "vimeo.com",
    "dailymotion.com",
    "tiktok.com",
    "tiktokcdn.com",
]

MUSIC_DOMAINS = [
    # Spotify
    "spotify.com",
    "scdn.co",              # Spotify's CDN
    "spotifycdn.com",
    "audio-ak.spotify.com",

    # Apple Music / iTunes
    "apple.com",
    "itunes.apple.com",
    "music.apple.com",
    "mzstatic.com",         # Apple media CDN

    # YouTube Music (separate from video YouTube)
    "music.youtube.com",

    # SoundCloud
    "soundcloud.com",
    "sndcdn.com",           # SoundCloud CDN

    # Amazon Music
    "music.amazon.com",

    # Deezer, Tidal
    "deezer.com",
    "tidal.com",
]

# ─────────────────────────────────────────────────────────────
# LAYER 2 — Port-based fallback (kept as backup)
# ─────────────────────────────────────────────────────────────
# These only apply if we have NOT identified the IP via DNS.
# Legacy protocols that some services still use occasionally.

VIDEO_PORTS = {
    1935,   # RTMP — old live streaming (some Twitch encoders still use this)
    554,    # RTSP — security cameras, old media servers
    8554,   # RTSP alternate
    1755,   # MMS — very old Windows Media
}

MUSIC_PORTS = {
    4070,   # Spotify's legacy non-HTTPS port (rarely used now)
    57621,  # Spotify local network discovery (LAN sync)
}

BROWSING_PORTS = {
    80,     # Plain HTTP
    443,    # HTTPS — used by everything modern
    53,     # DNS queries
    8080,   # HTTP alternate
    8443,   # HTTPS alternate
}

# ─────────────────────────────────────────────────────────────
# THE LIVE DNS TABLE
# ─────────────────────────────────────────────────────────────
# This dictionary is filled in at runtime as DNS packets arrive.
# Format: { "142.250.80.46": "video" }
#
# It starts empty. As packets flow through the sniffer,
# update_dns_table() below gets called with DNS data,
# and this table grows.

ip_category_table = {}   # { ip_string → category_string }


# ─────────────────────────────────────────────────────────────
# Function: update_dns_table
# ─────────────────────────────────────────────────────────────
def update_dns_table(domain: str, resolved_ips: list):
    """
    Called from sniffer.py when a DNS response is captured.
    
    Parameters:
      domain       — the domain name that was looked up
                     e.g. "googlevideo.com"
      resolved_ips — list of IP addresses the domain resolved to
                     e.g. ["142.250.80.46", "142.250.80.47"]
    
    What it does:
      Checks if the domain matches any VIDEO or MUSIC domain.
      If yes, stores every resolved IP in ip_category_table
      so future packets to those IPs are classified correctly.
    
    Example:
      Browser asks: "What's the IP of googlevideo.com?"
      DNS replies: "142.250.80.46"
      We store: ip_category_table["142.250.80.46"] = "video"
      Later, a packet goes to 142.250.80.46 on port 443
      → We look it up → "video" ✅  (not "normal_browsing" ❌)
    """
    category = _match_domain(domain)
    
    if category:
        for ip in resolved_ips:
            ip_category_table[ip] = category


def _match_domain(domain: str) -> str:
    """
    Internal helper: checks if a domain string contains
    any known video or music domain fragment.
    Returns 'video', 'music', or None.
    
    We use "in" checks rather than exact matches because:
    - "googlevideo.com" should match "rr1.sn-xxx.googlevideo.com"
    - "spotify.com" should match "audio-fa.scdn.co" → via scdn.co entry
    """
    domain_lower = domain.lower().rstrip(".")   # normalize

    for video_domain in VIDEO_DOMAINS:
        if video_domain in domain_lower:
            return "video"

    for music_domain in MUSIC_DOMAINS:
        if music_domain in domain_lower:
            return "music"

    return None   # no match


# ─────────────────────────────────────────────────────────────
# Function: classify_packet  (the main one called from sniffer)
# ─────────────────────────────────────────────────────────────
def classify_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> str:
    """
    Classifies a packet using the two-layer approach.

    Parameters:
      src_ip   — source IP address  (e.g. "192.168.1.5")
      dst_ip   — destination IP address (e.g. "142.250.80.46")
      src_port — source port number
      dst_port — destination port number

    Returns one of: 'video', 'music', 'normal_browsing', 'other'

    STEP 1: Check the DNS table first (most accurate).
    STEP 2: If not found, fall back to port-based detection.

    NOTE: The function signature changed! It now takes src_ip and
    dst_ip in addition to the ports. sniffer.py must pass these.
    """

    # ── STEP 1: DNS table lookup ──────────────────────────────
    # Check if the DESTINATION IP was identified via DNS.
    # (Destination = the server you're connecting to, like YouTube)
    if dst_ip in ip_category_table:
        return ip_category_table[dst_ip]

    # Also check source IP — handles server→client direction
    # (e.g., YouTube sending video data TO you)
    if src_ip in ip_category_table:
        return ip_category_table[src_ip]

    # ── STEP 2: Port-based fallback ───────────────────────────
    ports = {src_port, dst_port}

    if ports & VIDEO_PORTS:
        return "video"

    if ports & MUSIC_PORTS:
        return "music"

    if ports & BROWSING_PORTS:
        return "normal_browsing"

    return "other"