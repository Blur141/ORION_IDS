/**
 * serviceResolver.js — Pinpoint service identification from real packet data.
 *
 * Resolution order (highest → lowest confidence):
 *   1. TLS SNI hostname   (HTTPS — most accurate)
 *   2. DNS query domain
 *   3. Reverse-DNS hostname (src_hostname / dst_hostname)
 *   4. Destination IP prefix (known CDN / cloud ranges)
 *   5. Destination port  (fallback)
 */

// ─── Domain → Service map ─────────────────────────────────────────────────────
const DOMAIN_MAP = [
  // Google ecosystem
  { match: ["google.com", "googleapis.com", "googlevideo.com", "gstatic.com", "ggpht.com", "googleusercontent.com", "googlesyndication.com", "google-analytics.com", "googletagmanager.com", "doubleclick.net", "1e100.net"], name: "Google", emoji: "🔵", color: "#4285F4" },
  { match: ["youtube.com", "ytimg.com", "yt3.ggpht.com", "youtu.be", "youtube-nocookie.com"], name: "YouTube", emoji: "▶️", color: "#FF0000" },
  { match: ["meet.google.com", "hangouts.google.com"], name: "Google Meet", emoji: "📹", color: "#00BFA5" },
  { match: ["gmail.com", "mail.google.com"], name: "Gmail", emoji: "✉️", color: "#EA4335" },
  { match: ["drive.google.com"], name: "Google Drive", emoji: "📁", color: "#1A73E8" },
  { match: ["docs.google.com"], name: "Google Docs", emoji: "📄", color: "#1A73E8" },
  { match: ["calendar.google.com"], name: "Google Cal", emoji: "📅", color: "#1A73E8" },

  // Meta
  { match: ["facebook.com", "fb.com", "fbcdn.net", "facebook.net", "fbsbx.com", "fb.me"], name: "Facebook", emoji: "👤", color: "#1877F2" },
  { match: ["instagram.com", "cdninstagram.com", "ig.me"], name: "Instagram", emoji: "📸", color: "#E1306C" },
  { match: ["whatsapp.com", "whatsapp.net", "wa.me"], name: "WhatsApp", emoji: "💬", color: "#25D366" },
  { match: ["messenger.com"], name: "Messenger", emoji: "💙", color: "#0084FF" },
  { match: ["threads.net"], name: "Threads", emoji: "🧵", color: "#000000" },

  // Microsoft
  { match: ["microsoft.com", "microsoftonline.com", "msftconnecttest.com", "msedge.net", "bing.com", "azure.com", "azureedge.net", "windows.com", "windowsupdate.com", "live.com", "msn.com", "office.com", "office365.com", "sharepoint.com", "onedrive.com"], name: "Microsoft", emoji: "🪟", color: "#0078D4" },
  { match: ["teams.microsoft.com", "teams.live.com"], name: "MS Teams", emoji: "🟣", color: "#6264A7" },
  { match: ["outlook.com", "outlook.live.com"], name: "Outlook", emoji: "📨", color: "#0078D4" },
  { match: ["skype.com"], name: "Skype", emoji: "🔵", color: "#00AFF0" },

  // Apple
  { match: ["apple.com", "icloud.com", "mzstatic.com", "aaplimg.com", "cdn-apple.com", "apple-dns.net", "appleiphonecell.com"], name: "Apple", emoji: "🍎", color: "#555555" },

  // Amazon / AWS
  { match: ["amazon.com", "amazon.ae", "amazon.co.uk", "amazon.de", "amazonaws.com", "cloudfront.net", "awsstatic.com"], name: "Amazon", emoji: "📦", color: "#FF9900" },

  // Cloudflare
  { match: ["cloudflare.com", "cloudflareinsights.com", "cf-ipfs.com"], name: "Cloudflare", emoji: "🔶", color: "#F6821F" },

  // Akamai / CDNs
  { match: ["akamai.com", "akamaiedge.net", "akamaihd.net", "edgekey.net", "akamaitechnologies.com"], name: "Akamai CDN", emoji: "🌐", color: "#009BDE" },
  { match: ["fastly.net", "fastly.com"], name: "Fastly CDN", emoji: "⚡", color: "#FF282D" },

  // Streaming
  { match: ["netflix.com", "nflxvideo.net", "nflxso.net", "nflximg.net", "netflix.net"], name: "Netflix", emoji: "🎬", color: "#E50914" },
  { match: ["vimeo.com", "vimeocdn.com", "vhx.tv", "player.vimeo.com"], name: "Vimeo", emoji: "🎞️", color: "#1AB7EA" },
  { match: ["spotify.com", "scdn.co", "spotifycdn.com"], name: "Spotify", emoji: "🎵", color: "#1DB954" },
  { match: ["tiktok.com", "tiktokv.com", "tiktoklive.com", "muscdn.com"], name: "TikTok", emoji: "🎶", color: "#010101" },
  { match: ["twitch.tv", "twitchsvc.net", "jtvnw.net", "twitchdvr.com"], name: "Twitch", emoji: "🟣", color: "#9147FF" },
  { match: ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"], name: "Discord", emoji: "🎮", color: "#5865F2" },
  { match: ["disneyplus.com", "bamgrid.com"], name: "Disney+", emoji: "🏰", color: "#113CCF" },
  { match: ["primevideo.com", "aiv-cdn.net"], name: "Prime Video", emoji: "📺", color: "#00A8E0" },
  { match: ["hbomax.com", "max.com", "hbo.com"], name: "Max / HBO", emoji: "🎬", color: "#6B22FF" },
  { match: ["crunchyroll.com"], name: "Crunchyroll", emoji: "🎌", color: "#F47521" },
  { match: ["plex.tv", "plexapp.com"], name: "Plex", emoji: "📽️", color: "#E5A00D" },
  { match: ["dailymotion.com", "dmcdn.net"], name: "Dailymotion", emoji: "🎬", color: "#00B8F1" },
  { match: ["soundcloud.com", "sndcdn.com"], name: "SoundCloud", emoji: "🎵", color: "#FF5500" },

  // Social
  { match: ["twitter.com", "x.com", "t.co", "twimg.com"], name: "X / Twitter", emoji: "✖️", color: "#000000" },
  { match: ["linkedin.com", "licdn.com"], name: "LinkedIn", emoji: "💼", color: "#0A66C2" },
  { match: ["reddit.com", "redd.it", "redditmedia.com", "reddituploads.com", "redditstatic.com"], name: "Reddit", emoji: "🤖", color: "#FF4500" },
  { match: ["snapchat.com", "sc-cdn.net"], name: "Snapchat", emoji: "👻", color: "#FFFC00" },
  { match: ["pinterest.com", "pinimg.com"], name: "Pinterest", emoji: "📌", color: "#E60023" },

  // Messaging / collab
  { match: ["slack.com", "slack-edge.com", "slack-msgs.com", "slack-redir.net"], name: "Slack", emoji: "💬", color: "#4A154B" },
  { match: ["zoom.us", "zoom.com", "zoomus.io"], name: "Zoom", emoji: "📹", color: "#2D8CFF" },
  { match: ["telegram.org", "t.me", "telegram.me"], name: "Telegram", emoji: "✈️", color: "#2AABEE" },
  { match: ["signal.org"], name: "Signal", emoji: "🔒", color: "#3A76F0" },
  { match: ["webex.com"], name: "Webex", emoji: "📹", color: "#00B140" },

  // Developer tools
  { match: ["github.com", "githubusercontent.com", "githubassets.com"], name: "GitHub", emoji: "🐙", color: "#181717" },
  { match: ["gitlab.com"], name: "GitLab", emoji: "🦊", color: "#FC6D26" },
  { match: ["stackoverflow.com", "sstatic.net"], name: "Stack Overflow", emoji: "📚", color: "#F58025" },
  { match: ["npmjs.com", "npmjs.org"], name: "npm", emoji: "📦", color: "#CB3837" },
  { match: ["anthropic.com", "claude.ai"], name: "Claude AI", emoji: "🤖", color: "#CC785C" },
  { match: ["openai.com"], name: "OpenAI", emoji: "🤖", color: "#10A37F" },

  // Productivity
  { match: ["notion.so", "notion.com"], name: "Notion", emoji: "📓", color: "#000000" },
  { match: ["figma.com"], name: "Figma", emoji: "🎨", color: "#F24E1E" },
  { match: ["dropbox.com", "dropboxstatic.com"], name: "Dropbox", emoji: "📥", color: "#0061FF" },

  // Security / PKI / infra
  { match: ["ocsp.apple.com", "ocsp.digicert.com", "ocsp.comodoca.com", "crl.microsoft.com", "pki.goog"], name: "PKI / OCSP", emoji: "🔐", color: "#888888" },
  { match: ["nordvpn.com", "expressvpn.com", "surfshark.com", "protonvpn.com", "mullvad.net"], name: "VPN", emoji: "🔐", color: "#888888" },

  // Local
  { match: ["localhost"], name: "Localhost", emoji: "🏠", color: "#888888" },
];

// ─── IP prefix → Service ──────────────────────────────────────────────────────
const IP_PREFIX_MAP = [
  { prefixes: ["142.250.", "172.217.", "216.58.", "74.125.", "64.233.", "209.85.", "108.177.", "173.194."], name: "Google", emoji: "🔵", color: "#4285F4" },
  { prefixes: ["1.1.1.", "1.0.0.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71."], name: "Cloudflare", emoji: "🔶", color: "#F6821F" },
  { prefixes: ["31.13.", "157.240.", "163.70.", "179.60.", "185.60.", "129.134.", "102.132."], name: "Meta", emoji: "👤", color: "#1877F2" },
  { prefixes: ["151.101.", "199.232."], name: "Fastly CDN", emoji: "⚡", color: "#FF282D" },
  { prefixes: ["17."], name: "Apple", emoji: "🍎", color: "#555555" },
  { prefixes: ["224.", "239.", "255.", "0.0.0."], name: "Multicast", emoji: "📡", color: "#888888" },
];

// ─── Port → Service fallback ──────────────────────────────────────────────────
const PORT_MAP = {
  80: { name: "HTTP", emoji: "🌐", color: "#38BDF8" },
  443: { name: "HTTPS", emoji: "🔒", color: "#4ADE80" },
  8080: { name: "HTTP-Alt", emoji: "🌐", color: "#38BDF8" },
  8443: { name: "HTTPS-Alt", emoji: "🔒", color: "#4ADE80" },
  53: { name: "DNS", emoji: "🔍", color: "#A78BFA" },
  5353: { name: "mDNS", emoji: "📡", color: "#A78BFA" },
  22: { name: "SSH", emoji: "🔑", color: "#FACC15" },
  21: { name: "FTP", emoji: "📂", color: "#FB923C" },
  25: { name: "SMTP", emoji: "✉️", color: "#FB923C" },
  587: { name: "SMTP", emoji: "✉️", color: "#FB923C" },
  993: { name: "IMAP", emoji: "📧", color: "#FB923C" },
  995: { name: "POP3", emoji: "📧", color: "#FB923C" },
  3306: { name: "MySQL", emoji: "🗄️", color: "#F97316" },
  5432: { name: "PostgreSQL", emoji: "🐘", color: "#336791" },
  6379: { name: "Redis", emoji: "🔴", color: "#DC382D" },
  27017: { name: "MongoDB", emoji: "🍃", color: "#47A248" },
  3389: { name: "RDP", emoji: "🖥️", color: "#F87171" },
  5900: { name: "VNC", emoji: "🖥️", color: "#F87171" },
  67: { name: "DHCP", emoji: "📡", color: "#888888" },
  68: { name: "DHCP", emoji: "📡", color: "#888888" },
  123: { name: "NTP", emoji: "🕐", color: "#888888" },
  161: { name: "SNMP", emoji: "📡", color: "#888888" },
  500: { name: "IKE/VPN", emoji: "🔐", color: "#888888" },
  4500: { name: "IPSec", emoji: "🔐", color: "#888888" },
  1900: { name: "SSDP/UPnP", emoji: "📡", color: "#888888" },
  5355: { name: "LLMNR", emoji: "📡", color: "#888888" },
  137: { name: "NetBIOS", emoji: "📡", color: "#888888" },
  138: { name: "NetBIOS", emoji: "📡", color: "#888888" },
  139: { name: "SMB", emoji: "📁", color: "#888888" },
  445: { name: "SMB", emoji: "📁", color: "#888888" },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function matchDomain(hostname) {
  if (!hostname) return null;
  const h = hostname.replace(/\.$/, "").toLowerCase();
  for (const entry of DOMAIN_MAP) {
    for (const pattern of entry.match) {
      if (h === pattern || h.endsWith("." + pattern)) {
        return { ...entry, domain: h };
      }
    }
  }
  return null;
}

function matchIP(ip) {
  if (!ip) return null;
  for (const entry of IP_PREFIX_MAP) {
    for (const prefix of entry.prefixes) {
      if (ip.startsWith(prefix)) return { ...entry, domain: ip };
    }
  }
  return null;
}

function matchPort(port) {
  if (!port) return null;
  const entry = PORT_MAP[port];
  return entry ? { ...entry, domain: `port ${port}` } : null;
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * resolveService(packet) → { name, emoji, color, domain } | null
 */
export function resolveService(packet) {
  const { tls_sni, dns_query, src_hostname, dst_hostname, src_ip, dst_ip, dst_port, src_port } = packet || {};

  // 1. TLS SNI — most accurate for HTTPS
  if (tls_sni) {
    const m = matchDomain(tls_sni);
    if (m) return { ...m, domain: tls_sni };
    return { name: tls_sni, emoji: "🔒", color: "#4ADE80", domain: tls_sni };
  }

  // 2. DNS query
  if (dns_query) {
    const m = matchDomain(dns_query);
    if (m) return { ...m, domain: dns_query };
    return { name: dns_query, emoji: "🔍", color: "#A78BFA", domain: dns_query };
  }

  // 3. Reverse-DNS hostname — prefer dst (we're connecting TO them)
  const dstHost = dst_hostname && !dst_hostname.includes("docker.internal") ? dst_hostname : null;
  const srcHost = src_hostname && !src_hostname.includes("docker.internal") ? src_hostname : null;

  for (const host of [dstHost, srcHost]) {
    if (host) {
      const m = matchDomain(host);
      if (m) return { ...m, domain: host };
      // Unknown hostname — still show it
      const parts = host.replace(/\.$/, "").split(".");
      const root = parts.length > 2 ? parts.slice(-2).join(".") : host;
      return { name: root, emoji: "🌐", color: "#64748B", domain: host };
    }
  }

  // 4. IP prefix match — identify CDN/cloud by IP range
  const externalDst = dst_ip && !dst_ip.startsWith("192.168.") && !dst_ip.startsWith("10.") && !dst_ip.startsWith("172.") ? dst_ip : null;
  const externalSrc = src_ip && !src_ip.startsWith("192.168.") && !src_ip.startsWith("10.") && !src_ip.startsWith("172.") ? src_ip : null;

  for (const ip of [externalDst, externalSrc]) {
    if (ip) {
      const m = matchIP(ip);
      if (m) return { ...m, domain: ip };
    }
  }

  // 5. Port-based fallback
  const port = dst_port || src_port;
  if (port) return matchPort(port);

  return null;
}