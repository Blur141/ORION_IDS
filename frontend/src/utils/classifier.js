/**
 * classifier.js — Accurate traffic categorization for real network packets.
 *
 * Resolution order: TLS SNI → DNS query → reverse hostname → port → IP locality
 */

// ─── Category definitions (shown in the UI filter dropdown) ──────────────────
export const CATEGORIES = [
  { id: "all", label: "All Traffic" },
  { id: "streaming", label: "🎬 Streaming" },
  { id: "social", label: "👥 Social" },
  { id: "voip", label: "📹 VoIP / Video" },
  { id: "browsing", label: "🌐 Web Browsing" },
  { id: "messaging", label: "💬 Messaging" },
  { id: "cloud", label: "☁️ Cloud / CDN" },
  { id: "system", label: "⚙️ System / OS" },
  { id: "dns", label: "🔍 DNS" },
  { id: "local", label: "🏠 LAN / Local" },
  { id: "security", label: "🔐 Security / VPN" },
  { id: "database", label: "🗄️ Database" },
  { id: "devtools", label: "🛠️ Dev Tools" },
  { id: "other", label: "❓ Other" },
];

// ─── Domain suffix → category ─────────────────────────────────────────────────
const DOMAIN_CATEGORY = [
  // Streaming video/audio
  { domains: ["youtube.com", "googlevideo.com", "ytimg.com", "yt3.ggpht.com", "youtu.be", "youtube-nocookie.com"], cat: "streaming" },
  { domains: ["netflix.com", "nflxvideo.net", "nflxso.net", "nflximg.net"], cat: "streaming" },
  { domains: ["spotify.com", "scdn.co", "spotifycdn.com"], cat: "streaming" },
  { domains: ["tiktok.com", "tiktokv.com", "muscdn.com", "tiktoklive.com"], cat: "streaming" },
  { domains: ["vimeo.com", "vimeocdn.com", "vhx.tv", "player.vimeo.com"], cat: "streaming" },
  { domains: ["twitch.tv", "jtvnw.net", "twitchdvr.com", "twitchsvc.net"], cat: "streaming" },
  { domains: ["soundcloud.com", "sndcdn.com"], cat: "streaming" },
  { domains: ["disneyplus.com", "bamgrid.com"], cat: "streaming" },
  { domains: ["primevideo.com", "aiv-cdn.net"], cat: "streaming" },
  { domains: ["hbomax.com", "max.com", "hbo.com"], cat: "streaming" },
  { domains: ["crunchyroll.com"], cat: "streaming" },
  { domains: ["deezer.com"], cat: "streaming" },
  { domains: ["plex.tv", "plexapp.com"], cat: "streaming" },
  { domains: ["dailymotion.com", "dmcdn.net"], cat: "streaming" },

  // VoIP / Video conferencing
  { domains: ["meet.google.com", "hangouts.google.com"], cat: "voip" },
  { domains: ["zoom.us", "zoom.com", "zoomus.io"], cat: "voip" },
  { domains: ["teams.microsoft.com", "teams.live.com"], cat: "voip" },
  { domains: ["discord.com", "discord.gg", "discordapp.com", "discord.media"], cat: "voip" },
  { domains: ["webex.com"], cat: "voip" },
  { domains: ["skype.com"], cat: "voip" },
  { domains: ["whereby.com"], cat: "voip" },

  // Messaging
  { domains: ["whatsapp.com", "whatsapp.net", "wa.me"], cat: "messaging" },
  { domains: ["messenger.com"], cat: "messaging" },
  { domains: ["telegram.org", "t.me", "telegram.me"], cat: "messaging" },
  { domains: ["signal.org"], cat: "messaging" },
  { domains: ["slack.com", "slack-edge.com", "slack-msgs.com"], cat: "messaging" },

  // Social media
  { domains: ["facebook.com", "fb.com", "fbcdn.net", "facebook.net", "fbsbx.com"], cat: "social" },
  { domains: ["instagram.com", "cdninstagram.com"], cat: "social" },
  { domains: ["twitter.com", "x.com", "t.co", "twimg.com"], cat: "social" },
  { domains: ["linkedin.com", "licdn.com"], cat: "social" },
  { domains: ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"], cat: "social" },
  { domains: ["snapchat.com", "sc-cdn.net"], cat: "social" },
  { domains: ["threads.net"], cat: "social" },
  { domains: ["pinterest.com", "pinimg.com"], cat: "social" },

  // Cloud / CDN infrastructure
  { domains: ["cloudflare.com", "cloudflareinsights.com"], cat: "cloud" },
  { domains: ["amazonaws.com", "cloudfront.net", "awsstatic.com"], cat: "cloud" },
  { domains: ["azure.com", "azureedge.net", "microsoftonline.com"], cat: "cloud" },
  { domains: ["akamai.com", "akamaiedge.net", "akamaihd.net", "edgekey.net"], cat: "cloud" },
  { domains: ["fastly.net", "fastly.com"], cat: "cloud" },
  { domains: ["1e100.net", "googleapis.com", "gstatic.com", "googlesyndication.com"], cat: "cloud" },
  { domains: ["icloud.com", "cdn-apple.com", "mzstatic.com"], cat: "cloud" },
  { domains: ["dropbox.com"], cat: "cloud" },
  { domains: ["onedrive.com", "sharepoint.com", "office.com"], cat: "cloud" },
  { domains: ["drive.google.com", "docs.google.com"], cat: "cloud" },

  // System / OS telemetry / updates
  { domains: ["windowsupdate.com", "windows.com", "microsoft.com", "msftconnecttest.com", "msedge.net", "live.com", "bing.com"], cat: "system" },
  { domains: ["apple.com", "appleiphonecell.com", "apple-dns.net"], cat: "system" },
  { domains: ["ubuntu.com", "canonical.com"], cat: "system" },
  { domains: ["google-analytics.com", "googletagmanager.com", "doubleclick.net"], cat: "system" },
  { domains: ["segment.io", "segment.com", "mixpanel.com", "hotjar.com"], cat: "system" },

  // Security / VPN / PKI
  { domains: ["ocsp.digicert.com", "ocsp.comodoca.com", "crl.microsoft.com", "pki.goog", "ocsp.apple.com"], cat: "security" },
  { domains: ["nordvpn.com", "expressvpn.com", "surfshark.com", "protonvpn.com", "mullvad.net"], cat: "security" },

  // Developer tools
  { domains: ["github.com", "githubusercontent.com", "githubassets.com"], cat: "devtools" },
  { domains: ["gitlab.com"], cat: "devtools" },
  { domains: ["npmjs.com", "npmjs.org"], cat: "devtools" },
  { domains: ["pypi.org", "python.org"], cat: "devtools" },
  { domains: ["docker.com", "hub.docker.com"], cat: "devtools" },
  { domains: ["anthropic.com", "claude.ai"], cat: "devtools" },
  { domains: ["openai.com"], cat: "devtools" },
  { domains: ["stackoverflow.com", "sstatic.net"], cat: "devtools" },

  // Local / LAN
  { domains: ["localhost", "local", "localdomain", "lan"], cat: "local" },
];

// ─── Port → category ──────────────────────────────────────────────────────────
const PORT_CATEGORY = {
  53: "dns",
  5353: "dns",
  5355: "dns",
  22: "devtools",
  21: "devtools",
  3306: "database",
  5432: "database",
  6379: "database",
  27017: "database",
  1433: "database",
  3389: "system",
  5900: "system",
  67: "system",
  68: "system",
  123: "system",
  161: "system",
  137: "local",
  138: "local",
  139: "local",
  445: "local",
  1900: "local",
  500: "security",
  4500: "security",
  1194: "security",
};

// ─── IP helpers ───────────────────────────────────────────────────────────────
const PRIVATE_PREFIXES = ["192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "::1", "fe80:"];
const MULTICAST_PREFIXES = ["224.", "239.", "255.255.255.255", "ff02:", "ff01:"];

function isPrivateIP(ip) {
  if (!ip) return false;
  return PRIVATE_PREFIXES.some((p) => ip.startsWith(p));
}

function isMulticast(ip) {
  if (!ip) return false;
  return MULTICAST_PREFIXES.some((p) => ip.startsWith(p));
}

function domainCategory(hostname) {
  if (!hostname) return null;
  const h = hostname.replace(/\.$/, "").toLowerCase();
  for (const entry of DOMAIN_CATEGORY) {
    for (const pattern of entry.domains) {
      if (h === pattern || h.endsWith("." + pattern)) return entry.cat;
    }
  }
  return null;
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * classifyPacket(packet) → { category: string }
 */
export function classifyPacket(packet) {
  const { protocol, tls_sni, dns_query, src_hostname, dst_hostname, src_ip, dst_ip, dst_port, src_port } = packet || {};

  // ARP is always local
  if (protocol === "ARP") return { category: "local" };

  // Multicast / broadcast
  if (isMulticast(dst_ip) || isMulticast(src_ip)) return { category: "local" };

  // DNS protocol
  if (protocol === "DNS" || protocol === "mDNS") {
    if (dns_query) {
      const cat = domainCategory(dns_query);
      if (cat) return { category: cat };
    }
    return { category: "dns" };
  }

  // TLS SNI — highest confidence for HTTPS
  if (tls_sni) {
    const cat = domainCategory(tls_sni);
    return { category: cat || "browsing" };
  }

  // Reverse-DNS hostnames
  for (const host of [dst_hostname, src_hostname]) {
    if (host && !host.includes("docker.internal") && !host.includes("localhost")) {
      const cat = domainCategory(host);
      if (cat) return { category: cat };
    }
  }

  // Port-based
  const port = dst_port || src_port;
  if (port && PORT_CATEGORY[port]) return { category: PORT_CATEGORY[port] };

  // ICMP
  if (protocol === "ICMP" || protocol === "ICMPv6") return { category: "system" };

  // Both IPs private → LAN
  if (isPrivateIP(src_ip) && isPrivateIP(dst_ip)) return { category: "local" };

  // One external IP, unknown service → browsing
  if (!isPrivateIP(dst_ip) || !isPrivateIP(src_ip)) return { category: "browsing" };

  return { category: "other" };
}