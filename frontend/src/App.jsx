import { useState, useEffect, useMemo } from "react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import {
  Shield,
  ShieldAlert,
  ShieldOff,
  Activity,
  Wifi,
  WifiOff,
  AlertTriangle,
  Zap,
  Eye,
  Terminal,
  Globe,
  Server,
  TrendingUp,
  Clock,
  ChevronRight,
  Bell,
  Database,
  CheckCircle,
  Play,
  Square,
  RotateCcw,
  Search,
} from "lucide-react";
import { useIDSWebSocket } from "./hooks/useIDSWebSocket";
import { classifyPacket, CATEGORIES } from "./utils/classifier";
import { resolveService } from "./utils/serviceResolver";
import "./App.css";

const WS_URL = process.env.REACT_APP_WS_URL || "ws://localhost:8000/ws";
const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

const SEV = {
  info: {
    color: "#4ADE80",
    bg: "rgba(74,222,128,0.1)",
    label: "Normal",
    icon: Shield,
  },
  suspicious: {
    color: "#FACC15",
    bg: "rgba(250,204,21,0.1)",
    label: "Suspicious",
    icon: ShieldAlert,
  },
  malicious: {
    color: "#F87171",
    bg: "rgba(248,113,113,0.12)",
    label: "Malicious",
    icon: ShieldOff,
  },
};

const SeverityBadge = ({ severity }) => {
  const cfg = SEV[severity] || SEV.info;
  return (
    <span
      className="sev-badge"
      style={{ color: cfg.color, background: cfg.bg }}
    >
      {cfg.label}
    </span>
  );
};

const ServiceBadge = ({ packet }) => {
  const svc = resolveService(packet);
  if (!svc) return <span className="svc-none">—</span>;
  return (
    <div className="svc-badge-wrap">
      <span
        className="svc-badge"
        style={{ color: svc.color, borderColor: `${svc.color}44`, background: `${svc.color}14` }}
        title={svc.domain}
      >
        <span className="svc-emoji">{svc.emoji}</span>
        {svc.name}
      </span>
      <span className="svc-domain">{svc.domain}</span>
    </div>
  );
};

const StatCard = ({ icon: Icon, label, value, sub, color, pulse }) => (
  <div
    className={`stat-card ${pulse ? "pulse-border" : ""}`}
    style={{ "--accent": color }}
  >
    <div className="stat-icon" style={{ color }}>
      <Icon size={22} />
      {pulse && <span className="pulse-dot" style={{ background: color }} />}
    </div>
    <div className="stat-body">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  </div>
);

const AlertCard = ({ alert, onAck }) => {
  const cfg = SEV[alert.severity] || SEV.suspicious;
  const Icon = cfg.icon;
  return (
    <div
      className={`alert-card alert-${alert.severity} ${alert.is_acknowledged ? "acked" : ""}`}
    >
      <div className="alert-header">
        <Icon size={16} color={cfg.color} />
        <span className="alert-type" style={{ color: cfg.color }}>
          {alert.alert_type}
        </span>
        <span className="alert-time">
          {new Date(alert.timestamp).toLocaleTimeString()}
        </span>
        {!alert.is_acknowledged && (
          <button
            className="ack-btn"
            onClick={() => onAck(alert.id)}
            title="Acknowledge"
          >
            <CheckCircle size={14} />
          </button>
        )}
      </div>
      <div className="alert-src">
        <Globe size={11} /> {alert.src_ip}
        {alert.dst_ip && (
          <>
            <ChevronRight size={11} />
            {alert.dst_ip}
          </>
        )}
      </div>
      <div className="alert-desc">{alert.description}</div>
    </div>
  );
};

export default function App() {
  const { connected, stats, packets, alerts, packetRate, resetState } =
    useIDSWebSocket(WS_URL);
  const [activeTab, setActiveTab] = useState("live");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [localAlerts, setLocalAlerts] = useState([]);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [threatHistory, setThreatHistory] = useState([]);
  const [isCapturing, setIsCapturing] = useState(true);

  // Fetch initial capture status
  useEffect(() => {
    fetch(`${API_URL}/api/status`)
      .then((res) => res.json())
      .then((data) => setIsCapturing(data.status === "running"))
      .catch(() => { });
  }, []);

  // Control handlers
  const handleStart = async () => {
    try {
      await fetch(`${API_URL}/api/control/start`, { method: "POST" });
      setIsCapturing(true);
    } catch (e) {
      console.error("Start failed", e);
    }
  };

  const handleStop = async () => {
    try {
      await fetch(`${API_URL}/api/control/stop`, { method: "POST" });
      setIsCapturing(false);
    } catch (e) {
      console.error("Stop failed", e);
    }
  };

  const handleReset = async () => {
    // Clear all local UI state immediately
    resetState();
    setLocalAlerts([]);
    setTrafficHistory([]);
    setThreatHistory([]);
    // Stop capture if running
    if (isCapturing) {
      await fetch(`${API_URL}/api/control/stop`, { method: "POST" }).catch(
        () => { },
      );
    }
    // Reset backend stats
    await fetch(`${API_URL}/api/control/reset`, { method: "POST" }).catch(
      () => { },
    );
    // Leave capture stopped — user must press Start manually
    setIsCapturing(false);
  };

  // Classify all packets once
  const classifiedPackets = useMemo(() => {
    return packets.map((pkt) => ({
      ...pkt,
      category: classifyPacket(pkt).category,
      service: resolveService(pkt),
    }));
  }, [packets]);

  // Filter packets based on category, severity, and search query
  const filteredPackets = useMemo(() => {
    return classifiedPackets.filter((pkt) => {
      if (categoryFilter !== "all" && pkt.category !== categoryFilter)
        return false;
      if (severityFilter !== "all" && pkt.severity !== severityFilter)
        return false;
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const match = [
          pkt.src_ip,
          pkt.dst_ip,
          pkt.protocol,
          pkt.src_hostname,
          pkt.dst_hostname,
          pkt.service?.name,
          pkt.service?.domain,
          pkt.category,
          pkt.severity,
          pkt.attack_type,
        ].some((val) => val && String(val).toLowerCase().includes(query));
        if (!match) return false;
      }
      return true;
    });
  }, [classifiedPackets, categoryFilter, severityFilter, searchQuery]);

  // Sync alerts
  useEffect(() => {
    if (alerts.length > 0) setLocalAlerts(alerts);
  }, [alerts]);

  // Rolling charts
  useEffect(() => {
    if (!stats) return;
    const ts = new Date().toLocaleTimeString("en", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    setTrafficHistory((prev) => {
      const next = [
        ...prev,
        {
          time: ts,
          packets: stats.total_packets,
          bw: Math.round(stats.bandwidth_bps / 1024),
        },
      ];
      return next.slice(-30);
    });
    setThreatHistory((prev) => {
      const next = [
        ...prev,
        {
          time: ts,
          normal: stats.info_count,
          suspicious: stats.suspicious_count,
          malicious: stats.malicious_count,
        },
      ];
      return next.slice(-30);
    });
  }, [stats]);

  const acknowledgeAlert = async (id) => {
    try {
      await fetch(`${API_URL}/api/alerts/${id}/acknowledge`, {
        method: "PATCH",
      });
      setLocalAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, is_acknowledged: true } : a)),
      );
    } catch (e) {
      console.error(e);
    }
  };

  const fmtBytes = (b) => {
    if (!b) return "0 B/s";
    if (b < 1024) return `${b.toFixed(0)} B/s`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB/s`;
    return `${(b / 1024 / 1024).toFixed(2)} MB/s`;
  };

  const uptime = stats?.uptime_seconds
    ? `${Math.floor(stats.uptime_seconds / 60)}m ${Math.floor(stats.uptime_seconds % 60)}s`
    : "—";

  const unackedCount = localAlerts.filter((a) => !a.is_acknowledged).length;

  const protoData =
    stats?.protocol_distribution &&
      typeof stats.protocol_distribution === "object"
      ? Object.entries(stats.protocol_distribution).map(([name, value]) => ({
        name,
        value,
      }))
      : [];
  const PROTO_COLORS = [
    "#38BDF8",
    "#818CF8",
    "#4ADE80",
    "#FACC15",
    "#F87171",
    "#FB923C",
    "#A78BFA",
    "#34D399",
  ];

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <div className="logo">
            <Shield size={28} className="logo-icon" />
            <div>
              <span className="logo-title">ORION</span>
              <span className="logo-sub">Operational Reconnaissance & Intelligent Observation Network</span>
            </div>
          </div>
        </div>
        <div className="header-center">
          <nav className="tabs">
            {[
              { id: "live", label: "Live Feed", icon: Activity },
              {
                id: "alerts",
                label: "Alerts",
                icon: AlertTriangle,
                badge: unackedCount,
              },
              { id: "analytics", label: "Analytics", icon: TrendingUp },
            ].map((tab) => (
              <button
                key={tab.id}
                className={`tab ${activeTab === tab.id ? "active" : ""}`}
                onClick={() => setActiveTab(tab.id)}
              >
                <tab.icon size={15} />
                {tab.label}
                {tab.badge > 0 && (
                  <span className="tab-badge">{tab.badge}</span>
                )}
              </button>
            ))}
          </nav>
        </div>
        <div className="header-right">
          <div className={`conn-status ${connected ? "conn-ok" : "conn-err"}`}>
            {connected ? <Wifi size={14} /> : <WifiOff size={14} />}
            <span>{connected ? "Live" : "Reconnecting..."}</span>
          </div>
        </div>
      </header>

      {/* Control Bar */}
      <div className="control-bar">
        <div className="control-group">
          <button
            className={`control-btn ${isCapturing ? "active" : ""}`}
            onClick={handleStart}
            disabled={isCapturing}
            title="Start Capture"
          >
            <Play size={16} /> Start
          </button>
          <button
            className={`control-btn ${!isCapturing ? "active" : ""}`}
            onClick={handleStop}
            disabled={!isCapturing}
            title="Stop Capture"
          >
            <Square size={16} /> Stop
          </button>
          <button
            className="control-btn reset"
            onClick={handleReset}
            title="Reset and Restart"
          >
            <RotateCcw size={16} /> Reset
          </button>
        </div>
        <div className="control-status">
          {isCapturing ? (
            <span className="capture-on">
              <Wifi size={12} /> Capturing
            </span>
          ) : (
            <span className="capture-off">
              <WifiOff size={12} /> Stopped
            </span>
          )}
        </div>
      </div>

      <div className="stat-bar">
        <StatCard
          icon={Activity}
          label="Packets/sec"
          value={packetRate}
          color="#38BDF8"
        />
        <StatCard
          icon={Database}
          label="Total Packets"
          value={stats?.total_packets?.toLocaleString() || "0"}
          color="#818CF8"
        />
        <StatCard
          icon={Shield}
          label="Normal"
          value={stats?.info_count?.toLocaleString() || "0"}
          color="#4ADE80"
        />
        <StatCard
          icon={ShieldAlert}
          label="Suspicious"
          value={stats?.suspicious_count?.toLocaleString() || "0"}
          color="#FACC15"
          pulse={stats?.suspicious_count > 0}
        />
        <StatCard
          icon={ShieldOff}
          label="Malicious"
          value={stats?.malicious_count?.toLocaleString() || "0"}
          color="#F87171"
          pulse={stats?.malicious_count > 0}
        />
        <StatCard
          icon={Zap}
          label="Bandwidth"
          value={fmtBytes(stats?.bandwidth_bps)}
          color="#FB923C"
        />
        <StatCard icon={Clock} label="Uptime" value={uptime} color="#A78BFA" />
      </div>

      <main className="content">
        {activeTab === "live" && (
          <div className="panel-grid">
            <div className="panel panel-wide">
              <div className="panel-header">
                <Eye size={16} />
                <span>Live Packet Feed</span>
                <div className="panel-controls">
                  <div className="search-wrap">
                    <Search size={14} className="search-icon" />
                    <input
                      type="text"
                      className="filter-input"
                      placeholder="Search packets..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>
                  <select
                    className="filter-select"
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value)}
                  >
                    {CATEGORIES.map((cat) => (
                      <option key={cat.id} value={cat.id}>
                        {cat.label}
                      </option>
                    ))}
                  </select>
                  <select
                    className="filter-select"
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                  >
                    <option value="all">All Severities</option>
                    <option value="info">Normal</option>
                    <option value="suspicious">Suspicious</option>
                    <option value="malicious">Malicious</option>
                  </select>
                  <span className="packet-count">
                    {filteredPackets.length} packets
                  </span>
                </div>
              </div>
              <div className="table-wrap">
                {filteredPackets.length === 0 ? (
                  <div className="empty-state">
                    <Activity size={32} color="#64748B" />
                    <p>Waiting for packets...</p>
                  </div>
                ) : (
                  <table className="packet-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Protocol</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Service</th>
                        <th>Size</th>
                        <th>Severity</th>
                        <th>Attack</th>
                        <th>Category</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPackets
                        .slice(-200)
                        .reverse()
                        .map((pkt, idx) => (
                          <tr
                            key={pkt.id || idx}
                            className={`pkt-row sev-${pkt.severity}`}
                          >
                            <td>
                              {new Date(pkt.timestamp).toLocaleTimeString()}
                            </td>
                            <td>
                              <span className="proto-tag">{pkt.protocol}</span>
                            </td>
                            <td>
                              <div className="ip-cell">
                                <span className="mono">
                                  {pkt.src_ip || "—"}
                                  <span className="port">
                                    {pkt.src_port ? `:${pkt.src_port}` : ""}
                                  </span>
                                </span>
                                {pkt.src_hostname && (
                                  <span className="host-name" title={pkt.src_hostname}>
                                    {pkt.src_hostname.length > 22
                                      ? pkt.src_hostname.slice(0, 20) + "…"
                                      : pkt.src_hostname}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td>
                              <div className="ip-cell">
                                <span className="mono">
                                  {pkt.dst_ip || "—"}
                                  <span className="port">
                                    {pkt.dst_port ? `:${pkt.dst_port}` : ""}
                                  </span>
                                </span>
                                {pkt.dst_hostname && (
                                  <span className="host-name" title={pkt.dst_hostname}>
                                    {pkt.dst_hostname.length > 22
                                      ? pkt.dst_hostname.slice(0, 20) + "…"
                                      : pkt.dst_hostname}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td><ServiceBadge packet={pkt} /></td>
                            <td>{pkt.packet_size} B</td>
                            <td>
                              <SeverityBadge severity={pkt.severity} />
                            </td>
                            <td className="attack-cell">
                              {pkt.attack_type || ""}
                            </td>
                            <td className="category-tag">
                              {pkt.category === "streaming" && pkt.service ? (
                                <span
                                  className="streaming-tag"
                                  style={{ color: pkt.service.color, borderColor: `${pkt.service.color}55`, background: `${pkt.service.color}18` }}
                                >
                                  {pkt.service.emoji} {pkt.service.name}
                                </span>
                              ) : (
                                pkt.category
                              )}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            <div className="panel panel-narrow">
              <div className="panel-header">
                <Bell size={16} />
                <span>Recent Alerts</span>
                {unackedCount > 0 && (
                  <span className="alert-count">{unackedCount} new</span>
                )}
              </div>
              <div className="alerts-scroll">
                {localAlerts.length === 0 ? (
                  <div className="empty-state">
                    <Shield size={32} color="#4ADE80" />
                    <p>No threats detected</p>
                  </div>
                ) : (
                  localAlerts.map((a, i) => (
                    <AlertCard
                      key={a.id || i}
                      alert={a}
                      onAck={acknowledgeAlert}
                    />
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "alerts" && (
          <div className="panel-grid single">
            <div className="panel full-width">
              <div className="panel-header">
                <AlertTriangle size={16} />
                <span>All Alerts</span>
                <span className="panel-sub">
                  {localAlerts.length} total · {unackedCount} unacknowledged
                </span>
              </div>
              <div className="alerts-grid">
                {localAlerts.length === 0 ? (
                  <div className="empty-state large">
                    <Shield size={48} color="#4ADE80" />
                    <h3>All Clear</h3>
                    <p>No threats have been detected</p>
                  </div>
                ) : (
                  localAlerts.map((a, i) => (
                    <AlertCard
                      key={a.id || i}
                      alert={a}
                      onAck={acknowledgeAlert}
                    />
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === "analytics" && (
          <div className="analytics-grid">
            {trafficHistory.length > 0 && (
              <div className="panel chart-wide">
                <div className="panel-header">
                  <Activity size={16} />
                  <span>Traffic Timeline</span>
                </div>
                <AreaChart width={700} height={200} data={trafficHistory}>
                  <defs>
                    <linearGradient id="bwGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#38BDF8" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(255,255,255,0.05)"
                  />
                  <XAxis
                    dataKey="time"
                    tick={{ fill: "#64748B", fontSize: 10 }}
                  />
                  <YAxis tick={{ fill: "#64748B", fontSize: 10 }} />
                  <Tooltip
                    wrapperStyle={{
                      background: "#0F172A",
                      border: "1px solid #1E293B",
                      color: "#E2E8F0",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="bw"
                    stroke="#38BDF8"
                    fill="url(#bwGrad)"
                    name="KB/s"
                    strokeWidth={2}
                  />
                </AreaChart>
              </div>
            )}

            {threatHistory.length > 0 && (
              <div className="panel chart-wide">
                <div className="panel-header">
                  <ShieldAlert size={16} />
                  <span>Threat Activity</span>
                </div>
                <BarChart
                  width={700}
                  height={200}
                  data={threatHistory.slice(-20)}
                >
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(255,255,255,0.05)"
                  />
                  <XAxis
                    dataKey="time"
                    tick={{ fill: "#64748B", fontSize: 10 }}
                  />
                  <YAxis tick={{ fill: "#64748B", fontSize: 10 }} />
                  <Tooltip
                    wrapperStyle={{
                      background: "#0F172A",
                      border: "1px solid #1E293B",
                      color: "#E2E8F0",
                    }}
                  />
                  <Legend />
                  <Bar
                    dataKey="normal"
                    name="Normal"
                    fill="#4ADE80"
                    stackId="a"
                  />
                  <Bar
                    dataKey="suspicious"
                    name="Suspicious"
                    fill="#FACC15"
                    stackId="a"
                  />
                  <Bar
                    dataKey="malicious"
                    name="Malicious"
                    fill="#F87171"
                    stackId="a"
                  />
                </BarChart>
              </div>
            )}

            {protoData.length > 0 && (
              <div className="panel chart-small">
                <div className="panel-header">
                  <Globe size={16} />
                  <span>Protocol Mix</span>
                </div>
                <PieChart width={300} height={200}>
                  <Pie
                    data={protoData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    dataKey="value"
                    nameKey="name"
                    paddingAngle={3}
                    label={({ name, percent }) =>
                      `${name} ${(percent * 100).toFixed(0)}%`
                    }
                    labelLine={{ stroke: "#334155" }}
                  >
                    {protoData.map((_, i) => (
                      <Cell
                        key={i}
                        fill={PROTO_COLORS[i % PROTO_COLORS.length]}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    wrapperStyle={{
                      background: "#0F172A",
                      border: "1px solid #1E293B",
                      color: "#E2E8F0",
                    }}
                  />
                </PieChart>
              </div>
            )}
            <div className="panel chart-small">
              <div className="panel-header">
                <Server size={16} />
                <span>Top Source IPs</span>
              </div>
              <div className="ip-list">
                {(stats?.top_src_ips || []).slice(0, 8).map((item, i) => {
                  const max = stats?.top_src_ips?.[0]?.count || 1;
                  const pct = (item.count / max) * 100;
                  return (
                    <div key={i} className="ip-row">
                      <span className="ip-addr">{item.ip}</span>
                      <div className="ip-bar-wrap">
                        <div
                          className="ip-bar"
                          style={{
                            width: `${pct}%`,
                            background: PROTO_COLORS[i % PROTO_COLORS.length],
                          }}
                        />
                      </div>
                      <span className="ip-count">{item.count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
