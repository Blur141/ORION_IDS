import { useEffect, useRef, useState, useCallback } from 'react';

const THROTTLE_MS = 100;

// Ensures stats always has the shape the UI expects
function normalizeStats(raw) {
  if (!raw) return null;
  return {
    total_packets: raw.total_packets ?? 0,
    info_count: raw.info_count ?? 0,
    suspicious_count: raw.suspicious_count ?? 0,
    malicious_count: raw.malicious_count ?? 0,
    bandwidth_bps: raw.bandwidth_bps ?? 0,
    uptime_seconds: raw.uptime_seconds ?? 0,
    capture_mode: raw.capture_mode ?? null,
    protocol_distribution: (raw.protocol_distribution && typeof raw.protocol_distribution === 'object')
      ? raw.protocol_distribution
      : {},
    top_src_ips: Array.isArray(raw.top_src_ips) ? raw.top_src_ips : [],
  };
}

export function useIDSWebSocket(url) {
  const wsRef = useRef(null);
  const [connected, setConnected] = useState(false);
  const [stats, setStats] = useState(null);
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [packetRate, setPacketRate] = useState(0);

  const packetCountRef = useRef(0);
  const rateIntervalRef = useRef(null);
  const pendingPacketsRef = useRef([]);
  const throttleTimerRef = useRef(null);

  const flushPackets = useCallback(() => {
    if (pendingPacketsRef.current.length === 0) return;
    setPackets(prev => {
      const next = [...prev, ...pendingPacketsRef.current];
      return next.slice(-300);
    });
    pendingPacketsRef.current = [];
  }, []);

  const resetState = useCallback(() => {
    // Discard any buffered packets that haven't been flushed yet
    pendingPacketsRef.current = [];
    if (throttleTimerRef.current) {
      clearTimeout(throttleTimerRef.current);
      throttleTimerRef.current = null;
    }
    packetCountRef.current = 0;
    setPackets([]);
    setAlerts([]);
    setStats(null);
    setPacketRate(0);
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      console.log('[IDS] WebSocket connected');
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        if (msg.type === 'init') {
          setPackets(Array.isArray(msg.data?.recent_packets) ? msg.data.recent_packets : []);
          setAlerts(Array.isArray(msg.data?.recent_alerts) ? msg.data.recent_alerts : []);
          setStats(normalizeStats(msg.data?.stats));
        } else if (msg.type === 'packet') {
          if (msg.data) {
            packetCountRef.current++;
            pendingPacketsRef.current.push(msg.data);
            if (!throttleTimerRef.current) {
              throttleTimerRef.current = setTimeout(() => {
                flushPackets();
                throttleTimerRef.current = null;
              }, THROTTLE_MS);
            }
          }
        } else if (msg.type === 'alert') {
          if (msg.data) {
            setAlerts(prev => [msg.data, ...prev].slice(0, 50));
          }
        } else if (msg.type === 'stats') {
          setStats(normalizeStats(msg.data));
        }
      } catch (e) {
        console.error('[IDS] WS parse error', e);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      console.log('[IDS] WebSocket disconnected, retrying...');
      setTimeout(connect, 3000);
    };

    ws.onerror = (err) => console.error('[IDS] WebSocket error', err);
  }, [url, flushPackets]);

  useEffect(() => {
    connect();
    rateIntervalRef.current = setInterval(() => {
      setPacketRate(packetCountRef.current);
      packetCountRef.current = 0;
    }, 1000);

    return () => {
      wsRef.current?.close();
      clearInterval(rateIntervalRef.current);
      clearTimeout(throttleTimerRef.current);
    };
  }, [connect]);

  return { connected, stats, packets, alerts, packetRate, resetState };
}