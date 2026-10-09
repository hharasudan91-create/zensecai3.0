"use client";

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, Lock, ShieldAlert, Globe, PowerOff, Plus, AlertCircle, RefreshCw, Ban } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ReferenceLine, ReferenceArea, Area, ResponsiveContainer } from 'recharts';

export default function AnalyticsPage() {
  const [connections, setConnections] = useState<any[]>([]);
  const [selectedConnection, setSelectedConnection] = useState<string>('');
  const [isConnected, setIsConnected] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newConnData, setNewConnData] = useState({ website_url: '', customer_name: '' });
  const [addConnError, setAddConnError] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  // Real-time states
  const [securityEvents, setSecurityEvents] = useState<any[]>([]);
  const [chartData, setChartData] = useState<any[]>([]);
  const [faultExplanation, setFaultExplanation] = useState<any>(null);
  
  const [blockTimer, setBlockTimer] = useState<number | null>(null);
  const [blockPageTimer, setBlockPageTimer] = useState<number | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const demoIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const demoIndexRef = useRef<number>(0);
  const apiBase = process.env.NEXT_PUBLIC_API_BASE ?? 'http://localhost:8000';

  // Simulated score sequence for demo/presentation graph only.
  // These values are NEVER sent to the backend or WebSocket.
  const DEMO_SCORES: { score: number; risk_band: string }[] = [
    { score: 32, risk_band: 'LOW' },
    { score: 41, risk_band: 'LOW' },
    { score: 38, risk_band: 'LOW' },
    { score: 55, risk_band: 'MEDIUM' },
    { score: 47, risk_band: 'MEDIUM' },
    { score: 63, risk_band: 'MEDIUM' },
    { score: 58, risk_band: 'MEDIUM' },
    { score: 72, risk_band: 'HIGH' },
    { score: 68, risk_band: 'HIGH' },
    { score: 81, risk_band: 'CRITICAL' },
    { score: 76, risk_band: 'HIGH' },
    { score: 69, risk_band: 'HIGH' },
  ];

  const fetchConnections = async () => {
  try {
    const res = await fetch(`${apiBase}/api/v1/connections`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    setConnections(data);
  } catch (err) {
    console.error('Failed to load connections', err);
  }
};

  useEffect(() => {
    fetchConnections();
  }, []);

  useEffect(() => {
    let timerId: any;
    if (blockTimer !== null && blockTimer > 0) {
      timerId = setInterval(() => {
        setBlockTimer(prev => (prev && prev > 0 ? prev - 1 : 0));
      }, 1000);
    }
    return () => clearInterval(timerId);
  }, [blockTimer]);

  useEffect(() => {
    let timerId: any;
    if (blockPageTimer !== null && blockPageTimer > 0) {
      timerId = setInterval(() => {
        setBlockPageTimer(prev => (prev && prev > 0 ? prev - 1 : 0));
      }, 1000);
    }
    return () => clearInterval(timerId);
  }, [blockPageTimer]);

  const handleAddConnection = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    
    setAddConnError('');
    setIsSubmitting(true);

    if (!newConnData.customer_name.trim() || !newConnData.website_url.trim()) {
      setAddConnError("Customer Name and Website URL are required.");
      setIsSubmitting(false);
      return;
    }
    if (!/^https?:\/\//i.test(newConnData.website_url.trim())) {
      setAddConnError("Website URL must start with http:// or https://");
      setIsSubmitting(false);
      return;
    }

    try {
      const res = await fetch(`${apiBase}/api/v1/connections`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newConnData),
        mode: 'cors', // ensure CORS request
      });
      if (res.ok) {
        setShowAddModal(false);
        setNewConnData({ website_url: '', customer_name: '' });
        fetchConnections();
      } else {
        const errData = await res.json().catch(() => ({}));
        setAddConnError(errData.detail || "Failed to create connection.");
      }
    } catch (err) {
      console.error("Failed to add connection", err);
      setAddConnError("Network error: Backend is unavailable.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleConnect = () => {
    if (!selectedConnection) return;
    setIsConnected(true);
    setSecurityEvents([]);
    setChartData([]);
    setFaultExplanation(null);
    demoIndexRef.current = 0;

    if (wsRef.current) wsRef.current.close();

    // ── Demo ticker: feeds simulated score values into the graph every 2 s.
    // This is purely for visual presentation and does NOT touch the backend,
    // WebSocket logic, SECURITY_EVENT pipeline, or event feed table.
    if (demoIntervalRef.current) clearInterval(demoIntervalRef.current);
    demoIntervalRef.current = setInterval(() => {
      const idx = demoIndexRef.current % DEMO_SCORES.length;
      const point = DEMO_SCORES[idx];
      demoIndexRef.current += 1;
      const timeStr = new Date().toLocaleTimeString();
      setChartData(prev => {
        const updated = [...prev, { time: timeStr, score: point.score, risk_band: point.risk_band, demo: true }];
        return updated.slice(-20);
      });
    }, 2000);

    console.log('[ZentraSec WS] Connecting to', `${apiBase.replace(/^http/, 'ws')}/api/v1/ws/security-flow/${selectedConnection}`);
    const ws = new WebSocket(`${apiBase.replace(/^http/, 'ws')}/api/v1/ws/security-flow/${selectedConnection}`);

    ws.onopen = () => {
      console.log('[ZentraSec WS] Connected');
    };
    ws.onerror = (e) => {
      console.error('[ZentraSec WS] Error', e);
    };

    ws.onmessage = (event) => {
      console.log('[ZentraSec WS] Message received:', event.data);
      const data = JSON.parse(event.data);
      const now = new Date();
      const timeStr = now.toLocaleTimeString();

      if (data.type === 'SECURITY_EVENT') {
        setSecurityEvents(prev => [data, ...prev].slice(0, 50));
        setChartData(prev => {
          const newData = [...prev, { time: timeStr, score: data.anomaly_score, risk_band: data.risk_band }];
          return newData.slice(-20);
        });
      } else if (data.type === 'FAULT_EXPLANATION') {
        setFaultExplanation(data);
      }
    };

    wsRef.current = ws;
  };
  
  const disconnect = () => {
    if (wsRef.current) wsRef.current.close();
    if (demoIntervalRef.current) { clearInterval(demoIntervalRef.current); demoIntervalRef.current = null; }
    setIsConnected(false);
  };

  const handleBlockAccount = () => {
    setBlockTimer(10); // 10 seconds
    fetch(`${apiBase}/api/v1/incidents/SIMULATED/suspend-10sec`, {
        method: 'POST'
      }).catch(console.error);
  };

  const handleBlockPage = async () => {
    if (!selectedConnection) return;
    try {
      const res = await fetch(`${apiBase}/api/v1/connections/${selectedConnection}/block-page`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setBlockPageTimer(data.mitigation_time || 10);
      }
    } catch (err) {
      console.error('[ZentraSec] Block Page action failed', err);
    }
  };

  const formatTimer = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  };

  // Risk color utilities for UI classes and chart hex colors
const getRiskColor = (band: string) => {
  switch (band) {
    case 'CRITICAL': return 'text-red-500';
    case 'HIGH': return 'text-orange-500';
    case 'MEDIUM': return 'text-yellow-500';
    case 'LOW': default: return 'text-emerald-500';
  }
};

// Hex color values for chart styling
const getRiskHex = (band: string) => {
  switch (band) {
    case 'CRITICAL': return '#ef4444';
    case 'HIGH': return '#fb923c';
    case 'MEDIUM': return '#fbbf24';
    case 'LOW': default: return '#10b981';
  }
};

// Background utilities for risk badges
const getRiskBg = (band: string) => {
  switch (band) {
    case 'CRITICAL': return 'bg-red-500/20';
    case 'HIGH': return 'bg-orange-500/20';
    case 'MEDIUM': return 'bg-yellow-500/20';
    case 'LOW': default: return 'bg-emerald-500/20';
  }
};

// Custom dot component for chart points
const CustomDot = (props: any) => {
  const { cx, cy, payload } = props;
  const color = getRiskHex(payload.risk_band || 'LOW');
  return <circle cx={cx} cy={cy} r={4} fill={color} />;
};

  return (
    <div className="p-6 md:p-8 space-y-8 min-h-full bg-zinc-950 text-white">
      {/* Header section */}
      <div className="flex flex-col space-y-2">
        <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
          <Activity className="text-emerald-400 w-8 h-8" />
          SOC Dashboard - Live Analytics
        </h1>
        <p className="text-zinc-400 text-lg">
          Real-time Event Correlation and Risk Analysis
        </p>
      </div>

      {/* Connection Section */}
      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6 shadow-xl backdrop-blur-sm">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <Globe className="text-emerald-400" />
            Website Telemetry Connection
          </h2>
          <button 
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1 text-sm bg-zinc-800 hover:bg-zinc-700 px-3 py-1.5 rounded-md"
          >
            <Plus size={16} /> Add Connection
          </button>
        </div>

        <div className="flex flex-col sm:flex-row gap-4">
          <select 
            className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg py-3 px-4 focus:outline-none focus:border-emerald-500 transition-colors"
            value={selectedConnection}
            onChange={(e) => setSelectedConnection(e.target.value)}
            disabled={isConnected}
          >
            <option value="">-- Select Connection ID --</option>
            {connections.map(c => (
              <option key={c.connection_id} value={c.connection_id}>
                {c.customer_name} ({c.connection_id}) - {c.website_url}
              </option>
            ))}
          </select>
          
          {!isConnected ? (
            <button 
              onClick={handleConnect}
              disabled={!selectedConnection}
              className="px-6 py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded-lg font-medium transition-colors"
            >
              Start Monitoring
            </button>
          ) : (
            <button 
              onClick={disconnect}
              className="px-6 py-3 bg-red-600 hover:bg-red-500 rounded-lg font-medium transition-colors flex items-center gap-2"
            >
              <PowerOff size={18} /> Stop
            </button>
          )}
        </div>
        
        {/* Selected connection details */}
        {selectedConnection && connections.find(c => c.connection_id === selectedConnection) && (
            <div className="mt-4 text-xs text-zinc-500 flex gap-4">
                <span><strong className="text-zinc-400">ID:</strong> {selectedConnection}</span>
                <span><strong className="text-zinc-400">Token:</strong> {connections.find(c => c.connection_id === selectedConnection).secure_token}</span>
            </div>
        )}
      </div>

      <AnimatePresence>
        {isConnected && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Waveform Chart */}
              <div className="lg:col-span-2 bg-zinc-900/80 border border-zinc-800 rounded-xl p-6 shadow-xl relative">
                {/* DEMO DATA badge — clearly marks graph as simulated */}
                <div className="absolute top-4 right-4 flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/15 border border-amber-500/40 select-none">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-400"></span>
                  </span>
                  <span className="text-xs font-semibold tracking-widest uppercase text-amber-400">Simulated Data</span>
                </div>
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Activity className="text-emerald-400 w-5 h-5" />
                  Live Activity Waveform (Anomaly Score)
                </h3>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={chartData}>
                      <defs>
                        <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10b981" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#1e293b" stopOpacity={0.2} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                      <XAxis dataKey="time" stroke="#888" tick={{fontSize:12}} />
                      <YAxis domain={[0,100]} stroke="#888" tick={{fontSize:12}} />
                      <Tooltip contentStyle={{backgroundColor:'#18181b',borderColor:'#27272a'}} />
                      <ReferenceLine y={25} stroke="#34d399" strokeDasharray="3 3" label={{ position: 'top', value: 'Low', fill: '#34d399', fontSize: 12 }} />
                      <ReferenceLine y={50} stroke="#fbbf24" strokeDasharray="3 3" label={{ position: 'top', value: 'Medium', fill: '#fbbf24', fontSize: 12 }} />
                      <ReferenceLine y={75} stroke="#fb923c" strokeDasharray="3 3" label={{ position: 'top', value: 'High', fill: '#fb923c', fontSize: 12 }} />
                      <ReferenceLine y={60} stroke="#f59e0b" strokeDasharray="3 3" label={{ position: 'top', value: 'Suspicious', fill: '#f59e0b', fontSize: 12 }} />
                      <ReferenceLine y={80} stroke="#ef4444" strokeDasharray="3 3" label={{ position: 'top', value: 'Critical', fill: '#ef4444', fontSize: 12 }} />
                      <ReferenceArea y1={0} y2={25} fill="#10b981" fillOpacity={0.1} />
                      <ReferenceArea y1={25} y2={60} fill="#f59e0b" fillOpacity={0.1} />
                      <ReferenceArea y1={60} y2={100} fill="#ef4444" fillOpacity={0.1} />
                      <Area type="monotone" dataKey="score" stroke={false} fill="url(#scoreGradient)" />
                      <Line type="monotone" dataKey="score" stroke={getRiskHex(chartData[chartData.length - 1]?.risk_band || 'LOW')} strokeWidth={2} dot={<CustomDot />} activeDot={{ r: 6 }} isAnimationActive={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Risk Panel & AI Fault */}
              <div className="lg:col-span-1 space-y-6">
                <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6 shadow-xl">
                   <h3 className="text-lg font-semibold mb-4">Current Risk Level</h3>
                   {securityEvents.length > 0 ? (
                       <div className="text-center">
                           <div className={`text-5xl font-bold mb-2 ${getRiskColor(securityEvents[0].risk_band)}`}>
                               {securityEvents[0].anomaly_score}
                           </div>
                           <div className={`inline-block px-3 py-1 rounded text-sm font-semibold ${getRiskBg(securityEvents[0].risk_band)} ${getRiskColor(securityEvents[0].risk_band)}`}>
                               {securityEvents[0].risk_band}
                           </div>
                       </div>
                   ) : (
                       <div className="text-center text-zinc-500 py-4">Waiting for data...</div>
                   )}
                </div>

                <AnimatePresence>
                    {faultExplanation && (
                        <motion.div 
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            className="bg-red-950/40 border border-red-900 rounded-xl p-6 shadow-xl"
                        >
                            <h3 className="text-lg font-semibold text-red-400 mb-3 flex items-center gap-2">
                                <AlertCircle className="w-5 h-5" />
                                AI Copilot Fault Analysis
                            </h3>
                            <div className="text-sm text-red-200 mb-4 whitespace-pre-wrap">
                                {faultExplanation.explanation}
                            </div>
                            <h4 className="font-semibold text-red-300 mb-2 text-sm">Recommended Actions:</h4>
                            <ul className="list-disc pl-5 text-xs text-red-200/80 space-y-1">
                                {faultExplanation.recommended_actions?.map((action: string, i: number) => (
                                    <li key={i}>{action}</li>
                                ))}
                            </ul>
                        </motion.div>
                    )}
                </AnimatePresence>
              </div>

            </div>

            {/* Live Event Feed */}
            <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6 shadow-xl">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <RefreshCw className="w-5 h-5 text-emerald-400" />
                Live Event Feed
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="text-xs text-zinc-400 uppercase bg-zinc-800/50">
                    <tr>
                      <th className="px-4 py-3">Timestamp</th>
                      <th className="px-4 py-3">Event Type</th>
                      <th className="px-4 py-3">User</th>
                      <th className="px-4 py-3">Source IP</th>
                      <th className="px-4 py-3">Score</th>
                      <th className="px-4 py-3">Risk</th>
                      <th className="px-4 py-3">Detections</th>
                    </tr>
                  </thead>
                  <tbody>
                    {securityEvents.map((evt, idx) => (
                      <tr key={idx} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                        <td className="px-4 py-3 text-zinc-400 whitespace-nowrap">
                            {new Date(evt.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="px-4 py-3 font-medium text-zinc-200">{evt.event_type}</td>
                        <td className="px-4 py-3 text-zinc-400">{evt.user_id}</td>
                        <td className="px-4 py-3 text-zinc-400">{evt.source_ip}</td>
                        <td className="px-4 py-3 font-mono">{evt.anomaly_score.toFixed(1)}</td>
                        <td className="px-4 py-3">
                            <span className={`px-2 py-1 rounded text-xs font-semibold ${getRiskBg(evt.risk_band)} ${getRiskColor(evt.risk_band)}`}>
                                {evt.risk_band}
                            </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-red-400 max-w-[200px] truncate">
                            {evt.detections?.join(", ")}
                        </td>
                      </tr>
                    ))}
                    {securityEvents.length === 0 && (
                      <tr>
                        <td colSpan={7} className="px-4 py-8 text-center text-zinc-500">
                          Listening for incoming security events...
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
            
            {/* Incident Mitigation & Block Actions */}
            <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
               {((blockTimer !== null && blockTimer > 0) || (blockPageTimer !== null && blockPageTimer > 0)) && (
                 <div className="absolute inset-0 bg-red-950/20 backdrop-blur-[1px] pointer-events-none border border-red-500/30 rounded-xl z-10 flex items-center justify-center">
                    <div className="flex flex-col gap-3">
                      {blockTimer !== null && blockTimer > 0 && (
                        <div className="bg-red-950/90 border border-red-500/50 px-6 py-4 rounded-xl shadow-2xl flex items-center gap-4 animate-pulse">
                           <Lock className="text-red-500 w-8 h-8" />
                           <div>
                             <h3 className="text-red-400 font-bold text-lg">ACCOUNT BLOCKED</h3>
                             <p className="text-red-200 font-mono text-2xl">{formatTimer(blockTimer)}</p>
                           </div>
                        </div>
                      )}
                      {blockPageTimer !== null && blockPageTimer > 0 && (
                        <div className="bg-orange-950/90 border border-orange-500/50 px-6 py-4 rounded-xl shadow-2xl flex items-center gap-4 animate-pulse">
                           <Ban className="text-orange-500 w-8 h-8" />
                           <div>
                             <h3 className="text-orange-400 font-bold text-lg">PAGE ACCESS BLOCKED</h3>
                             <p className="text-orange-200 font-mono text-2xl">{formatTimer(blockPageTimer)}</p>
                           </div>
                        </div>
                      )}
                    </div>
                 </div>
               )}
               
               <div className="flex justify-between items-center mb-6">
                 <h3 className="text-xl font-semibold flex items-center gap-2">
                   <ShieldAlert className="w-5 h-5 text-amber-400" />
                   Critical Mitigations
                 </h3>
               </div>
               
               <p className="text-zinc-400 text-sm mb-6">If critical or unsolved anomalous login activity is detected on the customer's asset memory, you can temporarily suspend their account or block page access to contain immediate threats.</p>
               
               <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                 <div className="flex items-center gap-4 p-4 bg-zinc-950 border border-zinc-800 rounded-lg">
                   <div className="flex-1">
                     <h4 className="font-semibold text-zinc-200 mb-1">Block Login (10 Seconds)</h4>
                     <p className="text-xs text-zinc-500">Drops all active sessions and blocks incoming authentication for 7 minutes.</p>
                   </div>
                   <button 
                     onClick={handleBlockAccount}
                     disabled={blockTimer !== null && blockTimer > 0}
                     className="px-5 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:hover:bg-red-600 rounded text-sm font-medium transition-colors flex items-center gap-2 whitespace-nowrap"
                   >
                     <Lock size={16} />
                     {blockTimer !== null && blockTimer > 0 ? 'Blocked' : '🔒 Block Login'}
                   </button>
                 </div>
                 <div className="flex items-center gap-4 p-4 bg-zinc-950 border border-zinc-800 rounded-lg">
                   <div className="flex-1">
                     <h4 className="font-semibold text-zinc-200 mb-1">Block Page (7 Minutes)</h4>
                     <p className="text-xs text-zinc-500">Restricts access to the connected application page for 7 minutes.</p>
                   </div>
                   <button 
                     onClick={handleBlockPage}
                     disabled={(blockPageTimer !== null && blockPageTimer > 0) || !selectedConnection}
                     className="px-5 py-2 bg-orange-600 hover:bg-orange-500 disabled:opacity-50 disabled:hover:bg-orange-600 rounded text-sm font-medium transition-colors flex items-center gap-2 whitespace-nowrap"
                   >
                     <Ban size={16} />
                     {blockPageTimer !== null && blockPageTimer > 0 ? 'Blocked' : '🚫 Block Page'}
                   </button>
                 </div>
               </div>
            </div>

          </motion.div>
        )}
      </AnimatePresence>

      {/* Add Connection Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-zinc-900 border border-zinc-800 p-6 rounded-xl w-full max-w-md shadow-2xl">
            <h3 className="text-xl font-semibold mb-4">Add Website Connection</h3>
            
            {addConnError && (
              <div className="mb-4 p-3 bg-red-950/40 border border-red-900 rounded-md text-red-400 text-sm flex items-center gap-2">
                <AlertCircle size={16} />
                <span>{addConnError}</span>
              </div>
            )}
            
            <form onSubmit={handleAddConnection} className="space-y-4">
              <div>
                <label className="block text-sm text-zinc-400 mb-1">Customer Name</label>
                <input 
                  type="text" 
                  required
                  value={newConnData.customer_name}
                  onChange={e => setNewConnData({...newConnData, customer_name: e.target.value})}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500" 
                  placeholder="e.g. Acme Corp"
                />
              </div>
              <div>
                <label className="block text-sm text-zinc-400 mb-1">Website URL</label>
                <input 
                  type="url" 
                  required
                  value={newConnData.website_url}
                  onChange={e => setNewConnData({...newConnData, website_url: e.target.value})}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-white focus:outline-none focus:border-emerald-500" 
                  placeholder="https://example.com"
                />
              </div>
              <div className="flex justify-end gap-3 mt-6">
                <button 
                  type="button" 
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 rounded transition-colors"
                >
                  Cancel
                </button>
                <button 
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded transition-colors"
                >
                  {isSubmitting ? "Creating..." : "Create"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}