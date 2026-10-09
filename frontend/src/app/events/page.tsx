'use client';
import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Activity, ShieldCheck, ShieldAlert, CheckCircle2, Server, Globe, Cpu, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';

type NetworkEvent = {
    id: string;
    timestamp: string;
    sourceIp: string;
    user: string;
    action: string;
    target: string;
    phase: 'INGEST' | 'ML_ANALYSIS' | 'CORRELATION' | 'ALERT';
    riskScore: number;
    message: string;
};

const DUMMY_IPS = ['192.168.1.10', '10.0.4.15', '172.16.2.8', '45.33.22.1', '185.15.2.14'];
const DUMMY_USERS = ['root', 'system', 'j.smith', 'www-data', 'admin'];
const DUMMY_TARGETS = ['Prod-DB-01', 'App-Server-Web', 'Firewall-FW1', 'DESKTOP-JSmith', 'Mail-Server'];

export default function LiveEventsPage() {
    const [events, setEvents] = useState<NetworkEvent[]>([]);
    const [isPaused, setIsPaused] = useState(false);

    useEffect(() => {
        if (isPaused) return;

        const interval = setInterval(() => {
            const isAnomaly = Math.random() > 0.8;

            const riskScore = isAnomaly ? Math.floor(Math.random() * 40) + 60 : Math.floor(Math.random() * 20);
            let phase: NetworkEvent['phase'] = 'INGEST';
            if (riskScore > 30) phase = 'ML_ANALYSIS';
            if (riskScore > 60) phase = 'CORRELATION';
            if (riskScore > 85) phase = 'ALERT';

            const actionTypes = ['Auth', 'File Access', 'Network Conn', 'Syscall', 'Auth'];
            const action = actionTypes[Math.floor(Math.random() * actionTypes.length)];

            const newEvent: NetworkEvent = {
                id: `${Date.now()}-EVT-${Math.floor(Math.random() * 1000000)}`,
                timestamp: new Date().toISOString().split('T')[1].slice(0, -1),
                sourceIp: DUMMY_IPS[Math.floor(Math.random() * DUMMY_IPS.length)],
                user: DUMMY_USERS[Math.floor(Math.random() * DUMMY_USERS.length)],
                action,
                target: DUMMY_TARGETS[Math.floor(Math.random() * DUMMY_TARGETS.length)],
                phase,
                riskScore,
                message: isAnomaly
                    ? `Suspicious ${action.toLowerCase()} detected. Anomaly isolated via Scikit-learn model.`
                    : `Routine ${action.toLowerCase()} verified. Baseline matched.`,
            };

            setEvents(prev => [newEvent, ...prev].slice(0, 50));
        }, 1500);

        return () => clearInterval(interval);
    }, [isPaused]);

    return (
        <div className="flex flex-col h-[calc(100vh-6rem)] max-w-[1600px] mx-auto pb-6">
            <div className="flex items-center justify-between mb-6 flex-none">
                <div>
                    <h1 className="text-3xl font-semibold tracking-tight text-white mb-1">Live Event Pipeline</h1>
                    <p className="text-zinc-400 text-sm">Real-time log ingestion, ML anomaly detection, and correlation stream.</p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={() => setIsPaused(!isPaused)}
                        className={cn(
                            "px-4 py-2 rounded-lg text-sm font-medium border transition-colors",
                            isPaused
                                ? "bg-indigo-500/10 text-indigo-400 border-indigo-500/20 hover:bg-indigo-500/20"
                                : "bg-red-500/10 text-red-500 border-red-500/20 hover:bg-red-500/20"
                        )}
                    >
                        {isPaused ? 'Resume Stream' : 'Pause Stream'}
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-4 gap-4 mb-4 flex-none">
                <div className="glass-panel p-4 rounded-xl border border-[#27272a] shadow-inner">
                    <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2 flex items-center gap-1"><Server className="w-3 h-3" /> 1. Log Ingestion</h3>
                    <p className="text-xs text-zinc-400">Capturing raw Windows Event Logs, Syslog, and AWS CloudTrail.</p>
                </div>
                <div className="glass-panel p-4 rounded-xl border border-[#27272a] shadow-inner border-t-2 border-t-indigo-500">
                    <h3 className="text-xs font-semibold text-indigo-400 uppercase tracking-wider mb-2 flex items-center gap-1"><Cpu className="w-3 h-3" /> 2. ML Analysis</h3>
                    <p className="text-xs text-zinc-400">Isolation Forest (Python/Scikit-learn) mapping behavioral baselines.</p>
                </div>
                <div className="glass-panel p-4 rounded-xl border border-[#27272a] shadow-inner border-t-2 border-t-orange-500">
                    <h3 className="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-2 flex items-center gap-1"><ShieldCheck className="w-3 h-3" /> 3. Correlation</h3>
                    <p className="text-xs text-zinc-400">Linking disparate anomalous events across time into attack vectors.</p>
                </div>
                <div className="glass-panel p-4 rounded-xl border border-[#27272a] shadow-inner border-t-2 border-t-red-500">
                    <h3 className="text-xs font-semibold text-red-500 uppercase tracking-wider mb-2 flex items-center gap-1"><ShieldAlert className="w-3 h-3" /> 4. Alerting</h3>
                    <p className="text-xs text-zinc-400">Critical threats dispatched to SOC dashboard and AI Copilot.</p>
                </div>
            </div>

            <div className="flex-1 glass-panel border border-[#27272a] rounded-xl overflow-hidden flex flex-col font-mono text-xs shadow-2xl relative">
                <div className="bg-[#09090b] border-b border-[#27272a] p-3 flex text-zinc-500 font-semibold sticky top-0 z-10">
                    <div className="w-24">TIME</div>
                    <div className="w-28">PIPELINE STAGE</div>
                    <div className="w-28">SOURCE</div>
                    <div className="w-32">USER / ASSET</div>
                    <div className="w-20">RISK</div>
                    <div className="flex-1">AI INSIGHT / ACTION</div>
                </div>

                <div className="flex-1 overflow-y-auto p-2 space-y-1">
                    {events.length === 0 && (
                        <div className="text-center py-20 text-zinc-500 flex flex-col items-center">
                            <Activity className="w-8 h-8 mb-4 animate-pulse text-indigo-500" />
                            <p>Awaiting network telemetry stream...</p>
                        </div>
                    )}

                    <AnimatePresence initial={false}>
                        {events.map((evt) => (
                            <motion.div
                                key={evt.id}
                                initial={{ opacity: 0, x: -20, backgroundColor: 'rgba(99, 102, 241, 0.2)' }}
                                animate={{ opacity: 1, x: 0, backgroundColor: 'transparent' }}
                                transition={{ duration: 0.5 }}
                                className={cn(
                                    "flex p-2 rounded-md items-center border-l-2 transition-all",
                                    evt.phase === 'ALERT' ? 'border-red-500 bg-red-500/5 hover:bg-red-500/10' :
                                        evt.phase === 'CORRELATION' ? 'border-orange-500 bg-orange-500/5 hover:bg-orange-500/10' :
                                            evt.phase === 'ML_ANALYSIS' ? 'border-indigo-500 hover:bg-[#18181b]' :
                                                'border-zinc-700 hover:bg-[#18181b]'
                                )}
                            >
                                <div className="w-24 text-zinc-400">{evt.timestamp}</div>
                                <div className="w-28">
                                    <span className={cn(
                                        "px-1.5 py-0.5 rounded uppercase font-bold text-[9px]",
                                        evt.phase === 'ALERT' ? "bg-red-500/20 text-red-400" :
                                            evt.phase === 'CORRELATION' ? "bg-orange-500/20 text-orange-400" :
                                                evt.phase === 'ML_ANALYSIS' ? "bg-indigo-500/20 text-indigo-400" :
                                                    "bg-zinc-800 text-zinc-400"
                                    )}>
                                        {evt.phase}
                                    </span>
                                </div>
                                <div className="w-28 font-medium text-emerald-400">{evt.sourceIp}</div>
                                <div className="w-32 flex flex-col justify-center">
                                    <span className="text-zinc-200">{evt.user}</span>
                                    <span className="text-zinc-500 text-[10px]">{evt.target}</span>
                                </div>
                                <div className="w-20">
                                    <div className="flex items-center gap-2">
                                        <span className={cn(
                                            "font-bold",
                                            evt.riskScore > 85 ? "text-red-500" :
                                                evt.riskScore > 60 ? "text-orange-500" :
                                                    evt.riskScore > 30 ? "text-indigo-400" : "text-zinc-400"
                                        )}>{evt.riskScore}</span>
                                    </div>
                                </div>
                                <div className="flex-1 flex items-center text-zinc-300">
                                    {evt.phase === 'ALERT' && <AlertTriangle className="w-3 h-3 text-red-500 mr-2 shrink-0" />}
                                    {evt.phase === 'CORRELATION' && <Activity className="w-3 h-3 text-orange-500 mr-2 shrink-0" />}
                                    {evt.phase === 'ML_ANALYSIS' && <Terminal className="w-3 h-3 text-indigo-400 mr-2 shrink-0" />}
                                    {evt.phase === 'INGEST' && <CheckCircle2 className="w-3 h-3 text-zinc-500 mr-2 shrink-0" />}
                                    <span className="truncate">{evt.message}</span>
                                </div>
                            </motion.div>
                        ))}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
}
