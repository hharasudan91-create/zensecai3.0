"use client";

import { useState, useEffect } from "react";
import { Search, ShieldAlert, ShieldCheck, Activity, Globe, Crosshair, Server, ExternalLink, ActivitySquare } from "lucide-react";

export default function ThreatsPage() {
  const [summary, setSummary] = useState<any>(null);
  const [iocs, setIocs] = useState<any[]>([]);
  const [actors, setActors] = useState<any[]>([]);
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const [searchQuery, setSearchQuery] = useState("");
  const [searchResult, setSearchResult] = useState<any>(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState("");

  const fetchData = async () => {
    try {
      setLoading(true);
      const [sumRes, iocRes, actRes, statRes] = await Promise.all([
        fetch("http://localhost:8000/api/v1/threat-intel/summary").then(r => r.json()),
        fetch("http://localhost:8000/api/v1/threat-intel/iocs").then(r => r.json()),
        fetch("http://localhost:8000/api/v1/threat-intel/actors").then(r => r.json()),
        fetch("http://localhost:8000/api/v1/threat-intel/feeds/status").then(r => r.json())
      ]);
      setSummary(sumRes);
      setIocs(iocRes.iocs || []);
      setActors(actRes.actors || []);
      setStatus(statRes);
    } catch (e) {
      console.error("Failed to load TI data", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const detectType = (val: string) => {
    val = val.trim();
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(val)) return "ipv4";
    if (/^[0-9a-fA-F:]+$/.test(val) && val.includes(":")) return "ipv6";
    if (/^https?:\/\//i.test(val)) return "url";
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(val)) return "hash";
    return "domain";
  };

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    setSearchLoading(true);
    setSearchError("");
    setSearchResult(null);

    try {
      const payload = {
        indicator: searchQuery.trim(),
        indicator_type: detectType(searchQuery)
      };
      console.log('Lookup payload:', payload);
      const res = await fetch('http://localhost:8000/api/v1/threat-intel/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      console.log('Lookup response status:', res.status, 'data:', data);
      if (!res.ok) {
        let errMsg = 'Lookup failed';
        if (data.detail) {
          if (Array.isArray(data.detail)) {
            errMsg = data.detail.map((err: any) => `Invalid field '${err.loc.slice(-1)}': ${err.msg}`).join(' | ');
          } else {
            errMsg = data.detail;
          }
        }
        throw new Error(errMsg);
      }
      setSearchResult(data);
    } catch (e: any) {
      console.error('Lookup error:', e);
      setSearchError(e.message);
    } finally {
      setSearchLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] space-y-4">
        <ActivitySquare className="w-12 h-12 text-zinc-500 animate-spin" />
        <h1 className="text-xl text-zinc-300">Loading Threat Intelligence...</h1>
      </div>
    );
  }

  const getRepColor = (rep: string) => {
    if (rep === "MALICIOUS") return "text-red-500 bg-red-500/10 border-red-500/20";
    if (rep === "SUSPICIOUS") return "text-amber-500 bg-amber-500/10 border-amber-500/20";
    if (rep === "CLEAN") return "text-emerald-500 bg-emerald-500/10 border-emerald-500/20";
    return "text-zinc-400 bg-zinc-800 border-zinc-700";
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto pb-20">
      
      {/* Header & Status */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Globe className="text-blue-500" />
            Threat Intelligence
          </h1>
          <p className="text-zinc-400 mt-2">Global threat actors, campaigns, and IOC enrichment.</p>
        </div>
        
        {status && (
          <div className="flex items-center gap-3 bg-zinc-900/50 p-4 rounded-xl border border-zinc-800">
            <div className="relative">
              <div className={`w-3 h-3 rounded-full ${status.overall_status === 'ERROR' ? 'bg-red-500' : 'bg-emerald-500'}`} />
              <div className={`absolute inset-0 w-3 h-3 rounded-full animate-ping ${status.overall_status === 'ERROR' ? 'bg-red-500' : 'bg-emerald-500'}`} />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">{status.label}</p>
              <p className="text-xs text-zinc-500 flex gap-2 mt-1">
                {status.providers?.map((p: any) => (
                  <span key={p.name}>{p.name}: {p.mode}</span>
                ))}
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4">
            <p className="text-zinc-400 text-sm">Total IOCs</p>
            <p className="text-2xl font-bold text-white mt-1">{summary.total_iocs}</p>
          </div>
          <div className="bg-zinc-900/80 border border-red-900/50 rounded-xl p-4">
            <p className="text-red-400 text-sm">Malicious</p>
            <p className="text-2xl font-bold text-red-500 mt-1">{summary.malicious}</p>
          </div>
          <div className="bg-zinc-900/80 border border-amber-900/50 rounded-xl p-4">
            <p className="text-amber-400 text-sm">Suspicious</p>
            <p className="text-2xl font-bold text-amber-500 mt-1">{summary.suspicious}</p>
          </div>
          <div className="bg-zinc-900/80 border border-emerald-900/50 rounded-xl p-4">
            <p className="text-emerald-400 text-sm">Clean</p>
            <p className="text-2xl font-bold text-emerald-500 mt-1">{summary.clean}</p>
          </div>
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-4">
            <p className="text-zinc-400 text-sm">Threat Actors</p>
            <p className="text-2xl font-bold text-purple-400 mt-1">{summary.threat_actors_seen}</p>
          </div>
        </div>
      )}

      {/* Search / Lookup */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
        <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <Search className="w-5 h-5 text-blue-400" />
          IOC Lookup
        </h2>
        <form onSubmit={handleSearch} className="flex gap-4">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Enter IP, Domain, URL, or Hash..."
            className="flex-1 bg-black border border-zinc-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-blue-500"
          />
          <button 
            type="submit" 
            disabled={searchLoading}
            className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-lg font-medium transition-colors disabled:opacity-50"
          >
            {searchLoading ? "Searching..." : "Enrich"}
          </button>
        </form>
        
        {searchError && (
          <div className="mt-4 p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg">
            {searchError}
          </div>
        )}

        {searchResult && (
          <div className="mt-6 border border-zinc-800 rounded-lg overflow-hidden bg-black/50">
            <div className="bg-zinc-900 p-4 border-b border-zinc-800 flex justify-between items-center">
              <div>
                <h3 className="text-lg font-bold text-white">{searchResult.indicator}</h3>
                <p className="text-sm text-zinc-400">Type: {searchResult.indicator_type}</p>
              </div>
              <div className={`px-4 py-1 rounded-full border text-sm font-bold ${getRepColor(searchResult.reputation)}`}>
                {searchResult.reputation} ({searchResult.confidence}%)
              </div>
            </div>
            
            <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              <div>
                <p className="text-xs text-zinc-500 uppercase">Provider</p>
                <p className="text-sm text-white mt-1">{searchResult.source}</p>
                {searchResult.is_simulated && (
                  <span className="inline-block mt-2 text-[10px] bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded border border-purple-500/30">
                    SIMULATED DEMO DATA
                  </span>
                )}
              </div>
              <div>
                <p className="text-xs text-zinc-500 uppercase">Threat Actor</p>
                <p className="text-sm text-white mt-1">{searchResult.threat_actor || "Unknown"}</p>
              </div>
              <div>
                <p className="text-xs text-zinc-500 uppercase">Campaign</p>
                <p className="text-sm text-white mt-1">{searchResult.campaign || "N/A"}</p>
              </div>
              <div>
                <p className="text-xs text-zinc-500 uppercase">Organization / ASN</p>
                <p className="text-sm text-white mt-1">{searchResult.organization || "N/A"} {searchResult.asn ? `(${searchResult.asn})` : ""}</p>
              </div>
              <div>
                <p className="text-xs text-zinc-500 uppercase">Country</p>
                <p className="text-sm text-white mt-1">{searchResult.country || "Unknown"}</p>
              </div>
              <div>
                <p className="text-xs text-zinc-500 uppercase">First / Last Seen</p>
                <p className="text-sm text-white mt-1">
                  {searchResult.first_seen ? new Date(searchResult.first_seen).toLocaleDateString() : "N/A"} 
                  {" → "} 
                  {searchResult.last_seen ? new Date(searchResult.last_seen).toLocaleDateString() : "N/A"}
                </p>
              </div>
            </div>
            
            {searchResult.mitre_techniques && searchResult.mitre_techniques.length > 0 && (
              <div className="p-4 border-t border-zinc-800">
                <p className="text-xs text-zinc-500 uppercase mb-3">MITRE ATT&CK Techniques</p>
                <div className="flex flex-wrap gap-2">
                  {searchResult.mitre_techniques.map((t: any) => (
                    <span key={t.id} className="bg-zinc-800 border border-zinc-700 text-zinc-300 text-xs px-2 py-1 rounded flex items-center gap-1">
                      <Crosshair className="w-3 h-3" />
                      {t.id}: {t.name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Threat Actors */}
        <div className="lg:col-span-1 bg-zinc-900 border border-zinc-800 rounded-xl p-6">
          <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-purple-400" />
            Active Threat Actors
          </h2>
          <div className="space-y-4">
            {actors.length === 0 ? (
              <p className="text-zinc-500 text-sm">No threat actors tracked yet.</p>
            ) : (
              actors.map(actor => (
                <div key={actor.name} className="p-4 bg-black/40 border border-zinc-800 rounded-lg">
                  <div className="flex justify-between items-start mb-2">
                    <h3 className="text-white font-bold">{actor.name}</h3>
                    <span className="text-xs text-purple-400 border border-purple-900/50 bg-purple-900/20 px-2 py-0.5 rounded">
                      {actor.related_iocs?.length || 0} IOCs
                    </span>
                  </div>
                  <p className="text-xs text-zinc-400 mb-3">{actor.campaign || "Unknown Campaign"}</p>
                  
                  <div className="flex flex-wrap gap-1">
                    {actor.known_target_types?.slice(0, 3).map((t: string) => (
                      <span key={t} className="text-[10px] text-zinc-500 bg-zinc-800 px-1.5 py-0.5 rounded">{t}</span>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* IOC List */}
        <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl p-6 overflow-hidden flex flex-col">
          <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
            <Server className="w-5 h-5 text-zinc-400" />
            Recently Enriched IOCs
          </h2>
          
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-zinc-800 text-zinc-500 text-xs uppercase">
                  <th className="pb-3 font-medium">Indicator</th>
                  <th className="pb-3 font-medium">Reputation</th>
                  <th className="pb-3 font-medium">Actor</th>
                  <th className="pb-3 font-medium">Source</th>
                  <th className="pb-3 font-medium text-right">Last Seen</th>
                </tr>
              </thead>
              <tbody className="text-sm">
                {iocs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-4 text-center text-zinc-500">No IOCs recorded</td>
                  </tr>
                ) : (
                  iocs.slice(0, 15).map((ioc, idx) => (
                    <tr key={idx} className="border-b border-zinc-800/50 last:border-0 hover:bg-zinc-800/20">
                      <td className="py-3 text-white font-mono text-xs">{ioc.indicator}</td>
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${getRepColor(ioc.reputation)}`}>
                          {ioc.reputation}
                        </span>
                      </td>
                      <td className="py-3 text-zinc-400 text-xs">{ioc.threat_actor || "Unknown"}</td>
                      <td className="py-3 text-zinc-400 text-xs">
                        {ioc.source}
                        {ioc.is_simulated && <span className="ml-2 text-[10px] text-purple-400 border border-purple-900/50 rounded px-1">DEMO</span>}
                      </td>
                      <td className="py-3 text-zinc-500 text-xs text-right">
                        {ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : "-"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

    </div>
  );
}