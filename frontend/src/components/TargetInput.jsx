import React, { useState, useEffect } from 'react';
import { Search, Loader2, Shield, Zap } from 'lucide-react';

export default function TargetInput({ onScan, isLoading, activeTarget, scanMode = 'passive', onChangeScanMode }) {
  const [target, setTarget] = useState('');

  useEffect(() => {
    setTarget(activeTarget || '');
  }, [activeTarget]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (target.trim() && !isLoading) {
      // Re-triggering search ignores memory cache and performs a fresh live scan
      onScan(target.trim(), true);
    }
  };

  const handleQuickTarget = (domain) => {
    setTarget(domain);
    onScan(domain, true);
  };

  return (
    <div className="w-full flex flex-col lg:flex-row items-center justify-between gap-3 py-1.5">
      <div className="flex flex-col sm:flex-row items-center gap-2.5 w-full lg:w-auto flex-1 max-w-3xl">
        <form onSubmit={handleSubmit} className="relative flex-1 w-full">
          <div className="relative flex items-center">
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Target domain, URL, or IPv4/IPv6 (e.g. scanme.nmap.org, 1.1.1.1)..."
              disabled={isLoading}
              className="w-full bg-[#07090e] border border-[#1e2638] focus:border-[#38bdf8] focus:outline-none text-slate-100 text-sm font-mono px-3.5 py-2 pr-11 rounded transition-all placeholder:text-slate-600"
            />
            <button
              type="submit"
              disabled={isLoading || !target.trim()}
              title="Launch OSINT reconnaissance and attack surface scan"
              className="absolute right-1.5 p-1.5 bg-[#1e2638] hover:bg-[#0284c7] disabled:opacity-40 text-slate-100 rounded transition-colors flex items-center justify-center cursor-pointer"
            >
              {isLoading ? (
                <Loader2 size={15} className="animate-spin text-[#38bdf8]" />
              ) : (
                <Search size={15} />
              )}
            </button>
          </div>
        </form>

        {/* OPSEC Mode Switcher: Stealth (Passive) vs Active (Authorized) */}
        <div className="flex items-center bg-[#07090e] border border-[#1e2638] p-0.5 rounded font-mono text-[11px] shrink-0">
          <button
            type="button"
            onClick={() => onChangeScanMode && onChangeScanMode('passive')}
            title="Stealth Mode (100% passive: zero sensitive probing, zero port probing, standard Chrome User-Agent)"
            className={`px-2.5 py-1.5 rounded flex items-center space-x-1.5 transition-colors cursor-pointer ${
              scanMode === 'passive'
                ? 'bg-[#064e3b] text-[#a7f3d0] border border-[#10b981]/50 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield size={12} className={scanMode === 'passive' ? 'text-[#10b981]' : 'text-slate-500'} />
            <span>Stealth (Passive)</span>
          </button>
          <button
            type="button"
            onClick={() => onChangeScanMode && onChangeScanMode('active')}
            title="Active Mode (Authorized only: probes sensitive paths, CORS, and performs port banner grabbing)"
            className={`px-2.5 py-1.5 rounded flex items-center space-x-1.5 transition-colors cursor-pointer ${
              scanMode === 'active'
                ? 'bg-[#431407] text-[#fed7aa] border border-[#fb923c]/50 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Zap size={12} className={scanMode === 'active' ? 'text-[#fb923c]' : 'text-slate-500'} />
            <span>Active (Deep Audit)</span>
          </button>
        </div>
      </div>

      {/* Quick sample targets */}
      <div className="flex items-center space-x-2 text-xs font-mono text-slate-500 shrink-0">
        <span className="text-[11px] uppercase tracking-wider text-slate-600">Samples:</span>
        <button
          type="button"
          onClick={() => handleQuickTarget('scanme.nmap.org')}
          disabled={isLoading}
          className="hover:text-slate-300 underline decoration-slate-700 underline-offset-4 transition-colors cursor-pointer"
        >
          scanme.nmap.org
        </button>
        <span>·</span>
        <button
          type="button"
          onClick={() => handleQuickTarget('example.com')}
          disabled={isLoading}
          className="hover:text-slate-300 underline decoration-slate-700 underline-offset-4 transition-colors cursor-pointer"
        >
          example.com
        </button>
      </div>
    </div>
  );
}
