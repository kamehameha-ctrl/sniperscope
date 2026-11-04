import React, { useState } from 'react';
import { ShieldAlert, ExternalLink, ChevronDown, ChevronUp } from 'lucide-react';

export default function CveTable({ vulnerabilities, onSelectCve }) {
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState('');

  if (!vulnerabilities || vulnerabilities.length === 0) {
    return null;
  }

  const filtered = vulnerabilities.filter(v => 
    v.cve.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="border-t border-[#1e2638] bg-[#0b0e14] transition-all">
      <div 
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center justify-between px-4 py-2.5 cursor-pointer hover:bg-[#0f131c] transition-colors"
      >
        <div className="flex items-center space-x-2 text-xs font-mono">
          <ShieldAlert size={14} className="text-[#ef4444]" />
          <span className="font-semibold text-slate-200">Discovered Vulnerability Matrix</span>
          <span className="px-2 py-0.5 text-[10px] bg-[#2a1317] border border-[#7f1d1d] text-[#f87171] rounded-full">
            {vulnerabilities.length} CVEs
          </span>
        </div>
        <div className="text-slate-500">
          {isOpen ? <ChevronDown size={15} /> : <ChevronUp size={15} />}
        </div>
      </div>

      {isOpen && (
        <div className="p-4 border-t border-[#1e2638] max-h-64 overflow-y-auto font-mono text-xs">
          <div className="mb-3">
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by CVE identifier (e.g. CVE-2023)..."
              className="w-full max-w-xs bg-[#07090e] border border-[#1e2638] px-3 py-1.5 text-slate-200 rounded text-xs focus:outline-none focus:border-[#ef4444]"
            />
          </div>

          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#1e2638] text-slate-500 text-[11px] uppercase">
                <th className="py-2 px-3">CVE Identifier</th>
                <th className="py-2 px-3">Graph Focus</th>
                <th className="py-2 px-3 text-right">NIST Reference</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2638]/50 text-slate-300">
              {filtered.map((item) => (
                <tr key={item.cve} className="hover:bg-[#0f131c] transition-colors">
                  <td className="py-2 px-3 font-semibold text-slate-200">
                    {item.cve}
                  </td>
                  <td className="py-2 px-3">
                    <button
                      onClick={() => onSelectCve(`cve_${item.cve}`)}
                      className="text-[#38bdf8] hover:underline cursor-pointer"
                    >
                      Focus in Graph
                    </button>
                  </td>
                  <td className="py-2 px-3 text-right">
                    <a
                      href={item.nvd_url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center space-x-1 text-slate-400 hover:text-white transition-colors"
                    >
                      <span>NVD Details</span>
                      <ExternalLink size={11} />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
