import React, { useState, useEffect } from 'react';
import {
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Terminal,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Lock,
  Search,
  Copy,
  Check,
  Flame,
  AlertTriangle,
  Crosshair,
  Clock,
  Trash2,
  RefreshCw,
  Zap,
  Bug,
  FileText,
  X,
  Camera
} from 'lucide-react';
import { fetchBrandProtection } from '../services/api';

function SeverityBadge({ severity, cvss }) {
  const sev = (severity || 'MEDIUM').toUpperCase();
  const styles = {
    CRITICAL: 'bg-[#2d0f14] text-[#f87171] border-[#991b1b]',
    HIGH: 'bg-[#2e190e] text-[#fb923c] border-[#9a3412]',
    MEDIUM: 'bg-[#2b2108] text-[#facc15] border-[#854d0e]',
    LOW: 'bg-[#0f2438] text-[#38bdf8] border-[#0369a1]',
  };
  return (
    <span className={`inline-flex items-center space-x-1.5 px-2 py-0.5 text-[10px] font-mono font-bold uppercase border rounded ${styles[sev] || styles.MEDIUM}`}>
      <span>{sev}</span>
      {cvss !== null && cvss !== undefined && (
        <span className="opacity-95">· CVSS {Number(cvss).toFixed(1)}</span>
      )}
    </span>
  );
}

function copyTextToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    try {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-9999px';
      textArea.style.top = '0';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      const successful = document.execCommand('copy');
      document.body.removeChild(textArea);
      if (successful) {
        resolve();
      } else {
        reject(new Error('Could not copy command'));
      }
    } catch (err) {
      reject(err);
    }
  });
}

function CopyCommandBlock({ label, command }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await copyTextToClipboard(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div
      className={`rounded p-3 space-y-1.5 transition-all duration-200 border ${
        copied
          ? 'bg-[#06241b]/60 border-[#10b981]'
          : 'bg-[#090b10] border-[#1e2638]'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span
          className={`text-[10px] uppercase tracking-wider font-semibold transition-colors ${
            copied ? 'text-[#a7f3d0]' : 'text-slate-400'
          }`}
        >
          {label}
        </span>
        <button
          type="button"
          onClick={handleCopy}
          className={`px-2.5 py-1 rounded text-[10px] flex items-center space-x-1.5 cursor-pointer transition-all duration-200 border ${
            copied
              ? 'bg-[#064e3b] text-[#a7f3d0] border-[#10b981] font-bold'
              : 'bg-[#151c28] hover:bg-[#1e2638] text-slate-300 border-[#1e2638]'
          }`}
        >
          {copied ? (
            <>
              <Check size={12} className="text-[#10b981]" />
              <span>Command copied!</span>
            </>
          ) : (
            <>
              <Copy size={11} />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <pre
        onClick={handleCopy}
        title="Click to copy command"
        className={`text-[11px] overflow-x-auto whitespace-pre-wrap select-all p-2 rounded border cursor-pointer transition-colors duration-200 ${
          copied
            ? 'bg-[#041812] text-[#10b981] border-[#10b981]/60'
            : 'bg-[#06080c] text-[#38bdf8] border-[#141a26]'
        }`}
      >
        {command}
      </pre>
    </div>
  );
}

export default function IntelDossier({
  scanData,
  onFocusNode,
  recentScans = [],
  onSelectRecent,
  onClearRecent,
  onRefreshScan,
}) {
  const [activeSection, setActiveSection] = useState('all');
  const [activeCliTab, setActiveCliTab] = useState('all');
  const [brandData, setBrandData] = useState(null);
  const [brandLoading, setBrandLoading] = useState(false);
  const [brandError, setBrandError] = useState(null);
  const [selectedTakedown, setSelectedTakedown] = useState(null);
  const [copiedNotice, setCopiedNotice] = useState(false);
  const [screenshotNonce, setScreenshotNonce] = useState(0);

  useEffect(() => {
    if (scanData?.brand_protection && Object.keys(scanData.brand_protection).length > 0) {
      setBrandData(scanData.brand_protection);
    } else {
      setBrandData(null);
    }
  }, [scanData?.target, scanData?.brand_protection]);

  const handleAuditBrand = async () => {
    if (!target) return;
    setBrandLoading(true);
    setBrandError(null);
    try {
      const data = await fetchBrandProtection(target);
      setBrandData(data);
    } catch (err) {
      setBrandError(err.message || 'Error auditing brand protection');
    } finally {
      setBrandLoading(false);
    }
  };

  const handleCopyTakedown = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedNotice(true);
    setTimeout(() => setCopiedNotice(false), 2000);
  };

  if (!scanData) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-6 bg-[#090b10] select-text overflow-y-auto">
        <div className="max-w-xl w-full flex flex-col items-center text-center">
          <div className="w-12 h-12 rounded border border-[#38bdf8]/40 bg-[#0f172a] flex items-center justify-center text-[#38bdf8] mb-3">
            <Crosshair size={24} />
          </div>
          <div className="text-base font-mono text-slate-100 font-bold tracking-wide">
            SNIPERSCOPE // EASM & OSINT INTELLIGENCE STATION
          </div>
          <p className="text-xs font-mono text-slate-500 max-w-md mt-1.5 leading-relaxed">
            Enter a domain, URL, or IP address in the top bar to launch attack surface reconnaissance: open ports, exact component versions, TLS certificates, WAF/CDN, web exposures, CVEs with CVSS/EPSS/KEV, and active audit playbook.
          </p>

          {/* Local Cache Audit History */}
          {recentScans.length > 0 && (
            <div className="w-full mt-8 text-left bg-[#0c1017] border border-[#1e2638] rounded p-4 font-mono">
              <div className="flex items-center justify-between border-b border-[#1e2638] pb-2.5 mb-3">
                <div className="flex items-center space-x-2 text-xs font-bold text-slate-300 uppercase">
                  <Clock size={13} className="text-[#38bdf8]" />
                  <span>Locally Cached Sessions (Instant Load)</span>
                </div>
                <button
                  type="button"
                  onClick={onClearRecent}
                  className="text-[10px] text-slate-500 hover:text-[#ef4444] flex items-center space-x-1 cursor-pointer transition-colors"
                >
                  <Trash2 size={11} />
                  <span>Clear cache</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {recentScans.map((item) => (
                  <div
                    key={item.target}
                    onClick={() => onSelectRecent && onSelectRecent(item)}
                    className="p-3 bg-[#090b10] hover:bg-[#131926] border border-[#1e2638] hover:border-[#38bdf8]/50 rounded cursor-pointer transition-all flex items-center justify-between"
                    title="Restore cached session without re-scanning"
                  >
                    <div className="min-w-0 pr-2">
                      <div className="flex items-center space-x-1.5">
                        <span className="text-xs font-bold text-white truncate">{item.target}</span>
                        <span className="px-1.5 py-0.2 bg-[#064e3b]/60 border border-[#10b981]/40 text-[#a7f3d0] text-[9px] rounded uppercase shrink-0">
                          Cached
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {item.summary?.open_ports_count ?? 0} ports · {item.summary?.vulnerabilities_count ?? 0} CVEs
                      </div>
                    </div>
                    {item.risk && (
                      <div
                        className={`px-2 py-0.5 text-xs font-bold rounded border shrink-0 ${
                          item.risk.score >= 75
                            ? 'text-[#ef4444] border-[#991b1b] bg-[#2d0f14]/50'
                            : item.risk.score >= 50
                            ? 'text-[#fb923c] border-[#9a3412] bg-[#2e190e]/50'
                            : 'text-[#10b981] border-[#065f46] bg-[#064e3b]/40'
                        }`}
                      >
                        {item.risk.grade} ({item.risk.score})
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  const {
    target,
    scan_timestamp,
    scan_duration_sec,
    risk = {},
    summary = {},
    shodan = [],
    dns = {},
    rdap_domain = {},
    http_audit = {},
    subdomains = [],
    subdomain_ips = [],
    vulnerabilities = [],
    geo = {},
    perimeter_hosts = {},
  } = scanData;

  const navItems = [
    { id: 'all', label: 'Dossier', title: 'Full Dossier (All sections)', group: 'surface' },
    { id: 'services', label: `Services (${summary.open_ports_count || 0})`, title: 'Open Ports & Services', group: 'surface' },
    { id: 'http', label: 'Web & TLS', title: 'Web Security, TLS Certificate & WAF/CDN', group: 'surface' },
    { id: 'dns', label: `DNS (${summary.subdomains_count || 0})`, title: 'DNS Zone Records & Subdomains', group: 'surface' },
    { id: 'vulns', label: `CVEs (${summary.vulnerabilities_count || 0})`, title: 'Identified Vulnerabilities (Shodan CVEDB)', group: 'threats' },
    { id: 'brand', label: `Brand${brandData ? ` (${brandData.active_threats_count > 0 ? brandData.active_threats_count : (brandData.target_forensics?.is_recent ? '⚠️' : '0')})` : ''}`, title: 'Brand Protection, Lookalikes & Phishing Forensics', group: 'threats' },
    { id: 'dorks', label: 'Dorks', title: 'OSINT Google & Shodan Dorks', group: 'tools' },
    { id: 'playbook', label: 'CLI', title: 'CLI Playbook & Exploitation Commands', group: 'tools' },
  ];

  const showSection = (sec) => activeSection === 'all' || activeSection === sec;

  const primaryIp = shodan[0]?.ip || target;
  const openPortsStr = shodan[0]?.ports?.length ? shodan[0].ports.join(',') : '22,80,443';

  // Mapa rápido de IPs por subdominio
  const subIpMap = {};
  subdomain_ips.forEach((s) => {
    if (s.subdomain && s.ips?.length) {
      subIpMap[s.subdomain] = s.ips;
    }
  });

  const riskColor =
    risk.score >= 75
      ? 'text-[#ef4444] border-[#991b1b] bg-[#2d0f14]/50'
      : risk.score >= 50
      ? 'text-[#fb923c] border-[#9a3412] bg-[#2e190e]/50'
      : risk.score >= 25
      ? 'text-[#facc15] border-[#854d0e] bg-[#2b2108]/50'
      : 'text-[#10b981] border-[#065f46] bg-[#064e3b]/40';

  return (
    <div className="h-full flex flex-col bg-[#090b10] text-slate-200 select-text overflow-hidden">
      {/* Sub-barra de navegación rápida del Dossier */}
      <div className="px-4 py-2 bg-[#0c1017] border-b border-[#1e2638] flex items-center justify-between gap-2 shrink-0">
        <div className="flex items-center space-x-1 overflow-x-auto py-0.5">
          {navItems.map((item, idx) => {
            const prevItem = navItems[idx - 1];
            const isNewGroup = prevItem && prevItem.group !== item.group;
            return (
              <React.Fragment key={item.id}>
                {isNewGroup && (
                  <div className="h-3.5 w-px bg-[#1e2638] mx-1.5 self-center shrink-0" />
                )}
                <button
                  onClick={() => setActiveSection(item.id)}
                  title={item.title}
                  className={`px-2.5 py-1 text-[11px] font-mono rounded transition-colors cursor-pointer shrink-0 ${
                    activeSection === item.id
                      ? 'bg-[#1e2638] text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-[#141923]'
                  }`}
                >
                  {item.label}
                </button>
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Scrollable text content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-6 font-mono text-xs">
        {/* 1. TARGET HEADER, RISK SCORE & KEY FINDINGS (FULL DOSSIER ONLY) */}
        {activeSection === 'all' && (
          <section className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[#1e2638] pb-3">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-500">
                  Audited Target // Forensic Intelligence Dossier
                </div>
                <div className="text-lg font-bold text-white flex items-center space-x-2 mt-0.5">
                  <span>{target}</span>
                  <button
                    onClick={() => onFocusNode && onFocusNode(`target_${target}`)}
                    className="text-[10px] px-2 py-0.5 bg-[#151c28] hover:bg-[#1e2638] text-[#38bdf8] border border-[#1e2638] rounded font-normal cursor-pointer"
                  >
                    View in graph
                  </button>
                </div>
                <div className="text-[11px] text-slate-400 mt-1">
                  Scan: <span className="text-slate-300">{scan_timestamp}</span>
                  {scan_duration_sec !== undefined && (
                    <span> · Duration: <span className="text-[#10b981]">{scan_duration_sec}s</span></span>
                  )}
                  {rdap_domain?.registrar && rdap_domain.registrar !== 'Desconocido' && rdap_domain.registrar !== 'Unknown' && (
                    <span> · Registrar: <span className="text-slate-300">{rdap_domain.registrar}</span></span>
                  )}
                </div>

                {/* Geolocation & Infrastructure Classification */}
                {geo?.country && geo.country !== 'Desconocido' && (
                  <div className="flex flex-wrap items-center gap-1.5 mt-2 pt-2 border-t border-[#1e2638] text-[11px] font-mono">
                    <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded bg-[#101929] border border-[#1e2638] text-slate-200">
                      <span>{geo.flag || '🌐'}</span>
                      <span className="font-semibold">
                        {geo.city && geo.city !== 'Desconocido' ? `${geo.city}, ` : ''}{geo.country}
                      </span>
                    </span>
                    {geo.infra_provider && geo.infra_provider !== 'Desconocido' && (
                      <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded bg-[#101929] border border-[#1e2638] text-slate-300">
                        <span className="text-slate-500">Host:</span>
                        <span className="text-[#38bdf8] font-semibold">{geo.infra_provider}</span>
                        <span className="text-slate-500 text-[10px]">({geo.infra_category})</span>
                      </span>
                    )}
                    {geo.asn && geo.asn !== 'Desconocido' && geo.asn !== 'Private' && (
                      <span className="px-2 py-0.5 rounded bg-[#101929] border border-[#1e2638] text-slate-400 text-[10px]">
                        {geo.asn}
                      </span>
                    )}
                    {geo.is_anycast && (
                      <span className="px-1.5 py-0.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300 text-[10px] font-bold">
                        BGP ANYCAST
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Global Risk Score Badge */}
              {risk.score !== undefined && (
                <div className={`px-3.5 py-2 rounded border flex items-center space-x-3 ${riskColor}`}>
                  <div>
                    <div className="text-[10px] uppercase opacity-80">Risk Score</div>
                    <div className="text-lg font-bold leading-tight">
                      {risk.score}/100 · {risk.level}
                    </div>
                  </div>
                  <div className="text-2xl font-black px-2 py-0.5 border border-current rounded">
                    {risk.grade}
                  </div>
                </div>
              )}
            </div>

            {/* Surface Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-[#090b10] border border-[#1e2638] p-3 rounded">
                <div className="text-[10px] uppercase text-slate-500">Assets / IPs</div>
                <div className="text-xl font-bold text-[#10b981] mt-1">{summary.ips_count || 0}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">{summary.subdomains_count || 0} subdomains</div>
              </div>
              <div className="bg-[#090b10] border border-[#1e2638] p-3 rounded">
                <div className="text-[10px] uppercase text-slate-500">Open Ports</div>
                <div className="text-xl font-bold text-[#38bdf8] mt-1">{summary.open_ports_count || 0}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">Detected services</div>
              </div>
              <div className="bg-[#090b10] border border-[#1e2638] p-3 rounded">
                <div className="text-[10px] uppercase text-slate-500">Total CVEs</div>
                <div className={`text-xl font-bold mt-1 ${summary.vulnerabilities_count > 0 ? 'text-[#ef4444]' : 'text-slate-300'}`}>
                  {summary.vulnerabilities_count || 0}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">
                  {summary.critical_vulns || 0} Critical · {summary.high_vulns || 0} High
                </div>
              </div>
              <div className="bg-[#090b10] border border-[#1e2638] p-3 rounded">
                <div className="text-[10px] uppercase text-slate-500">WAF / Mail Security</div>
                <div className="text-xs font-bold text-slate-200 mt-1 truncate" title={http_audit?.waf_cdn || 'Direct IP / No WAF'}>
                  {http_audit?.waf_cdn || 'No WAF detected'}
                </div>
                <div className="flex items-center space-x-2 mt-1 text-[10px]">
                  <span className={dns.email_security?.has_spf ? (dns.email_security?.spf_policy === 'permissive' ? 'text-[#facc15]' : 'text-[#10b981]') : 'text-[#ef4444]'}>
                    SPF: {dns.email_security?.has_spf ? (dns.email_security?.spf_policy === 'permissive' ? 'PERMISSIVE' : 'OK') : 'NO'}
                  </span>
                  <span>·</span>
                  <span className={dns.email_security?.has_dmarc ? (dns.email_security?.dmarc_policy === 'none' ? 'text-[#facc15]' : 'text-[#10b981]') : 'text-[#ef4444]'}>
                    DMARC: {dns.email_security?.has_dmarc ? (dns.email_security?.dmarc_policy === 'none' ? 'WEAK (p=none)' : `OK (${dns.email_security?.dmarc_policy})`) : 'NO'}
                  </span>
                </div>
              </div>
            </div>

            {/* Analyst Priority Findings */}
            {risk.findings && risk.findings.length > 0 && (
              <div className="space-y-1.5 pt-1">
                <div className="text-[10px] uppercase tracking-wider text-slate-400 font-bold">
                  Priority Risk Vectors Detected:
                </div>
                <div className="space-y-1.5">
                  {risk.findings.map((f, idx) => (
                    <div
                      key={idx}
                      className="flex items-start space-x-2.5 bg-[#090b10] border border-[#1e2638] p-2.5 rounded text-[11px]"
                    >
                      <AlertTriangle
                        size={14}
                        className={`shrink-0 mt-0.5 ${
                          f.severity === 'CRITICAL'
                            ? 'text-[#ef4444]'
                            : f.severity === 'HIGH'
                            ? 'text-[#fb923c]'
                            : 'text-[#facc15]'
                        }`}
                      />
                      <div>
                        <span className="font-bold text-slate-100">{f.title}: </span>
                        <span className="text-slate-400 font-sans">{f.detail}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>
        )}

        {/* 2. NETWORK INFRASTRUCTURE, OPEN PORTS & RUNNING SERVICES */}
        {showSection('services') && (
          <section className="space-y-3">
            <div className="flex items-center justify-between border-b border-[#1e2638] pb-2">
              <div className="flex items-center space-x-2">
                <Server size={15} className="text-[#10b981]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                  Network Infrastructure, Open Ports & Running Services
                </h2>
              </div>
              <span className="text-[11px] text-slate-500">{shodan.length} host(s) audited</span>
            </div>

            {/* Associated Hosts Outside CDN Network */}
            {perimeter_hosts?.has_unproxied_hosts && (
              <div className="bg-[#0c121d] border border-[#38bdf8]/30 rounded p-3 text-xs font-mono space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-[#38bdf8] font-bold">
                    <Globe size={14} />
                    <span className="uppercase tracking-wider">
                      Associated Hosts Outside {perimeter_hosts.cdn_provider} Network
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-400 font-sans">
                    Perimeter Intelligence
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                  The primary target is routed through <span className="text-slate-200 font-semibold">{perimeter_hosts.cdn_provider}</span>. The following infrastructure hosts associated with the target domain resolve outside the CDN network:
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 pt-1">
                  {perimeter_hosts.unproxied_hosts.map((h, i) => (
                    <div
                      key={i}
                      className="p-2.5 rounded bg-[#07090e] border border-[#1e2638] flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0 pr-1">
                        <div className="font-bold text-white font-mono text-xs">{h.ip}</div>
                        <div className="text-[10px] text-slate-500 truncate" title={h.source}>
                          {h.source}
                        </div>
                      </div>
                      {onRefreshScan && (
                        <button
                          type="button"
                          onClick={() => onRefreshScan(h.ip)}
                          title={`Audit host ${h.ip}`}
                          className="px-2 py-1 text-[10px] bg-[#151c28] hover:bg-[#1e2638] text-[#38bdf8] hover:text-white border border-[#1e2638] rounded transition-colors cursor-pointer shrink-0"
                        >
                          Audit Host
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {shodan.length === 0 ? (
              <div className="bg-[#0d1119] border border-[#1e2638] p-4 rounded text-slate-500">
                No IP addresses or Shodan data found for this target.
              </div>
            ) : (
              shodan.map((host) => (
                <div key={host.ip} className="bg-[#0d1119] border border-[#1e2638] rounded overflow-hidden">
                  {/* Cabecera de la IP */}
                  <div className="bg-[#111722] px-4 py-3 border-b border-[#1e2638] flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-[#10b981]"></span>
                      <span className="text-sm font-bold text-white">{host.ip}</span>
                      {host.org && (
                        <span className="px-2 py-0.5 bg-[#1e2638] text-slate-200 rounded text-[11px]">
                          {host.org}
                        </span>
                      )}
                      {host.asn && (
                        <div className="flex items-center space-x-1">
                          <a
                            href={`https://ipinfo.io/AS${String(host.asn).replace(/[^0-9]/g, '')}`}
                            target="_blank"
                            rel="noreferrer"
                            title="View ASN details, IP ranges and organization on IPinfo"
                            className="inline-flex items-center space-x-1 px-2 py-0.5 bg-[#0f2438] hover:bg-[#1a3854] text-[#38bdf8] border border-[#0369a1] rounded text-[11px] font-mono transition-colors"
                          >
                            <span>{host.asn}</span>
                            <ExternalLink size={10} />
                          </a>
                          <a
                            href={`https://bgp.he.net/AS${String(host.asn).replace(/[^0-9]/g, '')}`}
                            target="_blank"
                            rel="noreferrer"
                            title="View BGP routes and peers on Hurricane Electric (BGP.he.net)"
                            className="inline-flex items-center px-1.5 py-0.5 bg-[#121824] hover:bg-[#1e2638] text-slate-400 hover:text-white border border-[#1e2638] rounded text-[10px] font-mono transition-colors"
                          >
                            BGP.he
                          </a>
                        </div>
                      )}
                      {host.os && (
                        <span className="px-2 py-0.5 bg-[#0f2438] border border-[#0369a1] text-[#38bdf8] rounded text-[10px]">
                          OS: {host.os}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center space-x-2">
                      {/* Quick Threat Intel links for IP */}
                      <div className="hidden sm:flex items-center space-x-1 font-mono text-[10px]">
                        <a
                          href={`https://www.virustotal.com/gui/ip-address/${host.ip}`}
                          target="_blank"
                          rel="noreferrer"
                          title="Analyze IP reputation on VirusTotal"
                          className="px-1.5 py-0.5 bg-[#121824] hover:bg-[#1f293d] text-slate-400 hover:text-[#38bdf8] border border-[#1e2638] rounded transition-colors inline-flex items-center space-x-0.5"
                        >
                          <span>VT</span>
                          <ExternalLink size={8} />
                        </a>
                        <a
                          href={`https://www.abuseipdb.com/check/${host.ip}`}
                          target="_blank"
                          rel="noreferrer"
                          title="Check abuse reports on AbuseIPDB"
                          className="px-1.5 py-0.5 bg-[#121824] hover:bg-[#1f293d] text-slate-400 hover:text-[#fb923c] border border-[#1e2638] rounded transition-colors inline-flex items-center space-x-0.5"
                        >
                          <span>AbuseIP</span>
                          <ExternalLink size={8} />
                        </a>
                        <a
                          href={`https://www.shodan.io/host/${host.ip}`}
                          target="_blank"
                          rel="noreferrer"
                          title="Host profile on Shodan"
                          className="px-1.5 py-0.5 bg-[#121824] hover:bg-[#1f293d] text-slate-400 hover:text-[#f87171] border border-[#1e2638] rounded transition-colors inline-flex items-center space-x-0.5"
                        >
                          <span>Shodan</span>
                          <ExternalLink size={8} />
                        </a>
                        <a
                          href={`https://otx.alienvault.com/indicator/ip/${host.ip}`}
                          target="_blank"
                          rel="noreferrer"
                          title="Indicators of compromise on AlienVault OTX"
                          className="px-1.5 py-0.5 bg-[#121824] hover:bg-[#1f293d] text-slate-400 hover:text-[#a78bfa] border border-[#1e2638] rounded transition-colors inline-flex items-center space-x-0.5"
                        >
                          <span>OTX</span>
                          <ExternalLink size={8} />
                        </a>
                      </div>
                      <span className="text-[10px] text-slate-500">{host.source}</span>
                      <button
                        onClick={() => onFocusNode && onFocusNode(`ip_${host.ip}`)}
                        className="px-2 py-0.5 bg-[#1a2233] hover:bg-[#253047] text-[#38bdf8] rounded text-[10px] cursor-pointer"
                      >
                        Focus IP
                      </button>
                    </div>
                  </div>

                  {/* Host Metadata */}
                  <div className="px-4 py-2.5 bg-[#0b0e15] border-b border-[#1e2638] grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] text-slate-400">
                    <div>
                      <span className="text-slate-500">ISP:</span>{' '}
                      <span className="text-slate-200">{host.isp || host.org || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Geolocation:</span>{' '}
                      <span className="text-slate-200">
                        {[host.city, host.country].filter(Boolean).join(', ') || 'N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Reverse DNS:</span>{' '}
                      <span className="text-slate-200">
                        {host.hostnames?.length > 0 ? host.hostnames.join(', ') : 'None'}
                      </span>
                    </div>
                  </div>

                  {/* System CPEs */}
                  {host.cpes && host.cpes.length > 0 && (
                    <div className="px-4 py-2 bg-[#090b10] border-b border-[#1e2638] flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] uppercase text-slate-500 mr-1">CPE Fingerprint:</span>
                      {host.cpes.map((cpe, i) => (
                        <span key={i} className="px-2 py-0.5 bg-[#121824] border border-[#1e2638] rounded text-[10px] text-slate-300">
                          {cpe}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Detailed Ports & Services List */}
                  <div className="divide-y divide-[#1e2638]">
                    {host.services && host.services.length > 0 ? (
                      host.services.map((srv) => (
                        <div key={`${host.ip}_${srv.port}_${srv.transport}`} className="p-4 space-y-2.5 hover:bg-[#0f141f] transition-colors">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="px-2.5 py-1 bg-[#1e1b4b] border border-[#6366f1] text-[#c7d2fe] font-bold rounded text-xs">
                                Port {srv.port} / {srv.transport?.toUpperCase()}
                              </span>
                              <span className="text-sm font-bold text-white">
                                {srv.product}{' '}
                                {srv.version && <span className="text-[#38bdf8]">v{srv.version}</span>}
                              </span>
                              {srv.info && <span className="text-slate-400 text-xs">{srv.info}</span>}
                              <span className="px-2 py-0.5 bg-[#141a26] border border-[#1e2638] text-slate-400 rounded text-[10px] uppercase">
                                Protocol: {srv.module || srv.protocol}
                              </span>
                            </div>

                            <div className="flex items-center space-x-2">
                              {srv.vulns_count > 0 && (
                                <span className="px-2 py-0.5 bg-[#2d0f14] border border-[#991b1b] text-[#f87171] rounded text-[10px] font-bold">
                                  {srv.vulns_count} CVEs on port
                                </span>
                              )}
                              <button
                                onClick={() => onFocusNode && onFocusNode(`port_${host.ip}_${srv.port}`)}
                                className="px-2 py-0.5 bg-[#151c28] hover:bg-[#1e2638] text-slate-300 border border-[#1e2638] rounded text-[10px] cursor-pointer"
                              >
                                View node
                              </button>
                            </div>
                          </div>

                          {/* HTTP / SSL / Cloud port metadata */}
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                            {srv.http && (
                              <div className="bg-[#090b10] border border-[#1e2638] p-2.5 rounded space-y-1">
                                <div className="text-[10px] uppercase text-[#38bdf8] font-semibold">HTTP Web Application</div>
                                {srv.http.title && <div><span className="text-slate-500">Title:</span> <span className="text-slate-200">{srv.http.title}</span></div>}
                                {srv.http.server && <div><span className="text-slate-500">Server:</span> <span className="text-slate-200">{srv.http.server}</span></div>}
                              </div>
                            )}

                            {srv.ssl && (
                              <div className="bg-[#090b10] border border-[#1e2638] p-2.5 rounded space-y-1">
                                <div className="text-[10px] uppercase text-[#10b981] font-semibold">Port SSL/TLS Certificate</div>
                                {srv.ssl.issuer && <div><span className="text-slate-500">Issuer:</span> <span className="text-slate-200">{srv.ssl.issuer}</span></div>}
                                {srv.ssl.subject && <div><span className="text-slate-500">Subject:</span> <span className="text-slate-200">{srv.ssl.subject}</span></div>}
                                {srv.ssl.cipher && <div><span className="text-slate-500">Cipher:</span> <span className="text-slate-200">{srv.ssl.cipher}</span></div>}
                              </div>
                            )}
                          </div>

                          {/* Banner / Server Response */}
                          {srv.banner && (
                            <div className="space-y-1">
                              <div className="text-[10px] uppercase text-slate-500">
                                Captured Banner / Fingerprint:
                              </div>
                              <pre className="p-2.5 bg-[#06080c] border border-[#1e2638] rounded text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                                {srv.banner}
                              </pre>
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="p-4 text-slate-500">No open ports reported on this IP.</div>
                    )}
                  </div>
                </div>
              ))
            )}
          </section>
        )}

        {/* 3. VULNERABILITY INTELLIGENCE CATALOG (SHODAN CVEDB + KEV + EPSS + POCS) */}
        {showSection('vulns') && (
          <section className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1e2638] pb-2">
              <div className="flex items-center space-x-2">
                <ShieldAlert size={15} className="text-[#ef4444]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                  Vulnerability Intelligence (Shodan CVEDB · CVSS · EPSS · CISA KEV)
                </h2>
              </div>
              <span className="text-[11px] text-slate-400">
                {vulnerabilities.length} enriched CVEs
              </span>
            </div>

            {vulnerabilities.length === 0 ? (
              <div className="bg-[#0d1119] border border-[#1e2638] p-4 rounded text-slate-500">
                No public vulnerabilities associated with exposed services detected.
              </div>
            ) : (
              <div className="space-y-3">
                {vulnerabilities.map((v) => (
                  <div
                    key={v.cve}
                    className={`bg-[#0d1119] border rounded p-4 space-y-2.5 transition-colors ${
                      v.kev ? 'border-[#dc2626]' : 'border-[#1e2638] hover:border-[#2e3b56]'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-bold text-white">{v.cve}</span>
                        <SeverityBadge severity={v.severity} cvss={v.cvss} />

                        {v.kev && (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 bg-[#dc2626] text-white text-[10px] font-bold rounded uppercase">
                            <Flame size={11} />
                            <span>CISA KEV · Actively Exploited</span>
                          </span>
                        )}

                        {v.ransomware_campaign && (
                          <span className="px-2 py-0.5 bg-[#7f1d1d] border border-[#ef4444] text-[#fecaca] text-[10px] font-bold rounded uppercase">
                            Ransomware: {v.ransomware_campaign}
                          </span>
                        )}

                        {v.epss !== null && v.epss !== undefined && (
                          <span className="px-2 py-0.5 bg-[#121824] border border-[#1e2638] text-slate-300 rounded text-[10px]">
                            EPSS: {(Number(v.epss) * 100).toFixed(2)}%
                            {v.ranking_epss ? ` (Percentile ${(Number(v.ranking_epss) * 100).toFixed(0)}%)` : ''}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center space-x-2 text-[11px]">
                        {v.published_time && (
                          <span className="text-slate-500 text-[10px]">Published: {v.published_time}</span>
                        )}
                        <button
                          onClick={() => onFocusNode && onFocusNode(`cve_${v.cve}`)}
                          className="px-2 py-0.5 bg-[#151c28] hover:bg-[#1e2638] text-[#38bdf8] border border-[#1e2638] rounded text-[10px] cursor-pointer"
                        >
                          View in graph
                        </button>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
                      {v.service && (
                        <span>
                          <span className="text-slate-500">Service on Host:</span>{' '}
                          <strong className="text-[#c7d2fe]">{v.service}</strong>
                        </span>
                      )}
                      {v.ports?.length > 0 && (
                        <span>
                          <span className="text-slate-500">Port(s):</span>{' '}
                          <strong className="text-slate-200">{v.ports.join(', ')}</strong>
                        </span>
                      )}
                      {v.vendor && (
                        <span>
                          <span className="text-slate-500">Vendor:</span>{' '}
                          <span className="text-slate-300">{v.vendor}</span>
                        </span>
                      )}
                      {v.ips?.length > 0 && (
                        <span>
                          <span className="text-slate-500">IP(s):</span>{' '}
                          <span className="text-slate-300">{v.ips.join(', ')}</span>
                        </span>
                      )}
                    </div>

                    <div className="bg-[#090b10] border border-[#141b29] p-3 rounded text-slate-200 text-xs font-sans leading-relaxed whitespace-pre-line">
                      {v.summary}
                    </div>

                    {v.propose_action && (
                      <div className="bg-[#0f2438]/60 border border-[#0369a1] p-2.5 rounded text-[11px] text-[#bae6fd] font-sans">
                        <strong>CISA KEV Mitigation:</strong> {v.propose_action}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-[11px]">
                      <div className="flex flex-wrap items-center gap-2">
                        <a
                          href={v.packetstorm_url || (v.cve && `https://packetstormsecurity.com/search/?q=${encodeURIComponent(v.cve)}`)}
                          target="_blank"
                          rel="noreferrer"
                          title="Exploits and advisories on Packet Storm Security"
                          className="inline-flex items-center space-x-1 px-2 py-0.5 bg-[#2d0f14] hover:bg-[#3d141b] text-[#f87171] border border-[#991b1b] rounded text-[10px] font-bold transition-colors"
                        >
                          <span>PacketStorm</span>
                          <ExternalLink size={9} />
                        </a>
                        <a
                          href={v.exploitdb_url || (v.cve && `https://www.exploit-db.com/search?cve=${encodeURIComponent(String(v.cve).replace('CVE-', ''))}`)}
                          target="_blank"
                          rel="noreferrer"
                          title="Search Exploit-DB archive (OffSec)"
                          className="inline-flex items-center space-x-1 px-2 py-0.5 bg-[#2e190e] hover:bg-[#3d2213] text-[#fb923c] border border-[#9a3412] rounded text-[10px] font-bold transition-colors"
                        >
                          <span>Exploit-DB</span>
                          <ExternalLink size={9} />
                        </a>
                        <a
                          href={v.vulners_url || (v.cve && `https://vulners.com/search?query=${encodeURIComponent(v.cve)}`)}
                          target="_blank"
                          rel="noreferrer"
                          title="Vulnerability and exploit correlation on Vulners"
                          className="inline-flex items-center space-x-1 px-2 py-0.5 bg-[#2b2108] hover:bg-[#3d2f0b] text-[#facc15] border border-[#854d0e] rounded text-[10px] transition-colors"
                        >
                          <span>Vulners</span>
                          <ExternalLink size={9} />
                        </a>
                        <a
                          href={v.nvd_url || (v.cve && `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}`)}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-[#38bdf8] hover:underline"
                        >
                          <span>NIST NVD</span>
                          <ExternalLink size={10} />
                        </a>
                        {v.github_poc_url && (
                          <a
                            href={v.github_poc_url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center space-x-1 text-slate-400 hover:text-white"
                          >
                            <span>GitHub</span>
                            <ExternalLink size={10} />
                          </a>
                        )}
                        <a
                          href={v.mitre_url || (v.cve && `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${encodeURIComponent(v.cve)}`)}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-slate-400 hover:text-white"
                        >
                          <span>MITRE</span>
                          <ExternalLink size={10} />
                        </a>
                      </div>

                      {v.references?.length > 0 && (
                        <a
                          href={v.references[0]}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-slate-400 hover:text-slate-200"
                        >
                          <span>Official Advisory ({v.references.length})</span>
                          <ExternalLink size={11} />
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {/* 4. WEB AUDIT, WAF/CDN, COOKIES/CORS, TLS/SSL CERTIFICATE, UPTIME & WAPPALYZER */}
        {showSection('http') && (
          <section className="space-y-4">
            <div className="flex items-center space-x-2 border-b border-[#1e2638] pb-2">
              <Lock size={15} className="text-[#38bdf8]" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                Web Audit, TLS X.509 & Web Technology Fingerprinting
              </h2>
            </div>

            {/* 4.1. WHO.IS SERVER STATUS & UPTIME CARD */}
            {http_audit?.uptime && (
              <div className="bg-[#0d1119] border border-[#1e2638] rounded overflow-hidden">
                <div className="bg-[#111722] px-4 py-3 border-b border-[#1e2638] flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#10b981] animate-pulse"></span>
                    <span className="text-xs font-bold uppercase tracking-wider text-white">Current Status & Uptime Information</span>
                  </div>
                  <span className="px-2 py-0.5 bg-[#064e3b] text-[#a7f3d0] border border-[#10b981]/50 rounded text-[10px] font-bold uppercase">
                    {http_audit.uptime.status || 'Active'}
                  </span>
                </div>
                <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="space-y-2.5">
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Status</span>
                      <span className="text-[#10b981] font-bold">{http_audit.uptime.status} ({http_audit.status_code || 200} OK)</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Server Type</span>
                      <span className="text-slate-200">{http_audit.uptime.server_type || http_audit.server || 'nginx'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Page Title</span>
                      <span className="text-white font-semibold">{http_audit.uptime.page_title}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Meta Description</span>
                      <p className="text-slate-300 font-sans text-[11px] leading-relaxed bg-[#07090e] p-2 rounded border border-[#1e2638]">
                        {http_audit.uptime.meta_description}
                      </p>
                    </div>
                  </div>
                  <div className="space-y-2.5">
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Meta Keywords</span>
                      <span className="text-slate-400">{http_audit.uptime.meta_keywords}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Response Time (Latency)</span>
                      <span className="text-[#38bdf8] font-bold">{http_audit.uptime.latency_ms ? `${http_audit.uptime.latency_ms} ms` : 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Last Checked</span>
                      <span className="text-slate-300">{http_audit.uptime.last_checked}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Redirect Chain</span>
                      <span className="text-slate-300">
                        {http_audit.uptime.redirects_count > 0 ? `${http_audit.uptime.redirects_count} redirect hop(s)` : 'No redirects observed'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* 4.2. WHO.IS COMPLETE SSL/TLS CERTIFICATE CARD */}
            {http_audit?.tls?.enabled && (
              <div className="bg-[#0d1119] border border-[#1e2638] rounded overflow-hidden">
                <div className="bg-[#111722] px-4 py-3 border-b border-[#1e2638] flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Lock size={14} className="text-[#10b981]" />
                    <span className="text-xs font-bold uppercase tracking-wider text-white">
                      SSL/TLS Certificate for {http_audit.tls.subject_cn || target}
                    </span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                    http_audit.tls.days_remaining < 15
                      ? 'bg-[#2d0f14] text-[#f87171] border-[#991b1b]'
                      : 'bg-[#064e3b] text-[#a7f3d0] border-[#10b981]/50'
                  }`}>
                    {http_audit.tls.days_remaining < 0 ? 'Expired' : 'Valid'}
                  </span>
                </div>

                <div className="p-4 space-y-4 font-mono text-xs">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Issued by (CA)</span>
                      <span className="text-white font-semibold text-sm">
                        {http_audit.tls.issuer_org || http_audit.tls.issuer_cn || "Let's Encrypt"}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Subject</span>
                      <span className="text-white font-semibold text-sm">
                        {http_audit.tls.subject_cn || target}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Valid from</span>
                      <span className="text-slate-300">{http_audit.tls.not_before || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Valid until</span>
                      <span className={http_audit.tls.days_remaining < 15 ? 'text-[#ef4444] font-bold' : 'text-[#10b981]'}>
                        {http_audit.tls.not_after || 'N/A'}{' '}
                        {http_audit.tls.days_remaining !== null && `(${http_audit.tls.days_remaining} days remaining)`}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Public key</span>
                      <span className="text-slate-200">{http_audit.tls.public_key || `${http_audit.tls.cipher_bits || 256}-bit`}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase">Serial</span>
                      <span className="text-slate-300 break-all select-all">{http_audit.tls.serial_number || 'N/A'}</span>
                    </div>
                  </div>

                  {/* SHA-256 Fingerprint */}
                  {http_audit.tls.fingerprint_sha256 && (
                    <div className="bg-[#07090e] p-2.5 rounded border border-[#1e2638] space-y-1">
                      <span className="text-slate-500 block text-[10px] uppercase">SHA-256 fingerprint</span>
                      <span className="text-[#38bdf8] select-all break-all text-[11px] font-mono">
                        {http_audit.tls.fingerprint_sha256}
                      </span>
                    </div>
                  )}

                  {/* Certification Chain */}
                  {http_audit.tls.chain?.length > 0 && (
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase mb-1">Chain</span>
                      <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-slate-300">
                        {http_audit.tls.chain.map((cNode, i) => (
                          <React.Fragment key={i}>
                            <span className="px-2 py-0.5 bg-[#141b29] border border-[#1e2638] rounded">
                              {cNode}
                            </span>
                            {i < http_audit.tls.chain.length - 1 && <span className="text-slate-600">→</span>}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Subject Alternative Names (SANs) */}
                  {http_audit.tls.san_domains?.length > 0 && (
                    <div>
                      <span className="text-slate-500 block text-[10px] uppercase mb-1">
                        Subject Alternative Names ({http_audit.tls.san_domains.length})
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {http_audit.tls.san_domains.map((san, i) => (
                          <span key={i} className="px-2 py-0.5 bg-[#090b10] border border-[#1e2638] rounded text-[11px] text-slate-300">
                            {san}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Certificate Authority Authorization (CAA) */}
                  <div className="pt-2 border-t border-[#1e2638]">
                    <span className="text-slate-400 block text-[11px] font-bold uppercase mb-1">
                      Certificate Authority Authorization (CAA)
                    </span>
                    {dns.records?.CAA && dns.records.CAA.length > 0 ? (
                      <div className="p-2.5 bg-[#064e3b]/30 border border-[#10b981]/40 rounded text-slate-200 text-xs space-y-1">
                        <span className="text-[#10b981] font-bold">CAA Policy published in DNS zone:</span>
                        {dns.records.CAA.map((caaItem, i) => (
                          <div key={i} className="text-[11px] font-mono text-[#a7f3d0]">• {caaItem.value}</div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-slate-400 text-xs">
                        No CAA policy is published for this domain — any certificate authority may issue for it.
                      </p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* 4.3. WAPPALYZER CARD // DETECTED TECHNOLOGIES, VERSIONS & DESCRIPTION */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded overflow-hidden">
              <div className="bg-[#111722] px-4 py-3 border-b border-[#1e2638] flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center space-x-2">
                  <Globe size={14} className="text-[#38bdf8]" />
                  <span className="text-xs font-bold uppercase tracking-wider text-white">
                    Detected Web Technologies & Software Stack (SCA Engine)
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  {http_audit?.scan_mode === 'active' ? (
                    <span className="px-2 py-0.5 rounded bg-[#3b0764]/50 border border-[#8b5cf6]/50 text-[#d8b4fe] text-[10px] font-mono flex items-center space-x-1" title="Active Mode: Infrastructure correlations and authorized socket banner probing">
                      <Zap size={11} className="text-[#c084fc]" />
                      <span>ACTIVE MODE</span>
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-[#064e3b]/50 border border-[#10b981]/50 text-[#a7f3d0] text-[10px] font-mono flex items-center space-x-1" title="Stealth Mode: 100% passive, no administrative port probing to guarantee legal compliance and stealth">
                      <Shield size={11} className="text-[#10b981]" />
                      <span>STEALTH MODE // PASSIVE</span>
                    </span>
                  )}
                  <span className="text-[11px] text-slate-400">
                    {http_audit?.wappalyzer?.length || http_audit?.technologies?.length || 0} components identified
                  </span>
                </div>
              </div>

              <div className="p-4">
                {http_audit?.wappalyzer && http_audit.wappalyzer.length > 0 ? (
                  <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {http_audit.wappalyzer.map((tech, i) => (
                      <div
                        key={i}
                        className={`p-3 rounded transition-all flex flex-col justify-between space-y-2 border ${
                          tech.vulnerable
                            ? 'bg-[#14080a] border-[#ef4444]/60 hover:border-[#ef4444]'
                            : 'bg-[#090b10] border-[#1e2638] hover:border-[#38bdf8]/50'
                        }`}
                      >
                        <div>
                          <div className="flex items-start justify-between gap-1.5">
                            <span className="text-xs font-bold text-white leading-tight">{tech.name}</span>
                            <div className="flex items-center space-x-1 shrink-0">
                              {tech.version_status === 'hardened' ? (
                                <span
                                  className="px-1.5 py-0.5 bg-[#f59e0b]/10 border border-[#f59e0b]/40 text-[#f59e0b] rounded text-[9px] font-mono font-bold flex items-center space-x-1"
                                  title="Defensive hardening directive active (server_tokens off). Stealth Mode respects legal boundaries and avoids probing administrative ports."
                                >
                                  <Shield size={10} className="text-[#f59e0b]" />
                                  <span>HIDDEN (HARDENED)</span>
                                </span>
                              ) : tech.version_status === 'inferred_active' ? (
                                <span
                                  className="px-1.5 py-0.5 bg-[#8b5cf6]/20 border border-[#8b5cf6]/60 text-[#c084fc] rounded text-[9px] font-mono font-bold flex items-center space-x-1"
                                  title={`Inferred actively via SSH banner on port 22 (${tech.provenance || 'Active Mode'})`}
                                >
                                  <Zap size={10} className="text-[#c084fc]" />
                                  <span>{tech.version}</span>
                                </span>
                              ) : tech.version_status === 'architecture' ? (
                                <span
                                  className="px-1.5 py-0.5 bg-[#06b6d4]/15 border border-[#06b6d4]/50 text-[#22d3ee] rounded text-[9px] font-mono font-bold"
                                  title="Static compilation architecture (Zero-JS on client / Islands)"
                                >
                                  {tech.version}
                                </span>
                              ) : tech.version ? (
                                <span className="px-1.5 py-0.2 bg-[#0284c7]/20 border border-[#38bdf8]/60 text-[#38bdf8] rounded text-[10px] font-mono font-bold">
                                  v{tech.version}
                                </span>
                              ) : null}
                              {tech.vulnerable && (
                                <span className="px-1.5 py-0.2 bg-[#450a0a] border border-[#ef4444]/80 text-[#fca5a5] rounded text-[9px] font-mono font-bold flex items-center space-x-1">
                                  <AlertTriangle size={9} className="text-[#ef4444]" />
                                  <span>VULN</span>
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="text-[10px] font-mono font-semibold text-[#10b981] uppercase tracking-wider mt-0.5">
                            {tech.category}
                          </div>
                          {tech.description && (
                            <p className="text-[11px] text-slate-400 font-sans mt-1.5 leading-snug line-clamp-2">
                              {tech.description}
                            </p>
                          )}
                          {tech.provenance && (
                            <div className="text-[9px] font-mono text-slate-500 flex items-center space-x-1 mt-1.5">
                              <span className="text-slate-600">Provenance:</span>
                              <span className={tech.detection_mode === 'active' ? 'text-[#c084fc] font-semibold' : 'text-slate-400'}>
                                {tech.provenance}
                              </span>
                            </div>
                          )}
                        </div>

                        {/* Breakdown of CVEs associated with the component if vulnerable */}
                        {tech.vulnerable && tech.vulnerabilities && tech.vulnerabilities.length > 0 && (
                          <div className="pt-2 border-t border-[#3b1216] space-y-1.5">
                            <div className="text-[10px] font-mono font-bold text-red-300 flex items-center justify-between">
                              <span className="flex items-center space-x-1">
                                <Bug size={11} className="text-[#ef4444]" />
                                <span>Critical CVEs / XSS ({tech.cve_count}):</span>
                              </span>
                              <span className="text-[9px] px-1 rounded bg-[#2b0d10] text-red-300 border border-red-800">
                                {tech.max_severity}
                              </span>
                            </div>
                            <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                              {tech.vulnerabilities.map((v, vIdx) => (
                                <div key={vIdx} className="p-1.5 bg-[#080203] border border-[#7f1d1d]/40 rounded text-[10px] font-mono">
                                  <div className="flex items-center justify-between">
                                    <span className="font-bold text-red-300">{v.cve}</span>
                                    <span className="text-[9px] text-slate-400">CVSS {v.cvss || '6.1'}</span>
                                  </div>
                                  <div className="text-slate-400 text-[10px] mt-0.5 font-sans leading-tight line-clamp-2">
                                    {v.title || v.summary}
                                  </div>
                                  <div className="flex flex-wrap items-center gap-1.5 mt-1 pt-1 border-t border-[#1e2638] text-[9px] font-mono">
                                    <a
                                      href={v.packetstorm_url || `https://packetstormsecurity.com/search/?q=${encodeURIComponent(v.cve)}`}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="text-[#f87171] hover:underline inline-flex items-center space-x-0.5 font-bold"
                                      title="Search exploit on PacketStorm Security"
                                    >
                                      <span>PacketStorm</span>
                                      <ExternalLink size={8} />
                                    </a>
                                    <a
                                      href={v.exploitdb_url || `https://www.exploit-db.com/search?cve=${encodeURIComponent(String(v.cve).replace('CVE-', ''))}`}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="text-[#fb923c] hover:underline inline-flex items-center space-x-0.5 font-bold"
                                      title="Search exploit on Exploit-DB"
                                    >
                                      <span>Exploit-DB</span>
                                      <ExternalLink size={8} />
                                    </a>
                                    <a
                                      href={v.vulners_url || `https://vulners.com/search?query=${encodeURIComponent(v.cve)}`}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="text-[#facc15] hover:underline inline-flex items-center space-x-0.5"
                                      title="Search in Vulners vulnerability database"
                                    >
                                      <span>Vulners</span>
                                      <ExternalLink size={8} />
                                    </a>
                                    <a
                                      href={v.nvd_url || `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}`}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="text-slate-400 hover:text-white inline-flex items-center space-x-0.5"
                                      title="Official entry on NIST NVD"
                                    >
                                      <span>NVD</span>
                                      <ExternalLink size={8} />
                                    </a>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {tech.website && (
                          <div className="pt-1.5 border-t border-[#141b29] flex items-center justify-between text-[10px] font-mono">
                            <span className="text-slate-600">Official docs</span>
                            <a
                              href={tech.website}
                              target="_blank"
                              rel="noreferrer"
                              className="text-[#38bdf8] hover:underline inline-flex items-center space-x-1"
                            >
                              <span>Visit</span>
                              <ExternalLink size={9} />
                            </a>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* Informational OPSEC Warning when Hardening is Detected in Stealth Mode */}
                  {http_audit?.wappalyzer?.some(t => t.version_status === 'hardened') && (http_audit?.scan_mode === 'passive' || !http_audit?.scan_mode) && (
                    <div className="mt-3 p-2.5 bg-[#171308] border border-[#f59e0b]/30 rounded text-[11px] text-amber-200/90 flex items-start space-x-2">
                      <Shield size={14} className="text-[#f59e0b] shrink-0 mt-0.5" />
                      <p>
                        <strong>OPSEC Hardening Notice:</strong> Components detected with versions suppressed by defensive hardening directives (e.g. <code className="text-[#f59e0b]">server_tokens off;</code>). In <strong>Stealth Mode</strong>, no packets are dispatched to administrative ports (such as SSH p22) to maintain full legal compliance and stealth. To probe versions via authorized active correlation, switch to <strong>Active Mode</strong>.
                      </p>
                    </div>
                  )}
                  </>
                ) : http_audit?.technologies && http_audit.technologies.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {http_audit.technologies.map((t, idx) => (
                      <span key={idx} className="px-2.5 py-1 bg-[#141b29] border border-[#1e2638] text-[#38bdf8] rounded text-xs font-mono">
                        {t}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-500 text-xs">No direct technological footprints detected in web response.</p>
                )}
              </div>
            </div>

            {/* 4.4. SECURITY HEADERS & COOKIES */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-200">
                HTTP Security Headers & Cookies
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-[11px]">
                  <thead>
                    <tr className="border-b border-[#1e2638] text-slate-500 uppercase text-[10px]">
                      <th className="py-2 px-3">Security Header</th>
                      <th className="py-2 px-3">Status</th>
                      <th className="py-2 px-3">Purpose / Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2638]/60">
                    {(http_audit.security_headers || []).map((sh) => (
                      <tr key={sh.header} className="hover:bg-[#111722]">
                        <td className="py-2 px-3 font-bold text-slate-200">{sh.header}</td>
                        <td className="py-2 px-3">
                          {sh.present ? (
                            <span className="inline-flex items-center space-x-1 text-[#10b981]">
                              <CheckCircle2 size={12} />
                              <span>Present</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center space-x-1 text-[#ef4444]">
                              <XCircle size={12} />
                              <span>Missing</span>
                            </span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-slate-400 break-all">
                          {sh.present ? <span className="text-slate-200">{sh.value}</span> : sh.description}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {http_audit.cookies_audit?.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-[#1e2638]">
                  <div className="text-[10px] uppercase text-slate-400 font-bold">
                    Session Cookie Audit (Set-Cookie):
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {http_audit.cookies_audit.map((ck, i) => (
                      <div key={i} className="bg-[#090b10] border border-[#1e2638] p-2.5 rounded flex items-center justify-between text-[11px]">
                        <span className="font-bold text-slate-200">{ck.name}</span>
                        <div className="flex items-center space-x-2 text-[10px]">
                          <span className={ck.secure ? 'text-[#10b981]' : 'text-[#ef4444]'}>
                            Secure: {ck.secure ? 'YES' : 'NO'}
                          </span>
                          <span className={ck.httponly ? 'text-[#10b981]' : 'text-[#ef4444]'}>
                            HttpOnly: {ck.httponly ? 'YES' : 'NO'}
                          </span>
                          <span className={ck.samesite ? 'text-[#10b981]' : 'text-[#facc15]'}>
                            SameSite: {ck.samesite ? 'YES' : 'NO'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* 5. DNS RECORDS, EMAIL SECURITY & SUBDOMAINS WITH ORIGIN IPs */}
        {showSection('dns') && (
          <section className="space-y-3">
            <div className="flex items-center space-x-2 border-b border-[#1e2638] pb-2">
              <Globe size={15} className="text-[#38bdf8]" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                DNS Reconnaissance, Email Security Policies & Subdomain Resolution (Origin IP Lookup)
              </h2>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* DNS Records */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="text-[11px] font-bold uppercase text-slate-400">DNS Zone Records</div>
                {dns.records && Object.values(dns.records).some((arr) => arr?.length > 0) ? (
                  <div className="space-y-2">
                    {Object.entries(dns.records).map(([rtype, records]) => {
                      if (!records || records.length === 0) return null;
                      return (
                        <div key={rtype} className="bg-[#090b10] border border-[#1e2638] p-2.5 rounded">
                          <div className="text-[10px] font-bold text-[#38bdf8] mb-1">
                            Record {rtype} (TTL: {records[0]?.ttl || 0}s)
                          </div>
                          <div className="space-y-1 text-slate-300 text-[11px] break-all">
                            {records.map((r, i) => (
                              <div key={i}>• {r.value}</div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-slate-500">No direct DNS records found.</div>
                )}
              </div>

              {/* Discovered Subdomains + Resolved IP */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold uppercase text-slate-400">
                    Public Certificate Subdomains (crt.sh)
                  </span>
                  <span className="text-[11px] text-slate-500">{subdomains.length} found</span>
                </div>

                {subdomains.length > 0 ? (
                  <div className="space-y-1.5 max-h-96 overflow-y-auto pr-1">
                    {subdomains.map((sub) => (
                      <div
                        key={sub}
                        onClick={() => onFocusNode && onFocusNode(`sub_${sub}`)}
                        className="px-3 py-2 bg-[#090b10] hover:bg-[#141b29] border border-[#1e2638] rounded text-[11px] flex items-center justify-between gap-2 cursor-pointer transition-colors"
                      >
                        <span className="text-slate-200 truncate">{sub}</span>
                        {subIpMap[sub] && (
                          <span className="text-[10px] px-1.5 py-0.5 bg-[#064e3b]/60 border border-[#10b981]/40 text-[#a7f3d0] rounded shrink-0">
                            {subIpMap[sub][0]}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-slate-500">
                    No additional subdomains discovered in Certificate Transparency logs.
                  </div>
                )}
              </div>
            </div>
          </section>
        )}

        {/* BRAND PROTECTION, LOOKALIKE DOMAINS & TAKEDOWN COORDINATION */}
        {showSection('brand') && (
          <section className="space-y-4">
            {(() => {
              const hasBrandThreats = Boolean(
                brandData?.active_threats_count > 0 ||
                (brandData?.target_forensics && (
                  brandData.target_forensics.severity === 'CRITICAL' ||
                  brandData.target_forensics.severity === 'HIGH' ||
                  brandData.target_forensics.suspected_brand
                ))
              );
              return (
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1e2638] pb-2">
                  <div className="flex items-center space-x-2">
                    {hasBrandThreats ? (
                      <ShieldAlert size={15} className="text-[#f87171]" />
                    ) : (
                      <ShieldCheck size={15} className="text-[#38bdf8]" />
                    )}
                    <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                      Brand Protection, Lookalike Domains & Takedown Coordination
                    </h2>
                    <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono font-bold border ${
                      hasBrandThreats
                        ? 'bg-red-950/70 border-red-500/40 text-red-300'
                        : 'bg-[#0f1d2e] border-[#0284c7]/40 text-[#38bdf8]'
                    }`}>
                      {hasBrandThreats ? 'Anti-Phishing DRP' : 'Brand Defense DRP'}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={handleAuditBrand}
                    disabled={brandLoading}
                    className={`px-3 py-1 rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors cursor-pointer border disabled:opacity-50 ${
                      hasBrandThreats
                        ? 'bg-red-950/40 hover:bg-red-900/60 text-red-200 border-red-700/60'
                        : 'bg-[#131926] hover:bg-[#1e2638] text-slate-300 hover:text-white border-[#1e2638]'
                    }`}
                  >
                    {brandLoading ? (
                      <RefreshCw size={11} className="animate-spin" />
                    ) : (
                      <Shield size={11} />
                    )}
                    <span>{brandLoading ? 'Auditing...' : (brandData ? 'Re-Audit' : 'Audit')}</span>
                  </button>
                </div>
              );
            })()}

            {/* Introductory Card when not audited yet */}
            {!brandData && !brandLoading && (
              <div className="bg-[#0c1017] border border-[#1e2638] rounded p-4 text-xs font-mono space-y-3">
                <p className="text-slate-300 font-sans leading-relaxed text-xs">
                  Proactively uncovers lookalike domains, typosquatting variants and visual homoglyphs (e.g. substitutions, transpositions, phishing keyword combos) targeting the brand <span className="text-white font-bold font-mono">{target}</span>. Resolves passive DNS (A/MX), ranks threats by recency and similarity, and prepares evidence packages for immediate takedowns.
                </p>
                <button
                  type="button"
                  onClick={handleAuditBrand}
                  className="px-3.5 py-1.5 bg-[#131926] hover:bg-[#1e2638] text-slate-200 hover:text-white border border-[#1e2638] rounded text-xs font-mono font-bold flex items-center space-x-2 transition-colors cursor-pointer"
                >
                  <Shield size={13} className="text-[#38bdf8]" />
                  <span>Audit</span>
                </button>
              </div>
            )}

            {brandLoading && (
              <div className="p-8 bg-[#0c1017] border border-[#1e2638] rounded text-center space-y-2">
                <RefreshCw size={20} className="animate-spin mx-auto text-red-400" />
                <div className="text-xs font-mono text-slate-300 font-bold">Generating Permutations & Resolving Passive DNS...</div>
                <div className="text-[11px] font-mono text-slate-500">
                  Checking visual homoglyphs, typosquatting mutations, active mailboxes (MX) and WHOIS records.
                </div>
              </div>
            )}

            {brandError && (
              <div className="p-3 bg-red-950/40 border border-red-800 rounded text-red-300 text-xs font-mono flex items-center space-x-2">
                <AlertTriangle size={14} className="shrink-0" />
                <span>{brandError}</span>
              </div>
            )}

            {brandData && (
              <div className="space-y-4">
                {/* 1. TARGET IDENTITY & INFRASTRUCTURE DOSSIER */}
                {brandData.target_forensics && (() => {
                  const isThreat =
                    brandData.target_forensics.severity === 'CRITICAL' ||
                    brandData.target_forensics.severity === 'HIGH' ||
                    Boolean(brandData.target_forensics.suspected_brand);

                  return (
                    <div className={`bg-[#0b0f17] rounded-lg overflow-hidden font-mono text-xs shadow-lg border ${
                      isThreat ? 'border-red-500/40' : 'border-[#1e2638]'
                    }`}>
                      {/* Header */}
                      <div className="bg-[#141b27] px-4 py-3 border-b border-[#1e2638] flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center space-x-2">
                          {isThreat ? (
                            <ShieldAlert size={16} className="text-red-400" />
                          ) : (
                            <ShieldCheck size={16} className="text-[#38bdf8]" />
                          )}
                          <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                            {isThreat ? 'Campaign Forensic Dossier' : 'Target Identity & Infrastructure'} // {brandData.target_forensics.domain}
                          </h3>
                          <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase border ${
                            brandData.target_forensics.severity === 'CRITICAL'
                              ? 'bg-red-950 text-red-300 border-red-600'
                              : brandData.target_forensics.severity === 'HIGH'
                              ? 'bg-amber-950 text-amber-300 border-amber-600'
                              : 'bg-[#0f2438] text-[#38bdf8] border-[#0369a1]'
                          }`}>
                            {isThreat
                              ? `${brandData.target_forensics.severity} · ${brandData.target_forensics.is_recent ? 'Recent Campaign' : 'Active Threat'}`
                              : 'Standard Infrastructure · Clean Domain'}
                          </span>
                        </div>

                        <button
                          type="button"
                          onClick={() => setSelectedTakedown(brandData.target_forensics)}
                          className={
                            isThreat
                              ? 'px-3 py-1 bg-red-700 hover:bg-red-600 text-white rounded text-xs font-bold inline-flex items-center space-x-1.5 shadow transition-all cursor-pointer'
                              : 'px-2.5 py-1 bg-[#151c29] hover:bg-[#1e2638] border border-[#1e2638] hover:border-slate-600 text-slate-300 hover:text-white rounded text-xs font-mono inline-flex items-center space-x-1.5 transition-all cursor-pointer'
                          }
                          title={isThreat ? 'Generate RFC Abuse Takedown package' : 'Export RFC Abuse / Evidence notice'}
                        >
                          <FileText size={12} className={isThreat ? 'text-white' : 'text-slate-400'} />
                          <span>{isThreat ? 'Generate Campaign Takedown' : 'Export RFC Notice'}</span>
                        </button>
                      </div>

                    {/* Verdict Banner: displayed ONLY on active threat alerts (CRITICAL / HIGH / Impersonation) to avoid redundant noise */}
                    {(brandData.target_forensics.severity === 'CRITICAL' ||
                      brandData.target_forensics.severity === 'HIGH' ||
                      brandData.target_forensics.suspected_brand) && (
                      <div className={`p-3 border-b text-xs flex flex-wrap items-center justify-between gap-2 ${
                        brandData.target_forensics.severity === 'CRITICAL'
                          ? 'bg-red-950/40 border-red-500/30 text-red-200'
                          : 'bg-amber-950/40 border-amber-500/30 text-amber-200'
                      }`}>
                        <div className="flex items-center space-x-2">
                          <AlertTriangle size={15} className={brandData.target_forensics.severity === 'CRITICAL' ? 'text-red-400 shrink-0' : 'text-amber-400 shrink-0'} />
                          <span className="font-semibold">{brandData.target_forensics.verdict}</span>
                        </div>
                        {brandData.target_forensics.suspected_brand && (
                          <span className="px-2 py-0.5 rounded bg-red-900/60 border border-red-500 text-white text-[10px] font-bold shrink-0">
                            Impersonation Target: {brandData.target_forensics.suspected_brand}
                          </span>
                        )}
                      </div>
                    )}

                    {/* Global Threat Intelligence & Zero-Day Feed Status */}
                    {brandData.target_forensics.reputation && (
                      <div className={`p-2.5 px-3 border-b flex flex-wrap items-center justify-between gap-2 text-xs ${
                        brandData.target_forensics.reputation.status === 'CONFIRMED_MALICIOUS'
                          ? 'bg-red-950/60 border-red-500/40 text-red-200'
                          : brandData.target_forensics.reputation.status === 'ZERO_DAY_SUSPECT'
                          ? 'bg-amber-950/50 border-amber-500/40 text-amber-200'
                          : 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
                      }`}>
                        <div className="flex items-center space-x-2">
                          <span className="font-bold tracking-wider uppercase text-[10px] px-1.5 py-0.5 rounded border border-current">
                            {brandData.target_forensics.reputation.badge}
                          </span>
                          <span className="text-[11px] font-sans">{brandData.target_forensics.reputation.description}</span>
                        </div>
                        {brandData.target_forensics.reputation.status === 'CONFIRMED_MALICIOUS' && (
                          <span className="text-[10px] uppercase font-bold text-red-400 bg-red-950 px-2 py-0.5 rounded border border-red-500/50">
                            Active Abuse Blocklist
                          </span>
                        )}
                      </div>
                    )}

                    {/* Forensic Details Grid */}
                    <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {/* Left: Metadata & Infrastructure */}
                      <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-2 text-[11px]">
                          <div className="p-2.5 bg-[#07090e] border border-[#1e2638] rounded">
                            <span className="text-slate-500 block text-[10px] uppercase">Age</span>
                            <span className={brandData.target_forensics.is_recent ? 'text-red-400 font-bold block' : 'text-slate-200 block'}>
                              {brandData.target_forensics.created_date ? brandData.target_forensics.recency_label : 'Undeclared'}
                            </span>
                            {brandData.target_forensics.created_date && (
                              <span className="text-slate-500 block text-[10px] mt-0.5">
                                {brandData.target_forensics.created_date.split('T')[0]}
                              </span>
                            )}
                          </div>

                          <div className="p-2.5 bg-[#07090e] border border-[#1e2638] rounded">
                            <span className="text-slate-500 block text-[10px] uppercase">Official Registrar</span>
                            <span className="text-white font-bold block truncate" title={brandData.target_forensics.registrar}>
                              {brandData.target_forensics.registrar}
                            </span>
                            <span className="text-slate-400 block text-[10px] mt-0.5 truncate" title={brandData.target_forensics.abuse_email}>
                              Abuse: {brandData.target_forensics.abuse_email}
                            </span>
                          </div>

                          <div className="p-2.5 bg-[#07090e] border border-[#1e2638] rounded">
                            <span className="text-slate-500 block text-[10px] uppercase">Web Hosting (IPs)</span>
                            <div className="flex items-center space-x-1.5 mt-0.5">
                              <span className="text-sky-400 font-bold truncate">
                                {brandData.target_forensics.a_records?.length > 0 ? brandData.target_forensics.a_records.join(', ') : 'No A records'}
                              </span>
                              {onRefreshScan && brandData.target_forensics.a_records?.length > 0 && (
                                <button
                                  type="button"
                                  onClick={() => onRefreshScan(brandData.target_forensics.a_records[0])}
                                  title={`Audit IP ${brandData.target_forensics.a_records[0]}`}
                                  className="text-[10px] text-slate-400 hover:text-sky-300 underline cursor-pointer"
                                >
                                  [Audit Host]
                                </button>
                              )}
                            </div>
                          </div>

                          <div className="p-2.5 bg-[#07090e] border border-[#1e2638] rounded">
                            <span className="text-slate-500 block text-[10px] uppercase">MX Mail Servers</span>
                            <span className={brandData.target_forensics.mx_records?.length > 0 ? 'text-amber-400 font-bold block truncate' : 'text-slate-500 block'}>
                              {brandData.target_forensics.mx_records?.length > 0 ? brandData.target_forensics.mx_records.join(', ') : 'No MX servers'}
                            </span>
                          </div>
                        </div>

                        {/* Co-hosting / Passive DNS */}
                        {brandData.target_forensics.co_hosted_domains?.length > 0 && (
                          <div className="p-2.5 bg-[#07090e] border border-[#1e2638] rounded space-y-1.5">
                            <div className="flex items-center justify-between text-[11px]">
                              <span className="text-slate-400 font-semibold uppercase text-[10px]">
                                Co-Hosting / Passive DNS ({brandData.target_forensics.co_hosted_domains.length} domains on same IP):
                              </span>
                              <span className="text-[10px] text-slate-500 font-mono">IP: {brandData.target_forensics.primary_ip}</span>
                            </div>
                            <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto pr-1">
                              {brandData.target_forensics.co_hosted_domains.map((dom, dIdx) => (
                                <span key={dIdx} className="px-1.5 py-0.2 bg-[#121722] border border-[#1e2638] text-slate-300 text-[10px] rounded font-mono">
                                  {dom}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Right: Live Visual Evidence & External Links */}
                      <div className="p-2.5 bg-[#07090e] border border-[#1e2638] rounded flex flex-col justify-between space-y-2">
                        <div className="flex items-center justify-between border-b border-[#1e2638] pb-1.5">
                          <div className="flex items-center space-x-1.5 text-[11px] font-semibold text-slate-300">
                            <Camera size={13} className="text-sky-400" />
                            <span>Visual Evidence (Live Screenshot)</span>
                          </div>
                          <div className="flex items-center space-x-2 text-[10px]">
                            <button
                              type="button"
                              onClick={() => setScreenshotNonce((prev) => prev + 1)}
                              title="Force screenshot refresh"
                              className="text-slate-400 hover:text-white flex items-center space-x-1 cursor-pointer transition-colors"
                            >
                              <RefreshCw size={10} />
                              <span>Refresh</span>
                            </button>
                            <a
                              href={brandData.target_forensics.screenshot_url}
                              target="_blank"
                              rel="noreferrer"
                              className="text-sky-400 hover:underline inline-flex items-center space-x-1"
                            >
                              <span>Expand</span>
                              <ExternalLink size={10} />
                            </a>
                          </div>
                        </div>

                        <div className="relative w-full h-44 bg-[#040609] border border-[#1e2638] rounded overflow-hidden flex items-center justify-center">
                          <img
                            key={screenshotNonce}
                            src={`${brandData.target_forensics.screenshot_url}${screenshotNonce ? `&v=${screenshotNonce}` : ''}`}
                            alt={`Live snapshot of ${brandData.target_forensics.domain}`}
                            className="w-full h-full object-cover object-top opacity-90 hover:opacity-100 transition-opacity"
                            onError={(e) => {
                              e.currentTarget.style.display = 'none';
                              const next = e.currentTarget.nextElementSibling;
                              if (next) next.style.display = 'flex';
                            }}
                          />
                          <div className="hidden absolute inset-0 flex flex-col items-center justify-center p-3 text-center text-slate-400 text-[11px]">
                            <span>Capture rendering or shielded by firewall.</span>
                            <a
                              href={`https://urlscan.io/search/#domain:${encodeURIComponent(brandData.target_forensics.domain)}`}
                              target="_blank"
                              rel="noreferrer"
                              className="text-sky-400 hover:underline mt-1 inline-flex items-center space-x-1"
                            >
                              <span>Search forensic captures on urlscan.io</span>
                              <ExternalLink size={10} />
                            </a>
                          </div>
                        </div>

                        {/* Quick Forensic Pivot Buttons */}
                        <div className="grid grid-cols-3 gap-1.5 pt-1 text-[10px]">
                          <a
                            href={`https://urlscan.io/search/#domain:${encodeURIComponent(brandData.target_forensics.domain)}`}
                            target="_blank"
                            rel="noreferrer"
                            className="p-1 bg-[#101520] hover:bg-[#1a2333] border border-[#1e2638] rounded text-slate-300 hover:text-white text-center transition-colors truncate"
                          >
                            urlscan.io
                          </a>
                          <a
                            href={`https://www.virustotal.com/gui/domain/${encodeURIComponent(brandData.target_forensics.domain)}`}
                            target="_blank"
                            rel="noreferrer"
                            className="p-1 bg-[#101520] hover:bg-[#1a2333] border border-[#1e2638] rounded text-slate-300 hover:text-white text-center transition-colors truncate"
                          >
                            VirusTotal
                          </a>
                          <a
                            href={`https://who.is/whois/${encodeURIComponent(brandData.target_forensics.domain)}`}
                            target="_blank"
                            rel="noreferrer"
                            className="p-1 bg-[#101520] hover:bg-[#1a2333] border border-[#1e2638] rounded text-slate-300 hover:text-white text-center transition-colors truncate"
                          >
                            Full WHOIS
                          </a>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })()}

                {/* 2. PROACTIVE BRAND CLONES & TYPOSQUATTING MONITORING */}
                <div className="border-t border-[#1e2638] pt-3 space-y-3">
                  <div className="flex items-center space-x-2">
                    <Globe size={14} className="text-slate-400" />
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                      Proactive Brand Clones & Typosquatting Monitoring ({brandData.total_candidates_analyzed} Permutations Analyzed)
                    </h3>
                  </div>

                  {/* KPI Metrics Summary */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                    <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                      <span className="text-slate-500 block text-[10px]">Analyzed Mutations:</span>
                      <span className="text-slate-200 font-bold text-sm">{brandData.total_candidates_analyzed}</span>
                    </div>
                    <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                      <span className="text-slate-500 block text-[10px]">Active Threats (DNS):</span>
                      <span className={`font-bold text-sm ${brandData.active_threats_count > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                        {brandData.active_threats_count}
                      </span>
                    </div>
                    <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                      <span className="text-slate-500 block text-[10px]">Critical Threats (Active MX):</span>
                      <span className={`font-bold text-sm ${brandData.critical_count > 0 ? 'text-red-400 font-extrabold' : 'text-slate-400'}`}>
                        {brandData.critical_count}
                      </span>
                    </div>
                    <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                      <span className="text-slate-500 block text-[10px]">Inactive Mutations:</span>
                      <span className="text-slate-400 font-bold text-sm">{brandData.inactive_sample_count}</span>
                    </div>
                  </div>

                  {/* Findings List */}
                  {brandData.findings && brandData.findings.length > 0 ? (
                    <div className="space-y-2">
                      {brandData.findings.map((f, fIdx) => (
                        <div
                          key={fIdx}
                          className={`p-3 rounded border text-xs font-mono space-y-2 transition-colors ${
                            f.severity === 'CRITICAL'
                              ? 'bg-[#180d10] border-red-500/50'
                              : f.severity === 'HIGH'
                              ? 'bg-[#18110b] border-amber-500/50'
                              : 'bg-[#0d1119] border-[#1e2638]'
                          }`}
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1e2638]/60 pb-2">
                            <div className="flex items-center space-x-2">
                              <span className="text-sm font-bold text-white font-mono">{f.domain}</span>
                              <span className="px-1.5 py-0.2 rounded bg-[#101929] border border-sky-500/40 text-sky-300 text-[10px] font-bold">
                                {f.similarity}% Match
                              </span>
                              <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold border ${
                                f.severity === 'CRITICAL'
                                  ? 'bg-red-950 text-red-300 border-red-700'
                                  : f.severity === 'HIGH'
                                  ? 'bg-amber-950 text-amber-300 border-amber-700'
                                  : 'bg-yellow-950 text-yellow-300 border-yellow-700'
                              }`}>
                                {f.severity}
                              </span>
                            </div>

                            <div className="flex items-center space-x-2">
                              <button
                                type="button"
                                onClick={() => setSelectedTakedown(f)}
                                className="px-2.5 py-1 bg-[#1e2638] hover:bg-red-900/60 text-slate-200 hover:text-white border border-[#2d374d] rounded text-[11px] inline-flex items-center space-x-1.5 transition-colors cursor-pointer"
                              >
                                <FileText size={11} className="text-red-400" />
                                <span>Evidence & Takedown</span>
                              </button>
                              {onRefreshScan && f.a_records?.length > 0 && (
                                <button
                                  type="button"
                                  onClick={() => onRefreshScan(f.a_records[0])}
                                  title={`Audit IP ${f.a_records[0]}`}
                                  className="px-2 py-1 bg-[#151c28] hover:bg-[#1e2638] text-[#38bdf8] border border-[#1e2638] rounded text-[11px] transition-colors cursor-pointer"
                                >
                                  Audit Host
                                </button>
                              )}
                            </div>
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] text-slate-300">
                            <div>
                              <span className="text-slate-500 block text-[10px]">Mutation Type:</span>
                              <span className="text-slate-200 font-semibold">{f.mutation_type}</span>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[10px]">Age:</span>
                              <span className={f.is_recent ? 'text-red-400 font-bold' : 'text-slate-300'}>
                                {f.recency_label}
                              </span>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[10px]">Registrar (WHOIS):</span>
                              <span className="text-slate-300 truncate block" title={f.registrar}>
                                {f.registrar || 'Unknown'}
                              </span>
                            </div>
                          </div>

                          {/* Active Infrastructure Badges */}
                          <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-[#1e2638]/40 text-[11px]">
                            {f.a_records?.length > 0 ? (
                              <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-[#090b10] border border-[#1e2638] text-slate-200">
                                <span className="text-slate-500">Web IP(s):</span>
                                <span className="text-sky-400 font-bold">{f.a_records.join(', ')}</span>
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded bg-[#090b10] border border-[#1e2638] text-slate-500">
                                No Active Web
                              </span>
                            )}

                            {f.mx_records?.length > 0 ? (
                              <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-red-950/60 border border-red-500/50 text-red-300 font-bold">
                                <span>⚠️ Active MX Servers:</span>
                                <span className="text-white">{f.mx_records.join(', ')}</span>
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded bg-[#090b10] border border-[#1e2638] text-slate-500">
                                No MX Servers
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 bg-[#061e16] border border-emerald-500/40 rounded text-emerald-300 text-xs font-mono flex items-center space-x-2">
                      <CheckCircle2 size={15} className="text-emerald-400 shrink-0" />
                      <span>No additional lookalike mutations or registered clones were detected for {target}.</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </section>
        )}

        {/* 6. CLI PLAYBOOK FOR CYBERSECURITY ANALYSTS / PENTESTERS */}
        {showSection('playbook') && (
          <section className="space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e2638] pb-2">
              <div className="flex items-center space-x-2">
                <Terminal size={15} className="text-[#10b981]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                  CLI Playbook
                </h2>
              </div>
              <span className="text-[10px] font-mono text-slate-500">Parameterized terminal commands</span>
            </div>

            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-4">
              <div className="p-3 bg-[#090b10] border border-[#1e2638] rounded text-[11px] text-slate-300 font-sans leading-relaxed">
                <span className="text-[#10b981] font-bold font-mono">AUTHORIZED USE DIRECTIVE: </span>
                Parameterized commands with detected IP (<code>{primaryIp}</code>), domain (<code>{target}</code>), and open ports (<code>{openPortsStr}</code>) strictly for approved environments.
              </div>

              {/* SECTION A: STEALTH MODE COMMANDS (PASSIVE / LOW NOISE) */}
              <div className="space-y-3 p-3 bg-[#081210] border border-[#10b981]/30 rounded">
                <div className="flex items-center justify-between">
                  <div className="text-[11px] font-bold uppercase text-[#10b981] flex items-center space-x-1.5 font-mono">
                    <Shield size={14} className="text-[#10b981]" />
                    <span>STEALTH MODE // Passive & Low-Noise Reconnaissance (Non-Intrusive)</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#064e3b] text-[#a7f3d0] border border-[#10b981]/40">
                    Safe · No Anomalous Traffic
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">
                  Commands designed to harvest intelligence without triggering IDS/IPS alerts or registering as attack patterns in target firewall/WAF.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                  <CopyCommandBlock
                    label="WHOIS / RDAP · Network Ownership and IP Range Lookup (Passive OSINT)"
                    command={`whois ${primaryIp} | grep -E "inetnum|CIDR|OrgName|netname|country"`}
                  />
                  <CopyCommandBlock
                    label="Dig · Zone DNS Record Enumeration without Web Interaction"
                    command={`dig ANY ${target} @8.8.8.8 +noall +answer`}
                  />
                  <CopyCommandBlock
                    label="cURL · Silent HTTP Header Inspection (Standard User-Agent)"
                    command={`curl -k -I -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" https://${target}`}
                  />
                  <CopyCommandBlock
                    label="OpenSSL · Passive X.509 Certificate Chain Inspection"
                    command={`openssl s_client -connect ${target}:443 -servername ${target} -showcerts </dev/null`}
                  />
                  <CopyCommandBlock
                    label="Subfinder · Passive Subdomain Discovery (No Direct Probing)"
                    command={`subfinder -d ${target} -silent -all`}
                  />
                  <CopyCommandBlock
                    label="Nmap Stealth · Evasive SYN Probing with Decoys & Fragmented Packets (Slow T2)"
                    command={`nmap -sS -Pn -T2 -f -D RND:5 -p ${openPortsStr} ${primaryIp}`}
                  />
                </div>
              </div>

              {/* SECTION B: ACTIVE MODE COMMANDS (INTRUSIVE / AUTHORIZED AUDITING) */}
              <div className="space-y-3 p-3 bg-[#180f0e] border border-[#ef4444]/30 rounded">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-[11px] font-bold uppercase text-[#f87171] flex items-center space-x-1.5 font-mono">
                    <Zap size={14} className="text-[#ef4444]" />
                    <span>ACTIVE MODE // Authorized Audit Playbook & OWASP Top 10 (2025)</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#450a0a] text-[#fca5a5] border border-[#ef4444]/40">
                    Approved Environments Only (39 Commands)
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">
                  <strong className="text-red-400">OPSEC Warning:</strong> These commands directly interact with target ports and services, producing visible entries in SIEM/WAF logs. Organized according to the official <strong>OWASP Top 10 (2025)</strong> standard and advanced infrastructure reconnaissance.
                </p>

                {/* Interactive Category Filter */}
                <div className="flex items-center space-x-1.5 overflow-x-auto pb-1.5 pt-1 border-b border-[#2d1b1b] text-[10px] font-mono scrollbar-thin">
                  {[
                    { id: 'all', label: 'All (39)' },
                    { id: 'infra', label: 'Infrastructure & Ports (9)' },
                    { id: 'owasp_a01', label: 'A01: Access & SSRF (3)' },
                    { id: 'owasp_a02', label: 'A02: Misconfig & Fuzzing (4)' },
                    { id: 'owasp_a03', label: 'A03: Supply Chain & JS (5)' },
                    { id: 'owasp_a04', label: 'A04: Cryptography & TLS (3)' },
                    { id: 'owasp_a05', label: 'A05: Injections (4)' },
                    { id: 'owasp_a06', label: 'A06: APIs & Design (3)' },
                    { id: 'owasp_a07', label: 'A07: Authentication (2)' },
                    { id: 'owasp_a08_10', label: 'A08-A10: Integrity, DNS & Exceptions (6)' },
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => setActiveCliTab(tab.id)}
                      className={`px-2.5 py-1 rounded whitespace-nowrap cursor-pointer transition-colors ${
                        activeCliTab === tab.id
                          ? 'bg-[#ef4444] text-white font-bold shadow-sm'
                          : 'bg-[#1e0a0d] hover:bg-[#2b1014] text-slate-300 border border-[#3b151a]'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>

                <div className="space-y-4 pt-1">
                  {/* B.1 Infrastructure & Ports */}
                  {(activeCliTab === 'all' || activeCliTab === 'infra') && (
                    <div className="space-y-2">
                      <div className="text-[10px] font-bold uppercase text-slate-300 font-mono flex items-center justify-between">
                        <span>B.1 Infrastructure Reconnaissance, Banners & Exposed Services</span>
                        <span className="text-slate-500 text-[9px]">9 Commands</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <CopyCommandBlock
                          label="Nmap · Comprehensive Version and Default Script Enumeration"
                          command={`nmap -sV -sC -Pn -p ${openPortsStr} ${primaryIp}`}
                        />
                        <CopyCommandBlock
                          label="Nmap · Automated CVE Audit with Vulners NSE Engine"
                          command={`nmap -sV --script vulners -p ${openPortsStr} ${primaryIp}`}
                        />
                        <CopyCommandBlock
                          label="Nmap · Complete Vulnerability Detection Suite (vuln)"
                          command={`nmap -sV --script vuln -p ${openPortsStr} ${primaryIp}`}
                        />
                        <CopyCommandBlock
                          label="Nmap · OS Detection and Aggressive Timing (T4)"
                          command={`nmap -A -O -T4 -Pn -p ${openPortsStr} ${primaryIp}`}
                        />
                        <CopyCommandBlock
                          label="Masscan · Ultra-fast Full 65,535 TCP Port Sweep"
                          command={`masscan -p1-65535 ${primaryIp} --rate=1000 -e eth0`}
                        />
                        <CopyCommandBlock
                          label="FTP Anon · Anonymous Access and Bounce Verification on Port 21"
                          command={`nmap -p 21 --script ftp-anon,ftp-bounce ${primaryIp}`}
                        />
                        <CopyCommandBlock
                          label="MySQL · Blank Root Password and Information Audit on Port 3306"
                          command={`nmap -p 3306 --script mysql-empty-password,mysql-info ${primaryIp}`}
                        />
                        <CopyCommandBlock
                          label="Redis CLI · Unauthenticated Access Check on Port 6379"
                          command={`redis-cli -h ${primaryIp} -p 6379 ping`}
                        />
                        <CopyCommandBlock
                          label="NetExec (nxc) · SMB / WinRM / Null Session Audit"
                          command={`nxc smb ${primaryIp} -u '' -p ''`}
                        />
                      </div>
                    </div>
                  )}

                  {/* B.2 A01:2025 – Broken Access Control & SSRF */}
                  {(activeCliTab === 'all' || activeCliTab === 'owasp_a01') && (
                    <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                      <div className="text-[10px] font-bold uppercase text-slate-300 font-mono flex items-center justify-between">
                        <span className="text-[#f87171]">A01:2025 · Broken Access Control, BOLA, BFLA & SSRF</span>
                        <span className="text-slate-500 text-[9px]">3 Commands</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <CopyCommandBlock
                          label="Nuclei · SSRF, IDOR and Access Control Bypass Detection"
                          command={`nuclei -u https://${target} -tags ssrf,idor,auth-bypass -severity high,critical`}
                        />
                        <CopyCommandBlock
                          label="cURL · Reverse Proxy Header Authorization Bypass Test"
                          command={`curl -k -s -I -H "X-Original-URL: /admin" -H "X-Forwarded-For: 127.0.0.1" https://${target}/`}
                        />
                        <CopyCommandBlock
                          label="Ffuf · Virtual Hosts and Hidden Subdomains Fuzzing"
                          command={`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u https://${target} -H "Host: FUZZ.${target}" -fs 0`}
                        />
                      </div>
                    </div>
                  )}

                  {/* B.3 A02:2025 – Security Misconfiguration */}
                  {(activeCliTab === 'all' || activeCliTab === 'owasp_a02') && (
                    <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                      <div className="text-[10px] font-bold uppercase text-slate-300 font-mono flex items-center justify-between">
                        <span className="text-[#fb923c]">A02:2025 · Security Misconfiguration & Path Fuzzing</span>
                        <span className="text-slate-500 text-[9px]">4 Commands</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <CopyCommandBlock
                          label="Nikto · Comprehensive Web Server Security & Misconfiguration Audit"
                          command={`nikto -h https://${target} -Tuning 123b -C all`}
                        />
                        <CopyCommandBlock
                          label="Feroxbuster · Recursive Fuzzing of Sensitive Paths (.env, .git, backups)"
                          command={`feroxbuster -u https://${target} -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt,json,env,git -t 30`}
                        />
                        <CopyCommandBlock
                          label="Gobuster · Sensitive Directory and File Discovery"
                          command={`gobuster dir -u https://${target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -k`}
                        />
                        <CopyCommandBlock
                          label="Wafw00f · Web Application Firewall (WAF) Fingerprinting"
                          command={`wafw00f https://${target}`}
                        />
                      </div>
                    </div>
                  )}

                  {/* B.4 A03:2025 – Software Supply Chain Failures & JS Leaks */}
                  {(activeCliTab === 'all' || activeCliTab === 'owasp_a03') && (
                    <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                      <div className="text-[10px] font-bold uppercase text-slate-300 font-mono flex items-center justify-between">
                        <span className="text-[#facc15]">A03:2025 · Software Supply Chain Failures, SCA & JS Leaks</span>
                        <span className="text-slate-500 text-[9px]">5 Commands</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <CopyCommandBlock
                          label="Nuclei · Component and CVE Audit across Web Dependencies"
                          command={`nuclei -u https://${target} -tags cve,tech,exposure -severity high,critical`}
                        />
                        <CopyCommandBlock
                          label="WPScan · WordPress Plugin, Theme and User Enumeration"
                          command={`wpscan --url https://${target} --enumerate p,t,u --api-token YOUR_WPSCAN_TOKEN`}
                        />
                        <CopyCommandBlock
                          label="TruffleHog · API Key and Secret Leak Detection in Web Routes"
                          command={`trufflehog url --include-paths https://${target}`}
                        />
                        <CopyCommandBlock
                          label="SecretFinder · Token and Credential Extraction in JavaScript Files"
                          command={`python3 SecretFinder.py -i https://${target} -e -o cli`}
                        />
                        <CopyCommandBlock
                          label="Jsluice · AST Analysis of JavaScript Bundles to Extract Hidden Endpoints"
                          command={`jsluice urls https://${target}`}
                        />
                      </div>
                    </div>
                  )}

                  {/* B.5 A04:2025 – Cryptographic Failures */}
                  {(activeCliTab === 'all' || activeCliTab === 'owasp_a04') && (
                    <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                      <div className="text-[10px] font-bold uppercase text-slate-300 font-mono flex items-center justify-between">
                        <span className="text-[#38bdf8]">A04:2025 · Cryptographic Failures, Ciphers & TLS Protocols</span>
                        <span className="text-slate-500 text-[9px]">3 Commands</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <CopyCommandBlock
                          label="sslscan · Cipher Suite, Deprecated Protocols (TLS 1.0/1.1) & Heartbleed Audit"
                          command={`sslscan --tlsall ${target}:443`}
                        />
                        <CopyCommandBlock
                          label="testssl.sh · Deep TLS Assessment (POODLE, DROWN, ROBOT, BEAST)"
                          command={`testssl.sh --full https://${target}`}
                        />
                        <CopyCommandBlock
                          label="ssh-audit · Weak Cipher and SSH Banner Analysis (Port 22)"
                          command={`ssh-audit -v ${primaryIp}`}
                        />
                      </div>
                    </div>
                  )}

                  {/* B.6 A05:2025 – Injection & Fuzzing */}
                  {(activeCliTab === 'all' || activeCliTab === 'owasp_a05') && (
                    <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                      <div className="text-[10px] font-bold uppercase text-slate-300 font-mono flex items-center justify-between">
                        <span className="text-[#f87171]">A05:2025 · Injection (SQLi, XSS, Command Injection) & Parameters</span>
                        <span className="text-slate-500 text-[9px]">4 Commands</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <CopyCommandBlock
                          label="SQLmap · Automated SQL Injection in Forms and Parameters"
                          command={`sqlmap -u "https://${target}/" --crawl=2 --batch --random-agent --level=2 --risk=1`}
                        />
                        <CopyCommandBlock
                          label="Dalfox · Advanced XSS Scanning (DOM, Reflected and Stored)"
                          command={`dalfox url https://${target} --skip-bav --silence`}
                        />
                        <CopyCommandBlock
                          label="Commix · OS Command Injection Detection and Exploitation"
                          command={`commix --url="https://${target}/" --batch`}
                        />
                        <CopyCommandBlock
                          label="Arjun · Hidden HTTP Parameter Discovery and Fuzzing"
                          command={`arjun -u https://${target} --get --passive`}
                        />
                      </div>
                    </div>
                  )}

                  {/* B.7 A06:2025 – Insecure Design & APIs */}
                  {(activeCliTab === 'all' || activeCliTab === 'owasp_a06') && (
                    <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                      <div className="text-[10px] font-bold uppercase text-slate-300 font-mono flex items-center justify-between">
                        <span className="text-[#c084fc]">A06:2025 · Insecure Design, Crawling & Modern APIs</span>
                        <span className="text-slate-500 text-[9px]">3 Commands</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <CopyCommandBlock
                          label="Katana · Active Web Crawler for JS Route and Form Discovery"
                          command={`katana -u https://${target} -d 4 -jc -kf -silent`}
                        />
                        <CopyCommandBlock
                          label="Kiterunner (kr) · REST / OpenAPI Route and Endpoint Fuzzing"
                          command={`kr scan https://${target} -w routes-large.kite -x 20`}
                        />
                        <CopyCommandBlock
                          label="GraphQL-Cop · Security Audit and Introspection Check on GraphQL Endpoints"
                          command={`graphql-cop -t https://${target}/graphql`}
                        />
                      </div>
                    </div>
                  )}

                  {/* B.8 A07:2025 – Authentication Failures */}
                  {(activeCliTab === 'all' || activeCliTab === 'owasp_a07') && (
                    <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                      <div className="text-[10px] font-bold uppercase text-slate-300 font-mono flex items-center justify-between">
                        <span className="text-[#f87171]">A07:2025 · Identification and Authentication Failures</span>
                        <span className="text-slate-500 text-[9px]">2 Commands</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <CopyCommandBlock
                          label="Nmap · Default Account Audit on Web and Administrative Services"
                          command={`nmap -p 22,21,80,443 --script http-default-accounts,ftp-anon ${primaryIp}`}
                        />
                        <CopyCommandBlock
                          label="Hydra · Controlled Dictionary Attack on Login Form"
                          command={`hydra -l admin -P /usr/share/wordlists/rockyou.txt ${primaryIp} http-post-form`}
                        />
                      </div>
                    </div>
                  )}

                  {/* B.9 A08-A10:2025 – Integrity, DNS, Spoofing & Exceptions */}
                  {(activeCliTab === 'all' || activeCliTab === 'owasp_a08_10') && (
                    <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                      <div className="text-[10px] font-bold uppercase text-slate-300 font-mono flex items-center justify-between">
                        <span className="text-[#a7f3d0]">A08-A10:2025 · Integrity, Subdomains, Spoofing, Logs & Exceptions</span>
                        <span className="text-slate-500 text-[9px]">6 Commands</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <CopyCommandBlock
                          label="Subzy · Subdomain Takeover Detection on Orphaned CNAMEs"
                          command={`subzy run --targets subdomains.txt --concurrency 20`}
                        />
                        <CopyCommandBlock
                          label="DNSx · Active DNS Resolution, Wildcard Filtering & CNAME Check"
                          command={`dnsx -d ${target} -w subdomains.txt -resp -a -cname`}
                        />
                        <CopyCommandBlock
                          label="Checkdmarc · Anti-Spoofing Policy Assessment (SPF / DKIM / DMARC)"
                          command={`checkdmarc ${target} --format json`}
                        />
                        <CopyCommandBlock
                          label="Nuclei · A08:2025 Insecure Deserialization & Integrity Failures"
                          command={`nuclei -u https://${target} -tags deserialization,integrity`}
                        />
                        <CopyCommandBlock
                          label="cURL · A09:2025 Server Telemetry & Alert Generation Probing"
                          command={`curl -k -s -A "SniperScope-AlertTest/1.0" -w "%{http_code}\n" -o /dev/null "https://${target}/audit_trigger_test"`}
                        />
                        <CopyCommandBlock
                          label="cURL · A10:2025 Stack Trace Leak and Unhandled Exception Probing"
                          command={`curl -k -s -i -H "X-Debug: 1" "https://${target}/%00" | grep -i -E "exception|traceback|stack"`}
                        />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </section>
        )}

        {/* 7. OSINT DORKS ASSISTANT & SHADOW ATTACK SURFACE DISCOVERY */}
        {showSection('dorks') && (
          <section className="space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e2638] pb-2">
              <div className="flex items-center space-x-2">
                <Search size={15} className="text-[#38bdf8]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                  OSINT Dorks Assistant & Shadow Attack Surface Discovery
                </h2>
              </div>
              <span className="text-[10px] font-mono text-slate-500">Preconfigured advanced reconnaissance queries</span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Shodan Dorks */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center space-x-2 text-xs font-bold uppercase font-mono text-[#f87171]">
                  <Flame size={14} className="text-[#f87171]" />
                  <span>Shodan Dorks (Shadow IT, Origin IPs & Exposures)</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 font-mono text-xs">
                  {[
                    {
                      title: 'Origin IP via SSL Subject CN',
                      code: `ssl.cert.subject.cn:"${target}"`,
                      query: `ssl.cert.subject.cn:"${target}"`,
                    },
                    {
                      title: 'Full SSL Certificate Dump',
                      code: `ssl:"${target}"`,
                      query: `ssl:"${target}"`,
                    },
                    {
                      title: 'Subdomains & Reverse DNS',
                      code: `hostname:"${target}"`,
                      query: `hostname:"${target}"`,
                    },
                    {
                      title: 'Direct Target IP Services',
                      code: `ip:"${primaryIp}"`,
                      query: `ip:"${primaryIp}"`,
                    },
                    {
                      title: 'Exposed Databases (SQL / NoSQL)',
                      code: `hostname:"${target}" port:3306,5432,27017,6379,9200`,
                      query: `hostname:"${target}" port:3306,5432,27017,6379,9200`,
                    },
                    {
                      title: 'Admin & Login Dashboards',
                      code: `ssl:"${target}" http.title:"Admin" OR "Login"`,
                      query: `ssl:"${target}" http.title:"Admin" OR http.title:"Login" OR http.title:"Dashboard"`,
                    },
                    {
                      title: 'Non-Standard Web & Dev Ports',
                      code: `hostname:"${target}" -port:80,443 http.status:200`,
                      query: `hostname:"${target}" -port:80,443 http.status:200`,
                    },
                    {
                      title: 'Open Directory Listings',
                      code: `hostname:"${target}" http.title:"Index of /"`,
                      query: `hostname:"${target}" http.title:"Index of /"`,
                    },
                    ...(shodan[0]?.org
                      ? [
                          {
                            title: 'Organization / ASN Range',
                            code: `org:"${shodan[0].org}"`,
                            query: `org:"${shodan[0].org}"`,
                          },
                        ]
                      : []),
                  ].map((dork, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between gap-2 overflow-hidden"
                    >
                      <div className="min-w-0 flex-1 pr-1">
                        <span className="text-slate-500 block text-[10px] truncate" title={dork.title}>
                          {dork.title}
                        </span>
                        <code className="text-slate-200 text-[11px] block break-all leading-tight mt-0.5">
                          {dork.code}
                        </code>
                      </div>
                      <a
                        href={`https://www.shodan.io/search?query=${encodeURIComponent(dork.query)}`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0 whitespace-nowrap"
                      >
                        <span>Shodan</span>
                        <ExternalLink size={9} />
                      </a>
                    </div>
                  ))}
                </div>
              </div>

              {/* Google Hacking Dorks */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center space-x-2 text-xs font-bold uppercase font-mono text-[#facc15]">
                  <Search size={14} className="text-[#facc15]" />
                  <span>Google Hacking / Reconnaissance Dorks</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 font-mono text-xs">
                  {[
                    {
                      title: 'Config & Secrets (.env, .yml, .ini)',
                      code: 'ext:env | ext:yml | ext:ini | inurl:.env',
                      query: `site:${target} (ext:env OR ext:yaml OR ext:yml OR ext:ini OR inurl:".env")`,
                    },
                    {
                      title: 'DB Dumps & Backups (.sql, .bak)',
                      code: 'ext:sql | ext:bak | ext:old | ext:backup',
                      query: `site:${target} (ext:sql OR ext:bak OR ext:old OR ext:backup OR ext:dump)`,
                    },
                    {
                      title: 'Exposed .git, Swagger & phpinfo',
                      code: 'inurl:".git" | intitle:"phpinfo()" | swagger',
                      query: `site:${target} (inurl:".git" OR intitle:"phpinfo()" OR inurl:swagger OR inurl:api-docs)`,
                    },
                    {
                      title: 'Admin Panels & CMS Logins',
                      code: 'inurl:admin | login | wp-admin | portal',
                      query: `site:${target} (inurl:admin OR inurl:login OR inurl:wp-admin OR inurl:portal OR inurl:dashboard)`,
                    },
                    {
                      title: 'Exposed Directory Listings',
                      code: 'intitle:"index of /"',
                      query: `site:${target} intitle:"index of /"`,
                    },
                    {
                      title: 'SQL Errors & Stack Traces',
                      code: '"SQL syntax" | "Uncaught Exception"',
                      query: `site:${target} ("SQL syntax" OR "mysql_fetch" OR "Warning: include" OR "Uncaught Exception" OR "Stack trace:")`,
                    },
                    {
                      title: 'Indexed Subdomains',
                      code: `site:*.${target} -www`,
                      query: `site:*.${target} -www`,
                    },
                    {
                      title: 'Public Documents & Spreadsheets',
                      code: 'filetype:pdf | xlsx | docx | csv',
                      query: `site:${target} (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv)`,
                    },
                    {
                      title: 'Cloud Storage Buckets (S3 / Azure / GCP)',
                      code: `"${target}" site:s3.amazonaws.com | blob`,
                      query: `"${target}" (site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com)`,
                    },
                    {
                      title: '3rd-Party Leaks (Pastebin, Trello, Postman)',
                      code: `"${target}" site:pastebin.com | trello`,
                      query: `"${target}" (site:pastebin.com OR site:trello.com OR site:postman.com OR site:jsfiddle.net)`,
                    },
                  ].map((dork, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between gap-2 overflow-hidden"
                    >
                      <div className="min-w-0 flex-1 pr-1">
                        <span className="text-slate-500 block text-[10px] truncate" title={dork.title}>
                          {dork.title}
                        </span>
                        <code className="text-slate-200 text-[11px] block break-all leading-tight mt-0.5">
                          {dork.code}
                        </code>
                      </div>
                      <a
                        href={`https://www.google.com/search?q=${encodeURIComponent(dork.query)}`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0 whitespace-nowrap"
                      >
                        <span>Dork</span>
                        <ExternalLink size={9} />
                      </a>
                    </div>
                  ))}
                </div>
              </div>

              {/* GitHub Leak Dorks */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3 lg:col-span-2">
                <div className="flex items-center space-x-2 text-xs font-bold uppercase font-mono text-[#a78bfa]">
                  <Bug size={14} className="text-[#a78bfa]" />
                  <span>GitHub Code Search / Credential Leaks</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-1 font-mono text-xs">
                  {[
                    {
                      title: 'Secrets & API Keys',
                      code: `"${target}" password | secret | api_key`,
                      query: `"${target}" (password OR secret OR api_key OR token)`,
                    },
                    {
                      title: '.env & Credentials Files',
                      code: `"${target}" filename:.env | credentials`,
                      query: `"${target}" (filename:.env OR filename:credentials OR filename:config.json)`,
                    },
                    {
                      title: 'Database Connection Strings',
                      code: `"${target}" mongodb:// | postgres:// | mysql://`,
                      query: `"${target}" (mongodb OR postgres OR mysql OR redis) password`,
                    },
                    {
                      title: 'Private Keys & Certificates',
                      code: `"${target}" "BEGIN RSA PRIVATE KEY"`,
                      query: `"${target}" ("BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY" OR extension:pem)`,
                    },
                  ].map((dork, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between gap-2 overflow-hidden"
                    >
                      <div className="min-w-0 flex-1 pr-1">
                        <span className="text-slate-500 block text-[10px] truncate" title={dork.title}>
                          {dork.title}
                        </span>
                        <code className="text-slate-200 text-[11px] block break-all leading-tight mt-0.5">
                          {dork.code}
                        </code>
                      </div>
                      <a
                        href={`https://github.com/search?q=${encodeURIComponent(dork.query)}&type=code`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2 py-1 bg-[#1e2638] hover:bg-[#7c3aed] text-purple-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0 whitespace-nowrap"
                      >
                        <span>GitHub</span>
                        <ExternalLink size={9} />
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* External Threat Intelligence Platforms */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-2">
              <div className="text-[11px] font-bold uppercase font-mono text-slate-300">
                Threat Intelligence & Passive Reconnaissance Platforms
              </div>
              <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-xs">
                <a
                  href={`https://www.virustotal.com/gui/domain/${encodeURIComponent(target)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-[#090b10] hover:bg-[#151c28] border border-[#1e2638] hover:border-[#38bdf8] text-slate-300 hover:text-white rounded transition-colors inline-flex items-center space-x-1.5"
                >
                  <Shield size={13} className="text-[#38bdf8]" />
                  <span>VirusTotal</span>
                  <ExternalLink size={10} />
                </a>
                <a
                  href={`https://urlscan.io/domain/${target}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-[#090b10] hover:bg-[#151c28] border border-[#1e2638] hover:border-[#38bdf8] text-slate-300 hover:text-white rounded transition-colors inline-flex items-center space-x-1.5"
                >
                  <Globe size={13} className="text-[#10b981]" />
                  <span>URLScan.io</span>
                  <ExternalLink size={10} />
                </a>
                <a
                  href={`https://otx.alienvault.com/indicator/domain/${encodeURIComponent(target)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-[#090b10] hover:bg-[#151c28] border border-[#1e2638] hover:border-[#38bdf8] text-slate-300 hover:text-white rounded transition-colors inline-flex items-center space-x-1.5"
                >
                  <ShieldAlert size={13} className="text-[#f87171]" />
                  <span>AlienVault OTX</span>
                  <ExternalLink size={10} />
                </a>
                <a
                  href={`https://search.censys.io/search?q=${encodeURIComponent(target)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-[#090b10] hover:bg-[#151c28] border border-[#1e2638] hover:border-[#38bdf8] text-slate-300 hover:text-white rounded transition-colors inline-flex items-center space-x-1.5"
                >
                  <Server size={13} className="text-[#38bdf8]" />
                  <span>Censys</span>
                  <ExternalLink size={10} />
                </a>
                <a
                  href={`https://web.archive.org/web/*/${encodeURIComponent(target)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-[#090b10] hover:bg-[#151c28] border border-[#1e2638] hover:border-[#38bdf8] text-slate-300 hover:text-white rounded transition-colors inline-flex items-center space-x-1.5"
                >
                  <Clock size={13} className="text-[#fb923c]" />
                  <span>Wayback Machine</span>
                  <ExternalLink size={10} />
                </a>
                <a
                  href={`https://crt.sh/?q=%.${encodeURIComponent(target)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-[#090b10] hover:bg-[#151c28] border border-[#1e2638] hover:border-[#38bdf8] text-slate-300 hover:text-white rounded transition-colors inline-flex items-center space-x-1.5"
                >
                  <Lock size={13} className="text-[#facc15]" />
                  <span>crt.sh (CT Logs)</span>
                  <ExternalLink size={10} />
                </a>
                <a
                  href={`https://securitytrails.com/domain/${encodeURIComponent(target)}/dns`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 bg-[#090b10] hover:bg-[#151c28] border border-[#1e2638] hover:border-[#38bdf8] text-slate-300 hover:text-white rounded transition-colors inline-flex items-center space-x-1.5"
                >
                  <Crosshair size={13} className="text-[#c084fc]" />
                  <span>SecurityTrails DNS</span>
                  <ExternalLink size={10} />
                </a>
              </div>
            </div>
          </section>
        )}
      </div>

      {/* TAKEDOWN & EVIDENCE DOSSIER MODAL */}
      {selectedTakedown && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b0e14] border border-[#2d374d] rounded-lg max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-mono">
            {/* Header */}
            <div className="bg-[#111722] px-4 py-3 border-b border-[#1e2638] flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ShieldAlert size={16} className="text-red-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  Takedown Dossier // {selectedTakedown.domain}
                </h3>
                <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                  selectedTakedown.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-500/60' :
                  selectedTakedown.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-500/60' :
                  'bg-yellow-950 text-yellow-300 border border-yellow-500/60'
                }`}>
                  {selectedTakedown.severity}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedTakedown(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-[#1a2333] transition-colors cursor-pointer"
              >
                <X size={16} />
              </button>
            </div>

            {/* Quick Evidence Summary */}
            <div className="p-4 bg-[#080a0f] border-b border-[#1e2638] grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Brand Similarity</span>
                <span className="text-red-400 font-bold">{selectedTakedown.similarity}%</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Domain Age</span>
                <span className={selectedTakedown.is_recent ? 'text-red-400 font-bold' : 'text-slate-300'}>
                  {selectedTakedown.recency_label}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Host IP(s)</span>
                <span className="text-sky-400 font-bold truncate block">
                  {selectedTakedown.a_records?.length > 0 ? selectedTakedown.a_records.join(', ') : 'None'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">MX Server</span>
                <span className="text-amber-400 font-bold truncate block">
                  {selectedTakedown.mx_records?.length > 0 ? selectedTakedown.mx_records.join(', ') : 'None'}
                </span>
              </div>
            </div>

            {/* Takedown Notice Body */}
            <div className="p-4 flex-1 overflow-y-auto space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-400 uppercase font-semibold">
                  Formal RFC Abuse Notification Template for Registrar / CERT:
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyTakedown(selectedTakedown.takedown_notice)}
                  className={`px-3 py-1 rounded text-xs inline-flex items-center space-x-1.5 transition-all font-bold cursor-pointer ${
                    copiedNotice
                      ? 'bg-emerald-600 text-white'
                      : 'bg-red-700 hover:bg-red-600 text-white shadow'
                  }`}
                >
                  {copiedNotice ? <Check size={13} /> : <Copy size={13} />}
                  <span>{copiedNotice ? 'Notice Copied!' : 'Copy Abuse Notice'}</span>
                </button>
              </div>

              <pre className="p-3 bg-[#05070a] border border-[#1e2638] rounded text-slate-300 text-[11px] leading-relaxed whitespace-pre-wrap font-mono select-all max-h-[300px] overflow-y-auto">
                {selectedTakedown.takedown_notice}
              </pre>

              <div className="pt-2 flex flex-wrap gap-2 text-xs">
                <a
                  href={`https://urlscan.io/search/#domain:${encodeURIComponent(selectedTakedown.domain)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 bg-[#131926] hover:bg-[#1e2638] border border-[#1e2638] hover:border-sky-400 text-slate-300 rounded inline-flex items-center space-x-1"
                >
                  <span>Investigate on urlscan.io</span>
                  <ExternalLink size={10} />
                </a>
                <a
                  href={`https://www.virustotal.com/gui/domain/${encodeURIComponent(selectedTakedown.domain)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 bg-[#131926] hover:bg-[#1e2638] border border-[#1e2638] hover:border-sky-400 text-slate-300 rounded inline-flex items-center space-x-1"
                >
                  <span>VirusTotal Reputation</span>
                  <ExternalLink size={10} />
                </a>
                <a
                  href={`https://who.is/whois/${encodeURIComponent(selectedTakedown.domain)}`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 bg-[#131926] hover:bg-[#1e2638] border border-[#1e2638] hover:border-sky-400 text-slate-300 rounded inline-flex items-center space-x-1"
                >
                  <span>Full WHOIS</span>
                  <ExternalLink size={10} />
                </a>
              </div>
            </div>

            {/* Footer */}
            <div className="bg-[#111722] px-4 py-2.5 border-t border-[#1e2638] flex justify-end">
              <button
                type="button"
                onClick={() => setSelectedTakedown(null)}
                className="px-3 py-1 bg-[#1a2333] hover:bg-[#253247] text-slate-300 hover:text-white rounded text-xs transition-colors cursor-pointer"
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
