import React, { useState } from 'react';
import {
  Server,
  Shield,
  ShieldAlert,
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
  Bug
} from 'lucide-react';

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
  const [cveFilter, setCveFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [activeSection, setActiveSection] = useState('all');
  const [activeCliTab, setActiveCliTab] = useState('all');

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
  } = scanData;

  const filteredVulns = vulnerabilities.filter((v) => {
    const matchesText =
      v.cve.toLowerCase().includes(cveFilter.toLowerCase()) ||
      (v.summary || '').toLowerCase().includes(cveFilter.toLowerCase()) ||
      (v.service || '').toLowerCase().includes(cveFilter.toLowerCase()) ||
      (v.product || '').toLowerCase().includes(cveFilter.toLowerCase());
    if (severityFilter === 'KEV') return matchesText && Boolean(v.kev);
    const matchesSev = severityFilter === 'ALL' || (v.severity || '').toUpperCase() === severityFilter;
    return matchesText && matchesSev;
  });

  const navItems = [
    { id: 'all', label: 'Full Dossier' },
    { id: 'services', label: `Ports & Services (${summary.open_ports_count || 0})` },
    { id: 'vulns', label: `CVEs (${summary.vulnerabilities_count || 0})` },
    { id: 'http', label: 'Web, TLS & WAF' },
    { id: 'dns', label: `DNS & Subdomains (${summary.subdomains_count || 0})` },
    { id: 'playbook', label: 'CLI Playbook' },
    { id: 'dorks', label: 'OSINT Dorks' },
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
      <div className="px-4 py-2 bg-[#0c1017] border-b border-[#1e2638] flex flex-wrap items-center justify-between gap-2 shrink-0">
        <div className="flex items-center space-x-1 overflow-x-auto">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveSection(item.id)}
              className={`px-2.5 py-1 text-[11px] font-mono rounded transition-colors cursor-pointer ${
                activeSection === item.id
                  ? 'bg-[#1e2638] text-white font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#141923]'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>

        {onRefreshScan && (
          <button
            onClick={() => onRefreshScan(target)}
            title="Force live re-scan bypassing cache"
            className="p-1.5 text-slate-400 hover:text-[#38bdf8] hover:bg-[#141923] rounded transition-colors cursor-pointer"
          >
            <RefreshCw size={13} />
          </button>
        )}
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
                Showing {filteredVulns.length} of {vulnerabilities.length} enriched CVEs
              </span>
            </div>

            {vulnerabilities.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 bg-[#0d1119] p-3 border border-[#1e2638] rounded">
                <div className="relative flex-1 min-w-[200px]">
                  <Search size={13} className="absolute left-2.5 top-2 text-slate-500" />
                  <input
                    type="text"
                    value={cveFilter}
                    onChange={(e) => setCveFilter(e.target.value)}
                    placeholder="Filter by CVE, product, module or impact (e.g. mod_ssl, RCE, DoS, CVE-2024)..."
                    className="w-full bg-[#07090e] border border-[#1e2638] pl-8 pr-3 py-1 text-xs text-slate-200 rounded focus:outline-none focus:border-[#38bdf8]"
                  />
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  {['ALL', 'KEV', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setSeverityFilter(sev)}
                      className={`px-2 py-1 text-[10px] font-bold rounded cursor-pointer transition-colors ${
                        severityFilter === sev
                          ? 'bg-[#38bdf8] text-[#090b10]'
                          : 'bg-[#121824] text-slate-400 hover:text-white border border-[#1e2638]'
                      }`}
                    >
                      {sev === 'ALL' ? 'ALL' : sev === 'KEV' ? 'CISA KEV' : sev}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {filteredVulns.length === 0 ? (
              <div className="bg-[#0d1119] border border-[#1e2638] p-4 rounded text-slate-500">
                {vulnerabilities.length === 0
                  ? 'No public vulnerabilities associated with exposed services detected.'
                  : 'No vulnerabilities match the current filter.'}
              </div>
            ) : (
              <div className="space-y-3">
                {filteredVulns.map((v) => (
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
                  <span>Shodan Dorks (Shadow IT & Certificates)</span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">
                  Discover satellite servers, staging environments, or target assets unlisted in official DNS:
                </p>
                <div className="space-y-2 pt-1 font-mono text-xs">
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">SSL Certificates / SANs</span>
                      <code className="text-slate-200">ssl:"{target}"</code>
                    </div>
                    <a
                      href={`https://www.shodan.io/search?query=ssl%3A%22${encodeURIComponent(target)}%22`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2.5 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>Launch Shodan</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Hostname / Reverse DNS</span>
                      <code className="text-slate-200">hostname:"{target}"</code>
                    </div>
                    <a
                      href={`https://www.shodan.io/search?query=hostname%3A%22${encodeURIComponent(target)}%22`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2.5 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>Launch Shodan</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>
                  {shodan[0]?.org && (
                    <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                      <div>
                        <span className="text-slate-500 block text-[10px]">Organization Range</span>
                        <code className="text-slate-200">org:"{shodan[0].org}"</code>
                      </div>
                      <a
                        href={`https://www.shodan.io/search?query=org%3A%22${encodeURIComponent(shodan[0].org)}%22`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2.5 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                      >
                        <span>Launch Shodan</span>
                        <ExternalLink size={9} />
                      </a>
                    </div>
                  )}
                </div>
              </div>

              {/* Google Hacking Dorks */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center space-x-2 text-xs font-bold uppercase font-mono text-[#facc15]">
                  <Search size={14} className="text-[#facc15]" />
                  <span>Google Hacking / Reconnaissance Dorks</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1 font-mono text-xs">
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Sensitive Files (.env, .sql, .log)</span>
                      <code className="text-slate-200 text-[11px]">ext:env | ext:sql | ext:log</code>
                    </div>
                    <a
                      href={`https://www.google.com/search?q=site%3A${encodeURIComponent(target)}+ext%3Aenv+OR+ext%3Asql+OR+ext%3Alog+OR+ext%3Abak+OR+ext%3Ayml`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>Google Dork</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Admin Panels & CMS Logins</span>
                      <code className="text-slate-200 text-[11px]">inurl:admin | login | wp-admin</code>
                    </div>
                    <a
                      href={`https://www.google.com/search?q=site%3A${encodeURIComponent(target)}+inurl%3Aadmin+OR+inurl%3Alogin+OR+inurl%3Awp-admin+OR+inurl%3Adashboard`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>Google Dork</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Exposed Directory Listings</span>
                      <code className="text-slate-200 text-[11px]">intitle:"index of"</code>
                    </div>
                    <a
                      href={`https://www.google.com/search?q=site%3A${encodeURIComponent(target)}+intitle%3A%22index+of%22`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>Google Dork</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Public Documents & Office Files</span>
                      <code className="text-slate-200 text-[11px]">filetype:pdf | xlsx | docx</code>
                    </div>
                    <a
                      href={`https://www.google.com/search?q=site%3A${encodeURIComponent(target)}+filetype%3Apdf+OR+filetype%3Axlsx+OR+filetype%3Adocx+OR+filetype%3Acsv`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>Google Dork</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Indexed Subdomains</span>
                      <code className="text-slate-200 text-[11px]">site:*.{target} -www</code>
                    </div>
                    <a
                      href={`https://www.google.com/search?q=site%3A*.${encodeURIComponent(target)}+-www.${encodeURIComponent(target)}`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>Google Dork</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Keys, VPNs & Certificates</span>
                      <code className="text-slate-200 text-[11px]">ext:pem | key | ovpn | conf</code>
                    </div>
                    <a
                      href={`https://www.google.com/search?q=site%3A${encodeURIComponent(target)}+ext%3Apem+OR+ext%3Akey+OR+ext%3Aovpn+OR+ext%3Aconf`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2 py-1 bg-[#1e2638] hover:bg-[#0284c7] text-[#38bdf8] hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>Google Dork</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>
                </div>
              </div>

              {/* GitHub Leak Dorks */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center space-x-2 text-xs font-bold uppercase font-mono text-[#a78bfa]">
                  <Bug size={14} className="text-[#a78bfa]" />
                  <span>GitHub Code Search / Credential Leaks</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1 font-mono text-xs">
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Secrets & Passwords</span>
                      <code className="text-slate-200 text-[11px]">"{target}" password | secret</code>
                    </div>
                    <a
                      href={`https://github.com/search?q=%22${encodeURIComponent(target)}%22+password+OR+secret+OR+api_key&type=code`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2 py-1 bg-[#1e2638] hover:bg-[#7c3aed] text-purple-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>GitHub Search</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                    <div>
                      <span className="text-slate-500 block text-[10px]">.env Files & Credentials</span>
                      <code className="text-slate-200 text-[11px]">"{target}" filename:.env</code>
                    </div>
                    <a
                      href={`https://github.com/search?q=%22${encodeURIComponent(target)}%22+filename%3A.env+OR+filename%3Acredentials&type=code`}
                      target="_blank"
                      rel="noreferrer"
                      className="px-2 py-1 bg-[#1e2638] hover:bg-[#7c3aed] text-purple-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                    >
                      <span>GitHub Search</span>
                      <ExternalLink size={9} />
                    </a>
                  </div>
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
    </div>
  );
}
