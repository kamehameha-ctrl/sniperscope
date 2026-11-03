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
  Zap
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
        reject(new Error('No se pudo copiar el comando'));
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
              <span>¡Comando copiado!</span>
            </>
          ) : (
            <>
              <Copy size={11} />
              <span>Copiar</span>
            </>
          )}
        </button>
      </div>
      <pre
        onClick={handleCopy}
        title="Haz clic para copiar el comando"
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

  if (!scanData) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-6 bg-[#090b10] select-text overflow-y-auto">
        <div className="max-w-xl w-full flex flex-col items-center text-center">
          <div className="w-12 h-12 rounded border border-[#38bdf8]/40 bg-[#0f172a] flex items-center justify-center text-[#38bdf8] mb-3">
            <Crosshair size={24} />
          </div>
          <div className="text-base font-mono text-slate-100 font-bold tracking-wide">
            SNIPERSCOPE // ESTACIÓN DE INTELIGENCIA EASM & OSINT
          </div>
          <p className="text-xs font-mono text-slate-500 max-w-md mt-1.5 leading-relaxed">
            Introduce un dominio, URL o dirección IP en la barra superior para iniciar el reconocimiento de superficie de ataque: puertos abiertos, versiones exactas, certificados TLS, WAF/CDN, exposiciones web, CVEs con CVSS/EPSS/KEV y playbook de auditoría.
          </p>

          {/* Historial de Auditorías Recientes en Caché */}
          {recentScans.length > 0 && (
            <div className="w-full mt-8 text-left bg-[#0c1017] border border-[#1e2638] rounded p-4 font-mono">
              <div className="flex items-center justify-between border-b border-[#1e2638] pb-2.5 mb-3">
                <div className="flex items-center space-x-2 text-xs font-bold text-slate-300 uppercase">
                  <Clock size={13} className="text-[#38bdf8]" />
                  <span>Sesiones en Caché Local (Carga Instantánea)</span>
                </div>
                <button
                  type="button"
                  onClick={onClearRecent}
                  className="text-[10px] text-slate-500 hover:text-[#ef4444] flex items-center space-x-1 cursor-pointer transition-colors"
                >
                  <Trash2 size={11} />
                  <span>Limpiar caché</span>
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {recentScans.map((item) => (
                  <div
                    key={item.target}
                    onClick={() => onSelectRecent && onSelectRecent(item)}
                    className="p-3 bg-[#090b10] hover:bg-[#131926] border border-[#1e2638] hover:border-[#38bdf8]/50 rounded cursor-pointer transition-all flex items-center justify-between"
                    title="Restaurar sesión guardada en caché sin volver a escanear"
                  >
                    <div className="min-w-0 pr-2">
                      <div className="flex items-center space-x-1.5">
                        <span className="text-xs font-bold text-white truncate">{item.target}</span>
                        <span className="px-1.5 py-0.2 bg-[#064e3b]/60 border border-[#10b981]/40 text-[#a7f3d0] text-[9px] rounded uppercase shrink-0">
                          Caché
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {item.summary?.open_ports_count ?? 0} puertos · {item.summary?.vulnerabilities_count ?? 0} CVEs
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
    { id: 'all', label: 'Dossier Completo' },
    { id: 'services', label: `Puertos & Servicios (${summary.open_ports_count || 0})` },
    { id: 'vulns', label: `CVEs (${summary.vulnerabilities_count || 0})` },
    { id: 'http', label: 'Web, TLS & WAF' },
    { id: 'dns', label: `DNS & Subdominios (${summary.subdomains_count || 0})` },
    { id: 'playbook', label: 'Playbook CLI' },
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
            title="Forzar nuevo escaneo en vivo ignorando caché"
            className="p-1.5 text-slate-400 hover:text-[#38bdf8] hover:bg-[#141923] rounded transition-colors cursor-pointer"
          >
            <RefreshCw size={13} />
          </button>
        )}
      </div>

      {/* Contenido scrollable en texto */}
      <div className="flex-1 overflow-y-auto p-4 space-y-6 font-mono text-xs">
        {/* 1. CABECERA DE OBJETIVO, RISK SCORE Y HALLAZGOS CLAVE (SOLO EN DOSSIER COMPLETO) */}
        {activeSection === 'all' && (
          <section className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[#1e2638] pb-3">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-500">
                  Objetivo Auditado // Dossier de Inteligencia Forense
                </div>
                <div className="text-lg font-bold text-white flex items-center space-x-2 mt-0.5">
                  <span>{target}</span>
                  <button
                    onClick={() => onFocusNode && onFocusNode(`target_${target}`)}
                    className="text-[10px] px-2 py-0.5 bg-[#151c28] hover:bg-[#1e2638] text-[#38bdf8] border border-[#1e2638] rounded font-normal cursor-pointer"
                  >
                    Ver en grafo
                  </button>
                </div>
                <div className="text-[11px] text-slate-400 mt-1">
                  Escaneo: <span className="text-slate-300">{scan_timestamp}</span>
                  {scan_duration_sec !== undefined && (
                    <span> · Duración: <span className="text-[#10b981]">{scan_duration_sec}s</span></span>
                  )}
                  {rdap_domain?.registrar && rdap_domain.registrar !== 'Desconocido' && (
                    <span> · Registrador: <span className="text-slate-300">{rdap_domain.registrar}</span></span>
                  )}
                </div>
              </div>

              {/* Badge de Risk Score Global */}
              {risk.score !== undefined && (
                <div className={`px-3.5 py-2 rounded border flex items-center space-x-3 ${riskColor}`}>
                  <div>
                    <div className="text-[10px] uppercase opacity-80">Índice de Riesgo</div>
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

            {/* Métricas de Superficie */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-[#090b10] border border-[#1e2638] p-3 rounded">
                <div className="text-[10px] uppercase text-slate-500">Activos / IPs</div>
                <div className="text-xl font-bold text-[#10b981] mt-1">{summary.ips_count || 0}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">{summary.subdomains_count || 0} subdominios</div>
              </div>
              <div className="bg-[#090b10] border border-[#1e2638] p-3 rounded">
                <div className="text-[10px] uppercase text-slate-500">Puertos Abiertos</div>
                <div className="text-xl font-bold text-[#38bdf8] mt-1">{summary.open_ports_count || 0}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">Servicios detectados</div>
              </div>
              <div className="bg-[#090b10] border border-[#1e2638] p-3 rounded">
                <div className="text-[10px] uppercase text-slate-500">Total CVEs</div>
                <div className={`text-xl font-bold mt-1 ${summary.vulnerabilities_count > 0 ? 'text-[#ef4444]' : 'text-slate-300'}`}>
                  {summary.vulnerabilities_count || 0}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">
                  {summary.critical_vulns || 0} Críticas · {summary.high_vulns || 0} Altas
                </div>
              </div>
              <div className="bg-[#090b10] border border-[#1e2638] p-3 rounded">
                <div className="text-[10px] uppercase text-slate-500">WAF / Correo</div>
                <div className="text-xs font-bold text-slate-200 mt-1 truncate" title={http_audit?.waf_cdn || 'IP Directa / Sin WAF'}>
                  {http_audit?.waf_cdn || 'Sin WAF detectado'}
                </div>
                <div className="flex items-center space-x-2 mt-1 text-[10px]">
                  <span className={dns.email_security?.has_spf ? 'text-[#10b981]' : 'text-[#ef4444]'}>
                    SPF: {dns.email_security?.has_spf ? 'OK' : 'NO'}
                  </span>
                  <span>·</span>
                  <span className={dns.email_security?.has_dmarc ? 'text-[#10b981]' : 'text-[#ef4444]'}>
                    DMARC: {dns.email_security?.has_dmarc ? 'OK' : 'NO'}
                  </span>
                </div>
              </div>
            </div>

            {/* Hallazgos Prioritarios para el Analista */}
            {risk.findings && risk.findings.length > 0 && (
              <div className="space-y-1.5 pt-1">
                <div className="text-[10px] uppercase tracking-wider text-slate-400 font-bold">
                  Vectores de Riesgo Prioritarios Detectados:
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

        {/* 2. INFRAESTRUCTURA, PUERTOS ABIERTOS Y SERVICIOS EN EJECUCIÓN */}
        {showSection('services') && (
          <section className="space-y-3">
            <div className="flex items-center justify-between border-b border-[#1e2638] pb-2">
              <div className="flex items-center space-x-2">
                <Server size={15} className="text-[#10b981]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                  Infraestructura de Red, Puertos Abiertos y Servicios en Ejecución
                </h2>
              </div>
              <span className="text-[11px] text-slate-500">{shodan.length} host(s) auditados</span>
            </div>

            {shodan.length === 0 ? (
              <div className="bg-[#0d1119] border border-[#1e2638] p-4 rounded text-slate-500">
                No se encontraron direcciones IP o datos de Shodan para este objetivo.
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
                            title="Ver información del ASN, rangos y empresa en IPinfo"
                            className="inline-flex items-center space-x-1 px-2 py-0.5 bg-[#0f2438] hover:bg-[#1a3854] text-[#38bdf8] border border-[#0369a1] rounded text-[11px] font-mono transition-colors"
                          >
                            <span>{host.asn}</span>
                            <ExternalLink size={10} />
                          </a>
                          <a
                            href={`https://bgp.he.net/AS${String(host.asn).replace(/[^0-9]/g, '')}`}
                            target="_blank"
                            rel="noreferrer"
                            title="Ver rutas BGP y peers en Hurricane Electric (BGP.he.net)"
                            className="inline-flex items-center px-1.5 py-0.5 bg-[#121824] hover:bg-[#1e2638] text-slate-400 hover:text-white border border-[#1e2638] rounded text-[10px] font-mono transition-colors"
                          >
                            BGP.he
                          </a>
                        </div>
                      )}
                      {host.os && (
                        <span className="px-2 py-0.5 bg-[#0f2438] border border-[#0369a1] text-[#38bdf8] rounded text-[10px]">
                          SO: {host.os}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center space-x-2">
                      <span className="text-[10px] text-slate-500">{host.source}</span>
                      <button
                        onClick={() => onFocusNode && onFocusNode(`ip_${host.ip}`)}
                        className="px-2 py-0.5 bg-[#1a2233] hover:bg-[#253047] text-[#38bdf8] rounded text-[10px] cursor-pointer"
                      >
                        Enfocar IP
                      </button>
                    </div>
                  </div>

                  {/* Metadatos del Host */}
                  <div className="px-4 py-2.5 bg-[#0b0e15] border-b border-[#1e2638] grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] text-slate-400">
                    <div>
                      <span className="text-slate-500">ISP:</span>{' '}
                      <span className="text-slate-200">{host.isp || host.org || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Geolocalización:</span>{' '}
                      <span className="text-slate-200">
                        {[host.city, host.country].filter(Boolean).join(', ') || 'N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Reverse DNS:</span>{' '}
                      <span className="text-slate-200">
                        {host.hostnames?.length > 0 ? host.hostnames.join(', ') : 'Ninguno'}
                      </span>
                    </div>
                  </div>

                  {/* CPEs de sistema */}
                  {host.cpes && host.cpes.length > 0 && (
                    <div className="px-4 py-2 bg-[#090b10] border-b border-[#1e2638] flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] uppercase text-slate-500 mr-1">Huella CPE:</span>
                      {host.cpes.map((cpe, i) => (
                        <span key={i} className="px-2 py-0.5 bg-[#121824] border border-[#1e2638] rounded text-[10px] text-slate-300">
                          {cpe}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Lista detallada de Puertos y Servicios */}
                  <div className="divide-y divide-[#1e2638]">
                    {host.services && host.services.length > 0 ? (
                      host.services.map((srv) => (
                        <div key={`${host.ip}_${srv.port}_${srv.transport}`} className="p-4 space-y-2.5 hover:bg-[#0f141f] transition-colors">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="px-2.5 py-1 bg-[#1e1b4b] border border-[#6366f1] text-[#c7d2fe] font-bold rounded text-xs">
                                Puerto {srv.port} / {srv.transport?.toUpperCase()}
                              </span>
                              <span className="text-sm font-bold text-white">
                                {srv.product}{' '}
                                {srv.version && <span className="text-[#38bdf8]">v{srv.version}</span>}
                              </span>
                              {srv.info && <span className="text-slate-400 text-xs">{srv.info}</span>}
                              <span className="px-2 py-0.5 bg-[#141a26] border border-[#1e2638] text-slate-400 rounded text-[10px] uppercase">
                                Protocolo: {srv.module || srv.protocol}
                              </span>
                            </div>

                            <div className="flex items-center space-x-2">
                              {srv.vulns_count > 0 && (
                                <span className="px-2 py-0.5 bg-[#2d0f14] border border-[#991b1b] text-[#f87171] rounded text-[10px] font-bold">
                                  {srv.vulns_count} CVEs en puerto
                                </span>
                              )}
                              <button
                                onClick={() => onFocusNode && onFocusNode(`port_${host.ip}_${srv.port}`)}
                                className="px-2 py-0.5 bg-[#151c28] hover:bg-[#1e2638] text-slate-300 border border-[#1e2638] rounded text-[10px] cursor-pointer"
                              >
                                Ver nodo
                              </button>
                            </div>
                          </div>

                          {/* Metadatos HTTP / SSL / Cloud del puerto */}
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                            {srv.http && (
                              <div className="bg-[#090b10] border border-[#1e2638] p-2.5 rounded space-y-1">
                                <div className="text-[10px] uppercase text-[#38bdf8] font-semibold">Aplicación Web HTTP</div>
                                {srv.http.title && <div><span className="text-slate-500">Título:</span> <span className="text-slate-200">{srv.http.title}</span></div>}
                                {srv.http.server && <div><span className="text-slate-500">Server:</span> <span className="text-slate-200">{srv.http.server}</span></div>}
                              </div>
                            )}

                            {srv.ssl && (
                              <div className="bg-[#090b10] border border-[#1e2638] p-2.5 rounded space-y-1">
                                <div className="text-[10px] uppercase text-[#10b981] font-semibold">Certificado SSL/TLS del Puerto</div>
                                {srv.ssl.issuer && <div><span className="text-slate-500">Emisor:</span> <span className="text-slate-200">{srv.ssl.issuer}</span></div>}
                                {srv.ssl.subject && <div><span className="text-slate-500">Sujeto:</span> <span className="text-slate-200">{srv.ssl.subject}</span></div>}
                                {srv.ssl.cipher && <div><span className="text-slate-500">Cipher:</span> <span className="text-slate-200">{srv.ssl.cipher}</span></div>}
                              </div>
                            )}
                          </div>

                          {/* Banner / Respuesta del Servidor */}
                          {srv.banner && (
                            <div className="space-y-1">
                              <div className="text-[10px] uppercase text-slate-500">
                                Banner / Fingerprint Capturado:
                              </div>
                              <pre className="p-2.5 bg-[#06080c] border border-[#1e2638] rounded text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                                {srv.banner}
                              </pre>
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="p-4 text-slate-500">No se reportaron puertos abiertos en esta IP.</div>
                    )}
                  </div>
                </div>
              ))
            )}
          </section>
        )}

        {/* 3. CATÁLOGO PROFUNDO DE VULNERABILIDADES (SHODAN CVEDB + KEV + EPSS + POCS) */}
        {showSection('vulns') && (
          <section className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1e2638] pb-2">
              <div className="flex items-center space-x-2">
                <ShieldAlert size={15} className="text-[#ef4444]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                  Inteligencia de Vulnerabilidades (Shodan CVEDB · CVSS · EPSS · CISA KEV)
                </h2>
              </div>
              <span className="text-[11px] text-slate-400">
                Mostrando {filteredVulns.length} de {vulnerabilities.length} CVEs enriquecidas
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
                    placeholder="Filtrar por CVE, producto, módulo o impacto (ej: mod_ssl, RCE, DoS, CVE-2024)..."
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
                      {sev === 'ALL' ? 'TODAS' : sev === 'KEV' ? 'CISA KEV' : sev}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {filteredVulns.length === 0 ? (
              <div className="bg-[#0d1119] border border-[#1e2638] p-4 rounded text-slate-500">
                {vulnerabilities.length === 0
                  ? 'No se detectaron vulnerabilidades públicas asociadas a los servicios expuestos.'
                  : 'Ninguna vulnerabilidad coincide con el filtro actual.'}
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
                            <span>CISA KEV · Explotada Activamente</span>
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
                            {v.ranking_epss ? ` (Percentil ${(Number(v.ranking_epss) * 100).toFixed(0)}%)` : ''}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center space-x-2 text-[11px]">
                        {v.published_time && (
                          <span className="text-slate-500 text-[10px]">Publicada: {v.published_time}</span>
                        )}
                        <button
                          onClick={() => onFocusNode && onFocusNode(`cve_${v.cve}`)}
                          className="px-2 py-0.5 bg-[#151c28] hover:bg-[#1e2638] text-[#38bdf8] border border-[#1e2638] rounded text-[10px] cursor-pointer"
                        >
                          Ver en grafo
                        </button>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
                      {v.service && (
                        <span>
                          <span className="text-slate-500">Servicio en Host:</span>{' '}
                          <strong className="text-[#c7d2fe]">{v.service}</strong>
                        </span>
                      )}
                      {v.ports?.length > 0 && (
                        <span>
                          <span className="text-slate-500">Puerto(s):</span>{' '}
                          <strong className="text-slate-200">{v.ports.join(', ')}</strong>
                        </span>
                      )}
                      {v.vendor && (
                        <span>
                          <span className="text-slate-500">Fabricante:</span>{' '}
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
                        <strong>Mitigación CISA KEV:</strong> {v.propose_action}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-[11px]">
                      <div className="flex flex-wrap items-center gap-3">
                        <a
                          href={v.nvd_url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-[#38bdf8] hover:underline"
                        >
                          <span>NIST NVD</span>
                          <ExternalLink size={11} />
                        </a>
                        <a
                          href={v.exploitdb_url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-[#fb923c] hover:underline"
                        >
                          <span>Exploit-DB</span>
                          <ExternalLink size={11} />
                        </a>
                        <a
                          href={v.github_poc_url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-[#10b981] hover:underline"
                        >
                          <span>GitHub PoCs</span>
                          <ExternalLink size={11} />
                        </a>
                        <a
                          href={v.mitre_url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-slate-400 hover:text-white"
                        >
                          <span>MITRE</span>
                          <ExternalLink size={11} />
                        </a>
                      </div>

                      {v.references?.length > 0 && (
                        <a
                          href={v.references[0]}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center space-x-1 text-slate-400 hover:text-slate-200"
                        >
                          <span>Advisory Oficial ({v.references.length})</span>
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

        {/* 4. AUDITORÍA WEB, WAF/CDN, COOKIES/CORS, CERTIFICADO TLS/SSL, UPTIME & WAPPALYZER */}
        {showSection('http') && (
          <section className="space-y-4">
            <div className="flex items-center space-x-2 border-b border-[#1e2638] pb-2">
              <Lock size={15} className="text-[#38bdf8]" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                Auditoría Web & Diagnóstico Forense (Estilo Who.is & Wappalyzer)
              </h2>
            </div>

            {/* 4.1. TARJETA WHO.IS DE ESTADO DEL SERVIDOR & UPTIME */}
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
                        {http_audit.uptime.redirects_count > 0 ? `${http_audit.uptime.redirects_count} salto(s) de redirección` : 'Sin redirecciones observadas'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* 4.2. TARJETA WHO.IS DE CERTIFICADO SSL/TLS COMPLETO */}
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

                  {/* Chain de certificación */}
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
                        <span className="text-[#10b981] font-bold">Política CAA publicada en la zona DNS:</span>
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

            {/* 4.3. TARJETA WAPPALYZER // TECNOLOGÍAS UTILIZADAS, VERSIONES & DESCRIPCIÓN */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded overflow-hidden">
              <div className="bg-[#111722] px-4 py-3 border-b border-[#1e2638] flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Globe size={14} className="text-[#38bdf8]" />
                  <span className="text-xs font-bold uppercase tracking-wider text-white">
                    Tecnologías Detectadas & Stack Técnico (Motor Wappalyzer)
                  </span>
                </div>
                <span className="text-[11px] text-slate-400">
                  {http_audit?.wappalyzer?.length || http_audit?.technologies?.length || 0} componentes identificados
                </span>
              </div>

              <div className="p-4">
                {http_audit?.wappalyzer && http_audit.wappalyzer.length > 0 ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {http_audit.wappalyzer.map((tech, i) => (
                      <div
                        key={i}
                        className="p-3 bg-[#090b10] border border-[#1e2638] hover:border-[#38bdf8]/50 rounded transition-all flex flex-col justify-between space-y-2"
                      >
                        <div>
                          <div className="flex items-start justify-between gap-1.5">
                            <span className="text-xs font-bold text-white leading-tight">{tech.name}</span>
                            {tech.version && (
                              <span className="px-1.5 py-0.2 bg-[#0284c7]/20 border border-[#38bdf8]/60 text-[#38bdf8] rounded text-[10px] font-mono font-bold shrink-0">
                                v{tech.version}
                              </span>
                            )}
                          </div>
                          <div className="text-[10px] font-mono font-semibold text-[#10b981] uppercase tracking-wider mt-0.5">
                            {tech.category}
                          </div>
                          {tech.description && (
                            <p className="text-[11px] text-slate-400 font-sans mt-1.5 leading-snug line-clamp-3">
                              {tech.description}
                            </p>
                          )}
                        </div>
                        {tech.website && (
                          <div className="pt-1.5 border-t border-[#141b29] flex items-center justify-between text-[10px] font-mono">
                            <span className="text-slate-600">Doc oficial</span>
                            <a
                              href={tech.website}
                              target="_blank"
                              rel="noreferrer"
                              className="text-[#38bdf8] hover:underline inline-flex items-center space-x-1"
                            >
                              <span>Visitar</span>
                              <ExternalLink size={9} />
                            </a>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : http_audit?.technologies && http_audit.technologies.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {http_audit.technologies.map((t, idx) => (
                      <span key={idx} className="px-2.5 py-1 bg-[#141b29] border border-[#1e2638] text-[#38bdf8] rounded text-xs font-mono">
                        {t}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-500 text-xs">No se detectaron huellas tecnológicas directas en la respuesta web.</p>
                )}
              </div>
            </div>

            {/* 4.4. CABECERAS DE SEGURIDAD & COOKIES */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Cabeceras de Seguridad HTTP & Cookies
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-[11px]">
                  <thead>
                    <tr className="border-b border-[#1e2638] text-slate-500 uppercase text-[10px]">
                      <th className="py-2 px-3">Cabecera de Seguridad</th>
                      <th className="py-2 px-3">Estado</th>
                      <th className="py-2 px-3">Propósito / Valor</th>
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
                              <span>Presente</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center space-x-1 text-[#ef4444]">
                              <XCircle size={12} />
                              <span>Ausente</span>
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
                    Auditoría de Cookies de Sesión (Set-Cookie):
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {http_audit.cookies_audit.map((ck, i) => (
                      <div key={i} className="bg-[#090b10] border border-[#1e2638] p-2.5 rounded flex items-center justify-between text-[11px]">
                        <span className="font-bold text-slate-200">{ck.name}</span>
                        <div className="flex items-center space-x-2 text-[10px]">
                          <span className={ck.secure ? 'text-[#10b981]' : 'text-[#ef4444]'}>
                            Secure: {ck.secure ? 'SÍ' : 'NO'}
                          </span>
                          <span className={ck.httponly ? 'text-[#10b981]' : 'text-[#ef4444]'}>
                            HttpOnly: {ck.httponly ? 'SÍ' : 'NO'}
                          </span>
                          <span className={ck.samesite ? 'text-[#10b981]' : 'text-[#facc15]'}>
                            SameSite: {ck.samesite ? 'SÍ' : 'NO'}
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

        {/* 5. REGISTROS DNS, EMAIL SECURITY & SUBDOMINIOS CON ORIGIN IPs */}
        {showSection('dns') && (
          <section className="space-y-3">
            <div className="flex items-center space-x-2 border-b border-[#1e2638] pb-2">
              <Globe size={15} className="text-[#38bdf8]" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                Reconocimiento DNS, Políticas de Correo y Subdominios (Origin IP Lookup)
              </h2>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Registros DNS */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="text-[11px] font-bold uppercase text-slate-400">Registros de Zona DNS</div>
                {dns.records && Object.values(dns.records).some((arr) => arr?.length > 0) ? (
                  <div className="space-y-2">
                    {Object.entries(dns.records).map(([rtype, records]) => {
                      if (!records || records.length === 0) return null;
                      return (
                        <div key={rtype} className="bg-[#090b10] border border-[#1e2638] p-2.5 rounded">
                          <div className="text-[10px] font-bold text-[#38bdf8] mb-1">
                            Registro {rtype} (TTL: {records[0]?.ttl || 0}s)
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
                  <div className="text-slate-500">Sin registros DNS directos.</div>
                )}
              </div>

              {/* Subdominios Descubiertos + IP Resuelta */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-bold uppercase text-slate-400">
                    Subdominios en Certificados Públicos (crt.sh)
                  </span>
                  <span className="text-[11px] text-slate-500">{subdomains.length} encontrados</span>
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
                    No se registraron subdominios adicionales en Certificate Transparency logs.
                  </div>
                )}
              </div>
            </div>
          </section>
        )}

        {/* 6. PLAYBOOK CLI PARA ANALISTAS DE CIBERSEGURIDAD / PENTESTERS */}
        {showSection('playbook') && (
          <section className="space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e2638] pb-2">
              <div className="flex items-center space-x-2">
                <Terminal size={15} className="text-[#10b981]" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
                  Playbook CLI
                </h2>
              </div>
              <span className="text-[10px] font-mono text-slate-500">Comandos parametrizados para terminal</span>
            </div>

            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-4">
              <div className="p-3 bg-[#090b10] border border-[#1e2638] rounded text-[11px] text-slate-300 font-sans leading-relaxed">
                <span className="text-[#10b981] font-bold font-mono">DIRECTIVA DE USO AUTORIZADO: </span>
                Comandos parametrizados con la IP detectada (<code>{primaryIp}</code>), dominio (<code>{target}</code>) y puertos abiertos (<code>{openPortsStr}</code>) únicamente en entornos aprobados.
              </div>

              {/* SECCIÓN A: COMANDOS EN MODO STEALTH (PASIVO / BAJO RUIDO) */}
              <div className="space-y-3 p-3 bg-[#081210] border border-[#10b981]/30 rounded">
                <div className="flex items-center justify-between">
                  <div className="text-[11px] font-bold uppercase text-[#10b981] flex items-center space-x-1.5 font-mono">
                    <Shield size={14} className="text-[#10b981]" />
                    <span>MODO STEALTH // Reconocimiento Pasivo & Bajo Ruido (No Intrusivo)</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#064e3b] text-[#a7f3d0] border border-[#10b981]/40">
                    Seguro · Sin Tráfico Anómalo
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">
                  Comandos orientados a recolectar inteligencia sin detonar alertas en sistemas de detección IDS/IPS ni registrarse como ataque en el firewall o WAF del objetivo.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                  <CopyCommandBlock
                    label="WHOIS / RDAP · Consulta de Propiedad de Red y Rangos IP (OSINT Pasivo)"
                    command={`whois ${primaryIp} | grep -E "inetnum|CIDR|OrgName|netname|country"`}
                  />
                  <CopyCommandBlock
                    label="Dig · Consulta de Registros DNS de Zona sin Interacción Web"
                    command={`dig ANY ${target} @8.8.8.8 +noall +answer`}
                  />
                  <CopyCommandBlock
                    label="cURL · Inspección Silenciosa de Cabeceras HTTP (User-Agent Estándar)"
                    command={`curl -k -I -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" https://${target}`}
                  />
                  <CopyCommandBlock
                    label="OpenSSL · Inspección Pasiva de Cadena de Certificados X.509"
                    command={`openssl s_client -connect ${target}:443 -servername ${target} -showcerts </dev/null`}
                  />
                  <CopyCommandBlock
                    label="Subfinder · Descubrimiento Pasivo de Subdominios (Sin Sondeo Directo)"
                    command={`subfinder -d ${target} -silent -all`}
                  />
                  <CopyCommandBlock
                    label="Nmap Stealth · Sondeo SYN Evasivo con Señuelos y Paquetes Fragmentados (T2 Lento)"
                    command={`nmap -sS -Pn -T2 -f -D RND:5 -p ${openPortsStr} ${primaryIp}`}
                  />
                </div>
              </div>

              {/* SECCIÓN B: COMANDOS EN MODO ACTIVO (INTRUSIVO / AUDITORÍA AUTORIZADA) */}
              <div className="space-y-3 p-3 bg-[#180f0e] border border-[#ef4444]/30 rounded">
                <div className="flex items-center justify-between">
                  <div className="text-[11px] font-bold uppercase text-[#f87171] flex items-center space-x-1.5 font-mono">
                    <Zap size={14} className="text-[#ef4444]" />
                    <span>MODO ACTIVO // Auditoría Intrusiva, Fuzzing & Análisis de Vulnerabilidades</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#450a0a] text-[#fca5a5] border border-[#ef4444]/40">
                    Solo Entornos Aprobados
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-sans">
                  <strong className="text-red-400">Atención:</strong> Estos comandos interactúan directamente con los puertos y servicios, generando registros visibles en SIEM y posibles bloqueos de seguridad.
                </p>

                <div className="space-y-4 pt-1">
                  {/* B.1 Red y Servicios */}
                  <div className="space-y-2">
                    <div className="text-[10px] font-bold uppercase text-slate-300 font-mono">
                      B.1 Escaneo de Versiones, Banners y Barrido de Puertos
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <CopyCommandBlock
                        label="Nmap · Escaneo Exhaustivo de Versiones y Scripts por Defecto"
                        command={`nmap -sV -sC -Pn -p ${openPortsStr} ${primaryIp}`}
                      />
                      <CopyCommandBlock
                        label="Nmap · Auditoría Automatizada de Vulnerabilidades y Exploits (Vulners NSE)"
                        command={`nmap -sV --script vulners -p ${openPortsStr} ${primaryIp}`}
                      />
                      <CopyCommandBlock
                        label="Nmap · Detección de Sistema Operativo y Tiempos Agresivos"
                        command={`nmap -A -O -T4 -Pn -p ${openPortsStr} ${primaryIp}`}
                      />
                      <CopyCommandBlock
                        label="Masscan · Barrido Ultrarrápido de los 65.535 Puertos TCP"
                        command={`masscan -p1-65535 ${primaryIp} --rate=1000 -e eth0`}
                      />
                    </div>
                  </div>

                  {/* B.2 Web & Fuzzing */}
                  <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                    <div className="text-[10px] font-bold uppercase text-slate-300 font-mono">
                      B.2 Auditoría Web, Fuzzing de Rutas y Escaneo de Plantillas
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <CopyCommandBlock
                        label="Nuclei · Escaneo de Plantillas de CVEs Críticas, Altas y Fugas"
                        command={`nuclei -u https://${target} -severity critical,high,medium -tags cve,exposure,misconfig`}
                      />
                      <CopyCommandBlock
                        label="Nikto · Auditoría Completa de Seguridad del Servidor Web"
                        command={`nikto -h https://${target} -Tuning 123b -C all`}
                      />
                      <CopyCommandBlock
                        label="Feroxbuster · Fuzzing Recursivo Rápido de Directorios y Archivos Ocultos"
                        command={`feroxbuster -u https://${target} -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt,json -t 30`}
                      />
                      <CopyCommandBlock
                        label="Gobuster · Descubrimiento de Rutas y Archivos Sensibles"
                        command={`gobuster dir -u https://${target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -k`}
                      />
                      <CopyCommandBlock
                        label="Ffuf · Fuzzing de Virtual Hosts / Subdominios Ocultos"
                        command={`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u https://${target} -H "Host: FUZZ.${target}" -fs 0`}
                      />
                      <CopyCommandBlock
                        label="WPScan · Auditoría de Plugins, Temas y Usuarios (si detecta WordPress)"
                        command={`wpscan --url https://${target} --enumerate p,t,u --api-token TU_TOKEN_WPSCAN`}
                      />
                    </div>
                  </div>

                  {/* B.3 Criptografía & Servicios Específicos */}
                  <div className="space-y-2 pt-2 border-t border-[#2d1b1b]">
                    <div className="text-[10px] font-bold uppercase text-slate-300 font-mono">
                      B.3 Criptografía Profunda & Servicios de Red (SSH / SMB / TLS)
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <CopyCommandBlock
                        label="sslscan · Auditoría de Cifrados, Protocolos Obsoletos (TLS 1.0/1.1) y Heartbleed"
                        command={`sslscan --tlsall ${target}:443`}
                      />
                      <CopyCommandBlock
                        label="testssl.sh · Evaluación Profunda de Vulnerabilidades TLS (POODLE, DROWN, ROBOT)"
                        command={`testssl.sh --full https://${target}`}
                      />
                      <CopyCommandBlock
                        label="ssh-audit · Análisis de Cifrados Débiles y Banners SSH (Puerto 22)"
                        command={`ssh-audit -v ${primaryIp}`}
                      />
                      <CopyCommandBlock
                        label="NetExec (nxc) · Auditoría de Protocolos SMB / WinRM / SSH"
                        command={`nxc smb ${primaryIp} -u '' -p ''`}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
