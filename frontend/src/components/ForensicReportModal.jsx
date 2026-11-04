import React, { useState } from 'react';
import { X, Printer, FileText, FileCode, Crosshair, Terminal } from 'lucide-react';

function generateRawTraceReport(scanData) {
  const { target, scan_timestamp, execution_trace = [] } = scanData;

  let raw = `================================================================================\n`;
  raw += `SNIPERSCOPE EASM v3.2 // FORENSIC RAW TRACE (STEP-BY-STEP / COMMAND-BY-COMMAND)\n`;
  raw += `================================================================================\n`;
  raw += `AUDITED TARGET  : ${target}\n`;
  raw += `SESSION TIME UTC: ${scan_timestamp}\n`;
  raw += `TOTAL STEPS     : ${execution_trace.length}\n`;
  raw += `================================================================================\n\n`;

  if (!execution_trace || execution_trace.length === 0) {
    raw += `[!] No execution trace available for this scan session.\n`;
    return raw;
  }

  execution_trace.forEach((item) => {
    raw += `--------------------------------------------------------------------------------\n`;
    raw += `[STEP ${item.step}] [${item.timestamp}] :: ${item.phase}\n`;
    raw += `OPERATION  : ${item.title}\n`;
    raw += `REASONING  : ${item.reasoning}\n`;
    raw += `CLI COMMAND: $ ${item.command}\n`;
    raw += `NET REQUEST: ${item.request}\n`;
    raw += `--------------------------------------------------------------------------------\n`;
    raw += `>>> CAPTURED RAW PAYLOAD OUTPUT:\n`;
    raw += `${item.raw_output}\n\n`;
  });

  raw += `================================================================================\n`;
  raw += `END OF FORENSIC RAW EXECUTION TRACE - SNIPERSCOPE - TARGET: ${target}\n`;
  raw += `================================================================================\n`;

  return raw;
}

function generateMarkdownReport(scanData) {
  const { target, scan_timestamp, risk = {}, summary = {}, shodan = [], dns = {}, http_audit = {}, vulnerabilities = [] } = scanData;

  let md = `# EXTERNAL ATTACK SURFACE & OSINT FORENSIC AUDIT REPORT\n\n`;
  md += `- **Audited Target:** \`${target}\`\n`;
  md += `- **Timestamp (UTC):** ${scan_timestamp}\n`;
  md += `- **Overall Risk Score:** **${risk.score ?? 0}/100 (${risk.level || 'N/A'} - Grade ${risk.grade || '-'})**\n`;
  md += `- **Classification:** TLP:AMBER (Confidential - Cybersecurity Authorized Use Only)\n`;
  md += `- **Analysis Engine:** SniperScope EASM v3.2 (Shodan API + Shodan CVEDB + TLS/HTTP & Path Audit)\n\n`;
  md += `---\n\n`;

  md += `## 1. EXECUTIVE SUMMARY & RISK POSTURE\n\n`;
  md += `| Indicator | Detected Value |\n`;
  md += `| :--- | :--- |\n`;
  md += `| **Overall Risk Score** | **${risk.score ?? 0}/100 (${risk.level || 'N/A'} - Grade ${risk.grade || '-'})** |\n`;
  md += `| **Active Host IPs** | ${summary.ips_count || 0} |\n`;
  md += `| **Public Subdomains (CRT.sh)** | ${summary.subdomains_count || 0} |\n`;
  md += `| **Exposed Ports & Services** | ${summary.open_ports_count || 0} |\n`;
  md += `| **Total Vulnerabilities (CVEs)** | ${summary.vulnerabilities_count || 0} (Critical: ${summary.critical_vulns || 0}, High: ${summary.high_vulns || 0}, Medium: ${summary.medium_vulns || 0}, CISA KEV: ${summary.kev_vulns || 0}) |\n`;
  md += `| **WAF / CDN Edge Protection** | ${http_audit?.waf_cdn || 'Not detected (Direct origin exposed)'} |\n`;
  md += `| **Email Anti-Spoofing (SPF / DMARC)** | SPF: ${dns.email_security?.has_spf ? 'CONFIGURED' : 'MISSING'} / DMARC: ${dns.email_security?.has_dmarc ? 'CONFIGURED' : 'MISSING'} |\n\n`;

  if (risk.findings && risk.findings.length > 0) {
    md += `### Priority Audit Findings:\n\n`;
    risk.findings.forEach((f) => {
      md += `- **[${f.severity}] ${f.title}:** ${f.detail}\n`;
    });
    md += `\n`;
  }

  md += `---\n\n`;
  md += `## 2. NETWORK INFRASTRUCTURE, OPEN PORTS & RUNNING SERVICES\n\n`;
  if (shodan.length === 0) {
    md += `No active Shodan hosts recorded.\n\n`;
  } else {
    shodan.forEach((h) => {
      md += `### Host IP: \`${h.ip}\`\n`;
      md += `- **Organization / ISP:** ${h.org || 'N/A'} (${h.isp || 'N/A'})\n`;
      md += `- **ASN:** ${h.asn || 'N/A'}\n`;
      md += `- **Inferred Operating System:** ${h.os || 'Not specified'}\n`;
      md += `- **Geographic Location:** ${[h.city, h.country].filter(Boolean).join(', ') || 'N/A'}\n`;
      md += `- **Identified CPEs:** ${h.cpes?.length ? h.cpes.map(c => `\`${c}\``).join(', ') : 'None'}\n\n`;

      if (h.services && h.services.length > 0) {
        md += `#### Running Services on \`${h.ip}\`:\n\n`;
        md += `| Port | Protocol | Service / Product | Version | Additional Info | CVEs |\n`;
        md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
        h.services.forEach((s) => {
          md += `| **${s.port}/${s.transport}** | ${s.module || s.protocol} | ${s.product} | \`${s.version || '-'}\` | ${s.info || '-'} | ${s.vulns_count || 0} |\n`;
        });
        md += `\n`;

        h.services.forEach((s) => {
          if (s.banner) {
            md += `**Banner Evidence (Port ${s.port}/${s.transport} - ${s.product}):**\n\`\`\`text\n${s.banner}\n\`\`\`\n\n`;
          }
        });
      }
    });
  }

  md += `---\n\n`;
  md += `## 3. WEB SECURITY AUDIT, TLS/SSL CERTIFICATE & EXPOSED ARTIFACTS\n\n`;
  if (http_audit?.tls?.enabled) {
    md += `### TLS/SSL Cryptographic Inspection (Port 443):\n`;
    md += `- **Protocol & Cipher Suite:** \`${http_audit.tls.protocol_version}\` · \`${http_audit.tls.cipher_suite}\` (${http_audit.tls.cipher_bits} bits)\n`;
    md += `- **Certificate Authority (CA):** ${http_audit.tls.issuer_org || http_audit.tls.issuer_cn || 'N/A'}\n`;
    md += `- **Expiration:** ${http_audit.tls.not_after || 'N/A'} (${http_audit.tls.days_remaining ?? '-'} days remaining)\n\n`;
  }

  if (http_audit?.reachable) {
    md += `- **Inspected URL:** ${http_audit.final_url}\n`;
    md += `- **HTTP Status Code:** ${http_audit.status_code}\n`;
    md += `- **Server Header:** \`${http_audit.server || 'Not disclosed (Hardened)'}\`\n`;
    md += `- **CORS Policy:** \`${http_audit.cors_policy?.allow_origin || 'Restricted / Not exposed'}\`\n\n`;
    md += `| Security Header | Status | Value / Description |\n`;
    md += `| :--- | :--- | :--- |\n`;
    (http_audit.security_headers || []).forEach((sh) => {
      md += `| \`${sh.header}\` | ${sh.present ? 'PRESENT' : 'MISSING'} | ${sh.present ? `\`${sh.value}\`` : sh.description} |\n`;
    });
    md += `\n`;

    if (http_audit.exposed_paths && http_audit.exposed_paths.length > 0) {
      md += `### Discovered Public Paths & Artifacts:\n\n`;
      http_audit.exposed_paths.forEach((ep) => {
        md += `- **[${ep.severity}] \`${ep.path}\` (HTTP ${ep.status}):** ${ep.label} (${ep.url})\n`;
      });
      md += `\n`;
    }
  } else {
    md += `The target provided no direct HTTP/HTTPS web response.\n\n`;
  }

  md += `---\n\n`;
  md += `## 4. TECHNICAL VULNERABILITY CATALOG (SHODAN CVEDB)\n\n`;
  if (vulnerabilities.length === 0) {
    md += `No known public vulnerabilities associated.\n\n`;
  } else {
    vulnerabilities.forEach((v) => {
      md += `### ${v.cve} [${v.severity || 'HIGH'}] ${v.cvss ? `(CVSS: ${v.cvss})` : ''} ${v.kev ? '[CISA KEV - ACTIVELY EXPLOITED]' : ''}\n`;
      md += `- **Component / Service:** ${v.service || v.product || 'Host'} ${v.ports?.length ? `(Ports: ${v.ports.join(', ')})` : ''}\n`;
      if (v.epss !== null && v.epss !== undefined) {
        md += `- **EPSS Exploit Probability:** ${(Number(v.epss) * 100).toFixed(2)}% ${v.ranking_epss ? `(Percentile ${(Number(v.ranking_epss) * 100).toFixed(0)}%)` : ''}\n`;
      }
      if (v.published_time) md += `- **Published Date:** ${v.published_time}\n`;
      md += `- **NIST NVD Reference:** ${v.nvd_url}\n`;
      md += `- **Technical Summary:** ${v.summary}\n\n`;
    });
  }

  md += `---\n\n`;
  md += `## 5. HARDENING & REMEDIATION RECOMMENDATIONS\n\n`;
  md += `1. **Priority Patching of Exposed Services:** Upgrade software components identified via CPE (prioritizing CVEs in CISA KEV catalog or CVSS >= 7.0).\n`;
  md += `2. **Banner Hardening:** Configure \`ServerTokens Prod\` (Apache) or \`server_tokens off\` (Nginx) to suppress version disclosure.\n`;
  md += `3. **Web Security Headers:** Enforce \`Strict-Transport-Security\`, \`Content-Security-Policy\`, and \`X-Frame-Options\`.\n`;
  md += `4. **Email Anti-Spoofing Policies:** Deploy strict TXT records for \`v=spf1\` and \`_dmarc\` with \`p=quarantine\` or \`p=reject\` policies.\n`;

  return md;
}

function generateStandaloneHtml(scanData) {
  const { target, scan_timestamp, risk = {}, summary = {}, shodan = [], dns = {}, http_audit = {}, vulnerabilities = [] } = scanData;

  const findingsHtml = (risk.findings || []).map((f) => `
    <div style="border-left: 4px solid ${f.severity === 'CRITICAL' ? '#dc2626' : f.severity === 'HIGH' ? '#ea580c' : '#ca8a04'}; background: #f9fafb; padding: 8px 12px; margin-bottom: 8px; font-size: 12px;">
      <strong>[${f.severity}] ${f.title}:</strong> ${f.detail}
    </div>
  `).join('');

  const servicesHtml = shodan.map((h) => `
    <div class="card">
      <div class="card-header">
        <strong>Host IP: ${h.ip}</strong>
        <span>Org: ${h.org || 'N/A'} | ASN: ${h.asn || 'N/A'} | SO: ${h.os || 'N/A'} | País: ${[h.city, h.country].filter(Boolean).join(', ') || 'N/A'}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Puerto</th>
            <th>Módulo</th>
            <th>Producto / Servicio</th>
            <th>Versión</th>
            <th>Detalles / SO</th>
            <th>CVEs</th>
          </tr>
        </thead>
        <tbody>
          ${(h.services || []).map(s => `
            <tr>
              <td><strong>${s.port}/${s.transport.toUpperCase()}</strong></td>
              <td>${s.module || s.protocol}</td>
              <td><strong>${s.product}</strong></td>
              <td><code>${s.version || '-'}</code></td>
              <td>${s.info || '-'} ${s.http?.title ? `| Título HTTP: "${s.http.title}"` : ''}</td>
              <td>${s.vulns_count || 0}</td>
            </tr>
            ${s.banner ? `<tr><td colspan="6"><pre class="banner">${s.banner.replace(/</g, '&lt;')}</pre></td></tr>` : ''}
          `).join('')}
        </tbody>
      </table>
    </div>
  `).join('');

  const vulnsHtml = vulnerabilities.map((v) => `
    <div class="vuln-item">
      <div class="vuln-head">
        <strong>${v.cve}</strong>
        <span class="badge badge-${(v.severity || 'HIGH').toLowerCase()}">${v.severity || 'HIGH'} ${v.cvss ? `· CVSS ${v.cvss}` : ''}</span>
        ${v.kev ? '<span class="badge badge-critical">CISA KEV · EXPLOTADA ACTIVAMENTE</span>' : ''}
        ${v.epss ? `<span class="meta">EPSS: ${(Number(v.epss) * 100).toFixed(2)}%</span>` : ''}
        <span class="meta">${v.service || v.product || ''} ${v.ports?.length ? `(Puerto ${v.ports.join(', ')})` : ''}</span>
      </div>
      <p style="margin: 6px 0; white-space: pre-line;">${v.summary}</p>
      <div class="ref"><a href="${v.nvd_url}" target="_blank">${v.nvd_url}</a></div>
    </div>
  `).join('');

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>SniperScope Informe Forense OSINT & EASM - ${target}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111827; background: #ffffff; margin: 0; padding: 36px; line-height: 1.5; font-size: 13px; }
    .container { max-width: 980px; margin: 0 auto; }
    header { border-bottom: 2px solid #111827; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }
    h1 { font-size: 22px; margin: 0 0 4px 0; letter-spacing: -0.02em; }
    h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #d1d5db; padding-bottom: 6px; margin-top: 28px; color: #1f2937; }
    .tlp { background: #fef3c7; color: #92400e; border: 1px solid #f59e0b; padding: 3px 8px; font-family: monospace; font-size: 11px; font-weight: bold; display: inline-block; }
    .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
    .kpi { border: 1px solid #d1d5db; padding: 12px; border-radius: 4px; background: #f9fafb; }
    .kpi .label { font-size: 10px; text-transform: uppercase; color: #6b7280; font-family: monospace; }
    .kpi .val { font-size: 20px; font-weight: bold; margin-top: 4px; color: #111827; }
    .card { border: 1px solid #d1d5db; border-radius: 4px; margin-bottom: 16px; overflow: hidden; }
    .card-header { background: #f3f4f6; padding: 10px 14px; border-bottom: 1px solid #d1d5db; display: flex; justify-content: space-between; font-family: monospace; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; vertical-align: top; }
    th { background: #f9fafb; font-size: 10px; text-transform: uppercase; color: #4b5563; font-family: monospace; }
    pre.banner { background: #111827; color: #e5e7eb; padding: 10px; border-radius: 4px; font-size: 11px; overflow-x: auto; margin: 4px 0; white-space: pre-wrap; }
    .vuln-item { border: 1px solid #e5e7eb; padding: 12px; border-radius: 4px; margin-bottom: 10px; page-break-inside: avoid; }
    .vuln-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; font-family: monospace; margin-bottom: 6px; }
    .badge { padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; color: #fff; }
    .badge-critical { background: #dc2626; }
    .badge-high { background: #ea580c; }
    .badge-medium { background: #ca8a04; }
    .badge-low { background: #0284c7; }
    .meta { color: #4b5563; font-size: 11px; }
    .ref a { color: #0284c7; font-family: monospace; font-size: 11px; text-decoration: none; }
    @media print { body { padding: 10px; } }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <div class="tlp">TLP:AMBER // INFORME FORENSE DE CIBERSEGURIDAD</div>
        <h1 style="margin-top:8px;">Auditoría de Superficie de Ataque: ${target}</h1>
        <div style="color:#4b5563; font-family:monospace; font-size:12px;">Generado por SniperScope EASM v3.0 · Fecha: ${scan_timestamp}</div>
      </div>
      <div style="text-align:right; font-family:monospace;">
        <div style="font-size:10px; text-transform:uppercase; color:#6b7280;">Índice de Riesgo</div>
        <div style="font-size:20px; font-weight:bold; color:#dc2626;">${risk.score ?? 0}/100 (${risk.level || 'N/A'} - Grado ${risk.grade || '-'})</div>
      </div>
    </header>

    <h2>1. Resumen Ejecutivo y Vectores de Riesgo</h2>
    <div class="kpis">
      <div class="kpi"><div class="label">IPs Activas</div><div class="val">${summary.ips_count || 0}</div></div>
      <div class="kpi"><div class="label">Puertos Abiertos</div><div class="val">${summary.open_ports_count || 0}</div></div>
      <div class="kpi"><div class="label">CVEs (${summary.critical_vulns || 0} Crít.)</div><div class="val">${summary.vulnerabilities_count || 0}</div></div>
      <div class="kpi"><div class="label">WAF / CDN</div><div class="val" style="font-size:13px;">${http_audit?.waf_cdn || 'Sin WAF'}</div></div>
    </div>
    ${findingsHtml}

    <h2>2. Infraestructura, Puertos Abiertos, Servicios y Banners (Shodan)</h2>
    ${servicesHtml || '<p>No se encontraron servicios expuestos.</p>'}

    <h2>3. Auditoría Web, TLS/SSL y Correo (SPF/DMARC)</h2>
    <p><strong>Seguridad de Correo:</strong> SPF: ${dns.email_security?.has_spf ? 'Configurado' : 'AUSENTE'} | DMARC: ${dns.email_security?.has_dmarc ? 'Configurado' : 'AUSENTE'}</p>
    ${http_audit?.tls?.enabled ? `<p><strong>Certificado TLS/SSL:</strong> ${http_audit.tls.protocol_version} (${http_audit.tls.cipher_suite}) · Emisor: ${http_audit.tls.issuer_org || http_audit.tls.issuer_cn || 'N/A'} · Expira: ${http_audit.tls.not_after} (${http_audit.tls.days_remaining} días restantes)</p>` : ''}
    ${http_audit?.reachable ? `
      <table>
        <thead><tr><th>Cabecera HTTP</th><th>Estado</th><th>Detalle</th></tr></thead>
        <tbody>
          ${(http_audit.security_headers || []).map(sh => `
            <tr>
              <td><code>${sh.header}</code></td>
              <td><strong>${sh.present ? 'PRESENTE' : 'AUSENTE'}</strong></td>
              <td>${sh.present ? sh.value : sh.description}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : '<p>Sin respuesta web directa en 80/443.</p>'}

    <h2>4. Catálogo de Vulnerabilidades Identificadas (${vulnerabilities.length} CVEs - Shodan CVEDB)</h2>
    ${vulnsHtml || '<p>Sin vulnerabilidades registradas.</p>'}

    <h2>5. Plan de Remediación Forense</h2>
    <ol>
      <li><strong>Actualización de Demonios y Servicios:</strong> Aplicar parches de seguridad en los servicios identificados (${shodan.flatMap(h => h.services?.map(s => `${s.product} ${s.version}`)).filter(Boolean).join(', ') || 'servicios expuestos'}).</li>
      <li><strong>Ocultación de Banners (Hardening):</strong> Deshabilitar la exposición de versiones exactas en las cabeceras de respuesta HTTP y SSH.</li>
      <li><strong>Cabeceras de Seguridad Web:</strong> Configurar HSTS, CSP y X-Frame-Options en el servidor frontal.</li>
      <li><strong>Protección de Dominio de Correo:</strong> Publicar registros SPF y DMARC restrictivos en la zona DNS de <code>${target}</code>.</li>
    </ol>
  </div>
</body>
</html>`;
}

export default function ForensicReportModal({ isOpen, onClose, scanData }) {
  // previewFormat: 'standard' | 'raw'
  const [previewFormat, setPreviewFormat] = useState('standard');

  if (!isOpen || !scanData) return null;

  const handlePrintPdf = () => {
    const htmlContent = generateStandaloneHtml(scanData);
    const printWin = window.open('', '_blank');
    if (printWin) {
      printWin.document.open();
      printWin.document.write(htmlContent);
      printWin.document.close();
      setTimeout(() => {
        printWin.focus();
        printWin.print();
      }, 350);
    }
  };

  const handleDownloadHtml = () => {
    const htmlContent = generateStandaloneHtml(scanData);
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SniperScope_Informe_Forense_${scanData.target}_${new Date().toISOString().slice(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadMarkdown = () => {
    const mdContent = generateMarkdownReport(scanData);
    const blob = new Blob([mdContent], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SniperScope_Informe_Forense_${scanData.target}_${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadRaw = () => {
    const rawContent = generateRawTraceReport(scanData);
    const blob = new Blob([rawContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SniperScope_Traza_RAW_${scanData.target}_${new Date().toISOString().slice(0, 10)}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 select-text">
      <div className="bg-[#0c1017] border border-[#1e2638] rounded-md w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden">
        {/* Cabecera del Modal */}
        <div className="px-5 py-3.5 border-b border-[#1e2638] flex items-center justify-between bg-[#0f141e]">
          <div className="flex items-center space-x-2.5">
            <Crosshair size={17} className="text-[#38bdf8]" />
            <div>
              <h3 className="text-sm font-mono font-bold text-white">
                SniperScope // Professional Forensic Security Report Generator
              </h3>
              <p className="text-[11px] font-mono text-slate-400">
                Target: {scanData.target} · {scanData.scan_timestamp}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* Format Preview Switcher: Standard vs RAW */}
            <div className="flex items-center bg-[#090b10] border border-[#1e2638] p-0.5 rounded font-mono text-[11px]">
              <button
                onClick={() => setPreviewFormat('standard')}
                className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
                  previewFormat === 'standard'
                    ? 'bg-[#1e2638] text-white font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Executive Report
              </button>
              <button
                onClick={() => setPreviewFormat('raw')}
                className={`px-2.5 py-1 rounded flex items-center space-x-1 transition-colors cursor-pointer ${
                  previewFormat === 'raw'
                    ? 'bg-[#10b981]/20 text-[#10b981] border border-[#10b981]/40 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Terminal size={12} />
                <span>RAW Trace (Step-by-Step)</span>
              </button>
            </div>

            <button
              onClick={onClose}
              aria-label="Close modal"
              title="Close modal"
              className="p-1 text-slate-400 hover:text-white hover:bg-[#1e2638] rounded cursor-pointer"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Export Action Bar */}
        <div className="px-5 py-3 bg-[#090b10] border-b border-[#1e2638] flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs font-mono text-slate-400">
            {previewFormat === 'raw'
              ? 'RAW Mode: Chronological command-by-command and request-by-request sequence with raw payloads.'
              : 'Executive & technical assessment deliverable formats:'}
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handlePrintPdf}
              className="px-3 py-1.5 bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-mono font-semibold rounded flex items-center space-x-1.5 transition-colors cursor-pointer"
            >
              <Printer size={14} />
              <span>Print / PDF</span>
            </button>
            <button
              onClick={handleDownloadHtml}
              className="px-3 py-1.5 bg-[#1e2638] hover:bg-[#2a354f] text-slate-100 text-xs font-mono rounded flex items-center space-x-1.5 transition-colors cursor-pointer"
            >
              <FileCode size={14} />
              <span>HTML (.html)</span>
            </button>
            <button
              onClick={handleDownloadMarkdown}
              className="px-3 py-1.5 bg-[#1e2638] hover:bg-[#2a354f] text-slate-100 text-xs font-mono rounded flex items-center space-x-1.5 transition-colors cursor-pointer"
            >
              <FileText size={14} />
              <span>Markdown (.md)</span>
            </button>
            <button
              onClick={() => {
                setPreviewFormat('raw');
                handleDownloadRaw();
              }}
              className="px-3 py-1.5 bg-[#064e3b] hover:bg-[#047857] border border-[#10b981]/50 text-[#a7f3d0] text-xs font-mono font-semibold rounded flex items-center space-x-1.5 transition-colors cursor-pointer"
              title="Download full raw execution trace file"
            >
              <Terminal size={14} />
              <span>RAW (.log)</span>
            </button>
          </div>
        </div>

        {/* Selected Format Preview */}
        <div className="flex-1 overflow-y-auto p-5 bg-[#07090e] font-mono text-xs text-slate-300">
          {previewFormat === 'raw' ? (
            <div className="space-y-4">
              {(scanData.execution_trace || []).map((item) => (
                <div key={item.step} className="bg-[#0b0f17] border border-[#1e2638] rounded overflow-hidden">
                  <div className="px-4 py-2.5 bg-[#111722] border-b border-[#1e2638] flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 bg-[#064e3b] text-[#a7f3d0] border border-[#10b981]/40 rounded text-[10px] font-bold">
                        STEP {item.step}
                      </span>
                      <span className="text-white font-bold">{item.title}</span>
                    </div>
                    <span className="text-[10px] text-slate-400">{item.timestamp} · {item.phase}</span>
                  </div>

                  <div className="p-3.5 space-y-2.5 text-[11px]">
                    <div className="text-slate-400 font-sans">
                      <strong className="text-slate-300 font-mono">Reasoning: </strong>
                      {item.reasoning}
                    </div>
                    <div className="bg-[#06080c] border border-[#141a26] p-2.5 rounded space-y-1">
                      <div>
                        <span className="text-slate-500">CLI COMMAND : </span>
                        <span className="text-[#10b981] font-semibold">$ {item.command}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">NET REQUEST : </span>
                        <span className="text-[#38bdf8]">{item.request}</span>
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase text-slate-500 mb-1">
                        Captured Raw Payload:
                      </div>
                      <pre className="p-3 bg-[#05070a] border border-[#1e2638] rounded text-[11px] text-slate-300 overflow-x-auto max-h-64 whitespace-pre-wrap">
                        {item.raw_output}
                      </pre>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <pre className="whitespace-pre-wrap leading-relaxed">
              {generateMarkdownReport(scanData)}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
