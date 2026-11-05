import React, { useState } from 'react';
import { X, Printer, FileText, FileCode, Crosshair, Terminal, Table } from 'lucide-react';

function escapeCsvField(val) {
  if (val === null || val === undefined) return '""';
  const str = String(val).replace(/"/g, '""');
  return `"${str}"`;
}

function generateCsvReport(scanData) {
  const {
    target,
    scan_timestamp,
    risk = {},
    summary = {},
    shodan = [],
    dns = {},
    http_audit = {},
    vulnerabilities = [],
    subdomains = [],
    brand_protection = {},
  } = scanData;

  const lines = [];

  // UTF-8 BOM is added on Blob creation
  lines.push('SNIPERSCOPE v3.6 // ATTACK SURFACE & FORENSIC AUDIT REPORT');
  lines.push(`Target,${escapeCsvField(target)}`);
  lines.push(`Session Timestamp (UTC),${escapeCsvField(scan_timestamp)}`);
  lines.push(`Analysis Engine,${escapeCsvField('SniperScope v3.6 Release (EASM & Anti-Phishing DRP Platform)')}`);
  lines.push(`Overall Risk Score,${escapeCsvField(`${risk.score ?? 0}/100 (Level: ${risk.level || 'N/A'}, Grade: ${risk.grade || '-'})`)}`);
  lines.push(`Active Host IPs,${escapeCsvField(summary.ips_count || 0)}`);
  lines.push(`Open Ports & Services,${escapeCsvField(summary.open_ports_count || 0)}`);
  lines.push(`Total Vulnerabilities (CVEs),${escapeCsvField(summary.vulnerabilities_count || 0)}`);
  lines.push(`CISA KEV Actively Exploited,${escapeCsvField(summary.kev_vulns || 0)}`);
  lines.push(`WAF / CDN Edge Protection,${escapeCsvField(http_audit?.waf_cdn || 'Direct Origin Exposed (No WAF)')}`);
  lines.push(`Email Anti-Spoofing,${escapeCsvField(`SPF: ${dns.email_security?.has_spf ? 'CONFIGURED' : 'MISSING'} | DMARC: ${dns.email_security?.has_dmarc ? 'CONFIGURED' : 'MISSING'}`)}`);
  lines.push('');

  // 1. BRAND PROTECTION & PHISHING CAMPAIGN FORENSICS
  const tf = brand_protection.target_forensics;
  if (tf) {
    lines.push('--- BRAND PROTECTION & PHISHING CAMPAIGN FORENSICS ---');
    lines.push('Target Domain,Severity,Verdict,Reputation Status,Reputation Details,Registration Date,Domain Age,Registrar,Abuse Email,Web Host IP,MX Mail Server,Co-Hosted Domains');
    lines.push([
      escapeCsvField(tf.domain),
      escapeCsvField(tf.severity),
      escapeCsvField(tf.verdict),
      escapeCsvField(tf.reputation?.badge || 'N/A'),
      escapeCsvField(tf.reputation?.description || 'N/A'),
      escapeCsvField(tf.created_date ? tf.created_date.split('T')[0] : 'Undeclared'),
      escapeCsvField(tf.recency_label || 'N/A'),
      escapeCsvField(tf.registrar || 'Unknown'),
      escapeCsvField(tf.abuse_email || 'N/A'),
      escapeCsvField(tf.a_records?.join('; ') || 'None'),
      escapeCsvField(tf.mx_records?.join('; ') || 'None'),
      escapeCsvField(tf.co_hosted_domains?.join('; ') || 'None'),
    ].join(','));
    lines.push('');
  }

  // Lookalikes
  const findings = brand_protection.findings || [];
  if (findings.length > 0) {
    lines.push('--- DETECTED LOOKALIKE DOMAINS & PHISHING MUTATIONS ---');
    lines.push('Lookalike Domain,Similarity Score,Mutation Type,Severity,Registrar,Age / Registration,Web Host IP,Active MX Servers');
    findings.forEach((f) => {
      lines.push([
        escapeCsvField(f.domain),
        escapeCsvField(`${f.similarity}%`),
        escapeCsvField(f.mutation_type),
        escapeCsvField(f.severity),
        escapeCsvField(f.registrar || 'Unknown'),
        escapeCsvField(f.recency_label || 'N/A'),
        escapeCsvField(f.a_records?.join('; ') || 'No Web'),
        escapeCsvField(f.mx_records?.join('; ') || 'No MX'),
      ].join(','));
    });
    lines.push('');
  }

  // 2. PRIORITY FINDINGS
  if (risk.findings && risk.findings.length > 0) {
    lines.push('--- PRIORITY AUDIT FINDINGS ---');
    lines.push('Severity,Title,Technical Detail');
    risk.findings.forEach((f) => {
      lines.push([
        escapeCsvField(f.severity),
        escapeCsvField(f.title),
        escapeCsvField(f.detail),
      ].join(','));
    });
    lines.push('');
  }

  // 3. WEB TECHNOLOGIES & EXPOSED PATHS
  if (http_audit?.technologies && http_audit.technologies.length > 0) {
    lines.push('--- DETECTED WEB TECHNOLOGIES ---');
    lines.push('Technology');
    http_audit.technologies.forEach((tech) => {
      lines.push(escapeCsvField(tech));
    });
    lines.push('');
  }

  if (http_audit?.exposed_paths && http_audit.exposed_paths.length > 0) {
    lines.push('--- DISCOVERED PUBLIC PATHS & ARTIFACTS ---');
    lines.push('Path,HTTP Status,Severity,Artifact Description');
    http_audit.exposed_paths.forEach((ep) => {
      lines.push([
        escapeCsvField(ep.path),
        escapeCsvField(ep.status),
        escapeCsvField(ep.severity),
        escapeCsvField(ep.label || ep.url || ''),
      ].join(','));
    });
    lines.push('');
  }

  // 3. NETWORK INFRASTRUCTURE & OPEN SERVICES
  lines.push('--- OPEN PORTS & RUNNING SERVICES ---');
  lines.push('Host IP,Port,Protocol,Service / Module,Product,Version,Identified CVEs Count,Details / Info');
  shodan.forEach((h) => {
    (h.services || []).forEach((s) => {
      lines.push([
        escapeCsvField(h.ip),
        escapeCsvField(s.port),
        escapeCsvField(s.transport?.toUpperCase() || 'TCP'),
        escapeCsvField(s.module || s.protocol),
        escapeCsvField(s.product),
        escapeCsvField(s.version || '-'),
        escapeCsvField(s.vulns_count || 0),
        escapeCsvField(s.info || '-'),
      ].join(','));
    });
  });
  lines.push('');

  // 4. VULNERABILITIES CATALOG (SHODAN CVEDB)
  lines.push('--- IDENTIFIED VULNERABILITIES (CVEDB) ---');
  lines.push('CVE ID,Severity,CVSS Score,EPSS Probability,CISA KEV (Actively Exploited),Component / Service,Affected Ports,Summary,NVD Link');
  vulnerabilities.forEach((v) => {
    lines.push([
      escapeCsvField(v.cve),
      escapeCsvField(v.severity || 'HIGH'),
      escapeCsvField(v.cvss || 'N/A'),
      escapeCsvField(v.epss ? `${(Number(v.epss) * 100).toFixed(2)}%` : 'N/A'),
      escapeCsvField(v.kev ? 'YES (CISA KEV)' : 'No'),
      escapeCsvField(v.service || v.product || 'Host'),
      escapeCsvField(v.ports?.join('; ') || '-'),
      escapeCsvField(v.summary?.replace(/\n/g, ' ') || ''),
      escapeCsvField(v.nvd_url || ''),
    ].join(','));
  });
  lines.push('');

  // 5. SUBDOMAINS
  if (subdomains.length > 0) {
    lines.push('--- PUBLIC SUBDOMAINS DISCOVERED ---');
    lines.push('Subdomain,Parent Target');
    subdomains.forEach((sd) => {
      lines.push(`${escapeCsvField(sd)},${escapeCsvField(target)}`);
    });
    lines.push('');
  }

  return lines.join('\r\n');
}

function generateRawTraceReport(scanData) {
  const { target, scan_timestamp, execution_trace = [] } = scanData;

  let raw = `================================================================================\n`;
  raw += `SNIPERSCOPE v3.6 // FORENSIC RAW TRACE (STEP-BY-STEP / COMMAND-BY-COMMAND)\n`;
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
  raw += `END OF FORENSIC RAW EXECUTION TRACE - SNIPERSCOPE v3.6 - TARGET: ${target}\n`;
  raw += `================================================================================\n`;

  return raw;
}

function generateMarkdownReport(scanData) {
  const {
    target,
    scan_timestamp,
    risk = {},
    summary = {},
    shodan = [],
    dns = {},
    http_audit = {},
    vulnerabilities = [],
    subdomains = [],
    brand_protection = {},
  } = scanData;

  let md = `# EXTERNAL ATTACK SURFACE & OSINT FORENSIC AUDIT REPORT\n\n`;
  md += `- **Audited Target:** \`${target}\`\n`;
  md += `- **Timestamp (UTC):** ${scan_timestamp}\n`;
  md += `- **Overall Risk Score:** **${risk.score ?? 0}/100 (${risk.level || 'N/A'} - Grade ${risk.grade || '-'})**\n`;
  md += `- **Classification:** TLP:AMBER (Confidential - Cybersecurity Authorized Use Only)\n`;
  md += `- **Analysis Engine:** SniperScope v3.6 Release (Attack Surface Intelligence & Anti-Phishing DRP Platform)\n\n`;
  md += `---\n\n`;

  md += `## 1. EXECUTIVE SUMMARY & RISK POSTURE\n\n`;
  md += `| Indicator | Detected Value |\n`;
  md += `| :--- | :--- |\n`;
  md += `| **Overall Risk Score** | **${risk.score ?? 0}/100 (${risk.level || 'N/A'} - Grade ${risk.grade || '-'})** |\n`;
  if (summary.ips_count) md += `| **Active Host IPs** | ${summary.ips_count} |\n`;
  if (summary.subdomains_count) md += `| **Public Subdomains (CRT.sh)** | ${summary.subdomains_count} |\n`;
  if (summary.open_ports_count) md += `| **Exposed Ports & Services** | ${summary.open_ports_count} |\n`;
  if (summary.vulnerabilities_count) md += `| **Total Vulnerabilities (CVEs)** | ${summary.vulnerabilities_count} (Critical: ${summary.critical_vulns || 0}, High: ${summary.high_vulns || 0}, Medium: ${summary.medium_vulns || 0}, CISA KEV: ${summary.kev_vulns || 0}) |\n`;
  md += `| **WAF / CDN Edge Protection** | ${http_audit?.waf_cdn || 'Direct Origin Exposed (No WAF/CDN Edge Detected)'} |\n`;
  if (dns.email_security) {
    md += `| **Email Anti-Spoofing (SPF / DMARC)** | SPF: ${dns.email_security?.has_spf ? 'CONFIGURED' : 'MISSING'} / DMARC: ${dns.email_security?.has_dmarc ? 'CONFIGURED' : 'MISSING'} |\n`;
  }
  md += `\n`;

  if (risk.findings && risk.findings.length > 0) {
    md += `### Priority Audit Findings:\n\n`;
    risk.findings.forEach((f) => {
      md += `- **[${f.severity}] ${f.title}:** ${f.detail}\n`;
    });
    md += `\n`;
  }

  // 2. Brand Protection & Phishing Forensics (omitted if empty)
  const tf = brand_protection.target_forensics;
  const brandFindings = brand_protection.findings || [];
  if (tf || brandFindings.length > 0) {
    md += `---\n\n`;
    md += `## 2. BRAND PROTECTION, PHISHING FORENSICS & REPUTATION\n\n`;
    if (tf) {
      md += `- **Analyzed Domain:** \`${tf.domain}\`\n`;
      md += `- **Threat Severity:** **${tf.severity}** (${tf.is_recent ? 'Recent Disposable Campaign' : 'Active Domain'})\n`;
      md += `- **Automated Verdict:** ${tf.verdict}\n`;
      if (tf.reputation) {
        md += `- **Threat Intelligence Status:** **${tf.reputation.badge}** — ${tf.reputation.description}\n`;
      }
      if (tf.created_date) {
        md += `- **Registration Date / Age:** ${tf.created_date.split('T')[0]} (${tf.recency_label || 'Active'})\n`;
      }
      if (tf.registrar) {
        md += `- **Official Registrar:** ${tf.registrar} (Designated Abuse: \`${tf.abuse_email || 'N/A'}\`)\n`;
      }
      if (tf.a_records?.length) {
        md += `- **Web Hosting IP(s):** ${tf.a_records.join(', ')}\n`;
      }
      if (tf.mx_records?.length) {
        md += `- **MX Mail Servers:** ${tf.mx_records.join(', ')}\n`;
      }
      if (tf.screenshot_url) {
        md += `- **Live Visual Snapshot:** Captured via headless rendering (${tf.screenshot_url})\n`;
      }
      if (tf.co_hosted_domains?.length) {
        md += `- **Co-Hosting / Passive DNS (${tf.co_hosted_domains.length} domains on same host):** ${tf.co_hosted_domains.slice(0, 12).join(', ')}\n`;
      }
      md += `\n`;
    }

    if (brandFindings.length > 0) {
      md += `### Registered Lookalike Domains & Typosquatting Clones (${brandFindings.length}):\n\n`;
      md += `| Domain | Match % | Mutation Type | Severity | Registrar | Web IP | MX Server |\n`;
      md += `| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n`;
      brandFindings.forEach((f) => {
        md += `| \`${f.domain}\` | ${f.similarity}% | ${f.mutation_type} | **${f.severity}** | ${f.registrar || 'Unknown'} | ${f.a_records?.[0] || '-'} | ${f.mx_records?.[0] || '-'} |\n`;
      });
      md += `\n`;
    }

    if (tf?.takedown_notice) {
      md += `### Attached Formal Takedown Notice (RFC 2142 / ICANN RAA 3.18):\n\n\`\`\`text\n${tf.takedown_notice}\n\`\`\`\n\n`;
    }
  }

  // 3. Discovered Subdomains (omitted if empty)
  if (subdomains && subdomains.length > 0) {
    md += `---\n\n`;
    md += `## 3. DISCOVERED PUBLIC SUBDOMAINS (${subdomains.length})\n\n`;
    subdomains.forEach((sd) => {
      md += `- \`${sd}\`\n`;
    });
    md += `\n`;
  }

  // 4. Network Infrastructure, Open Ports & Running Services (omitted if empty)
  if (shodan && shodan.length > 0) {
    md += `---\n\n`;
    md += `## 4. NETWORK INFRASTRUCTURE, OPEN PORTS & RUNNING SERVICES\n\n`;
    shodan.forEach((h) => {
      md += `### Host IP: \`${h.ip}\`\n`;
      if (h.org || h.isp) md += `- **Organization / ISP:** ${h.org || 'N/A'} (${h.isp || 'N/A'})\n`;
      if (h.asn) md += `- **ASN:** ${h.asn}\n`;
      if (h.os) md += `- **Inferred Operating System:** ${h.os}\n`;
      if (h.city || h.country) md += `- **Geographic Location:** ${[h.city, h.country].filter(Boolean).join(', ')}\n`;
      if (h.cpes?.length) md += `- **Identified CPEs:** ${h.cpes.map(c => `\`${c}\``).join(', ')}\n`;
      md += `\n`;

      if (h.services && h.services.length > 0) {
        md += `#### Running Services on \`${h.ip}\`:\n\n`;
        md += `| Port | Protocol | Service / Product | Version | Additional Info | CVEs |\n`;
        md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
        h.services.forEach((s) => {
          md += `| **${s.port}/${s.transport?.toUpperCase() || 'TCP'}** | ${s.module || s.protocol} | ${s.product} | \`${s.version || '-'}\` | ${s.info || '-'} | ${s.vulns_count || 0} |\n`;
        });
        md += `\n`;

        h.services.forEach((s) => {
          if (s.banner) {
            md += `**Banner Evidence (Port ${s.port}/${s.transport?.toUpperCase() || 'TCP'} - ${s.product}):**\n\`\`\`text\n${s.banner}\n\`\`\`\n\n`;
          }
        });
      }
    });
  }

  // 5. Web Security Audit, TLS/SSL Certificate & Exposed Artifacts
  if (http_audit && (http_audit.reachable || http_audit.tls?.enabled)) {
    md += `---\n\n`;
    md += `## 5. WEB SECURITY AUDIT, TLS/SSL CERTIFICATE & EXPOSED ARTIFACTS\n\n`;

    if (http_audit.technologies && http_audit.technologies.length > 0) {
      md += `### Detected Web Technology Stack:\n\n`;
      http_audit.technologies.forEach((tech) => {
        md += `- ${tech}\n`;
      });
      md += `\n`;
    }

    if (http_audit.tls?.enabled) {
      md += `### TLS/SSL Cryptographic Inspection (Port 443):\n`;
      md += `- **Protocol & Cipher Suite:** \`${http_audit.tls.protocol_version || 'TLS'}\` · \`${http_audit.tls.cipher_suite || 'N/A'}\` (${http_audit.tls.cipher_bits || 256} bits)\n`;
      md += `- **Certificate Authority (CA):** ${http_audit.tls.issuer_org || http_audit.tls.issuer_cn || 'N/A'}\n`;
      if (http_audit.tls.not_after) {
        md += `- **Expiration:** ${http_audit.tls.not_after} (${http_audit.tls.days_remaining ?? '-'} days remaining)\n`;
      }
      if (http_audit.tls.fingerprint_sha256) {
        md += `- **SHA-256 Fingerprint:** \`${http_audit.tls.fingerprint_sha256}\`\n`;
      }
      if (http_audit.tls.san_domains?.length) {
        md += `- **Subject Alternative Names (SANs):** ${http_audit.tls.san_domains.join(', ')}\n`;
      }
      md += `\n`;
    }

    if (http_audit.reachable) {
      if (http_audit.final_url) md += `- **Inspected URL:** ${http_audit.final_url}\n`;
      if (http_audit.status_code) md += `- **HTTP Status Code:** ${http_audit.status_code}\n`;
      if (http_audit.server) md += `- **Server Header:** \`${http_audit.server}\`\n`;
      if (http_audit.cors_policy?.allow_origin) md += `- **CORS Policy:** \`${http_audit.cors_policy.allow_origin}\`\n`;
      md += `\n`;

      if (http_audit.security_headers && http_audit.security_headers.length > 0) {
        md += `| Security Header | Status | Value / Description |\n`;
        md += `| :--- | :--- | :--- |\n`;
        http_audit.security_headers.forEach((sh) => {
          md += `| \`${sh.header}\` | ${sh.present ? 'PRESENT' : 'MISSING'} | ${sh.present ? `\`${sh.value}\`` : sh.description} |\n`;
        });
        md += `\n`;
      }

      if (http_audit.exposed_paths && http_audit.exposed_paths.length > 0) {
        md += `### Discovered Public Paths & Artifacts (${http_audit.exposed_paths.length}):\n\n`;
        http_audit.exposed_paths.forEach((ep) => {
          md += `- **[${ep.severity}] \`${ep.path}\` (HTTP ${ep.status}):** ${ep.label || ep.url}\n`;
        });
        md += `\n`;
      }
    }
  }

  // 6. Vulnerabilities Catalog (omitted if empty)
  if (vulnerabilities && vulnerabilities.length > 0) {
    md += `---\n\n`;
    md += `## 6. TECHNICAL VULNERABILITY CATALOG (SHODAN CVEDB - ${vulnerabilities.length} CVEs)\n\n`;
    vulnerabilities.forEach((v) => {
      md += `### ${v.cve} [${v.severity || 'HIGH'}] ${v.cvss ? `(CVSS: ${v.cvss})` : ''} ${v.kev ? '[CISA KEV - ACTIVELY EXPLOITED]' : ''}\n`;
      md += `- **Component / Service:** ${v.service || v.product || 'Host'} ${v.ports?.length ? `(Ports: ${v.ports.join(', ')})` : ''}\n`;
      if (v.epss !== null && v.epss !== undefined) {
        md += `- **EPSS Exploit Probability:** ${(Number(v.epss) * 100).toFixed(2)}% ${v.ranking_epss ? `(Percentile ${(Number(v.ranking_epss) * 100).toFixed(0)}%)` : ''}\n`;
      }
      if (v.published_time) md += `- **Published Date:** ${v.published_time}\n`;
      if (v.nvd_url) md += `- **NIST NVD Reference:** ${v.nvd_url}\n`;
      if (v.summary) md += `- **Technical Summary:** ${v.summary}\n`;
      md += `\n`;
    });
  }

  // 7. Forensic Hardening & Remediation Plan
  md += `---\n\n`;
  md += `## 7. FORENSIC HARDENING & REMEDIATION RECOMMENDATIONS\n\n`;
  md += `1. **Priority Patching of Exposed Services:** Upgrade software components identified via CPE (prioritizing CVEs in CISA KEV catalog or CVSS >= 7.0).\n`;
  md += `2. **Banner Obfuscation (Hardening):** Configure \`ServerTokens Prod\` (Apache) or \`server_tokens off\` (Nginx) to suppress version disclosure.\n`;
  md += `3. **Web Security Headers:** Enforce \`Strict-Transport-Security\`, \`Content-Security-Policy\`, and \`X-Frame-Options\`.\n`;
  md += `4. **Email Anti-Spoofing Policies:** Deploy strict TXT records for \`v=spf1\` and \`_dmarc\` with \`p=quarantine\` or \`p=reject\` policies.\n`;
  md += `5. **Brand Protection & Abuse Escalation:** Send automated RFC 2142 takedown notices to designated registrar abuse teams for identified lookalikes.\n`;

  return md;
}

function generateStandaloneHtml(scanData) {
  const {
    target,
    scan_timestamp,
    risk = {},
    summary = {},
    shodan = [],
    dns = {},
    http_audit = {},
    vulnerabilities = [],
    subdomains = [],
    brand_protection = {},
  } = scanData;

  const findingsHtml = (risk.findings || []).map((f) => `
    <div style="border-left: 4px solid ${f.severity === 'CRITICAL' ? '#dc2626' : f.severity === 'HIGH' ? '#ea580c' : '#ca8a04'}; background: #f9fafb; padding: 8px 12px; margin-bottom: 8px; font-size: 11.5px; border-radius: 2px;">
      <strong>[${f.severity}] ${f.title}:</strong> ${f.detail}
    </div>
  `).join('');

  const servicesHtml = (shodan || []).map((h) => `
    <div class="card">
      <div class="card-header">
        <strong>Host IP: ${h.ip}</strong>
        <span>Org: ${h.org || 'N/A'} | ASN: ${h.asn || 'N/A'} | OS: ${h.os || 'N/A'} | Location: ${[h.city, h.country].filter(Boolean).join(', ') || 'N/A'}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Port</th>
            <th>Module</th>
            <th>Product / Service</th>
            <th>Version</th>
            <th>Details / Info</th>
            <th>CVEs</th>
          </tr>
        </thead>
        <tbody>
          ${(h.services || []).map(s => `
            <tr>
              <td><strong>${s.port}/${(s.transport || 'tcp').toUpperCase()}</strong></td>
              <td>${s.module || s.protocol}</td>
              <td><strong>${s.product}</strong></td>
              <td><code>${s.version || '-'}</code></td>
              <td>${s.info || '-'} ${s.http?.title ? `| Title: "${s.http.title}"` : ''}</td>
              <td>${s.vulns_count || 0}</td>
            </tr>
            ${s.banner ? `<tr><td colspan="6"><pre class="banner">${s.banner.replace(/</g, '&lt;')}</pre></td></tr>` : ''}
          `).join('')}
        </tbody>
      </table>
    </div>
  `).join('');

  const vulnsHtml = (vulnerabilities || []).map((v) => `
    <div class="vuln-item">
      <div class="vuln-head">
        <strong>${v.cve}</strong>
        <span class="badge badge-${(v.severity || 'HIGH').toLowerCase()}">${v.severity || 'HIGH'} ${v.cvss ? `· CVSS ${v.cvss}` : ''}</span>
        ${v.kev ? '<span class="badge badge-critical">CISA KEV · ACTIVELY EXPLOITED</span>' : ''}
        ${v.epss ? `<span class="meta">EPSS: ${(Number(v.epss) * 100).toFixed(2)}%</span>` : ''}
        <span class="meta">${v.service || v.product || ''} ${v.ports?.length ? `(Port ${v.ports.join(', ')})` : ''}</span>
      </div>
      <p style="margin: 6px 0; white-space: pre-line;">${v.summary}</p>
      ${v.nvd_url ? `<div class="ref"><a href="${v.nvd_url}" target="_blank">${v.nvd_url}</a></div>` : ''}
    </div>
  `).join('');

  const tf = brand_protection.target_forensics;
  const brandFindings = brand_protection.findings || [];
  let brandHtml = '';
  if (tf || brandFindings.length > 0) {
    brandHtml = `
      <h2>2. Brand Protection, Phishing Campaign Forensics & Takedown</h2>
      ${tf ? `
        <div class="card" style="border-left: 4px solid #dc2626;">
          <div class="card-header" style="background:#fee2e2;">
            <strong>TARGET CAMPAIGN: ${tf.domain}</strong>
            <span style="font-weight:bold; color:#991b1b;">${tf.severity} · ${tf.is_recent ? 'Recent Disposable Campaign' : 'Active Domain'}</span>
          </div>
          <div style="padding:12px; font-size:11.5px;">
            <p style="margin:0 0 8px 0;"><strong>Verdict:</strong> ${tf.verdict}</p>
            ${tf.reputation ? `<p style="margin:0 0 8px 0;"><strong>Reputation Feed:</strong> <code>${tf.reputation.badge}</code> — ${tf.reputation.description}</p>` : ''}
            <div style="display:grid; grid-template-columns: repeat(2, 1fr); gap:8px; margin-top:8px;">
              ${tf.created_date ? `<div><strong>Registration Date:</strong> ${tf.created_date.split('T')[0]} (${tf.recency_label || 'Active'})</div>` : ''}
              ${tf.registrar ? `<div><strong>Official Registrar:</strong> ${tf.registrar} (Abuse: <code>${tf.abuse_email || 'N/A'}</code>)</div>` : ''}
              ${tf.a_records?.length ? `<div><strong>Web Host IP(s):</strong> ${tf.a_records.join(', ')}</div>` : ''}
              ${tf.mx_records?.length ? `<div><strong>MX Mail Servers:</strong> ${tf.mx_records.join(', ')}</div>` : ''}
            </div>

            ${tf.screenshot_url ? `
              <div style="margin-top: 12px;">
                <div style="font-weight: 600; font-size: 11px; margin-bottom: 4px; color: #374151;">Target Visual Snapshot (Automated Capture):</div>
                <img src="${tf.screenshot_url}" alt="Target Live Screenshot" class="screenshot-img" />
              </div>
            ` : ''}

            ${tf.co_hosted_domains?.length ? `
              <div style="margin-top: 12px;">
                <div style="font-weight: 600; font-size: 11px; margin-bottom: 4px; color: #374151;">
                  Passive DNS Co-Hosting (${tf.co_hosted_domains.length} suspicious domains on same host IP):
                </div>
                <div>
                  ${tf.co_hosted_domains.slice(0, 15).map(d => `<span class="tag">${d}</span>`).join('')}
                  ${tf.co_hosted_domains.length > 15 ? `<span class="meta">+${tf.co_hosted_domains.length - 15} more</span>` : ''}
                </div>
              </div>
            ` : ''}
          </div>
        </div>
      ` : ''}

      ${brandFindings.length > 0 ? `
        <div class="card" style="margin-top: 12px;">
          <div class="card-header">
            <strong>Detected Brand Lookalikes & Phishing Clones (${brandFindings.length})</strong>
          </div>
          <table>
            <thead>
              <tr>
                <th>Lookalike Domain</th>
                <th>Similarity</th>
                <th>Mutation Type</th>
                <th>Severity</th>
                <th>Registrar</th>
                <th>Resolved Host IP</th>
                <th>MX Server</th>
              </tr>
            </thead>
            <tbody>
              ${brandFindings.map(f => `
                <tr>
                  <td><strong><code>${f.domain}</code></strong></td>
                  <td>${f.similarity}%</td>
                  <td>${f.mutation_type}</td>
                  <td><span class="badge badge-${(f.severity || 'high').toLowerCase()}">${f.severity}</span></td>
                  <td>${f.registrar || 'Unknown'}</td>
                  <td>${f.a_records?.[0] || 'No Web'}</td>
                  <td>${f.mx_records?.[0] || 'No MX'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      ` : ''}

      ${tf?.takedown_notice ? `
        <div style="margin-top: 12px;">
          <div style="font-weight: 600; font-size: 11px; margin-bottom: 4px; color: #374151;">
            Legal Annex: Formal RFC 2142 / ICANN RAA 3.18 Takedown Abuse Notice:
          </div>
          <pre class="code-block">${tf.takedown_notice.replace(/</g, '&lt;')}</pre>
        </div>
      ` : ''}
    `;
  }

  const subdomainsHtml = (subdomains && subdomains.length > 0) ? `
    <h2>3. Discovered Public Subdomains (${subdomains.length})</h2>
    <div class="card">
      <div style="padding: 10px;">
        ${subdomains.map(sd => `<span class="tag">${sd}</span>`).join('')}
      </div>
    </div>
  ` : '';

  const webAuditHtml = (http_audit && (http_audit.reachable || http_audit.tls?.enabled)) ? `
    <h2>4. Web Security Audit, TLS/SSL & Exposed Artifacts</h2>
    <div style="margin-bottom: 8px;">
      <strong>Edge Protection:</strong> ${http_audit.waf_cdn || 'Direct Origin Exposed (No WAF/CDN Edge Detected)'}
    </div>
    ${dns.email_security ? `
      <p style="margin: 4px 0 8px 0;"><strong>Email Anti-Spoofing:</strong> SPF: ${dns.email_security.has_spf ? 'CONFIGURED' : 'MISSING'} | DMARC: ${dns.email_security.has_dmarc ? 'CONFIGURED' : 'MISSING'}</p>
    ` : ''}
    ${http_audit.technologies?.length ? `
      <div style="margin-bottom: 10px;">
        <strong>Detected Web Technologies:</strong>
        <div>${http_audit.technologies.map(t => `<span class="tag">${t}</span>`).join('')}</div>
      </div>
    ` : ''}
    ${http_audit.tls?.enabled ? `
      <div class="card" style="margin-top: 8px;">
        <div class="card-header">
          <strong>TLS/SSL Cryptographic Certificate (Port 443)</strong>
          <span>${http_audit.tls.protocol_version || 'TLS'} · ${http_audit.tls.cipher_suite || ''} (${http_audit.tls.cipher_bits || 256}-bit)</span>
        </div>
        <div style="padding: 8px 12px; font-size: 11px;">
          <div><strong>Certificate Issuer:</strong> ${http_audit.tls.issuer_org || http_audit.tls.issuer_cn || 'N/A'}</div>
          <div><strong>Validity Window:</strong> ${http_audit.tls.not_before || 'N/A'} to ${http_audit.tls.not_after || 'N/A'} (${http_audit.tls.days_remaining ?? 'N/A'} days remaining)</div>
          ${http_audit.tls.fingerprint_sha256 ? `<div><strong>SHA-256 Fingerprint:</strong> <code style="font-size:10px;">${http_audit.tls.fingerprint_sha256}</code></div>` : ''}
          ${http_audit.tls.san_domains?.length ? `<div style="margin-top: 4px;"><strong>Subject Alternative Names (SANs):</strong> ${http_audit.tls.san_domains.slice(0, 10).map(s => `<span class="tag">${s}</span>`).join('')}</div>` : ''}
        </div>
      </div>
    ` : ''}
    ${http_audit.reachable && http_audit.security_headers?.length ? `
      <table>
        <thead><tr><th>Security Header</th><th>Status</th><th>Value / Detail</th></tr></thead>
        <tbody>
          ${http_audit.security_headers.map(sh => `
            <tr>
              <td><code>${sh.header}</code></td>
              <td><strong>${sh.present ? 'PRESENT' : 'MISSING'}</strong></td>
              <td>${sh.present ? (sh.value || '') : sh.description}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : ''}
    ${http_audit.exposed_paths?.length ? `
      <div class="card" style="margin-top: 12px;">
        <div class="card-header" style="background: #fef2f2; color: #991b1b;">
          <strong>Discovered Public Paths & Artifacts (${http_audit.exposed_paths.length})</strong>
        </div>
        <table>
          <thead>
            <tr>
              <th>Path / Endpoint</th>
              <th>HTTP Status</th>
              <th>Severity</th>
              <th>Artifact Description</th>
            </tr>
          </thead>
          <tbody>
            ${http_audit.exposed_paths.map(ep => `
              <tr>
                <td><strong><code>${ep.path}</code></strong></td>
                <td>HTTP ${ep.status}</td>
                <td><span class="badge badge-${(ep.severity || 'medium').toLowerCase()}">${ep.severity}</span></td>
                <td>${ep.label || ep.url || '-'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    ` : ''}
  ` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>SniperScope Forensic Audit Report - ${target}</title>
  <style>
    @page {
      size: auto;
      margin: 0mm; /* Completely suppresses browser default header (date/title) and footer (about:blank) */
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #111827;
      background: #ffffff;
      margin: 0;
      padding: 24px;
      line-height: 1.5;
      font-size: 12px;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    .container { max-width: 960px; margin: 0 auto; }
    header {
      border-bottom: 2px solid #111827;
      padding-bottom: 14px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    h1 { font-size: 20px; margin: 0 0 4px 0; letter-spacing: -0.02em; font-weight: 800; }
    h2 {
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid #d1d5db;
      padding-bottom: 5px;
      margin-top: 24px;
      margin-bottom: 12px;
      color: #1f2937;
      font-weight: 700;
    }
    .tlp {
      background: #fef3c7;
      color: #92400e;
      border: 1px solid #f59e0b;
      padding: 3px 8px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 10px;
      font-weight: bold;
      display: inline-block;
      border-radius: 2px;
    }
    .kpis {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-bottom: 16px;
    }
    .kpi {
      border: 1px solid #e5e7eb;
      padding: 10px 12px;
      border-radius: 4px;
      background: #f9fafb;
    }
    .kpi .label {
      font-size: 9px;
      text-transform: uppercase;
      color: #6b7280;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-weight: 600;
    }
    .kpi .val {
      font-size: 18px;
      font-weight: bold;
      margin-top: 2px;
      color: #111827;
    }
    .card {
      border: 1px solid #d1d5db;
      border-radius: 4px;
      margin-bottom: 14px;
      overflow: hidden;
      page-break-inside: avoid;
    }
    .card-header {
      background: #f3f4f6;
      padding: 8px 12px;
      border-bottom: 1px solid #d1d5db;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11px;
    }
    table { width: 100%; border-collapse: collapse; font-size: 11px; page-break-inside: avoid; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 6px 10px; text-align: left; vertical-align: top; }
    th { background: #f9fafb; font-size: 9px; text-transform: uppercase; color: #4b5563; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    pre.banner {
      background: #111827;
      color: #e5e7eb;
      padding: 8px;
      border-radius: 4px;
      font-size: 10px;
      overflow-x: auto;
      margin: 4px 0;
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    pre.code-block {
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      color: #1f2937;
      padding: 10px;
      border-radius: 4px;
      font-size: 10.5px;
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      page-break-inside: avoid;
    }
    .vuln-item {
      border: 1px solid #e5e7eb;
      padding: 10px 12px;
      border-radius: 4px;
      margin-bottom: 8px;
      page-break-inside: avoid;
    }
    .vuln-head {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      margin-bottom: 4px;
    }
    .badge { padding: 2px 5px; border-radius: 3px; font-size: 9px; font-weight: bold; color: #fff; display: inline-block; }
    .badge-critical { background: #dc2626; }
    .badge-high { background: #ea580c; }
    .badge-medium { background: #ca8a04; }
    .badge-low { background: #0284c7; }
    .meta { color: #4b5563; font-size: 10.5px; }
    .ref a { color: #0284c7; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 10.5px; text-decoration: none; }
    .screenshot-img {
      max-height: 260px;
      width: 100%;
      object-fit: cover;
      border: 1px solid #d1d5db;
      border-radius: 4px;
      display: block;
      margin-top: 8px;
    }
    .tag {
      display: inline-block;
      background: #f1f5f9;
      color: #334155;
      border: 1px solid #cbd5e1;
      padding: 1px 6px;
      border-radius: 3px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 10px;
      margin: 2px 4px 2px 0;
    }
    footer {
      margin-top: 32px;
      border-top: 1px solid #e5e7eb;
      padding-top: 12px;
      display: flex;
      justify-content: space-between;
      color: #6b7280;
      font-size: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      page-break-inside: avoid;
    }
    @media print {
      body {
        margin: 0;
        padding: 12mm 15mm;
      }
      .no-print { display: none !important; }
      .card, .vuln-item, table, pre.code-block { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <div class="tlp">TLP:AMBER // CYBERSECURITY FORENSIC AUDIT REPORT</div>
        <h1 style="margin-top:8px;">Attack Surface Intelligence & EASM Audit: ${target}</h1>
        <div style="color:#4b5563; font-family:monospace; font-size:11px;">Generated by SniperScope v3.6 (EASM & Anti-Phishing DRP Platform) · Date: ${scan_timestamp}</div>
      </div>
      <div style="text-align:right; font-family:monospace;">
        <div style="font-size:9px; text-transform:uppercase; color:#6b7280;">Risk Posture</div>
        <div style="font-size:18px; font-weight:bold; color:#dc2626;">${risk.score ?? 0}/100 (${risk.level || 'N/A'} - Grade ${risk.grade || '-'})</div>
      </div>
    </header>

    <h2>1. Executive Summary & Risk Indicators</h2>
    <div class="kpis">
      <div class="kpi"><div class="label">Active Hosts</div><div class="val">${summary.ips_count || 0}</div></div>
      <div class="kpi"><div class="label">Open Ports</div><div class="val">${summary.open_ports_count || 0}</div></div>
      <div class="kpi"><div class="label">CVEs (${summary.critical_vulns || 0} Crit.)</div><div class="val">${summary.vulnerabilities_count || 0}</div></div>
      <div class="kpi"><div class="label">WAF / CDN Edge</div><div class="val" style="font-size:11px;">${http_audit?.waf_cdn || 'Direct Origin'}</div></div>
    </div>
    ${findingsHtml}

    ${brandHtml}

    ${subdomainsHtml}

    ${servicesHtml ? `
      <h2>5. Network Infrastructure, Open Ports & Running Services (Shodan)</h2>
      ${servicesHtml}
    ` : ''}

    ${webAuditHtml}

    ${vulnsHtml ? `
      <h2>6. Technical Vulnerability Catalog (${vulnerabilities.length} CVEs - Shodan CVEDB)</h2>
      ${vulnsHtml}
    ` : ''}

    <h2>7. Forensic Hardening & Remediation Plan</h2>
    <ol style="padding-left: 20px; line-height: 1.6;">
      <li><strong>Priority Patching:</strong> Upgrade exposed components identified via CPE, prioritizing CVEs in CISA KEV or CVSS >= 7.0.</li>
      <li><strong>Banner Obfuscation (Hardening):</strong> Disable software and OS version disclosure in HTTP and SSH headers.</li>
      <li><strong>Web Security Headers:</strong> Enforce HSTS, CSP, and X-Frame-Options on the frontend reverse proxy.</li>
      <li><strong>Email Protection:</strong> Publish strict SPF and DMARC enforcement records in target DNS zone.</li>
      <li><strong>Brand Protection & Abuse Escalation:</strong> Submit RFC 2142 takedown notices to designated registrar abuse contacts for identified phishing infrastructure.</li>
    </ol>

    <footer>
      <div>TLP:AMBER // CONFIDENTIAL CYBERSECURITY AUDIT REPORT</div>
      <div>Generated by SniperScope v3.6 · ${scan_timestamp}</div>
    </footer>
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
    const iframe = document.createElement('iframe');
    iframe.style.position = 'fixed';
    iframe.style.right = '0';
    iframe.style.bottom = '0';
    iframe.style.width = '0';
    iframe.style.height = '0';
    iframe.style.border = '0';
    iframe.style.visibility = 'hidden';
    document.body.appendChild(iframe);

    const doc = iframe.contentWindow.document;
    doc.open();
    doc.write(htmlContent);
    doc.close();

    setTimeout(() => {
      try {
        iframe.contentWindow.focus();
        iframe.contentWindow.print();
      } catch (err) {
        console.error('Print preview error:', err);
      } finally {
        setTimeout(() => {
          if (document.body.contains(iframe)) {
            document.body.removeChild(iframe);
          }
        }, 1000);
      }
    }, 250);
  };

  const handleDownloadHtml = () => {
    const htmlContent = generateStandaloneHtml(scanData);
    const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SniperScope_Forensic_Report_${scanData.target}_${new Date().toISOString().slice(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadMarkdown = () => {
    const mdContent = generateMarkdownReport(scanData);
    const blob = new Blob([mdContent], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SniperScope_Forensic_Report_${scanData.target}_${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadCsv = () => {
    const csvContent = generateCsvReport(scanData);
    // \uFEFF UTF-8 BOM ensures Microsoft Excel displays characters with correct encoding
    const blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SniperScope_Forensic_Export_${scanData.target}_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadRaw = () => {
    const rawContent = generateRawTraceReport(scanData);
    const blob = new Blob([rawContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SniperScope_Raw_Trace_${scanData.target}_${new Date().toISOString().slice(0, 10)}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 select-text">
      <div className="bg-[#0c1017] border border-[#1e2638] rounded-md w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="px-5 py-3.5 border-b border-[#1e2638] flex items-center justify-between bg-[#0f141e]">
          <div className="flex items-center space-x-2.5">
            <Crosshair size={17} className="text-[#38bdf8]" />
            <div>
              <h3 className="text-sm font-mono font-bold text-white">
                SniperScope // Professional Forensic Security Report Generator
              </h3>
              <p className="text-[11px] font-mono text-slate-400">
                Target: {scanData.target} · {scanData.scan_timestamp} · Engine: SniperScope v3.6
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
              onClick={handleDownloadCsv}
              className="px-3 py-1.5 bg-[#047857] hover:bg-[#065f46] text-white text-xs font-mono font-semibold rounded flex items-center space-x-1.5 transition-colors cursor-pointer"
              title="Download structured spreadsheet directly importable into Microsoft Excel"
            >
              <Table size={14} />
              <span>Excel (.csv)</span>
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
          <pre className="whitespace-pre-wrap font-mono leading-relaxed select-all">
            {previewFormat === 'raw'
              ? generateRawTraceReport(scanData)
              : generateMarkdownReport(scanData)}
          </pre>
        </div>
      </div>
    </div>
  );
}
