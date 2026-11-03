import React from 'react';
import { ExternalLink, AlertTriangle, X, Server, Globe, ShieldAlert } from 'lucide-react';

export default function NodeDetails({ selectedNode, onClose }) {
  if (!selectedNode) return null;

  const { type, label, meta } = selectedNode;

  return (
    <div className="bg-[#0c1017]/95 border border-[#1e2638] rounded shadow-lg p-4 font-mono text-xs text-slate-200 max-h-[45vh] overflow-y-auto backdrop-blur-md select-text">
      <div className="flex items-start justify-between gap-2 border-b border-[#1e2638] pb-2.5 mb-3">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-[#38bdf8] font-bold">
            Nodo Seleccionado · {type}
          </div>
          <div className="text-sm font-bold text-white break-all mt-0.5">{label}</div>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white hover:bg-[#1e2638] rounded cursor-pointer"
          >
            <X size={14} />
          </button>
        )}
      </div>

      {/* NODO TIPO IP */}
      {type === 'ip' && (
        <div className="space-y-2 text-[11px]">
          <div className="grid grid-cols-2 gap-2 bg-[#090b10] p-2.5 rounded border border-[#1e2638]">
            <div><span className="text-slate-500">Organización:</span> {meta?.org || 'N/A'}</div>
            <div><span className="text-slate-500">ISP:</span> {meta?.isp || 'N/A'}</div>
            <div><span className="text-slate-500">ASN:</span> {meta?.asn || 'N/A'}</div>
            <div><span className="text-slate-500">Sistema Operativo:</span> {meta?.os || 'N/A'}</div>
            <div><span className="text-slate-500">Ubicación:</span> {[meta?.city, meta?.country].filter(Boolean).join(', ') || 'N/A'}</div>
            <div><span className="text-slate-500">Puertos / CVEs:</span> {meta?.ports_count || 0} puertos · {meta?.vulns_count || 0} CVEs</div>
          </div>
          {meta?.cpes?.length > 0 && (
            <div className="text-[10px] text-slate-400">
              <span className="text-slate-500 uppercase">CPEs: </span>
              {meta.cpes.join(', ')}
            </div>
          )}
        </div>
      )}

      {/* NODO TIPO PUERTO / SERVICIO */}
      {type === 'port' && (
        <div className="space-y-2.5 text-[11px]">
          <div className="grid grid-cols-2 gap-2 bg-[#090b10] p-2.5 rounded border border-[#1e2638]">
            <div><span className="text-slate-500">Host IP:</span> {meta?.ip}</div>
            <div><span className="text-slate-500">Puerto:</span> {meta?.port}/{meta?.transport?.toUpperCase()}</div>
            <div><span className="text-slate-500">Servicio:</span> <strong className="text-white">{meta?.product}</strong></div>
            <div><span className="text-slate-500">Versión:</span> <span className="text-[#38bdf8]">{meta?.version || 'N/A'}</span></div>
            {meta?.info && <div><span className="text-slate-500">Info:</span> {meta.info}</div>}
            <div><span className="text-slate-500">Módulo:</span> {meta?.module || meta?.protocol}</div>
          </div>

          {meta?.http?.title && (
            <div className="bg-[#090b10] p-2 rounded border border-[#1e2638]">
              <span className="text-slate-500">Título HTTP: </span>
              <span className="text-slate-200">{meta.http.title}</span>
            </div>
          )}

          {meta?.banner && (
            <div>
              <div className="text-[10px] uppercase text-slate-500 mb-1">Banner Capturado:</div>
              <pre className="p-2 bg-[#06080c] border border-[#1e2638] rounded text-[10px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                {meta.banner}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* NODO TIPO CVE */}
      {type === 'cve' && (
        <div className="space-y-2.5 text-[11px]">
          <div className="flex flex-wrap items-center gap-2">
            <span className="px-2 py-0.5 bg-[#2d0f14] border border-[#991b1b] text-[#f87171] font-bold rounded text-[10px]">
              {meta?.severity || 'HIGH'} {meta?.cvss ? `· CVSS ${meta.cvss}` : ''}
            </span>
            {meta?.service && (
              <span className="text-slate-400">Servicio: <strong className="text-slate-200">{meta.service}</strong></span>
            )}
          </div>
          {meta?.summary && (
            <p className="text-slate-300 font-sans leading-relaxed bg-[#090b10] p-2.5 rounded border border-[#1e2638]">
              {meta.summary}
            </p>
          )}
          <div className="flex items-center space-x-3 pt-1">
            <a
              href={meta?.nvd_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center space-x-1 text-[#38bdf8] hover:underline"
            >
              <span>Ver en NIST NVD</span>
              <ExternalLink size={11} />
            </a>
            <a
              href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${meta?.cve}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center space-x-1 text-slate-400 hover:text-white"
            >
              <span>MITRE CVE</span>
              <ExternalLink size={11} />
            </a>
          </div>
        </div>
      )}

      {/* NODO TARGET / SUBDOMINIO */}
      {(type === 'target' || type === 'subdomain') && (
        <div className="text-[11px] text-slate-300">
          Host auditado: <strong>{label}</strong> ({type === 'target' ? 'Dominio/Objetivo Principal' : 'Subdominio en Certificados'})
        </div>
      )}
    </div>
  );
}
