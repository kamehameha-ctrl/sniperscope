import React, { useState } from 'react';
import { Crosshair, Lock, User, AlertCircle, ShieldCheck, Loader2 } from 'lucide-react';
import { loginOperator } from '../services/api';

export default function LoginScreen({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [acceptedRoe, setAcceptedRoe] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!acceptedRoe) {
      setErrorMsg('Debes confirmar el aviso de uso autorizado (Rules of Engagement) para operar la estación.');
      return;
    }
    setIsLoading(true);
    setErrorMsg(null);

    try {
      const res = await loginOperator(username, password);
      onLoginSuccess(res);
    } catch (err) {
      setErrorMsg(err.message || 'Error de autenticación');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-screen bg-[#090b10] text-slate-100 flex flex-col items-center justify-center p-4 font-mono select-text">
      <div className="w-full max-w-md bg-[#0c1017] border border-[#1e2638] rounded-md overflow-hidden shadow-2xl">
        {/* Cabecera del Terminal de Acceso */}
        <div className="px-6 py-5 bg-[#0f141e] border-b border-[#1e2638] flex items-center space-x-3.5">
          <div className="w-10 h-10 bg-[#0f172a] border border-[#38bdf8]/50 rounded flex items-center justify-center text-[#38bdf8] shrink-0">
            <Crosshair size={22} />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-base font-bold tracking-wider text-white">SNIPERSCOPE</h1>
              <span className="text-[10px] px-1.5 py-0.5 bg-[#1e2638] text-[#38bdf8] rounded font-semibold">
                v3.1 OPSEC
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Autenticación de Operador // Estación EASM & OSINT
            </p>
          </div>
        </div>

        {/* Formulario de Acceso */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {errorMsg && (
            <div className="p-3 bg-[#2a1317] border border-[#7f1d1d] rounded text-xs text-[#f87171] flex items-start space-x-2">
              <AlertCircle size={15} className="shrink-0 mt-0.5" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="space-y-1.5">
            <label className="block text-[11px] uppercase tracking-wider text-slate-400">
              Identificador de Operador
            </label>
            <div className="relative flex items-center">
              <User size={14} className="absolute left-3 text-slate-500" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Usuario operador..."
                required
                autoComplete="username"
                className="w-full bg-[#07090e] border border-[#1e2638] focus:border-[#38bdf8] focus:outline-none text-sm text-white pl-9 pr-3 py-2 rounded transition-colors"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-[11px] uppercase tracking-wider text-slate-400">
              Clave de Acceso Criptográfica
            </label>
            <div className="relative flex items-center">
              <Lock size={14} className="absolute left-3 text-slate-500" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                autoComplete="current-password"
                className="w-full bg-[#07090e] border border-[#1e2638] focus:border-[#38bdf8] focus:outline-none text-sm text-white pl-9 pr-3 py-2 rounded transition-colors"
              />
            </div>
          </div>

          {/* Aviso de Seguridad Operativa (OPSEC) y Conformidad Legal */}
          <div className="p-3 bg-[#090b10] border border-[#1e2638] rounded space-y-2 text-[11px] text-slate-400 font-sans leading-relaxed">
            <div className="flex items-center space-x-1.5 font-mono text-[10px] font-bold uppercase text-[#10b981]">
              <ShieldCheck size={13} />
              <span>Directiva OPSEC & Cumplimiento Legal</span>
            </div>
            <p>
              Por defecto, <strong>SniperScope</strong> opera en <strong>Modo Stealth (Pasivo)</strong>: las consultas de puertos, servicios y CVEs se realizan contra fuentes públicas (Shodan, CVEDB, CRT.sh, RDAP) sin realizar sondeos intrusivos sobre el objetivo. El <strong>Modo Activo</strong> solo debe emplearse sobre activos propios o con autorización expresa.
            </p>
            <label className="flex items-center space-x-2 pt-1 cursor-pointer text-slate-300 font-mono text-[11px]">
              <input
                type="checkbox"
                checked={acceptedRoe}
                onChange={(e) => setAcceptedRoe(e.target.checked)}
                className="rounded border-[#1e2638] bg-[#07090e] text-[#38bdf8] focus:ring-0 cursor-pointer"
              />
              <span>Confirmo uso autorizado de auditoría y análisis OSINT</span>
            </label>
          </div>

          <button
            type="submit"
            disabled={isLoading || !username.trim() || !password}
            className="w-full py-2.5 bg-[#0284c7] hover:bg-[#0369a1] disabled:opacity-40 text-white text-xs font-bold uppercase tracking-wider rounded transition-colors flex items-center justify-center space-x-2 cursor-pointer"
          >
            {isLoading ? (
              <>
                <Loader2 size={15} className="animate-spin" />
                <span>Verificando credenciales...</span>
              </>
            ) : (
              <span>Desbloquear Estación SniperScope</span>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
