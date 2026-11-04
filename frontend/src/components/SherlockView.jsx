import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  UserSearch,
  Search,
  ExternalLink,
  Copy,
  Check,
  Download,
  Square,
  RefreshCw,
  Globe,
  Code,
  Share2,
  Gamepad2,
  BookOpen,
  Music,
  MessageSquare,
  Clock,
  AlertTriangle,
  ArrowLeft,
  Phone,
  Mail,
  Building2,
  MapPin,
  FileText,
  CheckCircle2
} from 'lucide-react';
import { fetchSherlockSites, startSherlockStream, fetchPhoneOsint, fetchEmailOsint } from '../services/api';

const CATEGORY_ICONS = {
  'Todos': Globe,
  'España (ES)': Globe,
  'Coding & Dev': Code,
  'Social Media': Share2,
  'Gaming': Gamepad2,
  'Tech & Blogging': BookOpen,
  'Media & Creative': Music,
  'Discussion & Forums': MessageSquare,
};

const CATEGORY_COLORS = {
  'España (ES)': 'border-amber-500/40 text-amber-300 bg-amber-950/30',
  'Coding & Dev': 'border-sky-500/30 text-sky-400 bg-sky-950/30',
  'Social Media': 'border-purple-500/30 text-purple-400 bg-purple-950/30',
  'Gaming': 'border-emerald-500/30 text-emerald-400 bg-emerald-950/30',
  'Tech & Blogging': 'border-amber-500/30 text-amber-400 bg-amber-950/30',
  'Media & Creative': 'border-pink-500/30 text-pink-400 bg-pink-950/30',
  'Discussion & Forums': 'border-indigo-500/30 text-indigo-400 bg-indigo-950/30',
  'General': 'border-slate-500/30 text-slate-400 bg-slate-950/30',
};

function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.left = '-9999px';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand('copy');
  } finally {
    document.body.removeChild(textArea);
  }
  return Promise.resolve();
}

export default function SherlockView({ onBackToEasm }) {
  // Pestaña activa: 'username' | 'spain' | 'phone' | 'email'
  const [osintTab, setOsintTab] = useState('username');

  // --- ESTADO SHERLOCK USERNAME ---
  const [username, setUsername] = useState('');
  const [activeUsername, setActiveUsername] = useState('');
  const [categories, setCategories] = useState(['Todos']);
  const [selectedCategory, setSelectedCategory] = useState('Todos');
  const [totalCatalogCount, setTotalCatalogCount] = useState(0);

  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState({ checked: 0, total: 0, found: 0 });
  const [results, setResults] = useState([]);
  const [viewFilter, setViewFilter] = useState('found'); // 'found' | 'all'
  const [textSearch, setTextSearch] = useState('');
  const [copiedUrl, setCopiedUrl] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [scanSummary, setScanSummary] = useState(null);

  const cancelStreamRef = useRef(null);
  const startTimeRef = useRef(0);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const timerIntervalRef = useRef(null);

  // --- ESTADO ESPAÑA OSINT HUB ---
  const [spainQuery, setSpainQuery] = useState('');

  // --- ESTADO PHONE HUNTER ---
  const [phoneQuery, setPhoneQuery] = useState('');
  const [phoneLoading, setPhoneLoading] = useState(false);
  const [phoneData, setPhoneData] = useState(null);
  const [phoneError, setPhoneError] = useState(null);

  // --- ESTADO EMAIL HUNTER ---
  const [emailQuery, setEmailQuery] = useState('');
  const [emailLoading, setEmailLoading] = useState(false);
  const [emailData, setEmailData] = useState(null);
  const [emailError, setEmailError] = useState(null);

  // Cargar catálogo de plataformas Sherlock
  useEffect(() => {
    fetchSherlockSites()
      .then((data) => {
        if (data.categories) setCategories(data.categories);
        if (data.total) setTotalCatalogCount(data.total);
      })
      .catch((err) => {
        console.error('Error al cargar catálogo de Sherlock:', err);
      });

    return () => {
      if (cancelStreamRef.current) cancelStreamRef.current();
      if (timerIntervalRef.current) clearInterval(timerIntervalRef.current);
    };
  }, []);

  const handleStartScan = (targetUser = username) => {
    const clean = (targetUser || '').trim();
    if (!clean) return;

    if (cancelStreamRef.current) {
      cancelStreamRef.current();
      cancelStreamRef.current = null;
    }
    if (timerIntervalRef.current) {
      clearInterval(timerIntervalRef.current);
    }

    setErrorMessage(null);
    setResults([]);
    setScanSummary(null);
    setActiveUsername(clean);
    setIsScanning(true);
    setProgress({ checked: 0, total: 0, found: 0 });
    setElapsedSeconds(0);
    startTimeRef.current = Date.now();

    timerIntervalRef.current = setInterval(() => {
      setElapsedSeconds(((Date.now() - startTimeRef.current) / 1000).toFixed(1));
    }, 100);

    const cancelFn = startSherlockStream(clean, selectedCategory, {
      onInit: (data) => {
        setProgress({ checked: 0, total: data.total, found: 0 });
      },
      onProgress: (data) => {
        setResults((prev) => [data, ...prev]);
        setProgress({
          checked: data.checked_count,
          total: data.total,
          found: data.found_count,
        });
      },
      onComplete: (data) => {
        setIsScanning(false);
        setScanSummary(data);
        if (timerIntervalRef.current) {
          clearInterval(timerIntervalRef.current);
          timerIntervalRef.current = null;
        }
      },
      onError: (err) => {
        setIsScanning(false);
        setErrorMessage(err.message || 'Error durante el sondeo SOCMINT');
        if (timerIntervalRef.current) {
          clearInterval(timerIntervalRef.current);
          timerIntervalRef.current = null;
        }
      },
    });

    cancelStreamRef.current = cancelFn;
  };

  const handleStopScan = () => {
    if (cancelStreamRef.current) {
      cancelStreamRef.current();
      cancelStreamRef.current = null;
    }
    if (timerIntervalRef.current) {
      clearInterval(timerIntervalRef.current);
      timerIntervalRef.current = null;
    }
    setIsScanning(false);
  };

  const handleCopy = (text) => {
    copyToClipboard(text);
    setCopiedUrl(text);
    setTimeout(() => setCopiedUrl(null), 1800);
  };

  // Búsqueda de teléfono
  const handlePhoneSearch = async (e) => {
    if (e) e.preventDefault();
    const clean = phoneQuery.trim();
    if (!clean) return;
    setPhoneLoading(true);
    setPhoneError(null);
    try {
      const data = await fetchPhoneOsint(clean);
      if (data.error) {
        setPhoneError(data.error);
        setPhoneData(null);
      } else {
        setPhoneData(data);
      }
    } catch (err) {
      setPhoneError(err.message || 'Error al analizar el teléfono');
    } finally {
      setPhoneLoading(false);
    }
  };

  // Búsqueda de email
  const handleEmailSearch = async (e) => {
    if (e) e.preventDefault();
    const clean = emailQuery.trim();
    if (!clean) return;
    setEmailLoading(true);
    setEmailError(null);
    try {
      const data = await fetchEmailOsint(clean);
      if (data.error) {
        setEmailError(data.error);
        setEmailData(null);
      } else {
        setEmailData(data);
      }
    } catch (err) {
      setEmailError(err.message || 'Error al analizar el correo');
    } finally {
      setEmailLoading(false);
    }
  };

  const filteredResults = useMemo(() => {
    return results.filter((r) => {
      if (viewFilter === 'found' && !r.found) return false;
      if (textSearch.trim()) {
        const q = textSearch.toLowerCase();
        return r.site.toLowerCase().includes(q) || r.category.toLowerCase().includes(q);
      }
      return true;
    });
  }, [results, viewFilter, textSearch]);

  const confirmedProfiles = useMemo(() => {
    return results.filter((r) => r.found);
  }, [results]);

  const exportToJson = () => {
    const payload = {
      target_username: activeUsername,
      generated_at: new Date().toISOString(),
      summary: scanSummary,
      profiles: confirmedProfiles,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sherlock_osint_${activeUsername || 'user'}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const exportToMarkdown = () => {
    let md = `# 🕵️ Dossier Forense de Identidad Digital (SOCMINT)\n\n`;
    md += `**Objetivo (Username / Alias):** \`@${activeUsername}\`\n`;
    md += `**Fecha de Extracción:** ${new Date().toLocaleString()} (UTC)\n`;
    md += `**Plataformas Analizadas:** ${progress.checked} de ${progress.total}\n`;
    md += `**Perfiles Confirmados:** ${confirmedProfiles.length}\n`;
    md += `**Filtro Aplicado:** ${selectedCategory}\n\n`;
    md += `---\n\n`;
    md += `## 🌐 Perfiles Digitales Verificados\n\n`;
    md += `| Plataforma | Categoría | Enlace al Perfil | Latencia | Estado HTTP |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- |\n`;

    confirmedProfiles.forEach((p) => {
      md += `| **${p.site}** | ${p.category} | [${p.url}](${p.url}) | ${p.elapsed_ms}ms | ${p.status_code || 200} |\n`;
    });

    md += `\n---\n*Generado por SniperScope v3.2 // Sherlock SOCMINT Hunter*\n`;

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sherlock_dossier_${activeUsername || 'user'}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const percentComplete = progress.total > 0 ? Math.round((progress.checked / progress.total) * 100) : 0;

  return (
    <div className="flex flex-col h-full w-full bg-[#090b10] text-slate-100 overflow-hidden font-sans select-text">
      {/* 1. Sub-Header Sherlock Suite */}
      <div className="border-b border-[#1e2638] bg-[#0c1017] px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex items-center space-x-3">
          <button
            type="button"
            onClick={onBackToEasm}
            title="Volver a la vista de Red / IP (SniperScope)"
            className="flex items-center space-x-1.5 px-2.5 py-1 text-xs font-mono rounded border border-[#1e2638] bg-[#0f172a] text-slate-300 hover:text-sky-400 hover:border-sky-500/50 transition-colors cursor-pointer"
          >
            <ArrowLeft size={14} />
            <span>Volver a EASM</span>
          </button>
          <div className="h-4 w-px bg-[#1e2638]" />
          <div className="flex items-center space-x-2">
            <div className="w-6 h-6 rounded bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <UserSearch size={14} />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono font-bold tracking-wider text-sm text-slate-100">
                  SHERLOCK // SUITE DE INTELIGENCIA OSINT
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 bg-purple-950/50 text-purple-300 border border-purple-500/30 rounded">
                  {totalCatalogCount > 0 ? `${totalCatalogCount} PLATAFORMAS` : 'INDETECTABLE & PARALELO'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Acciones de exportación (solo en pestaña username con resultados) */}
        {osintTab === 'username' && confirmedProfiles.length > 0 && (
          <div className="flex items-center gap-2">
            <button
              onClick={exportToMarkdown}
              className="px-2.5 py-1 rounded bg-[#1e2638] hover:bg-[#28354f] text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-700/50"
              title="Descargar Dossier en Markdown"
            >
              <Download size={13} />
              <span>Dossier (.md)</span>
            </button>
            <button
              onClick={exportToJson}
              className="px-2.5 py-1 rounded bg-[#1e2638] hover:bg-[#28354f] text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-700/50"
              title="Descargar en JSON crudo"
            >
              <Download size={13} />
              <span>JSON</span>
            </button>
          </div>
        )}
      </div>

      {/* 2. Barra de Navegación por Pestañas Especializadas */}
      <div className="bg-[#0b0e14] border-b border-[#1e2638] px-4 py-2 flex items-center gap-2 overflow-x-auto shrink-0">
        <button
          type="button"
          onClick={() => setOsintTab('username')}
          className={`px-3 py-1.5 rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-all cursor-pointer border ${
            osintTab === 'username'
              ? 'bg-purple-950/70 border-purple-500 text-purple-200 shadow-sm shadow-purple-900/30'
              : 'bg-[#121824] border-[#1e2638] text-slate-400 hover:text-slate-200 hover:border-slate-600'
          }`}
        >
          <UserSearch size={14} />
          <span>Username SOCMINT</span>
        </button>

        <button
          type="button"
          onClick={() => setOsintTab('spain')}
          className={`px-3 py-1.5 rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-all cursor-pointer border ${
            osintTab === 'spain'
              ? 'bg-amber-950/70 border-amber-500 text-amber-200 shadow-sm shadow-amber-900/30'
              : 'bg-[#121824] border-[#1e2638] text-slate-400 hover:text-amber-300 hover:border-amber-500/40'
          }`}
        >
          <span className="text-sm leading-none">🇪🇸</span>
          <span>España OSINT Hub</span>
          <span className="text-[9px] px-1 py-0.2 bg-amber-900/50 text-amber-300 rounded border border-amber-600/40 font-mono">UNISHKA</span>
        </button>

        <button
          type="button"
          onClick={() => setOsintTab('phone')}
          className={`px-3 py-1.5 rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-all cursor-pointer border ${
            osintTab === 'phone'
              ? 'bg-emerald-950/70 border-emerald-500 text-emerald-200 shadow-sm shadow-emerald-900/30'
              : 'bg-[#121824] border-[#1e2638] text-slate-400 hover:text-emerald-300 hover:border-emerald-500/40'
          }`}
        >
          <Phone size={14} />
          <span>Phone Hunter</span>
          <span className="text-[9px] px-1 py-0.2 bg-emerald-900/50 text-emerald-300 rounded border border-emerald-600/40 font-mono">PhoneInfoga</span>
        </button>

        <button
          type="button"
          onClick={() => setOsintTab('email')}
          className={`px-3 py-1.5 rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-all cursor-pointer border ${
            osintTab === 'email'
              ? 'bg-sky-950/70 border-sky-500 text-sky-200 shadow-sm shadow-sky-900/30'
              : 'bg-[#121824] border-[#1e2638] text-slate-400 hover:text-sky-300 hover:border-sky-500/40'
          }`}
        >
          <Mail size={14} />
          <span>Email Hunter</span>
          <span className="text-[9px] px-1 py-0.2 bg-sky-900/50 text-sky-300 rounded border border-sky-600/40 font-mono">Epieos</span>
        </button>
      </div>

      {/* 3. CONTENIDO SEGÚN LA PESTAÑA SELECCIONADA */}

      {/* PESTAÑA 1: USERNAME SOCMINT */}
      {osintTab === 'username' && (
        <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
          {/* Barra de Búsqueda y Filtros de Categoría */}
          <div className="p-4 bg-[#0c1017]/50 border-b border-[#1e2638] shrink-0">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleStartScan();
              }}
              className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center max-w-4xl mx-auto"
            >
              <div className="relative flex-1">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 font-mono text-sm">
                  @
                </div>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Introduce un username / alias (ej. esskike, elonmusk, satoshi)..."
                  disabled={isScanning}
                  className="w-full pl-8 pr-4 py-2 bg-[#090b10] border border-[#1e2638] focus:border-purple-500 focus:outline-none rounded text-sm text-slate-100 placeholder-slate-500 font-mono transition-colors"
                />
              </div>

              {/* Selector de categoría */}
              <div className="flex items-center gap-2">
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  disabled={isScanning}
                  className="bg-[#090b10] border border-[#1e2638] focus:border-purple-500 text-slate-200 text-xs rounded px-3 py-2 font-mono outline-none cursor-pointer"
                >
                  {categories.map((cat) => (
                    <option key={cat} value={cat}>
                      {cat === 'España (ES)' ? '🇪🇸 España (ES)' : cat}
                    </option>
                  ))}
                </select>

                {isScanning ? (
                  <button
                    type="button"
                    onClick={handleStopScan}
                    className="px-4 py-2 bg-red-950/80 hover:bg-red-900 border border-red-700 text-red-200 rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors cursor-pointer"
                  >
                    <Square size={14} className="fill-current" />
                    <span>Detener</span>
                  </button>
                ) : (
                  <button
                    type="submit"
                    disabled={!username.trim()}
                    className="px-5 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:hover:bg-purple-600 text-white rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-all shadow-md shadow-purple-900/30 cursor-pointer"
                  >
                    <Search size={14} />
                    <span>Rastrear</span>
                  </button>
                )}
              </div>
            </form>

            {/* Barra de progreso interactiva */}
            {(isScanning || progress.checked > 0) && (
              <div className="max-w-4xl mx-auto mt-3 pt-3 border-t border-[#1e2638]/70">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1.5">
                  <div className="flex items-center space-x-2">
                    <span className="text-purple-400 font-bold">
                      {isScanning ? 'Escaneando en paralelo...' : 'Escaneo finalizado'}
                    </span>
                    <span>·</span>
                    <span className="text-slate-300">
                      {progress.checked} / {progress.total} plataformas
                    </span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="text-emerald-400 font-bold flex items-center space-x-1">
                      <CheckCircle2 size={13} />
                      <span>{progress.found} encontrados</span>
                    </span>
                    <span className="text-slate-500 flex items-center space-x-1">
                      <Clock size={12} />
                      <span>{elapsedSeconds}s</span>
                    </span>
                  </div>
                </div>
                <div className="w-full bg-[#141a26] h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-purple-500 h-full transition-all duration-150"
                    style={{ width: `${percentComplete}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Área de Resultados de Sherlock */}
          <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-4">
            {errorMessage && (
              <div className="max-w-4xl mx-auto p-3 bg-red-950/40 border border-red-800 rounded text-red-300 text-xs flex items-center space-x-2 font-mono">
                <AlertTriangle size={15} />
                <span>{errorMessage}</span>
              </div>
            )}

            {results.length > 0 && (
              <div className="max-w-4xl mx-auto flex items-center justify-between gap-3">
                <div className="flex items-center space-x-2 text-xs font-mono">
                  <button
                    onClick={() => setViewFilter('found')}
                    className={`px-3 py-1 rounded border transition-colors cursor-pointer ${
                      viewFilter === 'found'
                        ? 'bg-emerald-950/60 border-emerald-500 text-emerald-300 font-bold'
                        : 'bg-[#0f172a] border-[#1e2638] text-slate-400 hover:text-white'
                    }`}
                  >
                    Confirmados ({confirmedProfiles.length})
                  </button>
                  <button
                    onClick={() => setViewFilter('all')}
                    className={`px-3 py-1 rounded border transition-colors cursor-pointer ${
                      viewFilter === 'all'
                        ? 'bg-purple-950/60 border-purple-500 text-purple-300 font-bold'
                        : 'bg-[#0f172a] border-[#1e2638] text-slate-400 hover:text-white'
                    }`}
                  >
                    Todos ({results.length})
                  </button>
                </div>

                <div className="relative w-64">
                  <Search size={13} className="absolute left-2.5 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    value={textSearch}
                    onChange={(e) => setTextSearch(e.target.value)}
                    placeholder="Filtrar por nombre o categoría..."
                    className="w-full pl-8 pr-3 py-1 bg-[#0c1017] border border-[#1e2638] rounded text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>
            )}

            {results.length === 0 && !isScanning ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-8 text-slate-500">
                <div className="w-12 h-12 rounded-full border border-purple-500/30 bg-purple-950/20 flex items-center justify-center text-purple-400 mb-3">
                  <UserSearch size={22} />
                </div>
                <div className="font-mono text-sm text-slate-300 font-bold">
                  SISTEMA LISTO PARA INVESTIGACIÓN SOCMINT
                </div>
                <p className="text-xs font-mono text-slate-500 max-w-md mt-1 leading-relaxed">
                  Introduce el nombre de usuario de la persona investigada para rastrear en paralelo
                  más de {totalCatalogCount || 100} redes sociales, foros españoles, repositorios y plataformas de juego.
                </p>
              </div>
            ) : (
              <div className="max-w-4xl mx-auto grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {filteredResults.map((r, idx) => {
                  const CatIcon = CATEGORY_ICONS[r.category] || Globe;
                  const catStyle = CATEGORY_COLORS[r.category] || CATEGORY_COLORS['General'];
                  const isCopied = copiedUrl === r.url;

                  return (
                    <div
                      key={`${r.site}-${idx}`}
                      className={`p-3 rounded border transition-all flex flex-col justify-between ${
                        r.found
                          ? 'bg-[#0c131a] border-emerald-500/50 hover:border-emerald-400 shadow-sm shadow-emerald-950/20'
                          : 'bg-[#090b10] border-[#1e2638] opacity-60 hover:opacity-100'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-bold text-sm text-slate-100">{r.site}</span>
                          <span
                            className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase font-bold ${
                              r.found
                                ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                                : 'bg-slate-900 text-slate-500 border-slate-800'
                            }`}
                          >
                            {r.found ? 'CONFIRMADO' : 'NO DETECTADO'}
                          </span>
                        </div>

                        <div className="flex items-center space-x-1.5 mt-1.5">
                          <CatIcon size={11} className="text-slate-400 shrink-0" />
                          <span className={`text-[10px] font-mono px-1 rounded border ${catStyle}`}>
                            {r.category}
                          </span>
                        </div>
                      </div>

                      <div className="mt-3 pt-2 border-t border-[#1e2638] flex items-center justify-between text-xs font-mono">
                        <span className="text-[10px] text-slate-500">{r.elapsed_ms}ms</span>
                        <div className="flex items-center space-x-1.5">
                          <button
                            type="button"
                            onClick={() => handleCopy(r.url)}
                            title="Copiar URL del perfil"
                            className="p-1 rounded hover:bg-[#1a2333] text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                          >
                            {isCopied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                          </button>
                          <a
                            href={r.url}
                            target="_blank"
                            rel="noreferrer"
                            title="Abrir perfil en una nueva pestaña"
                            className="p-1 rounded bg-[#1a2333] hover:bg-[#25334d] text-sky-400 hover:text-white transition-colors inline-flex items-center space-x-1 text-[11px]"
                          >
                            <span>Abrir</span>
                            <ExternalLink size={11} />
                          </a>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* PESTAÑA 2: ESPAÑA OSINT HUB (UNISHKA GUIDE / CLARA RODRÍGUEZ CHIRINO) */}
      {osintTab === 'spain' && (
        <div className="flex-1 flex flex-col min-h-0 overflow-y-auto p-4 space-y-5 max-w-5xl mx-auto w-full">
          {/* Cabecera / Banner UNISHKA */}
          <div className="bg-gradient-to-r from-amber-950/40 via-[#0d131f] to-amber-950/20 border border-amber-600/40 rounded p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xl">🇪🇸</span>
                <span className="font-mono font-bold text-amber-300 text-sm tracking-wide">
                  CENTRO DE INVESTIGACIÓN OSINT // ESPAÑA
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-amber-900/60 text-amber-200 rounded border border-amber-500/50">
                  METODOLOGÍA UNISHKA
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans mt-1 max-w-2xl leading-relaxed">
                Herramientas y registros de transparencia basados en el estudio forense de <strong>Clara Rodríguez Chirino</strong> (UNISHKA Research).
                Explora boletines oficiales, adjudicaciones públicas, sentencias judiciales del CENDOJ, catastro inmobiliario y registros mercantiles.
              </p>
            </div>
            <a
              href="https://unishka.substack.com/p/osint-of-spain"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 bg-[#141b29] hover:bg-amber-950/60 border border-amber-600/50 hover:border-amber-400 text-amber-300 rounded text-xs font-mono inline-flex items-center space-x-1.5 transition-colors shrink-0"
            >
              <span>Ver Guía UNISHKA</span>
              <ExternalLink size={11} />
            </a>
          </div>

          {/* Buscador Contextual Español */}
          <div className="bg-[#0c1017] border border-[#1e2638] rounded p-3 flex flex-col sm:flex-row gap-2 items-center">
            <div className="relative flex-1 w-full">
              <Search size={14} className="absolute left-3 top-3 text-slate-500" />
              <input
                type="text"
                value={spainQuery}
                onChange={(e) => setSpainQuery(e.target.value)}
                placeholder="Escribe un Nombre, Apellidos, Razón Social, DNI/NIE o Matrícula..."
                className="w-full pl-9 pr-3 py-2 bg-[#090b10] border border-[#1e2638] rounded text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-amber-500"
              />
            </div>
            <span className="text-xs text-slate-500 font-mono hidden sm:inline">
              {spainQuery.trim() ? 'Consultas dinámicas armadas' : 'Escribe para autocompletar enlaces'}
            </span>
          </div>

          {/* Grid de 4 Bloques Forenses */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Bloque 1: Boletines Oficiales y Judicial */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-amber-300 uppercase">
                <FileText size={15} className="text-amber-400" />
                <span>1. Boletines Oficiales & Poder Judicial</span>
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">BOE (Boletín Oficial del Estado)</span>
                    <span className="text-[10px] text-slate-500">Sanciones, nombramientos, edictos, subastas públicas e indultos</span>
                  </div>
                  <a
                    href={
                      spainQuery.trim()
                        ? `https://www.boe.es/buscar/boe.php?campo%5B0%5D=DOC&dato%5B0%5D=${encodeURIComponent(spainQuery)}`
                        : 'https://www.boe.es'
                    }
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-amber-900/60 text-amber-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>{spainQuery.trim() ? 'Buscar en BOE' : 'Abrir BOE'}</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">BORME (Boletín Registro Mercantil)</span>
                    <span className="text-[10px] text-slate-500">Constitución de empresas, ceses y nombramientos de directores</span>
                  </div>
                  <a
                    href={
                      spainQuery.trim()
                        ? `https://www.boe.es/buscar/borme.php?campo%5B0%5D=DOC&dato%5B0%5D=${encodeURIComponent(spainQuery)}`
                        : 'https://www.boe.es/diario_borme/'
                    }
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-amber-900/60 text-amber-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>{spainQuery.trim() ? 'Buscar BORME' : 'Abrir BORME'}</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">CENDOJ (Poder Judicial)</span>
                    <span className="text-[10px] text-slate-500">Buscador oficial de sentencias firmes del Tribunal Supremo y Audiencias</span>
                  </div>
                  <a
                    href="https://www.poderjudicial.es/search/indexAN.jsp"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-amber-900/60 text-amber-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>CENDOJ Sentencias</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>

            {/* Bloque 2: Contratación Pública & Entramados Societarios */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-sky-300 uppercase">
                <Building2 size={15} className="text-sky-400" />
                <span>2. Contratación Pública & Empresas</span>
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">PLACSP (Contratación del Estado)</span>
                    <span className="text-[10px] text-slate-500">Licitaciones públicas, adjudicaciones a empresas e importes adjudicados</span>
                  </div>
                  <a
                    href="https://contrataciondelestado.es/wps/portal/licitaciones"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-sky-900/60 text-sky-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>PLACSP Licitaciones</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">Datoscif / Infonif</span>
                    <span className="text-[10px] text-slate-500">Estructura mercantil, administradores, CIF y vinculaciones entre sociedades</span>
                  </div>
                  <a
                    href={
                      spainQuery.trim()
                        ? `https://www.datoscif.es/buscar?q=${encodeURIComponent(spainQuery)}`
                        : 'https://www.datoscif.es'
                    }
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-sky-900/60 text-sky-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>{spainQuery.trim() ? 'Buscar CIF' : 'Datoscif'}</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">CNMV (Advertencias de Fraude)</span>
                    <span className="text-[10px] text-slate-500">Buscador oficial de sociedades de inversión y chiringuitos financieros</span>
                  </div>
                  <a
                    href="https://www.cnmv.es/portal/consultas/Busqueda.aspx"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-sky-900/60 text-sky-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>CNMV Registro</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>

            {/* Bloque 3: Inmuebles, Territorio & Vehículos */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-emerald-300 uppercase">
                <MapPin size={15} className="text-emerald-400" />
                <span>3. Catastro Inmobiliario & Vehículos</span>
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">Sede Electrónica del Catastro</span>
                    <span className="text-[10px] text-slate-500">Búsqueda de parcelas, m², año de construcción e historial por referencia</span>
                  </div>
                  <a
                    href="https://www.sedecatastro.gob.es"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-emerald-900/60 text-emerald-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>Sede Catastro</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">DGT (Distintivo & Matrícula)</span>
                    <span className="text-[10px] text-slate-500">Comprobación pública de vehículo y distintivo ambiental por matrícula</span>
                  </div>
                  <a
                    href="https://sede.dgt.gob.es/es/vehiculos/distintivo-ambiental/"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-emerald-900/60 text-emerald-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>DGT Matrículas</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">Colegio de Registradores (Propiedad)</span>
                    <span className="text-[10px] text-slate-500">Solicitud oficial de notas simples de fincas e inmuebles inscritos</span>
                  </div>
                  <a
                    href="https://geoportal.registradores.org"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-emerald-900/60 text-emerald-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>Geoportal Fincas</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>

            {/* Bloque 4: Demografía e Identidad */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-purple-300 uppercase">
                <Globe size={15} className="text-purple-400" />
                <span>4. Demografía, INE & Guías Telefónicas</span>
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">INE (Distribución de Nombres y Apellidos)</span>
                    <span className="text-[10px] text-slate-500">Frecuencia y mapa provincial exacto de cualquier nombre o apellido en España</span>
                  </div>
                  <a
                    href="https://www.ine.es/widgets/nombapell/index.shtml"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-purple-900/60 text-purple-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>Mapa INE</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">Páginas Blancas / Infobel España</span>
                    <span className="text-[10px] text-slate-500">Guías telefónicas residenciales y comerciales en territorio español</span>
                  </div>
                  <a
                    href="https://www.paginasamarillas.es"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-purple-900/60 text-purple-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>Páginas Amarillas</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>
          </div>

          {/* Bloque 5: Dorks Especializados de España (UNISHKA Style) */}
          <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-amber-300 uppercase">
                <Search size={14} className="text-amber-400" />
                <span>Google Hacking Dorks Especializados (España / UNISHKA)</span>
              </div>
              {spainQuery && (
                <span className="text-[11px] font-mono text-slate-400">
                  Target: <strong className="text-amber-300">{spainQuery}</strong>
                </span>
              )}
            </div>

            {(() => {
              const q = spainQuery.trim() || 'NOMBRE_O_EMPRESA';
              const dorks = [
                {
                  title: 'Apariciones en BOE & Resoluciones Oficiales',
                  dork: `site:boe.es "${q}"`,
                },
                {
                  title: 'Contratos Públicos y Adjudicaciones Estatales',
                  dork: `site:contrataciondelestado.es "${q}"`,
                },
                {
                  title: 'Base Nacional de Subvenciones (Hacienda)',
                  dork: `site:pap.hacienda.gob.es/bdnstrans/ "${q}"`,
                },
                {
                  title: 'Portal de la Transparencia y Declaraciones Públicas',
                  dork: `site:transparencia.gob.es filetype:pdf "${q}"`,
                },
                {
                  title: 'Foros y Comunidades Españolas (Forocoches / Burbuja)',
                  dork: `site:forocoches.com OR site:burbuja.info "${q}"`,
                },
                {
                  title: 'Documentos Oficiales Administrativos (PDF)',
                  dork: `site:es filetype:pdf ("resolución" OR "adjudicación") "${q}"`,
                },
              ];

              return (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono pt-1">
                  {dorks.map((d, dIdx) => (
                    <div
                      key={dIdx}
                      className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between gap-2"
                    >
                      <div className="overflow-hidden">
                        <span className="text-slate-400 block text-[10px] truncate">{d.title}</span>
                        <code className="text-slate-200 text-[11px] truncate block">{d.dork}</code>
                      </div>
                      <div className="flex items-center space-x-1 shrink-0">
                        <button
                          type="button"
                          onClick={() => handleCopy(d.dork)}
                          title="Copiar Dork"
                          className="px-2 py-1 bg-[#151c28] hover:bg-[#1e2638] text-slate-300 rounded text-[10px] transition-colors"
                        >
                          {copiedUrl === d.dork ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                        </button>
                        <a
                          href={`https://www.google.com/search?q=${encodeURIComponent(d.dork)}`}
                          target="_blank"
                          rel="noreferrer"
                          className="px-2 py-1 bg-[#1a2333] hover:bg-amber-900/60 text-amber-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                        >
                          <span>Lanzar</span>
                          <ExternalLink size={9} />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {/* PESTAÑA 3: PHONE HUNTER (PHONEINFOGA STYLE) */}
      {osintTab === 'phone' && (
        <div className="flex-1 flex flex-col min-h-0 overflow-y-auto p-4 space-y-4 max-w-4xl mx-auto w-full">
          {/* Formulario de búsqueda telefónica */}
          <div className="bg-[#0c1017] border border-[#1e2638] rounded p-4">
            <div className="flex items-center space-x-2 text-xs font-mono font-bold text-emerald-400 uppercase mb-2">
              <Phone size={15} />
              <span>Rastreo Telefónico de Inteligencia (PhoneInfoga Style)</span>
            </div>
            <form onSubmit={handlePhoneSearch} className="flex gap-2 items-center">
              <input
                type="text"
                value={phoneQuery}
                onChange={(e) => setPhoneQuery(e.target.value)}
                placeholder="Introduce un teléfono (ej. +34 612 34 56 78 o 912345678)..."
                disabled={phoneLoading}
                className="flex-1 px-3 py-2 bg-[#090b10] border border-[#1e2638] rounded text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <button
                type="submit"
                disabled={phoneLoading || !phoneQuery.trim()}
                className="px-5 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors cursor-pointer shrink-0"
              >
                {phoneLoading ? <RefreshCw size={13} className="animate-spin" /> : <Search size={13} />}
                <span>{phoneLoading ? 'Analizando...' : 'Auditar Teléfono'}</span>
              </button>
            </form>
          </div>

          {phoneError && (
            <div className="p-3 bg-red-950/40 border border-red-800 rounded text-red-300 text-xs font-mono flex items-center space-x-2">
              <AlertTriangle size={14} />
              <span>{phoneError}</span>
            </div>
          )}

          {/* Resultados de Teléfono */}
          {phoneData && (
            <div className="space-y-4">
              {/* Tarjeta de Especificación Técnica E.164 */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#1e2638] pb-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xl">📞</span>
                    <div>
                      <span className="font-mono font-bold text-slate-100 text-base">{phoneData.e164_format}</span>
                      <span className="text-[11px] font-mono text-slate-500 ml-2">({phoneData.country})</span>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 bg-emerald-950 text-emerald-300 border border-emerald-700 text-[10px] font-mono font-bold rounded">
                    {phoneData.line_type}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">País / Prefijo:</span>
                    <span className="text-slate-200 font-bold">{phoneData.country} ({phoneData.dial_code})</span>
                  </div>
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Localización / Cobertura:</span>
                    <span className="text-slate-200 font-bold">{phoneData.location}</span>
                  </div>
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Operador Asignado (CNMC):</span>
                    <span className="text-emerald-400 font-bold">{phoneData.operator_assigned}</span>
                  </div>
                </div>

                {/* Acciones de Mensajería Directa sin Guardar Contacto */}
                <div className="pt-2 border-t border-[#1e2638] flex flex-wrap gap-2">
                  <a
                    href={phoneData.direct_messaging.whatsapp_url}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 bg-[#064e3b] hover:bg-[#047857] text-[#a7f3d0] border border-[#10b981] rounded text-xs font-mono font-bold inline-flex items-center space-x-1.5 transition-colors"
                  >
                    <span>💬 Abrir Chat en WhatsApp Web</span>
                    <ExternalLink size={11} />
                  </a>
                  <a
                    href={phoneData.direct_messaging.telegram_url}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 bg-[#0f2438] hover:bg-[#15344f] text-[#38bdf8] border border-[#0284c7] rounded text-xs font-mono font-bold inline-flex items-center space-x-1.5 transition-colors"
                  >
                    <span>✈️ Abrir Perfil en Telegram</span>
                    <ExternalLink size={11} />
                  </a>
                </div>
              </div>

              {/* Reputación & Bases de Datos de SPAM */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-2">
                <div className="text-xs font-mono font-bold text-slate-300 uppercase">
                  Bases de Datos de Reputación, Denuncias & SPAM Telefónico
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono pt-1">
                  {phoneData.reputation_checks.map((rep, rIdx) => (
                    <div
                      key={rIdx}
                      className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between"
                    >
                      <div>
                        <span className="text-slate-200 font-bold block">{rep.name}</span>
                        <span className="text-[10px] text-slate-500">{rep.description}</span>
                      </div>
                      <a
                        href={rep.url}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2.5 py-1 bg-[#1a2333] hover:bg-[#28354f] text-slate-200 rounded text-[10px] inline-flex items-center space-x-1 transition-colors shrink-0"
                      >
                        <span>Consultar</span>
                        <ExternalLink size={9} />
                      </a>
                    </div>
                  ))}
                </div>
              </div>

              {/* Dorks PhoneInfoga */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-2">
                <div className="text-xs font-mono font-bold text-emerald-400 uppercase">
                  PhoneInfoga Google Dorks (Huella Digital del Número)
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono pt-1">
                  {phoneData.phoneinfoga_dorks.map((d, dIdx) => (
                    <div
                      key={dIdx}
                      className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between gap-2"
                    >
                      <div className="overflow-hidden">
                        <span className="text-slate-400 text-[10px] block truncate">{d.title}</span>
                        <code className="text-slate-200 text-[11px] block truncate">{d.dork}</code>
                      </div>
                      <div className="flex items-center space-x-1 shrink-0">
                        <button
                          type="button"
                          onClick={() => handleCopy(d.dork)}
                          title="Copiar Dork"
                          className="px-2 py-1 bg-[#151c28] hover:bg-[#1e2638] text-slate-300 rounded text-[10px] transition-colors"
                        >
                          {copiedUrl === d.dork ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                        </button>
                        <a
                          href={d.url}
                          target="_blank"
                          rel="noreferrer"
                          className="px-2 py-1 bg-[#1a2333] hover:bg-emerald-900/60 text-emerald-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                        >
                          <span>Lanzar</span>
                          <ExternalLink size={9} />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* PESTAÑA 4: EMAIL HUNTER (EPIEOS STYLE) */}
      {osintTab === 'email' && (
        <div className="flex-1 flex flex-col min-h-0 overflow-y-auto p-4 space-y-4 max-w-4xl mx-auto w-full">
          {/* Formulario de búsqueda de email */}
          <div className="bg-[#0c1017] border border-[#1e2638] rounded p-4">
            <div className="flex items-center space-x-2 text-xs font-mono font-bold text-sky-400 uppercase mb-2">
              <Mail size={15} />
              <span>Rastreo Forense de Correo Electrónico (Epieos Style)</span>
            </div>
            <form onSubmit={handleEmailSearch} className="flex gap-2 items-center">
              <input
                type="email"
                value={emailQuery}
                onChange={(e) => setEmailQuery(e.target.value)}
                placeholder="Introduce una dirección de correo (ej. objetivo@empresa.com)..."
                disabled={emailLoading}
                className="flex-1 px-3 py-2 bg-[#090b10] border border-[#1e2638] rounded text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
              <button
                type="submit"
                disabled={emailLoading || !emailQuery.trim()}
                className="px-5 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors cursor-pointer shrink-0"
              >
                {emailLoading ? <RefreshCw size={13} className="animate-spin" /> : <Search size={13} />}
                <span>{emailLoading ? 'Verificando...' : 'Auditar Email'}</span>
              </button>
            </form>
          </div>

          {emailError && (
            <div className="p-3 bg-red-950/40 border border-red-800 rounded text-red-300 text-xs font-mono flex items-center space-x-2">
              <AlertTriangle size={14} />
              <span>{emailError}</span>
            </div>
          )}

          {/* Resultados de Email */}
          {emailData && (
            <div className="space-y-4">
              {/* Tarjeta de Resumen & Verificación de Dominio */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#1e2638] pb-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xl">📧</span>
                    <div>
                      <span className="font-mono font-bold text-slate-100 text-base">{emailData.email}</span>
                      <span className="text-[11px] font-mono text-slate-500 ml-2">(@{emailData.domain})</span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    {emailData.is_disposable ? (
                      <span className="px-2 py-0.5 bg-red-950 text-red-300 border border-red-700 text-[10px] font-mono font-bold rounded flex items-center space-x-1">
                        <AlertTriangle size={10} />
                        <span>CORREO TEMPORAL / DESECHABLE</span>
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 bg-emerald-950 text-emerald-300 border border-emerald-700 text-[10px] font-mono font-bold rounded">
                        PROVEEDOR VÁLIDO / ESTÁNDAR
                      </span>
                    )}
                  </div>
                </div>

                {/* Parámetros DNS de correo */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs font-mono">
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Registros MX (Buzón Activo):</span>
                    <span className={emailData.dns.mx_active ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                      {emailData.dns.mx_active ? 'Activo (Recibe correo)' : 'Sin registros MX'}
                    </span>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Registro SPF (Antispoofing):</span>
                    <span className={emailData.dns.has_spf ? 'text-sky-400 font-bold' : 'text-amber-400 font-bold'}>
                      {emailData.dns.has_spf ? 'Configurado' : 'No detectado'}
                    </span>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Política DMARC:</span>
                    <span className="text-purple-400 font-bold uppercase">
                      {emailData.dns.dmarc_policy ? `p=${emailData.dns.dmarc_policy}` : 'Sin política DMARC'}
                    </span>
                  </div>
                </div>

                {/* Perfil Gravatar Detectado */}
                {emailData.gravatar?.found && (
                  <div className="p-3 bg-[#061e2d] border border-sky-500/50 rounded flex items-center space-x-3 mt-2">
                    {emailData.gravatar.avatar_url && (
                      <img
                        src={emailData.gravatar.avatar_url}
                        alt="Gravatar Avatar"
                        className="w-12 h-12 rounded-full border border-sky-400 shadow-md object-cover"
                      />
                    )}
                    <div className="text-xs font-mono">
                      <div className="text-sky-300 font-bold flex items-center space-x-1.5">
                        <span>Perfil Gravatar Detectado</span>
                        <CheckCircle2 size={13} className="text-emerald-400" />
                      </div>
                      {emailData.gravatar.display_name && (
                        <div className="text-slate-200 text-sm font-bold mt-0.5">
                          {emailData.gravatar.display_name}
                        </div>
                      )}
                      {emailData.gravatar.location && (
                        <div className="text-slate-400 text-[10px]">
                          Ubicación: {emailData.gravatar.location}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Plataformas de Investigación Externa (Epieos, HIBP, IntelX) */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-2">
                <div className="text-xs font-mono font-bold text-slate-300 uppercase">
                  Plataformas de Análisis de Cuenta & Fugas (Epieos / Breaches)
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono pt-1">
                  {emailData.investigation_links.map((link, lIdx) => (
                    <div
                      key={lIdx}
                      className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between gap-2"
                    >
                      <div>
                        <div className="flex items-center space-x-1.5">
                          <span className="text-slate-200 font-bold">{link.name}</span>
                          <span className={`text-[9px] px-1 py-0.2 rounded border font-mono font-bold ${link.badge_color}`}>
                            {link.badge}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-500 block mt-0.5">{link.description}</span>
                      </div>
                      <a
                        href={link.url}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2.5 py-1 bg-[#1a2333] hover:bg-[#28354f] text-sky-400 hover:text-white rounded text-[10px] inline-flex items-center space-x-1 transition-colors shrink-0"
                      >
                        <span>Investigar</span>
                        <ExternalLink size={9} />
                      </a>
                    </div>
                  ))}
                </div>
              </div>

              {/* Dorks de Correo Electrónico */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-2">
                <div className="text-xs font-mono font-bold text-sky-400 uppercase">
                  Google Hacking Dorks (Huella del Correo & Fugas)
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono pt-1">
                  {emailData.email_dorks.map((d, dIdx) => (
                    <div
                      key={dIdx}
                      className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between gap-2"
                    >
                      <div className="overflow-hidden">
                        <span className="text-slate-400 text-[10px] block truncate">{d.title}</span>
                        <code className="text-slate-200 text-[11px] block truncate">{d.dork}</code>
                      </div>
                      <div className="flex items-center space-x-1 shrink-0">
                        <button
                          type="button"
                          onClick={() => handleCopy(d.dork)}
                          title="Copiar Dork"
                          className="px-2 py-1 bg-[#151c28] hover:bg-[#1e2638] text-slate-300 rounded text-[10px] transition-colors"
                        >
                          {copiedUrl === d.dork ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                        </button>
                        <a
                          href={d.url}
                          target="_blank"
                          rel="noreferrer"
                          className="px-2 py-1 bg-[#1a2333] hover:bg-sky-900/60 text-sky-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1"
                        >
                          <span>Lanzar</span>
                          <ExternalLink size={9} />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
