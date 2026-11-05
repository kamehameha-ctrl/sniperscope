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
  'All': Globe,
  'Todos': Globe,
  'Spain (ES)': Globe,
  'España (ES)': Globe,
  'Coding & Dev': Code,
  'Social Media': Share2,
  'Gaming': Gamepad2,
  'Tech & Blogging': BookOpen,
  'Media & Creative': Music,
  'Discussion & Forums': MessageSquare,
};

const CATEGORY_COLORS = {
  'Spain (ES)': 'border-amber-500/40 text-amber-300 bg-amber-950/30',
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
  const [categories, setCategories] = useState(['All']);
  const [selectedCategory, setSelectedCategory] = useState('All');
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

  // --- SPAIN OSINT HUB STATE ---
  const [spainQuery, setSpainQuery] = useState('');

  // --- PHONE HUNTER STATE ---
  const [phoneQuery, setPhoneQuery] = useState('');
  const [phoneLoading, setPhoneLoading] = useState(false);
  const [phoneData, setPhoneData] = useState(null);
  const [phoneError, setPhoneError] = useState(null);

  // --- EMAIL HUNTER STATE ---
  const [emailQuery, setEmailQuery] = useState('');
  const [emailLoading, setEmailLoading] = useState(false);
  const [emailData, setEmailData] = useState(null);
  const [emailError, setEmailError] = useState(null);

  // Load Sherlock platform catalog
  useEffect(() => {
    fetchSherlockSites()
      .then((data) => {
        if (data.categories) {
          const mapped = data.categories.map((c) => (c === 'Todos' ? 'All' : c === 'España (ES)' ? 'Spain (ES)' : c));
          setCategories(mapped);
        }
        if (data.total) setTotalCatalogCount(data.total);
      })
      .catch((err) => {
        console.error('Error loading Sherlock catalog:', err);
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

    const apiCategory = selectedCategory === 'All' ? 'Todos' : selectedCategory === 'Spain (ES)' ? 'España (ES)' : selectedCategory;
    const cancelFn = startSherlockStream(clean, apiCategory, {
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
        setErrorMessage(err.message || 'Error during SOCMINT reconnaissance');
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

  // Phone lookup
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
      setPhoneError(err.message || 'Error analyzing phone number');
    } finally {
      setPhoneLoading(false);
    }
  };

  // Email lookup
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
      setEmailError(err.message || 'Error analyzing email address');
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
    a.download = `footprint_osint_${activeUsername || 'user'}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const exportToMarkdown = () => {
    let md = `# 🕵️ Digital Footprint Forensic Dossier (SOCMINT)\n\n`;
    md += `**Target (Username / Handle):** \`@${activeUsername}\`\n`;
    md += `**Extraction Timestamp:** ${new Date().toLocaleString()} (UTC)\n`;
    md += `**Platforms Audited:** ${progress.checked} of ${progress.total}\n`;
    md += `**Confirmed Profiles:** ${confirmedProfiles.length}\n`;
    md += `**Category Filter:** ${selectedCategory}\n\n`;
    md += `---\n\n`;
    md += `## 🌐 Verified Digital Profiles\n\n`;
    md += `| Platform | Category | Profile URL | Latency | HTTP Status |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- |\n`;

    confirmedProfiles.forEach((p) => {
      md += `| **${p.site}** | ${p.category} | [${p.url}](${p.url}) | ${p.elapsed_ms}ms | ${p.status_code || 200} |\n`;
    });

    md += `\n---\n*Generated by SniperScope v3.5 // Digital Footprint Intelligence Suite*\n`;

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `footprint_dossier_${activeUsername || 'user'}.md`;
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
            title="Return to Network / IP Scanner (SniperScope)"
            className="flex items-center space-x-1.5 px-2.5 py-1 text-xs font-mono rounded border border-[#1e2638] bg-[#0f172a] text-slate-300 hover:text-sky-400 hover:border-sky-500/50 transition-colors cursor-pointer"
          >
            <ArrowLeft size={14} />
            <span>Back to EASM</span>
          </button>
          <div className="h-4 w-px bg-[#1e2638]" />
          <div className="flex items-center space-x-2">
            <div className="w-6 h-6 rounded bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <UserSearch size={14} />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono font-bold tracking-wider text-sm text-slate-100">
                  DIGITAL FOOTPRINT // OSINT INTELLIGENCE SUITE
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 bg-purple-950/50 text-purple-300 border border-purple-500/30 rounded">
                  {totalCatalogCount > 0 ? `${totalCatalogCount} PLATFORMS` : 'PARALLEL & LOW NOISE'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Export Actions (only on username tab with results) */}
        {osintTab === 'username' && confirmedProfiles.length > 0 && (
          <div className="flex items-center gap-2">
            <button
              onClick={exportToMarkdown}
              className="px-2.5 py-1 rounded bg-[#1e2638] hover:bg-[#28354f] text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-700/50"
              title="Download Markdown Dossier"
            >
              <Download size={13} />
              <span>Dossier (.md)</span>
            </button>
            <button
              onClick={exportToJson}
              className="px-2.5 py-1 rounded bg-[#1e2638] hover:bg-[#28354f] text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer border border-slate-700/50"
              title="Download Raw JSON"
            >
              <Download size={13} />
              <span>JSON</span>
            </button>
          </div>
        )}
      </div>

      {/* 2. Specialized OSINT Tab Navigation */}
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
          <span>Spain OSINT Hub</span>
          <span className="text-[9px] px-1 py-0.2 bg-amber-900/50 text-amber-300 rounded border border-amber-600/40 font-mono">REGISTRIES</span>
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
          <span className="text-[9px] px-1 py-0.2 bg-emerald-900/50 text-emerald-300 rounded border border-emerald-600/40 font-mono">Global Phone</span>
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
          <span className="text-[9px] px-1 py-0.2 bg-sky-900/50 text-sky-300 rounded border border-sky-600/40 font-mono">Email OSINT</span>
        </button>
      </div>

      {/* 3. ACTIVE TAB CONTENT */}

      {/* TAB 1: USERNAME SOCMINT */}
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
                  placeholder="Enter username / alias (e.g. satoshi, elonmusk, torvalds)..."
                  disabled={isScanning}
                  className="w-full pl-8 pr-4 py-2 bg-[#090b10] border border-[#1e2638] focus:border-purple-500 focus:outline-none rounded text-sm text-slate-100 placeholder-slate-500 font-mono transition-colors"
                />
              </div>

              {/* Category selector */}
              <div className="flex items-center gap-2">
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  disabled={isScanning}
                  className="bg-[#090b10] border border-[#1e2638] focus:border-purple-500 text-slate-200 text-xs rounded px-3 py-2 font-mono outline-none cursor-pointer"
                >
                  {categories.map((cat) => (
                    <option key={cat} value={cat}>
                      {cat === 'España (ES)' || cat === 'Spain (ES)' ? '🇪🇸 Spain (ES)' : cat === 'Todos' ? 'All' : cat}
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
                    <span>Stop</span>
                  </button>
                ) : (
                  <button
                    type="submit"
                    disabled={!username.trim()}
                    className="px-5 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:hover:bg-purple-600 text-white rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-all shadow-md shadow-purple-900/30 cursor-pointer"
                  >
                    <Search size={14} />
                    <span>Track</span>
                  </button>
                )}
              </div>
            </form>

            {/* Interactive progress bar */}
            {(isScanning || progress.checked > 0) && (
              <div className="max-w-4xl mx-auto mt-3 pt-3 border-t border-[#1e2638]/70">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1.5">
                  <div className="flex items-center space-x-2">
                    <span className="text-purple-400 font-bold">
                      {isScanning ? 'Scanning in parallel...' : 'Scan completed'}
                    </span>
                    <span>·</span>
                    <span className="text-slate-300">
                      {progress.checked} / {progress.total} platforms
                    </span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="text-emerald-400 font-bold flex items-center space-x-1">
                      <CheckCircle2 size={13} />
                      <span>{progress.found} found</span>
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

          {/* Sherlock Results Area */}
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
                    Confirmed ({confirmedProfiles.length})
                  </button>
                  <button
                    onClick={() => setViewFilter('all')}
                    className={`px-3 py-1 rounded border transition-colors cursor-pointer ${
                      viewFilter === 'all'
                        ? 'bg-purple-950/60 border-purple-500 text-purple-300 font-bold'
                        : 'bg-[#0f172a] border-[#1e2638] text-slate-400 hover:text-white'
                    }`}
                  >
                    All ({results.length})
                  </button>
                </div>

                <div className="relative w-64">
                  <Search size={13} className="absolute left-2.5 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    value={textSearch}
                    onChange={(e) => setTextSearch(e.target.value)}
                    placeholder="Filter by name or category..."
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
                  SYSTEM READY FOR SOCMINT RECONNAISSANCE
                </div>
                <p className="text-xs font-mono text-slate-500 max-w-md mt-1 leading-relaxed">
                  Enter target username to scan in parallel across more than {totalCatalogCount || 100} social networks, Spanish forums, repositories, and gaming platforms.
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
                            {r.found ? 'CONFIRMED' : 'NOT DETECTED'}
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
                            title="Copy profile URL"
                            className="p-1 rounded hover:bg-[#1a2333] text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                          >
                            {isCopied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                          </button>
                          <a
                            href={r.url}
                            target="_blank"
                            rel="noreferrer"
                            title="Open profile in a new tab"
                            className="p-1 rounded bg-[#1a2333] hover:bg-[#25334d] text-sky-400 hover:text-white transition-colors inline-flex items-center space-x-1 text-[11px]"
                          >
                            <span>Open</span>
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

      {/* TAB 2: SPAIN OSINT HUB (OFFICIAL REGISTRIES & GAZETTES) */}
      {osintTab === 'spain' && (
        <div className="flex-1 flex flex-col min-h-0 overflow-y-auto p-4 space-y-5 max-w-5xl mx-auto w-full">
          {/* Header Banner */}
          <div className="bg-gradient-to-r from-amber-950/40 via-[#0d131f] to-amber-950/20 border border-amber-600/40 rounded p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xl">🇪🇸</span>
                <span className="font-mono font-bold text-amber-300 text-sm tracking-wide">
                  OSINT RESEARCH HUB // SPAIN
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-amber-900/60 text-amber-200 rounded border border-amber-500/50">
                  OFFICIAL PUBLIC REGISTRIES
                </span>
              </div>
              <p className="text-xs text-slate-400 font-sans mt-1 max-w-2xl leading-relaxed">
                Investigative tools, public transparency portals, official gazettes, government procurement, CENDOJ judicial rulings, cadastre, and commercial registries in Spain.
              </p>
            </div>
          </div>

          {/* Contextual Spanish Search Bar */}
          <div className="bg-[#0c1017] border border-[#1e2638] rounded p-3 flex flex-col sm:flex-row gap-2 items-center">
            <div className="relative flex-1 w-full">
              <Search size={14} className="absolute left-3 top-3 text-slate-500" />
              <input
                type="text"
                value={spainQuery}
                onChange={(e) => setSpainQuery(e.target.value)}
                placeholder="Enter Full Name, Company Name, Tax ID (DNI/NIE/CIF) or License Plate..."
                className="w-full pl-9 pr-3 py-2 bg-[#090b10] border border-[#1e2638] rounded text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-amber-500"
              />
            </div>
            <span className="text-xs text-slate-500 font-mono hidden sm:inline">
              {spainQuery.trim() ? 'Dynamic query links ready' : 'Type to autocomplete lookup links'}
            </span>
          </div>

          {/* Grid of 4 Forensic Blocks */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Block 1: Official Gazettes & Judiciary */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-amber-300 uppercase">
                <FileText size={15} className="text-amber-400" />
                <span>1. Official Gazettes & Judiciary</span>
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">BOE (State Official Gazette)</span>
                    <span className="text-[10px] text-slate-500">Sanctions, appointments, edicts, public auctions and pardons</span>
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
                    <span>{spainQuery.trim() ? 'Search BOE' : 'Open BOE'}</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">BORME (Commercial Registry Gazette)</span>
                    <span className="text-[10px] text-slate-500">Company incorporations, director appointments and revocations</span>
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
                    <span>{spainQuery.trim() ? 'Search BORME' : 'Open BORME'}</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">CENDOJ (Judicial Power Case Law)</span>
                    <span className="text-[10px] text-slate-500">Official case law repository for Supreme Court and regional courts</span>
                  </div>
                  <a
                    href="https://www.poderjudicial.es/search/indexAN.jsp"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-amber-900/60 text-amber-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>CENDOJ Rulings</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>

            {/* Block 2: Public Procurement & Corporate Networks */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-sky-300 uppercase">
                <Building2 size={15} className="text-sky-400" />
                <span>2. Public Procurement & Corporate Networks</span>
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">PLACSP (State Procurement Platform)</span>
                    <span className="text-[10px] text-slate-500">Public tenders, government vendor awards and contracted amounts</span>
                  </div>
                  <a
                    href="https://contrataciondelestado.es/wps/portal/licitaciones"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-sky-900/60 text-sky-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>PLACSP Tenders</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">Datoscif / Infonif</span>
                    <span className="text-[10px] text-slate-500">Corporate structure, shareholders, CIF and cross-company links</span>
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
                    <span>{spainQuery.trim() ? 'Search CIF' : 'Datoscif'}</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">CNMV (Securities & Fraud Alerts)</span>
                    <span className="text-[10px] text-slate-500">Official registry of investment firms and unauthorized boiler rooms</span>
                  </div>
                  <a
                    href="https://www.cnmv.es/portal/consultas/Busqueda.aspx"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-sky-900/60 text-sky-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>CNMV Registry</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>

            {/* Block 3: Real Estate Cadastre & Vehicles */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-emerald-300 uppercase">
                <MapPin size={15} className="text-emerald-400" />
                <span>3. Real Estate Cadastre & Vehicles</span>
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">Sede Electrónica del Catastro</span>
                    <span className="text-[10px] text-slate-500">Cadastral reference parcel lookup, m², construction year and history</span>
                  </div>
                  <a
                    href="https://www.sedecatastro.gob.es"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-emerald-900/60 text-emerald-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>Cadastre Portal</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">DGT (Vehicle & Environmental Badge)</span>
                    <span className="text-[10px] text-slate-500">Public vehicle inspection and environmental sticker verification</span>
                  </div>
                  <a
                    href="https://sede.dgt.gob.es/es/vehiculos/distintivo-ambiental/"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-emerald-900/60 text-emerald-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>DGT License Plates</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">Colegio de Registradores (Propiedad)</span>
                    <span className="text-[10px] text-slate-500">Official land registry ownership reports and property records</span>
                  </div>
                  <a
                    href="https://geoportal.registradores.org"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-emerald-900/60 text-emerald-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>Property Geoportal</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>

            {/* Block 4: Demographics & Identity */}
            <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-purple-300 uppercase">
                <Globe size={15} className="text-purple-400" />
                <span>4. Demographics, INE & Phone Directories</span>
              </div>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">INE (First & Last Name Distribution)</span>
                    <span className="text-[10px] text-slate-500">Frequency and exact provincial breakdown for any first or last name in Spain</span>
                  </div>
                  <a
                    href="https://www.ine.es/widgets/nombapell/index.shtml"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-purple-900/60 text-purple-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>INE Map</span>
                    <ExternalLink size={10} />
                  </a>
                </div>

                <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded flex items-center justify-between">
                  <div>
                    <span className="text-slate-200 font-bold block">Páginas Blancas / Infobel España</span>
                    <span className="text-[10px] text-slate-500">Residential and business telephone directories across Spain</span>
                  </div>
                  <a
                    href="https://www.paginasamarillas.es"
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1 bg-[#1a2333] hover:bg-purple-900/60 text-purple-300 hover:text-white rounded text-[10px] transition-colors inline-flex items-center space-x-1 shrink-0"
                  >
                    <span>Yellow Pages</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>
          </div>

          {/* Block 5: Specialized Google Dorks (Spain Public Registries) */}
          <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-xs font-mono font-bold text-amber-300 uppercase">
                <Search size={14} className="text-amber-400" />
                <span>Specialized Google Hacking Dorks (Spain Public Registries)</span>
              </div>
              {spainQuery && (
                <span className="text-[11px] font-mono text-slate-400">
                  Target: <strong className="text-amber-300">{spainQuery}</strong>
                </span>
              )}
            </div>

            {(() => {
              const q = spainQuery.trim() || 'TARGET_NAME_OR_COMPANY';
              const dorks = [
                {
                  title: 'BOE Appearances & Official Resolutions',
                  dork: `site:boe.es "${q}"`,
                },
                {
                  title: 'Public Contracts & State Awards',
                  dork: `site:contrataciondelestado.es "${q}"`,
                },
                {
                  title: 'National Subsidies Database (Treasury)',
                  dork: `site:pap.hacienda.gob.es/bdnstrans/ "${q}"`,
                },
                {
                  title: 'Transparency Portal & Public Disclosures',
                  dork: `site:transparencia.gob.es filetype:pdf "${q}"`,
                },
                {
                  title: 'Spanish Forums & Communities (Forocoches / Burbuja)',
                  dork: `site:forocoches.com OR site:burbuja.info "${q}"`,
                },
                {
                  title: 'Official Administrative Documents (PDF)',
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
                          title="Copy Dork"
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
                          <span>Launch</span>
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

      {/* TAB 3: PHONE HUNTER */}
      {osintTab === 'phone' && (
        <div className="flex-1 flex flex-col min-h-0 overflow-y-auto p-4 space-y-4 max-w-4xl mx-auto w-full">
          {/* Phone Search Form */}
          <div className="bg-[#0c1017] border border-[#1e2638] rounded p-4">
            <div className="flex items-center space-x-2 text-xs font-mono font-bold text-emerald-400 uppercase mb-2">
              <Phone size={15} />
              <span>Intelligence Phone Recon</span>
            </div>
            <form onSubmit={handlePhoneSearch} className="flex gap-2 items-center">
              <input
                type="text"
                value={phoneQuery}
                onChange={(e) => setPhoneQuery(e.target.value)}
                placeholder="Enter phone number (e.g. +34 612 34 56 78 or +1 415 555 2671)..."
                disabled={phoneLoading}
                className="flex-1 px-3 py-2 bg-[#090b10] border border-[#1e2638] rounded text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <button
                type="submit"
                disabled={phoneLoading || !phoneQuery.trim()}
                className="px-5 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors cursor-pointer shrink-0"
              >
                {phoneLoading ? <RefreshCw size={13} className="animate-spin" /> : <Search size={13} />}
                <span>{phoneLoading ? 'Analyzing...' : 'Audit Phone'}</span>
              </button>
            </form>
          </div>

          {phoneError && (
            <div className="p-3 bg-red-950/40 border border-red-800 rounded text-red-300 text-xs font-mono flex items-center space-x-2">
              <AlertTriangle size={14} />
              <span>{phoneError}</span>
            </div>
          )}

          {/* Phone Results */}
          {phoneData && (
            <div className="space-y-4">
              {/* Technical E.164 Specification Card */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#1e2638] pb-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xl">{phoneData.flag || '📞'}</span>
                    <div>
                      <span className="font-mono font-bold text-slate-100 text-base">{phoneData.e164_format}</span>
                      <span className="text-[11px] font-mono text-slate-400 ml-2">
                        {phoneData.country} ({phoneData.national_format})
                      </span>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 text-[10px] font-mono font-bold rounded">
                    {phoneData.line_type}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 text-xs font-mono">
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">País y Prefijo:</span>
                    <span className="text-slate-200 font-bold">{phoneData.country} ({phoneData.dial_code})</span>
                  </div>
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Operador Asignado:</span>
                    <span className="text-emerald-400 font-bold truncate block" title={phoneData.carrier}>
                      {phoneData.carrier}
                    </span>
                  </div>
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Red ITU-T (MCC / MNC):</span>
                    <span className="text-purple-400 font-bold">
                      {phoneData.network_codes?.mcc ? `MCC ${phoneData.network_codes.mcc} · MNC ${phoneData.network_codes.mnc}` : 'No disponible'}
                    </span>
                  </div>
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Zona Horaria:</span>
                    <span className="text-slate-200 font-bold">
                      {phoneData.timezones?.join(', ') || 'UTC'}
                    </span>
                  </div>
                </div>

                {/* Direct Messaging Actions */}
                <div className="pt-2 border-t border-[#1e2638] flex flex-wrap gap-2">
                  <a
                    href={phoneData.direct_messaging.whatsapp_url}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 bg-[#064e3b] hover:bg-[#047857] text-[#a7f3d0] border border-[#10b981]/50 rounded text-xs font-mono font-bold inline-flex items-center space-x-1.5 transition-colors cursor-pointer"
                  >
                    <span>💬 Chat WhatsApp Web (Directo)</span>
                    <ExternalLink size={11} />
                  </a>
                  <a
                    href={phoneData.direct_messaging.telegram_url}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 bg-[#0f2438] hover:bg-[#15344f] text-[#38bdf8] border border-[#0284c7]/50 rounded text-xs font-mono font-bold inline-flex items-center space-x-1.5 transition-colors cursor-pointer"
                  >
                    <span>✈️ Abrir Telegram</span>
                    <ExternalLink size={11} />
                  </a>
                </div>
              </div>

              {/* Live Spam Reputation & Complaints Card */}
              {phoneData.reputation && (
                <div className={`p-4 rounded border text-xs font-mono space-y-2 ${
                  phoneData.reputation.risk_level === 'CRITICAL'
                    ? 'bg-red-950/20 border-red-500/40'
                    : phoneData.reputation.risk_level === 'MEDIUM'
                    ? 'bg-amber-950/20 border-amber-500/40'
                    : 'bg-[#0d1119] border-[#1e2638]'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm">🛡️</span>
                      <span className="font-bold uppercase tracking-wider text-slate-200">
                        Reputación y Denuncias de Spam Telefónico
                      </span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      phoneData.reputation.risk_level === 'CRITICAL'
                        ? 'bg-red-950 text-red-300 border-red-700'
                        : phoneData.reputation.risk_level === 'MEDIUM'
                        ? 'bg-amber-950 text-amber-300 border-amber-700'
                        : 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    }`}>
                      {phoneData.reputation.status}
                    </span>
                  </div>

                  <p className="text-[11px] text-slate-300 font-sans leading-relaxed pt-1">
                    {phoneData.reputation.detail}
                  </p>

                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] text-slate-400">
                    <span className="inline-flex items-center space-x-1">
                      <span className="text-slate-500">Puntuación:</span>
                      <span className="text-slate-200 font-bold">{phoneData.reputation.score_label}</span>
                    </span>
                    {phoneData.reputation.searches && phoneData.reputation.searches !== '0' && (
                      <span className="inline-flex items-center space-x-1">
                        <span className="text-slate-500">Búsquedas registradas:</span>
                        <span className="text-sky-400 font-bold">{phoneData.reputation.searches}</span>
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Phone Data Breaches (LeakCheck) */}
              {phoneData.breaches && (
                <div className={`p-4 rounded border text-xs font-mono space-y-2.5 ${
                  phoneData.breaches.exposed
                    ? 'bg-red-950/20 border-red-500/40'
                    : 'bg-[#0d1119] border-[#1e2638]'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <AlertTriangle size={14} className={phoneData.breaches.exposed ? 'text-red-400' : 'text-emerald-400'} />
                      <span className="font-bold uppercase tracking-wider text-slate-200">
                        Auditoría de Filtraciones del Número Telefónico
                      </span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      phoneData.breaches.exposed
                        ? 'bg-red-950 text-red-300 border-red-700'
                        : 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    }`}>
                      {phoneData.breaches.status_label}
                    </span>
                  </div>

                  {phoneData.breaches.exposed ? (
                    <div className="space-y-2 pt-1">
                      {phoneData.breaches.fields?.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] text-slate-500 font-sans">Datos expuestos:</span>
                          {phoneData.breaches.fields.map((fld, fIdx) => (
                            <span
                              key={fIdx}
                              className="px-1.5 py-0.2 rounded bg-[#161d2b] border border-amber-500/40 text-amber-300 text-[10px] uppercase font-bold"
                            >
                              {fld}
                            </span>
                          ))}
                        </div>
                      )}
                      {phoneData.breaches.sources?.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-0.5">
                          {phoneData.breaches.sources.map((src, sIdx) => (
                            <span
                              key={sIdx}
                              className="px-2 py-0.5 rounded bg-[#10141d] border border-red-900/50 text-red-300 text-[10px]"
                            >
                              {src}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-[11px] text-slate-400 font-sans">
                      No constan apariciones de este número de teléfono en las bases de datos de credenciales filtradas.
                    </p>
                  )}
                </div>
              )}

              {/* Quick Verification Checks */}
              {phoneData.quick_checks && (
                <div className="bg-[#0d1119] border border-[#1e2638] rounded p-3 text-xs font-mono">
                  <span className="text-slate-500 block text-[10px] uppercase font-bold mb-2">
                    Consultas Externas de Identidad:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {phoneData.quick_checks.map((check, cIdx) => (
                      <a
                        key={cIdx}
                        href={check.url}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2.5 py-1 bg-[#151c28] hover:bg-[#1e2638] text-slate-300 hover:text-white border border-[#1e2638] rounded text-[11px] inline-flex items-center space-x-1.5 transition-colors cursor-pointer"
                      >
                        <span>{check.name}</span>
                        <ExternalLink size={10} className="text-slate-500" />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: EMAIL HUNTER */}
      {osintTab === 'email' && (
        <div className="flex-1 flex flex-col min-h-0 overflow-y-auto p-4 space-y-4 max-w-4xl mx-auto w-full">
          {/* Email Search Form */}
          <div className="bg-[#0c1017] border border-[#1e2638] rounded p-4">
            <div className="flex items-center space-x-2 text-xs font-mono font-bold text-sky-400 uppercase mb-2">
              <Mail size={15} />
              <span>Forensic Email Recon</span>
            </div>
            <form onSubmit={handleEmailSearch} className="flex gap-2 items-center">
              <input
                type="email"
                value={emailQuery}
                onChange={(e) => setEmailQuery(e.target.value)}
                placeholder="Enter email address (e.g. target@company.com)..."
                disabled={emailLoading}
                className="flex-1 px-3 py-2 bg-[#090b10] border border-[#1e2638] rounded text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
              <button
                type="submit"
                disabled={emailLoading || !emailQuery.trim()}
                className="px-5 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors cursor-pointer shrink-0"
              >
                {emailLoading ? <RefreshCw size={13} className="animate-spin" /> : <Search size={13} />}
                <span>{emailLoading ? 'Verifying...' : 'Audit Email'}</span>
              </button>
            </form>
          </div>

          {emailError && (
            <div className="p-3 bg-red-950/40 border border-red-800 rounded text-red-300 text-xs font-mono flex items-center space-x-2">
              <AlertTriangle size={14} />
              <span>{emailError}</span>
            </div>
          )}

          {/* Email Results */}
          {emailData && (
            <div className="space-y-4">
              {/* Summary & Domain Verification Card */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-[#1e2638] pb-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xl">📧</span>
                    <div>
                      <span className="font-mono font-bold text-slate-100 text-base">{emailData.email}</span>
                      <span className="text-[11px] font-mono text-slate-400 ml-2">(@{emailData.domain})</span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    {emailData.is_disposable ? (
                      <span className="px-2 py-0.5 bg-red-950 text-red-300 border border-red-700 text-[10px] font-mono font-bold rounded flex items-center space-x-1">
                        <AlertTriangle size={10} />
                        <span>CORREO TEMPORAL / DESECHABLE</span>
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 bg-sky-950 text-sky-300 border border-sky-700/60 text-[10px] font-mono font-bold rounded">
                        {emailData.provider || 'DOMINIO ESTÁNDAR'}
                      </span>
                    )}
                  </div>
                </div>

                {/* Email Verification, Domain Age & DNS Parameters */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 text-xs font-mono">
                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Verificación de Buzón (SMTP):</span>
                    <span className={`font-bold block truncate ${
                      emailData.mailbox?.status === 'DELIVERABLE'
                        ? 'text-emerald-400'
                        : emailData.mailbox?.status === 'CATCH_ALL'
                        ? 'text-sky-400'
                        : emailData.mailbox?.status === 'UNDELIVERABLE'
                        ? 'text-red-400'
                        : 'text-amber-400'
                    }`} title={emailData.mailbox?.label}>
                      {emailData.mailbox?.label || 'No verificado'}
                    </span>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Antigüedad del Dominio:</span>
                    <span className={`font-bold block truncate ${
                      emailData.domain_age?.risk_level === 'CRITICAL'
                        ? 'text-red-400 font-extrabold'
                        : emailData.domain_age?.risk_level === 'MEDIUM'
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`} title={emailData.domain_age?.age_label}>
                      {emailData.domain_age?.age_label || 'No disponible'}
                    </span>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Seguridad SPF:</span>
                    <span className={emailData.dns.has_spf ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
                      {emailData.dns.has_spf ? 'Configurado' : 'No configurado'}
                    </span>
                  </div>

                  <div className="p-2.5 bg-[#090b10] border border-[#1e2638] rounded">
                    <span className="text-slate-500 block text-[10px]">Política DMARC:</span>
                    <span className="text-purple-400 font-bold uppercase">
                      {emailData.dns.dmarc_policy ? `p=${emailData.dns.dmarc_policy}` : 'Sin DMARC'}
                    </span>
                  </div>
                </div>

                {/* Phishing Warning Banner */}
                {emailData.domain_age?.phishing_warning && (
                  <div className="p-2.5 rounded bg-red-950/40 border border-red-500/50 text-red-300 text-xs font-mono flex items-center space-x-2">
                    <AlertTriangle size={14} className="text-red-400 shrink-0" />
                    <span>{emailData.domain_age.phishing_warning}</span>
                  </div>
                )}
              </div>

              {/* Registered Accounts in Live Services (Holehe-style) */}
              <div className="bg-[#0d1119] border border-[#1e2638] rounded p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-xs font-mono font-bold text-sky-400 uppercase">
                    <CheckCircle2 size={14} className="text-emerald-400" />
                    <span>Cuentas Registradas en Plataformas ({emailData.registered_platforms?.length || 0})</span>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono">Reconocimiento Anónimo en Vivo</span>
                </div>

                {emailData.registered_platforms && emailData.registered_platforms.length > 0 ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5 pt-1">
                    {emailData.registered_platforms.map((plat, pIdx) => (
                      <div
                        key={pIdx}
                        className="p-3 bg-[#090b10] border border-[#1e2638] rounded flex items-center space-x-3"
                      >
                        {plat.avatar_url ? (
                          <img
                            src={plat.avatar_url}
                            alt={plat.platform}
                            className="w-10 h-10 rounded-full border border-sky-500/40 object-cover shrink-0"
                          />
                        ) : (
                          <div className="w-10 h-10 rounded-full bg-[#151c28] border border-[#1e2638] flex items-center justify-center text-xs font-bold text-sky-400 shrink-0">
                            {plat.platform.charAt(0)}
                          </div>
                        )}
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-200 font-bold text-xs font-mono">{plat.platform}</span>
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono font-bold">
                              REGISTRADO
                            </span>
                          </div>
                          {plat.username && (
                            <span className="text-[11px] text-sky-400 font-mono truncate block">
                              @{plat.username}
                            </span>
                          )}
                          {plat.name && plat.name !== plat.username && (
                            <span className="text-[10px] text-slate-400 truncate block">
                              {plat.name}
                            </span>
                          )}
                          {plat.details && (
                            <span className="text-[10px] text-slate-500 truncate block">
                              {plat.details}
                            </span>
                          )}
                          {plat.profile_url && (
                            <a
                              href={plat.profile_url}
                              target="_blank"
                              rel="noreferrer"
                              className="text-[10px] text-slate-400 hover:text-white inline-flex items-center space-x-1 mt-1 transition-colors"
                            >
                              <span>Ver Perfil</span>
                              <ExternalLink size={8} />
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 bg-[#090b10] border border-[#1e2638] rounded text-slate-500 text-xs font-mono">
                    No se detectaron perfiles públicos activos en las plataformas auditadas (GitHub, Duolingo, WordPress, Gravatar, Archive.org).
                  </div>
                )}
              </div>

              {/* Data Breaches & Leaks (XposedOrNot) */}
              {emailData.breaches && (
                <div className={`p-4 rounded border text-xs font-mono space-y-2.5 ${
                  emailData.breaches.exposed
                    ? 'bg-red-950/20 border-red-500/40'
                    : 'bg-[#0d1119] border-[#1e2638]'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <AlertTriangle size={14} className={emailData.breaches.exposed ? 'text-red-400' : 'text-emerald-400'} />
                      <span className="font-bold uppercase tracking-wider text-slate-200">
                        Auditoría de Brechas y Filtraciones Masivas
                      </span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      emailData.breaches.exposed
                        ? 'bg-red-950 text-red-300 border-red-700'
                        : 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    }`}>
                      {emailData.breaches.status_label}
                    </span>
                  </div>

                  {emailData.breaches.exposed && emailData.breaches.breaches?.length > 0 && (
                    <div className="space-y-1.5 pt-1">
                      <span className="text-[11px] text-slate-400 block font-sans">
                        Filtraciones documentadas en las que ha aparecido esta dirección:
                      </span>
                      <div className="flex flex-wrap gap-1.5 max-h-36 overflow-y-auto pt-0.5">
                        {emailData.breaches.breaches.map((bName, bIdx) => (
                          <span
                            key={bIdx}
                            className="px-2 py-0.5 rounded bg-[#10141d] border border-red-900/50 text-red-300 text-[10px] font-mono"
                          >
                            {bName}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {!emailData.breaches.exposed && (
                    <p className="text-[11px] text-slate-400 font-sans">
                      No constan apariciones de este correo electrónico en las bases de datos públicas de credenciales comprometidas.
                    </p>
                  )}
                </div>
              )}

              {/* Quick Verification Actions */}
              {emailData.quick_links && (
                <div className="bg-[#0d1119] border border-[#1e2638] rounded p-3 text-xs font-mono">
                  <span className="text-slate-500 block text-[10px] uppercase font-bold mb-2">
                    Pivotaje Externo de Identidad:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {emailData.quick_links.map((link, qIdx) => (
                      <a
                        key={qIdx}
                        href={link.url}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2.5 py-1 bg-[#151c28] hover:bg-[#1e2638] text-slate-300 hover:text-white border border-[#1e2638] rounded text-[11px] inline-flex items-center space-x-1.5 transition-colors cursor-pointer"
                      >
                        <span>{link.name}</span>
                        <ExternalLink size={10} className="text-slate-500" />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
