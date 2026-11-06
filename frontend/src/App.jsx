import React, { useState, useEffect } from 'react';
import { Crosshair, AlertCircle, Columns, FileText, Network, Download, LogOut, UserSearch } from 'lucide-react';
import TargetInput from './components/TargetInput';
import GraphCanvas from './components/GraphCanvas';
import IntelDossier from './components/IntelDossier';
import NodeDetails from './components/NodeDetails';
import ForensicReportModal from './components/ForensicReportModal';
import LoginScreen from './components/LoginScreen';
import SherlockView from './components/SherlockView';
import { fetchScan, checkShodanStatus, verifyAuthSession, clearAuthToken } from './services/api';

const RECENT_SCANS_KEY = 'sniperscope_sessions_cache_v3';
const LEGACY_SCANS_KEY = 'sniperscope_recent_scans';

function isValidCachedSession(item) {
  return Boolean(
    item &&
      typeof item === 'object' &&
      typeof item.target === 'string' &&
      item.summary &&
      item.risk &&
      item.graph
  );
}

export default function App() {
  const [authState, setAuthState] = useState({
    checking: true,
    authenticated: false,
    username: '',
  });
  const [scanData, setScanData] = useState(null);
  const [activeTarget, setActiveTarget] = useState('');
  const [scanMode, setScanMode] = useState('passive');
  const [selectedNode, setSelectedNode] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const [shodanInfo, setShodanInfo] = useState(null);
  // activeModule: 'easm' (Infraestructura / Red / IP) | 'sherlock' (Identidad / SOCMINT)
  const [activeModule, setActiveModule] = useState(() => {
    try {
      return typeof window !== 'undefined' && window.location.pathname.startsWith('/sherlock')
        ? 'sherlock'
        : 'easm';
    } catch {
      return 'easm';
    }
  });
  // viewMode: 'split' (Texto izq + Grafo der) | 'text' (Solo Texto) | 'graph' (Solo Grafo)
  const [viewMode, setViewMode] = useState('split');
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [recentScans, setRecentScans] = useState(() => {
    try {
      localStorage.removeItem(LEGACY_SCANS_KEY);
      const raw = localStorage.getItem(RECENT_SCANS_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter(isValidCachedSession) : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    verifyAuthSession().then((res) => {
      if (res.authenticated) {
        setAuthState({
          checking: false,
          authenticated: true,
          username: res.username || 'sniperadmin',
        });
        checkShodanStatus().then((status) => setShodanInfo(status));
      } else {
        setAuthState({ checking: false, authenticated: false, username: '' });
      }
    });
  }, []);

  useEffect(() => {
    const handlePopState = () => {
      const isSherlock = window.location.pathname.startsWith('/sherlock');
      setActiveModule(isSherlock ? 'sherlock' : 'easm');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const handleSwitchModule = (moduleName) => {
    setActiveModule(moduleName);
    try {
      const targetPath = moduleName === 'sherlock' ? '/sherlock' : '/';
      if (window.location.pathname !== targetPath) {
        window.history.pushState({}, '', targetPath);
      }
    } catch {
      // Ignore
    }
  };

  const handleLoginSuccess = (loginData) => {
    setAuthState({
      checking: false,
      authenticated: true,
      username: loginData.username || 'sniperadmin',
    });
    checkShodanStatus().then((status) => setShodanInfo(status));
  };

  const handleLogout = () => {
    clearAuthToken();
    setAuthState({ checking: false, authenticated: false, username: '' });
    setScanData(null);
    setSelectedNode(null);
    setErrorMessage(null);
  };

  const saveRecentScan = (data) => {
    if (!isValidCachedSession(data)) return;
    setRecentScans((prev) => {
      const filtered = prev.filter((item) => item.target !== data.target);
      const updated = [data, ...filtered].slice(0, 8);
      try {
        localStorage.setItem(RECENT_SCANS_KEY, JSON.stringify(updated));
      } catch {
        try {
          localStorage.setItem(RECENT_SCANS_KEY, JSON.stringify(updated.slice(0, 3)));
        } catch {
          // Mantener en memoria
        }
      }
      return updated;
    });
  };

  const handleClearRecent = () => {
    setRecentScans([]);
    try {
      localStorage.removeItem(RECENT_SCANS_KEY);
    } catch {
      // Ignore
    }
  };

  const handleGoHome = () => {
    handleSwitchModule('easm');
    setScanData(null);
    setSelectedNode(null);
    setErrorMessage(null);
    setActiveTarget('');
    setIsReportModalOpen(false);
  };

  const handleSelectRecent = (sessionItem) => {
    setErrorMessage(null);
    setSelectedNode(null);

    if (isValidCachedSession(sessionItem)) {
      setScanData(sessionItem);
      setActiveTarget(sessionItem.target);
      if (sessionItem.scan_mode) {
        setScanMode(sessionItem.scan_mode);
      }
      return;
    }

    const targetName = typeof sessionItem === 'string' ? sessionItem : sessionItem?.target;
    const cachedMatch = recentScans.find(
      (item) => item.target === targetName && isValidCachedSession(item)
    );

    if (cachedMatch) {
      setScanData(cachedMatch);
      setActiveTarget(cachedMatch.target);
    } else {
      setErrorMessage(
        `La sesión "${targetName || 'seleccionada'}" ya no dispone de datos completos en caché. Introdúcela en el buscador superior si deseas ejecutar una nueva consulta.`
      );
    }
  };

  const handleScan = async (target, refresh = false) => {
    const cleanTarget = typeof target === 'string' ? target.trim() : String(target?.target || '').trim();
    if (!cleanTarget) return;

    setIsLoading(true);
    setErrorMessage(null);
    setSelectedNode(null);
    setActiveTarget(cleanTarget);

    try {
      const data = await fetchScan(cleanTarget, refresh, scanMode);
      setScanData(data);
      setActiveTarget(data.target || cleanTarget);
      saveRecentScan(data);
    } catch (err) {
      if (err.status === 401) {
        handleLogout();
        return;
      }
      setErrorMessage(err.message || 'Error al ejecutar el reconocimiento');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectNode = (node) => {
    setSelectedNode(node);
  };

  const handleFocusNodeInGraph = (nodeId) => {
    if (scanData?.graph?.nodes) {
      const found = scanData.graph.nodes.find((n) => n.data.id === nodeId);
      if (found) {
        setSelectedNode(found.data);
        if (viewMode === 'text') {
          setViewMode('split');
        }
      }
    }
  };

  if (authState.checking) {
    return (
      <div className="h-screen w-screen bg-[#090b10] flex items-center justify-center font-mono text-xs text-slate-400">
        Verificando sesión de operador SniperScope...
      </div>
    );
  }

  if (!authState.authenticated) {
    return <LoginScreen onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="flex flex-col h-screen w-screen bg-[#090b10] text-slate-100 font-sans overflow-hidden">
      {/* 1. Header Superior Técnico (Shell) */}
      <header className="min-h-14 py-2 border-b border-[#1e2638] bg-[#0c1017] px-4 flex flex-wrap items-center justify-between gap-3 shrink-0">
        {/* Bloque de Marca e Icono (Clicable para volver a Inicio) */}
        <button
          type="button"
          onClick={handleGoHome}
          title="Return to SniperScope Home Dashboard"
          className="flex items-center space-x-3 text-left group cursor-pointer focus:outline-none"
        >
          <div className="w-7 h-7 bg-[#0f172a] border border-[#38bdf8]/40 group-hover:border-[#38bdf8] group-hover:bg-[#38bdf8]/10 rounded flex items-center justify-center text-[#38bdf8] transition-colors">
            <Crosshair size={16} />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-mono font-bold tracking-wider text-sm text-slate-100 group-hover:text-[#38bdf8] transition-colors">
                SNIPERSCOPE
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-[#1e2638] text-slate-300 rounded">
                EASM // FORENSIC OSINT
              </span>
            </div>
            <div className="text-[10px] font-mono text-slate-500">
              Attack Surface Intelligence, Shodan CVEDB & Vulnerability Assessment
            </div>
          </div>
        </button>

        {/* View Mode Switcher + Export Report + Shodan Status + Logout */}
        <div className="flex items-center gap-2 text-xs font-mono">
          {/* Direct Access to Digital Footprint SOCMINT */}
          <button
            type="button"
            onClick={() => handleSwitchModule(activeModule === 'sherlock' ? 'easm' : 'sherlock')}
            title={
              activeModule === 'sherlock'
                ? 'Back to Infrastructure & Network Scanner (EASM)'
                : 'Digital Footprint // Identity & Account Reconnaissance (SOCMINT)'
            }
            aria-label="Digital Footprint Reconnaissance"
            className={`p-2 rounded flex items-center justify-center transition-all cursor-pointer border ${
              activeModule === 'sherlock'
                ? 'bg-purple-950/80 border-purple-500 text-purple-300 shadow-md shadow-purple-900/40 ring-1 ring-purple-500/50'
                : 'bg-[#090b10] border-[#1e2638] text-slate-400 hover:text-purple-400 hover:border-purple-500/40'
            }`}
          >
            <UserSearch size={16} />
          </button>

          {/* View Mode Selector */}
          <div className="flex items-center bg-[#090b10] border border-[#1e2638] p-0.5 rounded">
            <button
              onClick={() => setViewMode('split')}
              className={`p-1.5 rounded flex items-center justify-center transition-colors cursor-pointer ${
                viewMode === 'split'
                  ? 'bg-[#1e2638] text-[#38bdf8]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Split View (Dossier + Topology Graph)"
              aria-label="Split View"
            >
              <Columns size={16} />
            </button>
            <button
              onClick={() => setViewMode('text')}
              className={`p-1.5 rounded flex items-center justify-center transition-colors cursor-pointer ${
                viewMode === 'text'
                  ? 'bg-[#1e2638] text-[#38bdf8]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Text Dossier Only"
              aria-label="Text Only"
            >
              <FileText size={16} />
            </button>
            <button
              onClick={() => setViewMode('graph')}
              className={`p-1.5 rounded flex items-center justify-center transition-colors cursor-pointer ${
                viewMode === 'graph'
                  ? 'bg-[#1e2638] text-[#38bdf8]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="Interactive Relationship Graph Only"
              aria-label="Graph Only"
            >
              <Network size={16} />
            </button>
          </div>

          {/* Export Report Button */}
          <button
            onClick={() => setIsReportModalOpen(true)}
            disabled={!scanData}
            title="Export Professional Forensic Security Report"
            aria-label="Export Forensic Report"
            className="p-2 bg-[#0284c7] hover:bg-[#0369a1] disabled:opacity-40 disabled:pointer-events-none text-white rounded flex items-center justify-center transition-colors cursor-pointer"
          >
            <Download size={16} />
          </button>

          {/* Shodan & Proxy Status */}
          {shodanInfo && (
            <div className="hidden sm:flex items-center space-x-2 bg-[#090b10] border border-[#1e2638] px-2.5 py-1.5 rounded">
              <span className={`w-2 h-2 rounded-full ${shodanInfo.configured ? 'bg-[#10b981]' : 'bg-[#eab308]'}`} />
              <span className="text-slate-400">Shodan:</span>
              <span className="text-slate-200 font-semibold uppercase">{shodanInfo.plan || 'Active'}</span>
              {shodanInfo.proxy_configured && (
                <span
                  title={
                    shodanInfo.proxy_active
                      ? 'Cloudflare WARP tunnel activo en 127.0.0.1:40000'
                      : 'Cloudflare WARP desconectado · Conexión directa a internet sin proxy'
                  }
                  className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                    shodanInfo.proxy_active
                      ? 'bg-[#064e3b] text-[#a7f3d0] border-[#10b981]/50'
                      : 'bg-[#141a24] text-slate-400 border-[#1e2638]'
                  }`}
                >
                  {shodanInfo.proxy_active ? 'WARP: ON' : 'WARP: OFF'}
                </span>
              )}
            </div>
          )}

          {/* Lock Workstation / Logout Button */}
          <button
            onClick={handleLogout}
            title={`Lock Workstation (${authState.username})`}
            aria-label="Lock Workstation"
            className="p-2 bg-[#151c28] hover:bg-[#2a1317] text-slate-400 hover:text-[#f87171] border border-[#1e2638] rounded flex items-center justify-center transition-colors cursor-pointer"
          >
            <LogOut size={15} />
          </button>
        </div>
      </header>

      {activeModule === 'sherlock' ? (
        <div className="flex-1 min-h-0 overflow-hidden">
          <SherlockView onBackToEasm={() => handleSwitchModule('easm')} />
        </div>
      ) : (
        <>
          {/* 2. Barra de Búsqueda y Selector de Modo OPSEC */}
          <div className="px-4 py-1 border-b border-[#1e2638] bg-[#090b10] shrink-0">
            <TargetInput
              onScan={(t, forceRefresh = true) => handleScan(t, forceRefresh)}
              isLoading={isLoading}
              activeTarget={activeTarget}
              scanMode={scanMode}
              onChangeScanMode={setScanMode}
            />
          </div>

          {/* Alerta de Error */}
          {errorMessage && (
            <div className="px-4 py-2 bg-[#2a1317] border-b border-[#7f1d1d] text-[#f87171] text-xs font-mono flex items-center space-x-2 shrink-0">
              <AlertCircle size={14} />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* 3. Área de Trabajo Principal según viewMode */}
          <main className="relative flex-1 flex flex-col lg:flex-row min-h-0 overflow-hidden">
            {/* Overlay Animado de Escaneo Activo durante la búsqueda */}
            {isLoading && (
              <div className="absolute inset-0 z-30 bg-[#07090e]/85 backdrop-blur-sm flex flex-col items-center justify-center p-6 text-center select-none">
                <div className="relative flex items-center justify-center mb-4">
                  <div className="w-16 h-16 rounded-full border border-[#38bdf8]/30 animate-ping absolute" />
                  <div className="w-14 h-14 rounded-full border border-[#38bdf8]/60 flex items-center justify-center bg-[#0d1527] shadow-[0_0_20px_rgba(56,189,248,0.25)]">
                    <Crosshair size={26} className="text-[#38bdf8] animate-spin [animation-duration:4s]" />
                  </div>
                </div>
                <div className="font-mono text-sm font-bold text-white tracking-wide">
                  EXECUTING PARALLEL RECONNAISSANCE PIPELINE
                </div>
                <div className="font-mono text-xs text-[#38bdf8] mt-1">
                  Target: <span className="text-white font-semibold">{activeTarget}</span>
                </div>
                <div className="flex flex-wrap items-center justify-center gap-2 mt-4 text-[10px] font-mono text-slate-400">
                  <span className="px-2 py-0.5 rounded bg-[#101929] border border-[#1e2638] animate-pulse">
                    DNS & CAA
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#101929] border border-[#1e2638] animate-pulse [animation-delay:150ms]">
                    Certificate Transparency
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#101929] border border-[#1e2638] animate-pulse [animation-delay:300ms]">
                    Shodan & CVEDB
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#101929] border border-[#1e2638] animate-pulse [animation-delay:450ms]">
                    TLS X.509 & Web Tech
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#101929] border border-[#1e2638] animate-pulse [animation-delay:600ms]">
                    RDAP & ASN
                  </span>
                </div>
              </div>
            )}

            {/* COLUMNA IZQUIERDA: DOSSIER DE INFORMACIÓN EN TEXTO */}
            {(viewMode === 'split' || viewMode === 'text') && (
              <div
                className={`h-full min-h-0 overflow-hidden ${
                  viewMode === 'split'
                    ? 'w-full lg:w-[55%] xl:w-[57%] border-b lg:border-b-0 lg:border-r border-[#1e2638]'
                    : 'w-full'
                }`}
              >
                <IntelDossier
                  scanData={scanData}
                  onFocusNode={handleFocusNodeInGraph}
                  onOpenReport={() => setIsReportModalOpen(true)}
                  recentScans={recentScans}
                  onSelectRecent={handleSelectRecent}
                  onClearRecent={handleClearRecent}
                  onRefreshScan={(t) => handleScan(t, true)}
                />
              </div>
            )}

            {/* COLUMNA DERECHA: GRAFO DE RELACIONES INTERACTIVO */}
            {(viewMode === 'split' || viewMode === 'graph') && (
              <div
                className={`h-full min-h-0 relative overflow-hidden ${
                  viewMode === 'split' ? 'w-full lg:w-[45%] xl:w-[43%]' : 'w-full'
                }`}
              >
                <GraphCanvas
                  graphData={scanData?.graph}
                  onSelectNode={handleSelectNode}
                  selectedNodeId={selectedNode?.id}
                />

                {/* Tarjeta flotante de inspección cuando se selecciona un nodo en el grafo */}
                {selectedNode && (
                  <div className="absolute top-3 right-3 z-20 w-80 sm:w-96 max-w-[calc(100%-1.5rem)]">
                    <NodeDetails
                      selectedNode={selectedNode}
                      onClose={() => setSelectedNode(null)}
                    />
                  </div>
                )}
              </div>
            )}
          </main>

          {/* Modal de Exportación de Informe Forense */}
          <ForensicReportModal
            isOpen={isReportModalOpen}
            onClose={() => setIsReportModalOpen(false)}
            scanData={scanData}
          />
        </>
      )}
    </div>
  );
}
