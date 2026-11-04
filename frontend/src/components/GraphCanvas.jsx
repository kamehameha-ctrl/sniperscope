import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import { ZoomIn, ZoomOut, Maximize2, RotateCcw, Share2, CircleDot, Network } from 'lucide-react';

export default function GraphCanvas({ graphData, onSelectNode, selectedNodeId }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [layoutMode, setLayoutMode] = useState('cose'); // 'cose', 'concentric', 'breadthfirst'

  const getLayoutConfig = (mode) => {
    switch (mode) {
      case 'concentric':
        return {
          name: 'concentric',
          animate: true,
          animationDuration: 500,
          concentric: (node) => {
            const type = node.data('type');
            if (type === 'target') return 4;
            if (type === 'ip') return 3;
            if (type === 'subdomain') return 2;
            if (type === 'port') return 1;
            return 0;
          },
          levelWidth: () => 1,
          padding: 50,
          spacingFactor: 1.5,
          minNodeSpacing: 60,
        };
      case 'breadthfirst':
        return {
          name: 'breadthfirst',
          animate: true,
          animationDuration: 500,
          directed: true,
          padding: 50,
          spacingFactor: 1.4,
          roots: '[type = "target"]',
        };
      case 'cose':
      default:
        return {
          name: 'cose',
          animate: true,
          animationDuration: 600,
          nodeRepulsion: 45000,
          idealEdgeLength: 140,
          gravity: 0.08,
          nodeOverlap: 30,
          nestingFactor: 1.2,
          numIter: 1000,
          coolingFactor: 0.95,
          padding: 50,
        };
    }
  };

  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      style: [
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': '#2a354f',
            'curve-style': 'bezier',
            'opacity': 0.7,
            'target-arrow-shape': 'none',
          }
        },
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#cbd5e1',
            'font-size': '11px',
            'font-family': 'ui-monospace, monospace',
            'text-valign': 'bottom',
            'text-margin-y': 7,
            'text-wrap': 'wrap',
            'text-max-width': '110px',
            'text-background-color': '#07090e',
            'text-background-opacity': 0.88,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'text-border-width': 1,
            'text-border-color': '#1e2638',
            'text-border-opacity': 0.8,
            'background-color': '#1e2638',
            'border-width': 1.5,
            'border-color': '#3b4b6e',
            'width': 28,
            'height': 28,
          }
        },
        {
          selector: 'node[type = "target"]',
          style: {
            'background-color': '#0284c7',
            'border-color': '#38bdf8',
            'border-width': 3,
            'width': 44,
            'height': 44,
            'font-size': '13px',
            'font-weight': 'bold',
            'color': '#f8fafc',
            'text-border-color': '#0284c7',
          }
        },
        {
          selector: 'node[type = "subdomain"]',
          style: {
            'background-color': '#1e293b',
            'border-color': '#64748b',
            'width': 24,
            'height': 24,
            'font-size': '10px',
            'color': '#94a3b8',
          }
        },
        {
          selector: 'node[type = "ip"]',
          style: {
            'background-color': '#064e3b',
            'border-color': '#10b981',
            'border-width': 2,
            'width': 34,
            'height': 34,
            'font-size': '11px',
            'color': '#a7f3d0',
            'text-border-color': '#064e3b',
          }
        },
        {
          selector: 'node[type = "port"]',
          style: {
            'background-color': '#1e1b4b',
            'border-color': '#818cf8',
            'border-width': 1.5,
            'width': 24,
            'height': 24,
            'font-size': '10px',
            'color': '#c7d2fe',
            'text-border-color': '#312e81',
          }
        },
        {
          selector: 'node[type = "cve"]',
          style: {
            'background-color': '#7f1d1d',
            'border-color': '#ef4444',
            'border-width': 2,
            'width': 26,
            'height': 26,
            'font-size': '10px',
            'font-weight': 'bold',
            'color': '#fecaca',
            'text-border-color': '#7f1d1d',
          }
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#f8fafc',
            'border-width': 3,
            'overlay-color': '#38bdf8',
            'overlay-opacity': 0.15,
            'overlay-padding': 6,
          }
        }
      ],
      layout: getLayoutConfig('cose'),
      minZoom: 0.2,
      maxZoom: 3.0,
      wheelSensitivity: 0.25,
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      onSelectNode({
        id: node.id(),
        ...node.data()
      });
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        onSelectNode(null);
      }
    });

    cyRef.current = cy;

    let rafId = null;
    const resizeObserver = new ResizeObserver(() => {
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(() => {
        const instance = cyRef.current;
        if (instance && !instance.destroyed()) {
          instance.resize();
          if (instance.elements().length > 0) {
            instance.fit(undefined, 40);
          }
        }
      });
    });
    resizeObserver.observe(containerRef.current);

    return () => {
      if (rafId) cancelAnimationFrame(rafId);
      resizeObserver.disconnect();
      cy.destroy();
    };
  }, []);

  // Recargar elementos cuando cambia graphData o layoutMode
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;

    cy.elements().remove();

    if (!graphData) return;

    const elements = [
      ...(graphData.nodes || []),
      ...(graphData.edges || [])
    ];

    if (elements.length > 0) {
      cy.add(elements);
      const layout = cy.layout(getLayoutConfig(layoutMode));
      layout.on('layoutstop', () => {
        if (!cy.destroyed()) cy.fit(undefined, 50);
      });
      layout.run();
    }
  }, [graphData, layoutMode]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || cy.destroyed()) return;
    if (selectedNodeId) {
      cy.nodes().unselect();
      const targetNode = cy.getElementById(selectedNodeId);
      if (targetNode.length) {
        targetNode.select();
        cy.animate({
          center: { eles: targetNode },
          duration: 320,
        });
      }
    } else {
      cy.nodes().unselect();
    }
  }, [selectedNodeId]);

  const applyLayout = (mode) => {
    setLayoutMode(mode);
    const cy = cyRef.current;
    if (cy && !cy.destroyed() && cy.elements().length > 0) {
      const layout = cy.layout(getLayoutConfig(mode));
      layout.on('layoutstop', () => {
        if (!cy.destroyed()) cy.fit(undefined, 50);
      });
      layout.run();
    }
  };

  return (
    <div className="relative w-full h-full bg-[#07090e] overflow-hidden flex flex-col">
      {/* Barra de controles del lienzo y modos de distribución */}
      <div className="absolute top-3 left-3 z-10 flex items-center space-x-2">
        <div className="flex items-center space-x-1 bg-[#0f131c]/90 border border-[#1e2638] px-2 py-1 rounded backdrop-blur-sm">
          <button
            onClick={() => cyRef.current && !cyRef.current.destroyed() && cyRef.current.zoom(cyRef.current.zoom() * 1.25)}
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-[#1a2233] rounded transition-colors cursor-pointer"
            title="Zoom In"
          >
            <ZoomIn size={14} />
          </button>
          <button
            onClick={() => cyRef.current && !cyRef.current.destroyed() && cyRef.current.zoom(cyRef.current.zoom() * 0.8)}
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-[#1a2233] rounded transition-colors cursor-pointer"
            title="Zoom Out"
          >
            <ZoomOut size={14} />
          </button>
          <button
            onClick={() => cyRef.current && !cyRef.current.destroyed() && cyRef.current.elements().length > 0 && cyRef.current.fit(undefined, 50)}
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-[#1a2233] rounded transition-colors cursor-pointer"
            title="Ajustar al centro"
          >
            <Maximize2 size={14} />
          </button>
          <button
            onClick={() => applyLayout(layoutMode)}
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-[#1a2233] rounded transition-colors cursor-pointer"
            title="Reorganize graph layout"
          >
            <RotateCcw size={14} />
          </button>
        </div>

        {/* Layout Selector */}
        <div className="flex items-center space-x-1 bg-[#0f131c]/90 border border-[#1e2638] p-1 rounded backdrop-blur-sm text-xs font-mono">
          <button
            onClick={() => applyLayout('cose')}
            className={`px-2 py-1 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
              layoutMode === 'cose'
                ? 'bg-blue-600/30 text-blue-400 border border-blue-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a2233]'
            }`}
            title="Physics-based Force-directed layout (Cose Anti-collision)"
          >
            <Share2 size={12} />
            <span>Force</span>
          </button>
          <button
            onClick={() => applyLayout('concentric')}
            className={`px-2 py-1 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
              layoutMode === 'concentric'
                ? 'bg-blue-600/30 text-blue-400 border border-blue-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a2233]'
            }`}
            title="Concentric Radial layout (Clear hierarchy without overlaps)"
          >
            <CircleDot size={12} />
            <span>Radial</span>
          </button>
          <button
            onClick={() => applyLayout('breadthfirst')}
            className={`px-2 py-1 rounded transition-colors cursor-pointer flex items-center gap-1.5 ${
              layoutMode === 'breadthfirst'
                ? 'bg-blue-600/30 text-blue-400 border border-blue-500/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a2233]'
            }`}
            title="Hierarchical Tree layout"
          >
            <Network size={12} />
            <span>Tree</span>
          </button>
        </div>
      </div>

      {/* Node Legend */}
      <div className="absolute bottom-3 left-3 z-10 flex flex-wrap items-center gap-3 bg-[#0f131c]/90 border border-[#1e2638] px-3 py-1.5 rounded text-[11px] font-mono backdrop-blur-sm text-slate-400">
        <span className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#0284c7] border border-[#38bdf8]"></span>
          <span>Target</span>
        </span>
        <span className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#064e3b] border border-[#10b981]"></span>
          <span>Host IP</span>
        </span>
        <span className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#1e1b4b] border border-[#818cf8]"></span>
          <span>Port / Service</span>
        </span>
        <span className="flex items-center space-x-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#7f1d1d] border border-[#ef4444]"></span>
          <span>Vulnerability (CVE)</span>
        </span>
      </div>

      {/* Contenedor del canvas de Cytoscape */}
      <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
    </div>
  );
}
