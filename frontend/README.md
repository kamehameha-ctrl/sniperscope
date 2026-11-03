# 🎯 SniperScope // Frontend Application

Interfaz SPA interactiva de alta densidad construida sobre **React 19**, **Vite 8**, **Tailwind CSS v4** y **Cytoscape.js**.

## 🚀 Comandos de Desarrollo

```bash
# Instalar dependencias
npm install

# Iniciar servidor de desarrollo en modo LAN (0.0.0.0:5173)
npm run dev

# Compilar para producción (Vite build)
npm run build

# Análisis estático y linter (Oxlint)
npm run lint
```

## 🏗️ Estructura de Componentes

- **`App.jsx`**: Shell principal, gestión de autenticación con el backend, estado reactivo, conmutador de vistas (`split`, `text`, `graph`) y caché de sesiones local.
- **`components/LoginScreen.jsx`**: Pasarela de acceso con validación criptográfica HMAC-SHA256 y token en `sessionStorage`.
- **`components/TargetInput.jsx`**: Barra de búsqueda con normalización de dominios/IPs y selector OPSEC (`Stealth` vs `Activo`).
- **`components/IntelDossier.jsx`**: Resumen ejecutivo, desglose de puertos y banners, tabla CVE con filtros CVSS/EPSS/KEV, inspección TLS/Uptime (estilo who.is), motor Wappalyzer y Playbook CLI con comandos Kali Linux.
- **`components/GraphCanvas.jsx`**: Renderizado de topología interactiva con Cytoscape.js anti-colisión y selector de modos (`Fuerza`, `Radial Concéntrico`, `Árbol`).
- **`components/NodeDetails.jsx`**: Inspector flotante de metadatos al seleccionar nodos en el grafo.
- **`components/ForensicReportModal.jsx`**: Exportador en 4 formatos: PDF, HTML interactivo autocontenido, Markdown (`TLP:AMBER`) y traza forense cronológica RAW (`.log`).
