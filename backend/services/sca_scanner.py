"""Motor SCA (Software Composition Analysis) y Correlación de Vulnerabilidades Web.

Analiza versiones de librerías cliente, frameworks y software web descubiertos
por el motor Wappalyzer, correlacionándolos con vulnerabilidades CVE conocidas,
vectores de ataque (XSS, Prototype Pollution, RCE) y enlaces directos a PoCs.
"""
from typing import Dict, List, Any, Optional, Tuple
import re


def _parse_version(version_str: Optional[str]) -> Optional[Tuple[int, ...]]:
    """Convierte una cadena de versión '1.7.2' o 'v2.4.49' en una tupla de enteros (1, 7, 2)."""
    if not version_str:
        return None
    low = version_str.lower()
    if any(k in low for k in ("oculta", "server_tokens", "prod", "zero-js", "hardened", "none")):
        return None
    cleaned = re.sub(r'^[^\d]*', '', version_str.replace("~", "").strip())
    # Extraer los primeros 3 números
    parts = re.findall(r'\d+', cleaned)
    if not parts:
        return None
    try:
        return tuple(int(p) for p in parts[:3])
    except Exception:
        return None


def evaluate_technology_vulnerabilities(tech_name: str, version_str: Optional[str]) -> List[Dict[str, Any]]:
    """Evalúa si una versión específica de un componente o librería web tiene CVEs conocidas."""
    if not version_str:
        return []

    parsed = _parse_version(version_str)
    if not parsed:
        return []

    vulns: List[Dict[str, Any]] = []
    norm_name = tech_name.strip().lower()

    # 1. JQUERY
    if "jquery" in norm_name and "ui" not in norm_name and "mobile" not in norm_name:
        # jQuery < 3.5.0
        if parsed < (3, 5, 0):
            vulns.append({
                "cve": "CVE-2020-11022",
                "title": "Cross-Site Scripting (XSS) en Manipulación de HTML",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "Expresiones regulares internas de jQuery al procesar HTML sin filtrar permiten ejecución arbitraria de JavaScript incluso con librerías de sanitización.",
                "affected_versions": "< 3.5.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-11022",
                "poc_url": "https://github.com/search?q=CVE-2020-11022+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2020-11022",
                "remediation": "Actualizar a jQuery 3.7.1 o versión 3.5.0+"
            })
            vulns.append({
                "cve": "CVE-2020-11023",
                "title": "Evasión de Sanitización XSS en htmlPrefilter",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "Fallo en jQuery.htmlPrefilter que reemplaza etiquetas cerradas de forma insegura permitiendo ejecución de código inyectado.",
                "affected_versions": "< 3.5.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-11023",
                "poc_url": "https://github.com/search?q=CVE-2020-11023+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2020-11023",
                "remediation": "Actualizar a jQuery 3.7.1"
            })

        # jQuery < 3.4.0
        if parsed < (3, 4, 0):
            vulns.append({
                "cve": "CVE-2019-11358",
                "title": "Prototype Pollution en jQuery.extend",
                "severity": "HIGH",
                "cvss": 7.5,
                "vector": "Prototype Pollution",
                "summary": "Uso inseguro de Object.prototype en la función deep extend (jQuery.extend(true, {}, ...)) permite sobreescribir propiedades del prototipo global Object.",
                "affected_versions": "< 3.4.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-11358",
                "poc_url": "https://github.com/search?q=CVE-2019-11358+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2019-11358",
                "remediation": "Actualizar a jQuery 3.4.0+"
            })

        # jQuery < 3.0.0
        if parsed < (3, 0, 0):
            vulns.append({
                "cve": "CVE-2015-9251",
                "title": "Inyección Cross-Domain vía dataType: 'script'",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "Las peticiones AJAX cross-domain sin especificar dataType ejecutan automáticamente respuestas que contengan cabeceras text/javascript.",
                "affected_versions": "< 3.0.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2015-9251",
                "poc_url": "https://github.com/search?q=CVE-2015-9251+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2015-9251",
                "remediation": "Actualizar a jQuery 3.0.0+"
            })

        # jQuery < 1.9.0 (incluye 1.7.2)
        if parsed < (1, 9, 0):
            vulns.append({
                "cve": "CVE-2012-6708",
                "title": "Selector XSS en Función Central $()",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "La función selectora de jQuery $(str) parsea cadenas que comienzan con caracteres hash o etiquetas como HTML en vez de selectores CSS si provienen de entrada de usuario sin sanitizar.",
                "affected_versions": "< 1.9.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2012-6708",
                "poc_url": "https://github.com/search?q=CVE-2012-6708+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2012-6708",
                "remediation": "Actualizar urgentemente a rama moderna jQuery 3.x"
            })

    # 2. BOOTSTRAP
    elif "bootstrap" in norm_name:
        if parsed < (4, 3, 1) or (parsed[0] == 3 and parsed < (3, 4, 1)):
            vulns.append({
                "cve": "CVE-2019-8331",
                "title": "Cross-Site Scripting en Tooltip y Popover",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "Los plugins tooltip y popover de Bootstrap no sanitizan las opciones data-template y data-content antes de inyectarlas en el DOM.",
                "affected_versions": "< 4.3.1 / < 3.4.1",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331",
                "poc_url": "https://github.com/search?q=CVE-2019-8331+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2019-8331",
                "remediation": "Actualizar a Bootstrap 4.3.1+ o 5.x"
            })
            vulns.append({
                "cve": "CVE-2018-14041",
                "title": "XSS vía data-parent en Plugin Collapse",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "Vulnerabilidad XSS en el atributo data-parent del componente Collapse de Bootstrap.",
                "affected_versions": "< 4.1.2",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2018-14041",
                "poc_url": "https://github.com/search?q=CVE-2018-14041+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2018-14041",
                "remediation": "Actualizar a versión parcheada"
            })

    # 3. LODASH
    elif "lodash" in norm_name:
        if parsed < (4, 17, 21):
            vulns.append({
                "cve": "CVE-2021-23337",
                "title": "Inyección de Comandos en Función template",
                "severity": "HIGH",
                "cvss": 7.2,
                "vector": "Command Injection",
                "summary": "Uso de fuentes no confiables en lodash.template permite inyección de código arbitrario.",
                "affected_versions": "< 4.17.21",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                "poc_url": "https://github.com/search?q=CVE-2021-23337+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-23337",
                "remediation": "Actualizar a Lodash 4.17.21+"
            })
            vulns.append({
                "cve": "CVE-2020-8203",
                "title": "Prototype Pollution en zipObjectDeep",
                "severity": "HIGH",
                "cvss": 7.4,
                "vector": "Prototype Pollution",
                "summary": "Prototype pollution en utilidades deep de asignación de objetos.",
                "affected_versions": "< 4.17.19",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
                "poc_url": "https://github.com/search?q=CVE-2020-8203+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2020-8203",
                "remediation": "Actualizar a Lodash 4.17.21+"
            })

    # 4. WORDPRESS CORE
    elif "wordpress" in norm_name:
        if parsed < (6, 4, 2):
            vulns.append({
                "cve": "CVE-2023-39999",
                "title": "Cadena de Deserialización POP / Ejecución de Código",
                "severity": "HIGH",
                "cvss": 7.5,
                "vector": "Object Injection / RCE",
                "summary": "Cadena POP en WP_Theme que permite ejecución de código arbitrario en ciertas combinaciones de plugins con deserialización.",
                "affected_versions": "< 6.4.2",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-39999",
                "poc_url": "https://github.com/search?q=CVE-2023-39999+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2023-39999",
                "remediation": "Actualizar WordPress Core a versión 6.4.2 o 6.5+"
            })
        if parsed < (5, 8, 0):
            vulns.append({
                "cve": "CVE-2021-29447",
                "title": "Ataque XXE y Fuga de Archivos Arbitrarios vía WAV",
                "severity": "HIGH",
                "cvss": 7.5,
                "vector": "XML External Entity (XXE)",
                "summary": "Subida de archivos WAV en la biblioteca de medios permite leer archivos del servidor y SSRF.",
                "affected_versions": "5.6.0 - 5.7.1",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-29447",
                "poc_url": "https://github.com/search?q=CVE-2021-29447+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-29447",
                "remediation": "Actualizar WordPress Core"
            })

    # 5. APACHE HTTP SERVER
    elif "apache" in norm_name:
        if parsed in ((2, 4, 49), (2, 4, 50)):
            vulns.append({
                "cve": "CVE-2021-41773",
                "title": "Path Traversal & RCE en Apache HTTP Server",
                "severity": "CRITICAL",
                "cvss": 7.5,
                "vector": "Path Traversal / Remote Code Execution",
                "summary": "Fallo en la normalización de rutas permite recorrer el sistema de archivos (/cgi-bin/.%2e/.%2e/) y ejecutar binarios como /bin/sh.",
                "affected_versions": "2.4.49",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                "poc_url": "https://github.com/search?q=CVE-2021-41773+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-41773",
                "remediation": "Actualizar inmediatamente a Apache 2.4.51 o superior"
            })
            vulns.append({
                "cve": "CVE-2021-42013",
                "title": "Bypass de Parche CVE-2021-41773 con RCE Crítico",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "vector": "Remote Code Execution (RCE)",
                "summary": "Parche incompleto de CVE-2021-41773 permite ejecución de código remoto mediante doble codificación URL (%%32%65).",
                "affected_versions": "2.4.49, 2.4.50",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
                "poc_url": "https://github.com/search?q=CVE-2021-42013+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-42013",
                "remediation": "Actualizar a Apache 2.4.51+"
            })
        elif parsed < (2, 4, 53):
            vulns.append({
                "cve": "CVE-2022-22720",
                "title": "HTTP Request Smuggling en Apache",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "vector": "HTTP Request Smuggling",
                "summary": "Desbordamiento de entero al procesar peticiones con tamaños masivos en mod_reqtimeout.",
                "affected_versions": "< 2.4.53",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-22720",
                "poc_url": "https://github.com/search?q=CVE-2022-22720+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2022-22720",
                "remediation": "Actualizar a Apache 2.4.53+"
            })

    # 6. NGINX
    elif "nginx" in norm_name:
        if parsed < (1, 20, 1):
            vulns.append({
                "cve": "CVE-2021-23017",
                "title": "Corrupción de Memoria de 1-byte en Resolver DNS",
                "severity": "HIGH",
                "cvss": 7.7,
                "vector": "Buffer Overflow / Memory Corruption",
                "summary": "Fallo en el módulo resolver de Nginx al procesar respuestas DNS maliciosas permitiendo ejecución de código o DoS.",
                "affected_versions": "0.6.18 - 1.20.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
                "poc_url": "https://github.com/search?q=CVE-2021-23017+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-23017",
                "remediation": "Actualizar a Nginx 1.20.1+ o 1.22+"
            })

    # 7. PHP
    elif "php" in norm_name:
        if parsed < (8, 0, 0):
            vulns.append({
                "cve": "CVE-2019-11043",
                "title": "Remote Code Execution en php-fpm (Nginx)",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "vector": "Remote Code Execution (RCE)",
                "summary": "Desbordamiento en env_path_info en php-fpm que permite a atacantes remotos ejecutar código arbitrario enviando URLs especialmente manipuladas.",
                "affected_versions": "PHP 7.1.x < 7.1.33, 7.2.x < 7.2.24, 7.3.x < 7.3.11",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043",
                "poc_url": "https://github.com/search?q=CVE-2019-11043+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2019-11043",
                "remediation": "Actualizar urgentemente a rama soportada PHP 8.2+"
            })

    # Asociar metadatos técnicos comunes y fuentes de exploits verificadas
    for v in vulns:
        cve_id = v.get("cve", "")
        clean_num = cve_id.upper().replace("CVE-", "")
        v["service"] = f"{tech_name} {version_str}"
        v["product"] = tech_name
        v["version"] = version_str
        v["source"] = "SCA Web Technology Audit"
        v["packetstorm_url"] = f"https://packetstormsecurity.com/search/?q={cve_id}"
        v["vulners_url"] = f"https://vulners.com/search?query={cve_id}"
        v["exploitdb_url"] = f"https://www.exploit-db.com/search?cve={clean_num}"
        v["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return vulns


def enrich_wappalyzer_components(wapp_components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enriquece la lista de componentes detectados por Wappalyzer con evaluación de vulnerabilidades."""
    enriched = []
    for item in wapp_components:
        tech_copy = dict(item)
        name = tech_copy.get("name", "")
        ver = tech_copy.get("version")
        vulns = evaluate_technology_vulnerabilities(name, ver)
        tech_copy["vulnerable"] = len(vulns) > 0
        tech_copy["vulnerabilities"] = vulns
        if vulns:
            has_crit = any(v.get("severity") == "CRITICAL" for v in vulns)
            has_high = any(v.get("severity") == "HIGH" for v in vulns)
            tech_copy["max_severity"] = "CRITICAL" if has_crit else ("HIGH" if has_high else "MEDIUM")
            tech_copy["cve_count"] = len(vulns)
        else:
            tech_copy["max_severity"] = None
            tech_copy["cve_count"] = 0
        enriched.append(tech_copy)
    return enriched
