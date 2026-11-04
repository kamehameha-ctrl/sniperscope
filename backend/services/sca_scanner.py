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
                "title": "Cross-Site Scripting (XSS) in HTML Manipulation",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "jQuery internal regular expressions while processing unfiltered HTML allow arbitrary JavaScript execution even with sanitization libraries.",
                "affected_versions": "< 3.5.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-11022",
                "poc_url": "https://github.com/search?q=CVE-2020-11022+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2020-11022",
                "remediation": "Upgrade to jQuery 3.7.1 or version 3.5.0+"
            })
            vulns.append({
                "cve": "CVE-2020-11023",
                "title": "XSS Sanitization Bypass in htmlPrefilter",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "Flaw in jQuery.htmlPrefilter replaces closed tags insecurely, leading to injected code execution.",
                "affected_versions": "< 3.5.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-11023",
                "poc_url": "https://github.com/search?q=CVE-2020-11023+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2020-11023",
                "remediation": "Upgrade to jQuery 3.7.1"
            })

        # jQuery < 3.4.0
        if parsed < (3, 4, 0):
            vulns.append({
                "cve": "CVE-2019-11358",
                "title": "Prototype Pollution in jQuery.extend",
                "severity": "HIGH",
                "cvss": 7.5,
                "vector": "Prototype Pollution",
                "summary": "Insecure usage of Object.prototype in deep extend (jQuery.extend(true, {}, ...)) allows modifying the prototype of the global Object.",
                "affected_versions": "< 3.4.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-11358",
                "poc_url": "https://github.com/search?q=CVE-2019-11358+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2019-11358",
                "remediation": "Upgrade to jQuery 3.4.0+"
            })

        # jQuery < 3.0.0
        if parsed < (3, 0, 0):
            vulns.append({
                "cve": "CVE-2015-9251",
                "title": "Cross-Domain Script Injection via dataType: 'script'",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "Cross-domain AJAX requests without explicit dataType automatically execute responses containing text/javascript headers.",
                "affected_versions": "< 3.0.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2015-9251",
                "poc_url": "https://github.com/search?q=CVE-2015-9251+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2015-9251",
                "remediation": "Upgrade to jQuery 3.0.0+"
            })

        # jQuery < 1.9.0 (incluye 1.7.2)
        if parsed < (1, 9, 0):
            vulns.append({
                "cve": "CVE-2012-6708",
                "title": "Selector XSS in Core $() Function",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "The jQuery $(str) selector function parses strings starting with hash characters or tags as HTML rather than CSS selectors if supplied from untrusted user input.",
                "affected_versions": "< 1.9.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2012-6708",
                "poc_url": "https://github.com/search?q=CVE-2012-6708+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2012-6708",
                "remediation": "Upgrade urgently to modern jQuery 3.x branch"
            })

    # 2. BOOTSTRAP
    elif "bootstrap" in norm_name:
        if parsed < (4, 3, 1) or (parsed[0] == 3 and parsed < (3, 4, 1)):
            vulns.append({
                "cve": "CVE-2019-8331",
                "title": "Cross-Site Scripting in Tooltip and Popover",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "Bootstrap tooltip and popover plugins do not sanitize data-template and data-content options before injecting them into the DOM.",
                "affected_versions": "< 4.3.1 / < 3.4.1",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331",
                "poc_url": "https://github.com/search?q=CVE-2019-8331+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2019-8331",
                "remediation": "Upgrade to Bootstrap 4.3.1+ or 5.x"
            })
            vulns.append({
                "cve": "CVE-2018-14041",
                "title": "XSS via data-parent in Collapse Plugin",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "vector": "Cross-Site Scripting (XSS)",
                "summary": "XSS vulnerability in the data-parent attribute of the Bootstrap Collapse component.",
                "affected_versions": "< 4.1.2",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2018-14041",
                "poc_url": "https://github.com/search?q=CVE-2018-14041+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2018-14041",
                "remediation": "Upgrade to patched version (4.1.2+)"
            })

    # 3. LODASH
    elif "lodash" in norm_name:
        if parsed < (4, 17, 21):
            vulns.append({
                "cve": "CVE-2021-23337",
                "title": "Command Injection in template Function",
                "severity": "HIGH",
                "cvss": 7.2,
                "vector": "Command Injection",
                "summary": "Untrusted input in lodash.template allows arbitrary code injection.",
                "affected_versions": "< 4.17.21",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                "poc_url": "https://github.com/search?q=CVE-2021-23337+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-23337",
                "remediation": "Upgrade to Lodash 4.17.21+"
            })
            vulns.append({
                "cve": "CVE-2020-8203",
                "title": "Prototype Pollution in zipObjectDeep",
                "severity": "HIGH",
                "cvss": 7.4,
                "vector": "Prototype Pollution",
                "summary": "Prototype pollution in deep object assignment utilities.",
                "affected_versions": "< 4.17.19",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
                "poc_url": "https://github.com/search?q=CVE-2020-8203+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2020-8203",
                "remediation": "Upgrade to Lodash 4.17.21+"
            })

    # 4. WORDPRESS CORE
    elif "wordpress" in norm_name:
        if parsed < (6, 4, 2):
            vulns.append({
                "cve": "CVE-2023-39999",
                "title": "POP Deserialization Chain / Code Execution",
                "severity": "HIGH",
                "cvss": 7.5,
                "vector": "Object Injection / RCE",
                "summary": "POP chain in WP_Theme allows arbitrary code execution in specific plugin combinations with deserialization.",
                "affected_versions": "< 6.4.2",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-39999",
                "poc_url": "https://github.com/search?q=CVE-2023-39999+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2023-39999",
                "remediation": "Upgrade WordPress Core to version 6.4.2 or 6.5+"
            })
        if parsed < (5, 8, 0):
            vulns.append({
                "cve": "CVE-2021-29447",
                "title": "XXE Attack & Arbitrary File Leak via WAV Upload",
                "severity": "HIGH",
                "cvss": 7.5,
                "vector": "XML External Entity (XXE)",
                "summary": "WAV file uploads in the media library enable reading server files and triggering SSRF.",
                "affected_versions": "5.6.0 - 5.7.1",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-29447",
                "poc_url": "https://github.com/search?q=CVE-2021-29447+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-29447",
                "remediation": "Upgrade WordPress Core to 5.8+"
            })

    # 5. APACHE HTTP SERVER
    elif "apache" in norm_name:
        if parsed in ((2, 4, 49), (2, 4, 50)):
            vulns.append({
                "cve": "CVE-2021-41773",
                "title": "Path Traversal & RCE in Apache HTTP Server",
                "severity": "CRITICAL",
                "cvss": 7.5,
                "vector": "Path Traversal / Remote Code Execution",
                "summary": "Flaw in path normalization allows mapping URLs outside docroot (/cgi-bin/.%2e/.%2e/) and executing binaries such as /bin/sh.",
                "affected_versions": "2.4.49",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                "poc_url": "https://github.com/search?q=CVE-2021-41773+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-41773",
                "remediation": "Upgrade immediately to Apache 2.4.51 or higher"
            })
            vulns.append({
                "cve": "CVE-2021-42013",
                "title": "Patch Bypass for CVE-2021-41773 with Critical RCE",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "vector": "Remote Code Execution (RCE)",
                "summary": "Incomplete patch for CVE-2021-41773 allows remote code execution via double URL encoding (%%32%65).",
                "affected_versions": "2.4.49, 2.4.50",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
                "poc_url": "https://github.com/search?q=CVE-2021-42013+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-42013",
                "remediation": "Upgrade to Apache 2.4.51+"
            })
        elif parsed < (2, 4, 53):
            vulns.append({
                "cve": "CVE-2022-22720",
                "title": "HTTP Request Smuggling in Apache",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "vector": "HTTP Request Smuggling",
                "summary": "Integer overflow when processing requests with massive sizes in mod_reqtimeout.",
                "affected_versions": "< 2.4.53",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-22720",
                "poc_url": "https://github.com/search?q=CVE-2022-22720+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2022-22720",
                "remediation": "Upgrade to Apache 2.4.53+"
            })

    # 6. NGINX
    elif "nginx" in norm_name:
        if parsed < (1, 20, 1):
            vulns.append({
                "cve": "CVE-2021-23017",
                "title": "1-byte Memory Corruption in DNS Resolver",
                "severity": "HIGH",
                "cvss": 7.7,
                "vector": "Buffer Overflow / Memory Corruption",
                "summary": "Off-by-one bug in Nginx resolver module while processing malicious DNS responses, leading to code execution or DoS.",
                "affected_versions": "0.6.18 - 1.20.0",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
                "poc_url": "https://github.com/search?q=CVE-2021-23017+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2021-23017",
                "remediation": "Upgrade to Nginx 1.20.1+ or 1.22+"
            })

    # 7. PHP
    elif "php" in norm_name:
        if parsed < (8, 0, 0):
            vulns.append({
                "cve": "CVE-2019-11043",
                "title": "Remote Code Execution in php-fpm (Nginx)",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "vector": "Remote Code Execution (RCE)",
                "summary": "Buffer underflow in env_path_info in php-fpm allowing remote attackers to execute arbitrary code via crafted URLs.",
                "affected_versions": "PHP 7.1.x < 7.1.33, 7.2.x < 7.2.24, 7.3.x < 7.3.11",
                "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2019-11043",
                "poc_url": "https://github.com/search?q=CVE-2019-11043+poc&type=repositories",
                "exploitdb_url": "https://www.exploit-db.com/search?cve=2019-11043",
                "remediation": "Upgrade urgently to supported PHP 8.2+ branch"
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
