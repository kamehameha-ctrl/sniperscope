"""Servicio de inteligencia de números de teléfono (OSINT Telefónico Multi-Fuente).

Combina validación estructural libphonenumber (>200 países), inteligencia del
Plan Nacional de Numeración (CNMC España y tarificación especial), correlación
en paralelo de bases comunitarias de denuncias (ListaSpam, TelefonoSpam,
ResponderONo/ShouldIAnswer, CleverDialer, Tellows, 800Notes), auditoría de
filtraciones en doble formato (LeakCheck), detección de palabras clave de
fraude/estafa sobre testimonios reales, hemeroteca (Google News RSS) y búsqueda
opcional web/X (Twitter).
"""
from typing import Dict, Any, List, Optional, Tuple
import os
import re
import html
import json
import asyncio
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import quote
import httpx

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone, PhoneNumberFormat
except ImportError:
    phonenumbers = None
    geocoder = None
    carrier = None
    timezone = None
    PhoneNumberFormat = None

try:
    from services.http_scanner import is_proxy_reachable
except ImportError:
    try:
        from backend.services.http_scanner import is_proxy_reachable
    except ImportError:
        def is_proxy_reachable(_proxy_url: Optional[str]) -> bool:
            return False

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

LINE_TYPE_MAP = {
    0: "Línea Fija Terrestre",
    1: "Móvil / Celular",
    2: "Fija o Móvil",
    3: "Número Gratuito (Toll-Free / 900)",
    4: "Tarificación Especial / Alto Coste",
    5: "Tarificación Compartida",
    6: "Telefonía IP / Virtual (VoIP)",
    7: "Número Personal",
    8: "Buscapersonas (Pager)",
    9: "Número de Acceso Universal (UAN)",
    10: "Buzón de Voz",
    -1: "Telefonía General",
}

FLAG_MAP = {
    "ES": "🇪🇸", "US": "🇺🇸", "GB": "🇬🇧", "FR": "🇫🇷", "DE": "🇩🇪", "IT": "🇮🇹", "PT": "🇵🇹",
    "MX": "🇲🇽", "AR": "🇦🇷", "CO": "🇨🇴", "CL": "🇨🇱", "PE": "🇵🇪", "BR": "🇧🇷", "CA": "🇨🇦",
    "CH": "🇨🇭", "NL": "🇳🇱", "BE": "🇧🇪", "RU": "🇷🇺", "CN": "🇨🇳", "JP": "🇯🇵", "AU": "🇦🇺",
}

COUNTRY_NAME_FALLBACK = {
    "ES": "España", "US": "Estados Unidos", "CA": "Canadá", "GB": "Reino Unido", "FR": "Francia",
    "DE": "Alemania", "IT": "Italia", "PT": "Portugal", "MX": "México", "AR": "Argentina",
    "CO": "Colombia", "CL": "Chile", "PE": "Perú", "BR": "Brasil", "CH": "Suiza",
    "NL": "Países Bajos", "BE": "Bélgica", "RU": "Rusia", "CN": "China", "JP": "Japón", "AU": "Australia",
}

MCC_TABLE = {
    "ES": "214", "US": "310", "CA": "302", "GB": "234", "FR": "208", "DE": "262",
    "IT": "222", "PT": "268", "MX": "334", "AR": "722", "CO": "732", "CL": "730",
    "PE": "716", "BR": "724", "CH": "228", "NL": "204", "BE": "206", "RU": "250",
    "CN": "460", "JP": "440", "AU": "505",
}

# Prefijos provinciales oficiales de telefonía fija en España (CNMC)
ES_PROVINCE_PREFIXES = {
    "91": "Madrid", "81": "Madrid",
    "93": "Barcelona", "83": "Barcelona",
    "920": "Ávila", "820": "Ávila",
    "921": "Segovia", "821": "Segovia",
    "922": "Santa Cruz de Tenerife", "822": "Santa Cruz de Tenerife",
    "923": "Salamanca", "823": "Salamanca",
    "924": "Badajoz", "824": "Badajoz",
    "925": "Toledo", "825": "Toledo",
    "926": "Ciudad Real", "826": "Ciudad Real",
    "927": "Cáceres", "827": "Cáceres",
    "928": "Las Palmas", "828": "Las Palmas",
    "941": "La Rioja", "841": "La Rioja",
    "942": "Cantabria", "842": "Cantabria",
    "943": "Gipuzkoa", "843": "Gipuzkoa",
    "944": "Bizkaia", "946": "Bizkaia", "844": "Bizkaia", "846": "Bizkaia",
    "945": "Álava", "845": "Álava",
    "947": "Burgos", "847": "Burgos",
    "948": "Navarra", "848": "Navarra",
    "949": "Guadalajara", "849": "Guadalajara",
    "950": "Almería", "850": "Almería",
    "951": "Málaga", "952": "Málaga", "851": "Málaga", "852": "Málaga",
    "953": "Jaén", "853": "Jaén",
    "954": "Sevilla", "955": "Sevilla", "854": "Sevilla", "855": "Sevilla",
    "956": "Cádiz / Ceuta", "856": "Cádiz / Ceuta",
    "957": "Córdoba", "857": "Córdoba",
    "958": "Granada", "858": "Granada",
    "959": "Huelva", "859": "Huelva",
    "960": "Valencia", "961": "Valencia", "962": "Valencia", "963": "Valencia", "860": "Valencia",
    "964": "Castellón", "864": "Castellón",
    "965": "Alicante", "966": "Alicante", "865": "Alicante",
    "967": "Albacete", "867": "Albacete",
    "968": "Murcia", "868": "Murcia",
    "969": "Cuenca", "869": "Cuenca",
    "971": "Illes Balears", "871": "Illes Balears",
    "972": "Girona", "872": "Girona",
    "973": "Lleida", "873": "Lleida",
    "974": "Huesca", "874": "Huesca",
    "975": "Soria", "875": "Soria",
    "976": "Zaragoza", "876": "Zaragoza",
    "977": "Tarragona", "877": "Tarragona",
    "978": "Teruel", "878": "Teruel",
    "979": "Palencia", "879": "Palencia",
    "980": "Zamora", "880": "Zamora",
    "981": "A Coruña", "881": "A Coruña",
    "982": "Lugo", "882": "Lugo",
    "983": "Valladolid", "883": "Valladolid",
    "984": "Asturias", "985": "Asturias", "884": "Asturias", "885": "Asturias",
    "986": "Pontevedra", "886": "Pontevedra",
    "987": "León", "887": "León",
    "988": "Ourense", "888": "Ourense",
}

HIGH_FRAUD_KEYWORDS = (
    "estafa", "estafador", "estafadora", "estafadores", "fraude", "timo", "timador",
    "suplantacion", "suplantación", "phishing", "smishing", "vishing", "bizum",
    "entradas", "concierto", "extorsion", "extorsión", "amenaza", "secuestro",
    "policia", "policía", "guardia civil", "comisaria", "comisaría", "juzgado",
    "scam", "fraud", "impersonat", "robo", "robado", "engano", "engaño",
    "wallapop", "milanuncios", "vinted", "transferencia", "cripto", "binance",
    "dni", "usurpacion", "usurpación", "estafando",
)

SPAM_COMMERCIAL_KEYWORDS = (
    "comercial", "publicidad", "telemarketing", "pesado", "pesados", "molesto",
    "acoso", "recobros", "cobros", "encuesta", "spam", "robot", "grabacion",
    "grabación", "contestador", "seguros", "luz", "fibra", "tarifa", "vendedor",
    "enervante", "teleoperador", "call center", "llamada silenciosa",
)

RISK_PRIORITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "CLEAN": 1}


def _clean_text(fragment: str) -> str:
    """Limpia etiquetas HTML, decodifica entidades y normaliza espacios."""
    if not fragment:
        return ""
    no_scripts = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", fragment)
    no_tags = re.sub(r"<[^>]+>", " ", no_scripts)
    unescaped = html.unescape(no_tags)
    return re.sub(r"\s+", " ", unescaped).strip()


def _decode_response(resp: httpx.Response) -> str:
    """Decodifica respuestas HTML respetando charsets ISO-8859-1/Windows-1252 cuando aplican."""
    content_type = (resp.headers.get("content-type") or "").lower()
    raw_head = resp.content[:1200].lower()
    if (
        "iso-8859-1" in content_type
        or "windows-1252" in content_type
        or b"charset=iso-8859-1" in raw_head
        or b"charset=\"iso-8859-1\"" in raw_head
    ):
        return resp.content.decode("cp1252", errors="replace")
    return resp.text


def _parse_int(raw: Optional[str]) -> int:
    """Convierte cadenas numéricas con separadores de miles ('1.234' o '1,234') a int."""
    if not raw:
        return 0
    digits = re.sub(r"\D", "", str(raw))
    return int(digits) if digits else 0


def _detect_keywords(text: str, keywords: Tuple[str, ...]) -> List[str]:
    """Devuelve palabras clave coincidentes con frontera de palabra evitando falsos positivos (ej. robot vs robo)."""
    low = (text or "").lower()
    found: List[str] = []
    for kw in keywords:
        # Coincidencia al inicio de palabra y terminación completa para evitar 'robot' -> 'robo' o 'fraude' -> 'fraud'
        pattern = rf"(?<!\w){re.escape(kw)}(?!\w)"
        if re.search(pattern, low) and kw not in found:
            found.append(kw)
    return found


def _extract_number_variants(
    national_number: str,
    e164_format: str,
    international_format: str,
    national_format: str,
) -> Dict[str, Any]:
    """Genera variantes de formato del teléfono usadas en webs, foros y X/Twitter."""
    nat_digits = re.sub(r"\D", "", national_number)
    variants: List[str] = []

    def _add(val: str) -> None:
        v = val.strip()
        if v and v not in variants:
            variants.append(v)

    _add(nat_digits)
    if national_format:
        _add(national_format)
    if len(nat_digits) == 9:
        # Formatos españoles típicos en redes/foros: 677 100 320, 677 10 03 20, 677-100-320
        _add(f"{nat_digits[:3]} {nat_digits[3:5]} {nat_digits[5:7]} {nat_digits[7:]}")
        _add(f"{nat_digits[:3]} {nat_digits[3:6]} {nat_digits[6:]}")
        _add(f"{nat_digits[:3]}-{nat_digits[3:6]}-{nat_digits[6:]}")
    elif len(nat_digits) == 10:
        _add(f"{nat_digits[:3]}-{nat_digits[3:6]}-{nat_digits[6:]}")
        _add(f"({nat_digits[:3]}) {nat_digits[3:6]}-{nat_digits[6:]}")

    _add(e164_format)
    _add(international_format)

    return {
        "formats": variants,
        "search_or_query": " OR ".join(f'"{v}"' for v in variants[:5]),
    }


def _resolve_spain_numbering_intel(
    country_code: str,
    national_number: str,
    geo_desc: str,
) -> Dict[str, Any]:
    """Extrae inteligencia determinista de provincia y tarificación especial en España (CNMC)."""
    nat = re.sub(r"\D", "", national_number)
    if country_code != "ES" or not nat:
        return {
            "geo_enriched": geo_desc,
            "tariff_class": "Estándar",
            "tariff_warning": None,
            "special_risk": False,
            "portability_note": None,
        }

    enriched_geo = geo_desc
    if len(nat) == 9 and nat[0] in ("8", "9"):
        prov = ES_PROVINCE_PREFIXES.get(nat[:2]) or ES_PROVINCE_PREFIXES.get(nat[:3])
        if prov and (not geo_desc or geo_desc.lower() in ("españa", "spain", "nacional")):
            enriched_geo = f"España ({prov})"
        elif prov and prov.lower() not in geo_desc.lower():
            enriched_geo = f"{geo_desc} ({prov})"

    tariff_class = "Tarifa Nacional Estándar"
    tariff_warning: Optional[str] = None
    special_risk = False
    portability_note: Optional[str] = None

    if nat.startswith(("803", "806", "807", "905", "907")):
        tariff_class = "Tarificación Adicional / Alto Coste"
        tariff_warning = (
            f"Prefijo {nat[:3]} de tarificación especial con coste elevado por minuto/llamada. "
            "Frecuente en fraudes de devolución de llamada (Wangiri) o líneas de pago."
        )
        special_risk = True
    elif nat.startswith(("901", "902")):
        tariff_class = f"Red Inteligente ({nat[:3]} - No incluido en tarifas planas)"
        tariff_warning = (
            f"Numeración {nat[:3]} de coste compartido o directo fuera de bonos habituales."
        )
    elif nat.startswith(("800", "900")):
        tariff_class = f"Línea Gratuita ({nat[:3]} / Toll-Free)"
    elif nat.startswith("70"):
        tariff_class = "Numeración Personal (Desvío 70x)"
    elif nat.startswith("590"):
        tariff_class = "Servicios M2M / IoT"
    elif nat[0] in ("6", "7"):
        tariff_class = "Telefonía Móvil Nacional"
        portability_note = (
            "El operador mostrado corresponde a la asignación original del bloque CNMC; "
            "la línea puede haber sido portada a otra operadora."
        )

    return {
        "geo_enriched": enriched_geo,
        "tariff_class": tariff_class,
        "tariff_warning": tariff_warning,
        "special_risk": special_risk,
        "portability_note": portability_note,
    }


def _resolve_mcc_mnc(country_code: str, carrier_name: Optional[str]) -> Dict[str, Any]:
    """Resuelve los códigos Mobile Country Code (MCC) y Mobile Network Code (MNC) bajo estándar ITU-T E.212."""
    mcc = MCC_TABLE.get(country_code, "000")
    mnc = "01"

    c_lower = (carrier_name or "").lower()
    if country_code == "ES":
        if any(k in c_lower for k in ("vodafone", "airtel", "ono", "lowi")):
            mnc = "01"
        elif any(k in c_lower for k in ("orange", "amena", "simyo", "jazztel")):
            mnc = "03"
        elif any(k in c_lower for k in ("yoigo", "másmóvil", "masmovil", "pepephone")):
            mnc = "04"
        elif any(k in c_lower for k in ("digi",)):
            mnc = "34"
        elif any(k in c_lower for k in ("euskaltel",)):
            mnc = "08"
        elif any(k in c_lower for k in ("lycamobile",)):
            mnc = "25"
        else:
            mnc = "07"
    elif country_code == "US":
        if "verizon" in c_lower:
            mnc = "012"
        elif "at&t" in c_lower:
            mnc = "410"
        elif "t-mobile" in c_lower:
            mnc = "260"
        else:
            mnc = "001"

    return {
        "mcc": mcc,
        "mnc": mnc,
        "imsi_routing": f"{mcc}-{mnc}",
        "standard": "ITU-T E.212",
    }


def _make_source_result(
    source: str,
    url: str,
    status: str = "clean",
    risk_level: str = "CLEAN",
    rating_label: str = "Sin reportes",
    reports_count: int = 0,
    searches_count: int = 0,
    blocks_count: int = 0,
    reported_entity: Optional[str] = None,
    operator_detected: Optional[str] = None,
    categories: Optional[List[str]] = None,
    last_activity: Optional[str] = None,
    comments: Optional[List[Dict[str, Any]]] = None,
    summary: str = "Sin incidencias registradas en esta base de datos.",
) -> Dict[str, Any]:
    """Construye una estructura normalizada de respuesta por cada fuente OSINT."""
    return {
        "source": source,
        "url": url,
        "status": status,
        "risk_level": risk_level,
        "rating_label": rating_label,
        "reports_count": reports_count,
        "searches_count": searches_count,
        "blocks_count": blocks_count,
        "reported_entity": reported_entity,
        "operator_detected": operator_detected,
        "categories": categories or [],
        "last_activity": last_activity,
        "comments": comments or [],
        "summary": summary,
    }


async def _query_listaspam(client: httpx.AsyncClient, clean_nat: str) -> Dict[str, Any]:
    """Consulta denuncias, búsquedas y testimonios reales en ListaSpam.com."""
    url = f"https://www.listaspam.com/busca.php?Telefono={clean_nat}"
    try:
        r = await client.get(url)
        if r.status_code != 200:
            return _make_source_result("ListaSpam", url, status="unavailable", rating_label=f"HTTP {r.status_code}", summary="Fuente temporalmente inaccesible.")

        html_text = _decode_response(r)
        if "Just a moment" in html_text or "cf-challenge" in html_text.lower():
            return _make_source_result("ListaSpam", url, status="unavailable", rating_label="Protegido", summary="Protección anti-bot activa.")

        rating_m = re.search(
            r'title="Valoraci[óo]n global:\s*([^"]+)"[^>]*class="phone_rating([^"]*)"',
            html_text,
            re.I,
        )
        rating_label = _clean_text(rating_m.group(1)) if rating_m else ""
        rating_class = rating_m.group(2) if rating_m else ""

        reports_m = re.search(
            r'class="n_reports".*?<span class="result">\s*(?:<a[^>]*>)?\s*([\d\.,]+)',
            html_text,
            re.S | re.I,
        )
        searches_m = re.search(
            r'class="n_search".*?<span class="result">\s*([\d\.,]+)',
            html_text,
            re.S | re.I,
        )
        last_m = re.search(
            r'class="l_search".*?<span class="result">(.*?)</span>',
            html_text,
            re.S | re.I,
        )
        op_m = re.search(r'<div class="operator">(.*?)</div>', html_text, re.S | re.I)
        type_m = re.search(r'<div class="type_of_call">(.*?)</div>', html_text, re.S | re.I)

        reports_count = _parse_int(reports_m.group(1) if reports_m else "0")
        searches_count = _parse_int(searches_m.group(1) if searches_m else "0")
        last_activity = _clean_text(last_m.group(1)) if last_m else None
        operator_reported = _clean_text(op_m.group(1)) if op_m else None
        call_type = _clean_text(type_m.group(1)) if type_m else None

        comments: List[Dict[str, Any]] = []
        comment_blocks = re.findall(r'(?is)<li class="comment-box"[^>]*>(.*?)</li>', html_text)
        for blk in comment_blocks[:15]:
            text_m = re.search(r'(?is)<p[^>]*itemprop="text"[^>]*>(.*?)</p>', blk)
            if not text_m:
                continue
            comment_text = _clean_text(text_m.group(1))
            if not comment_text:
                continue
            author_m = re.search(r'(?is)Por(?:&nbsp;|\s)*<span>(.*?)</span>', blk)
            time_m = re.search(r'(?is)<time[^>]*datetime="([^"]+)"[^>]*>(.*?)</time>', blk)
            if time_m:
                date_str = f"{time_m.group(1)[:10]} ({_clean_text(time_m.group(2))})"
            else:
                date_str = "Fecha reciente"
            c_rate_m = re.search(r'title="[^"]*marc[óo] este tel[ée]fono como\s*([^"]+)"', blk, re.I)
            c_cat = _clean_text(c_rate_m.group(1)) if c_rate_m else (rating_label or "Denuncia")
            comments.append({
                "source": "ListaSpam",
                "author": _clean_text(author_m.group(1)) if author_m else "Anónimo",
                "date": date_str,
                "category": c_cat,
                "text": comment_text,
                "url": url,
            })

        total_hits = max(reports_count, len(comments))
        low_rating = rating_label.lower()
        categories = [call_type] if call_type else []

        if total_hits > 0 or any(k in low_rating for k in ("peligroso", "molesto", "sospechoso")):
            if "peligroso" in low_rating or "result-1" in rating_class or total_hits >= 5:
                risk_level = "CRITICAL"
            elif "molesto" in low_rating or "sospechoso" in low_rating or "result-2" in rating_class or total_hits >= 2:
                risk_level = "HIGH"
            else:
                risk_level = "MEDIUM"

            return _make_source_result(
                "ListaSpam",
                url,
                status="found",
                risk_level=risk_level,
                rating_label=rating_label or "Reportado",
                reports_count=total_hits,
                searches_count=searches_count,
                operator_detected=operator_reported,
                categories=categories,
                last_activity=last_activity,
                comments=comments,
                summary=f"{rating_label or 'Reportado'}: {total_hits} denuncia(s) y {searches_count} búsquedas.",
            )

        return _make_source_result(
            "ListaSpam",
            url,
            status="clean",
            risk_level="CLEAN",
            rating_label=rating_label or "Sin denuncias",
            searches_count=searches_count,
            operator_detected=operator_reported,
            categories=categories,
            last_activity=last_activity,
            summary=f"0 denuncias registradas ({searches_count} búsquedas).",
        )
    except Exception:
        return _make_source_result("ListaSpam", url, status="unavailable", rating_label="Timeout / Error", summary="No se pudo consultar ListaSpam.")


async def _query_telefonospam(client: httpx.AsyncClient, clean_nat: str, country_code: str) -> Optional[Dict[str, Any]]:
    """Consulta TelefonoSpam.com para numeración española."""
    if country_code != "ES" or len(clean_nat) != 9:
        return None

    url = f"https://www.telefonospam.com/{clean_nat}"
    try:
        r = await client.get(url)
        if r.status_code != 200:
            return _make_source_result("TelefonoSpam", url, status="unavailable", rating_label=f"HTTP {r.status_code}", summary="Fuente temporalmente inaccesible.")

        html_text = _decode_response(r)
        reports_m = re.search(r"<li>Denuncias<b>(\d+)</b></li>", html_text, re.I)
        searches_m = re.search(r"<li>B[úu]squedas<b>(\d+)</b></li>", html_text, re.I)
        last_m = re.search(r"<li>[ÚU]ltima denuncia<b>(.*?)</b></li>", html_text, re.I)
        tag_m = re.search(r'<span class="fr-tag[^"]*">(.*?)</span>', html_text, re.S | re.I)
        entity_m = re.search(r"Seg[úu]n los usuarios:\s*<b>(.*?)</b>", html_text, re.S | re.I)

        reports_count = _parse_int(reports_m.group(1) if reports_m else "0")
        searches_count = _parse_int(searches_m.group(1) if searches_m else "0")
        last_activity = _clean_text(last_m.group(1)) if last_m else None
        tag_label = _clean_text(tag_m.group(1)) if tag_m else ""
        reported_entity = _clean_text(entity_m.group(1)) if entity_m else None

        comments: List[Dict[str, Any]] = []
        blocks = re.findall(r'(?is)<div id="comentario">(.*?)</div>\s*(?=<div id="comentario">|<div id=\'pags\'|<div id="pags")', html_text)
        if not blocks:
            # Fallback regex individual para bloques de comentario
            blocks = re.findall(r'(?is)<div id="comentario">(.*?<div id="com">.*?</div>)</div>', html_text)

        for blk in blocks[:15]:
            com_m = re.search(r'(?is)<div id="com">(.*?)</div>', blk)
            if not com_m:
                continue
            comment_text = _clean_text(com_m.group(1))
            if not comment_text:
                continue
            time_m = re.search(r'(?is)<time[^>]*datetime="([^"]+)"[^>]*>(.*?)</time>', blk)
            date_str = f"{time_m.group(1)[:10]} ({_clean_text(time_m.group(2))})" if time_m else "Reciente"
            type_m = re.search(r"Tipo de llamada:\s*<em>(.*?)</em>", blk, re.S | re.I)
            cat_str = _clean_text(type_m.group(1)) if type_m else (tag_label or "Denuncia")
            comments.append({
                "source": "TelefonoSpam",
                "author": "Anónimo",
                "date": date_str,
                "category": cat_str,
                "text": comment_text,
                "url": url,
            })

        total_hits = max(reports_count, len(comments))
        if total_hits > 0:
            low_tag = tag_label.lower()
            if any(k in low_tag for k in ("estafa", "fraude", "peligroso")) or total_hits >= 5:
                risk_level = "CRITICAL"
            elif total_hits >= 2 or "comercial" in low_tag or "cobros" in low_tag:
                risk_level = "HIGH"
            else:
                risk_level = "MEDIUM"

            return _make_source_result(
                "TelefonoSpam",
                url,
                status="found",
                risk_level=risk_level,
                rating_label=tag_label or "Denunciado",
                reports_count=total_hits,
                searches_count=searches_count,
                reported_entity=reported_entity,
                categories=[tag_label] if tag_label else [],
                last_activity=last_activity,
                comments=comments,
                summary=f"{total_hits} denuncia(s){f' ({tag_label})' if tag_label else ''}{f' · Atribuido a {reported_entity}' if reported_entity else ''}.",
            )

        return _make_source_result(
            "TelefonoSpam",
            url,
            status="clean",
            risk_level="CLEAN",
            rating_label="0 denuncias",
            searches_count=searches_count,
            summary="Sin denuncias registradas en TelefonoSpam.",
        )
    except Exception:
        return _make_source_result("TelefonoSpam", url, status="unavailable", rating_label="Timeout / Error", summary="No se pudo consultar TelefonoSpam.")


async def _query_shouldianswer(
    client: httpx.AsyncClient,
    clean_nat: str,
    clean_e164_digits: str,
    country_code: str,
) -> Dict[str, Any]:
    """Consulta ResponderONo.es / ShouldIAnswer (.co.uk / .net) y extrae JSON-LD y categorías."""
    if country_code == "ES":
        source_name = "ResponderONo"
        url = f"https://www.responderono.es/numero-de-telefono/{clean_nat}"
    elif country_code == "GB":
        source_name = "ShouldIAnswer UK"
        url = f"https://www.shouldianswer.co.uk/phone-number/{clean_nat}"
    else:
        source_name = "ShouldIAnswer"
        url = f"https://www.shouldianswer.net/phone-number/{clean_e164_digits}"

    try:
        r = await client.get(url)
        if r.status_code != 200:
            return _make_source_result(source_name, url, status="unavailable", rating_label=f"HTTP {r.status_code}", summary="Fuente temporalmente inaccesible.")

        html_text = _decode_response(r)
        rating_value = 2.5
        rating_count = 0
        review_count = 0

        for ld_raw in re.findall(r'(?is)<script type="application/ld\+json">(.*?)</script>', html_text):
            try:
                ld_json = json.loads(ld_raw)
                agg = ld_json.get("aggregateRating") or {}
                if agg:
                    rating_value = float(agg.get("ratingValue", 2.5))
                    rating_count = int(agg.get("ratingCount", 0))
                    review_count = int(agg.get("reviewCount", 0))
                    break
            except Exception:
                continue

        score_cls_m = re.search(r'<div class="score\s+([^"]+)"', html_text, re.I)
        score_cls = score_cls_m.group(1).lower() if score_cls_m else "unknown"

        cat_block_m = re.search(r'(?is)<div class="categories">.*?<ul>(.*?)</ul>', html_text)
        categories = [_clean_text(x) for x in re.findall(r"(?is)<li[^>]*>(.*?)</li>", cat_block_m.group(1))] if cat_block_m else []

        rat_block_m = re.search(r'(?is)<div class="ratings">.*?<ul>(.*?)</ul>', html_text)
        evals = [_clean_text(x) for x in re.findall(r"(?is)<li[^>]*>(.*?)</li>", rat_block_m.group(1))] if rat_block_m else []

        comments: List[Dict[str, Any]] = []
        # Extraer reseñas textuales reales (excluyendo formulario reviewNew)
        for rev_blk in re.findall(r'(?is)<div class="review\s+(?!reviewNew)[^"]*">(.*?)</div>\s*</div>', html_text)[:10]:
            rev_txt_m = re.search(r'(?is)(?:<div class="description"[^>]*>|<p[^>]*>)(.*?)</(?:div|p)>', rev_blk)
            rev_txt = _clean_text(rev_txt_m.group(1)) if rev_txt_m else ""
            if len(rev_txt) >= 5:
                comments.append({
                    "source": source_name,
                    "author": "Comunidad",
                    "date": "Valoración registrada",
                    "category": categories[0] if categories else score_cls.capitalize(),
                    "text": rev_txt,
                    "url": url,
                })

        total_reports = max(rating_count, review_count)
        if total_reports > 0 and not comments and (categories or evals):
            joined_summary = " · ".join(filter(None, [", ".join(evals), ", ".join(categories)]))
            comments.append({
                "source": source_name,
                "author": "Agregado comunitario",
                "date": "Resumen de votos",
                "category": categories[0] if categories else score_cls.capitalize(),
                "text": joined_summary,
                "url": url,
            })

        if total_reports > 0 or score_cls == "negative":
            cats_low = " ".join(categories).lower()
            if any(k in cats_low for k in ("estafa", "scam", "fraud", "phishing")) or (score_cls == "negative" and total_reports >= 5):
                risk_level = "CRITICAL"
            elif score_cls == "negative" or rating_value <= 2.0:
                risk_level = "HIGH"
            elif rating_value < 3.0:
                risk_level = "MEDIUM"
            else:
                risk_level = "CLEAN"

            label = "Negativa" if score_cls == "negative" else ("Positiva" if score_cls == "positive" else f"Nota {rating_value}/5")
            return _make_source_result(
                source_name,
                url,
                status="found",
                risk_level=risk_level,
                rating_label=f"{label} ({total_reports} votos)",
                reports_count=total_reports,
                categories=categories,
                comments=comments,
                summary=f"Calificación {label} ({total_reports} evaluaciones){f' · {', '.join(categories[:2])}' if categories else ''}.",
            )

        return _make_source_result(source_name, url, status="clean", risk_level="CLEAN", rating_label="Sin evaluaciones", summary="Sin reseñas registradas.")
    except Exception:
        return _make_source_result(source_name, url, status="unavailable", rating_label="Timeout / Error", summary=f"No se pudo consultar {source_name}.")


async def _query_cleverdialer(client: httpx.AsyncClient, clean_nat: str, country_code: str) -> Optional[Dict[str, Any]]:
    """Consulta CleverDialer (.es o .de) extrayendo bloqueos, estrellas y comentarios."""
    if country_code == "ES":
        url = f"https://www.cleverdialer.es/numero/{clean_nat}"
    elif country_code == "DE":
        url = f"https://www.cleverdialer.de/telefonnummer/{clean_nat}"
    else:
        return None

    try:
        r = await client.get(url)
        if r.status_code != 200:
            return _make_source_result("CleverDialer", url, status="unavailable", rating_label=f"HTTP {r.status_code}", summary="Sin ficha activa en CleverDialer.")

        html_text = _decode_response(r)
        is_caution = "cuidado con el número" in html_text.lower() or "cuidado con este número" in html_text.lower() or "vorsicht" in html_text.lower()
        rating_m = re.search(r'<div class="rating-text">\s*<span>([\d,\.]+)\s+(?:de|von)\s+5\s+(?:estrellas|sterne)</span>.*?(\d+)\s+(?:valoraci|bewertung)', html_text, re.S | re.I)
        stars_val = float(rating_m.group(1).replace(",", ".")) if rating_m else 0.0
        eval_count = int(rating_m.group(2)) if rating_m else 0

        blocks_m = re.search(r"(\d+)\s+(?:veces bloqueado|mal blockiert)", html_text, re.I)
        blocks_count = int(blocks_m.group(1)) if blocks_m else 0

        last_m = re.search(r"(?:Última llamada|Letzter Anruf):\s*<[^>]*>([^<]+)<", html_text, re.I)
        last_activity = _clean_text(last_m.group(1)) if last_m else None

        comments: List[Dict[str, Any]] = []
        row_pattern = r'(?is)<tr[^>]*data-timestamp="([^"]*)"[^>]*>.*?<span class="stars-(\d+)"[^>]*>.*?<td class="comment">(.*?)</td>\s*<td class="date-time">(.*?)</td>'
        for _ts, c_stars, c_text_raw, c_date_raw in re.findall(row_pattern, html_text)[:15]:
            c_text = _clean_text(c_text_raw)
            if not c_text:
                continue
            comments.append({
                "source": "CleverDialer",
                "author": "Usuario App",
                "date": _clean_text(c_date_raw) or "Reciente",
                "category": f"{c_stars}/5 estrellas",
                "text": c_text,
                "url": url,
            })

        total_reports = max(eval_count, len(comments))
        if total_reports > 0 or blocks_count > 0 or is_caution:
            if is_caution or blocks_count >= 3 or (total_reports > 0 and stars_val <= 1.5):
                risk_level = "HIGH"
            elif blocks_count > 0 or (total_reports > 0 and stars_val <= 2.5):
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW" if stars_val < 4 else "CLEAN"

            if risk_level == "LOW":
                risk_level = "MEDIUM"

            return _make_source_result(
                "CleverDialer",
                url,
                status="found",
                risk_level=risk_level,
                rating_label=f"{'⚠️ Cuidado · ' if is_caution else ''}{stars_val}/5 ({total_reports} val.)",
                reports_count=total_reports,
                blocks_count=blocks_count,
                last_activity=last_activity,
                comments=comments,
                summary=f"{total_reports} valoración(es) y {blocks_count} bloqueo(s) en app CleverDialer.",
            )

        return _make_source_result("CleverDialer", url, status="clean", risk_level="CLEAN", rating_label="0 valoraciones", summary="Sin reportes ni bloqueos en CleverDialer.")
    except Exception:
        return _make_source_result("CleverDialer", url, status="unavailable", rating_label="Timeout / Error", summary="No se pudo consultar CleverDialer.")


async def _query_tellows(client: httpx.AsyncClient, clean_nat: str, country_code: str) -> Optional[Dict[str, Any]]:
    """Consulta Tellows.es validando evaluaciones reales y extrayendo comentarios."""
    if country_code != "ES":
        return None

    url = f"https://www.tellows.es/num/{clean_nat}"
    try:
        r = await client.get(url)
        if r.status_code != 200:
            return _make_source_result("Tellows ES", url, status="unavailable", rating_label=f"HTTP {r.status_code}", summary="Fuente temporalmente inaccesible.")

        html_text = _decode_response(r)
        if "Just a moment" in html_text or "cf-challenge" in html_text.lower():
            return _make_source_result("Tellows ES", url, status="unavailable", rating_label="Protegido", summary="Protección anti-bot activa.")

        score_m = re.search(r"score/s(\d+)\.jpg", html_text)
        eval_m = re.search(r"Evaluaciones:\s*(?:<[^>]*>)*(\d+)", html_text, re.I)
        types_m = re.search(r"<b>Tipos de llamada:</b>\s*([^<\r\n]+)", html_text, re.I)
        name_m = re.search(r"<b>Nombre:</b>\s*([^<\r\n]+)", html_text, re.I)

        eval_count = int(eval_m.group(1)) if eval_m else 0
        score_val = int(score_m.group(1)) if score_m else 5
        call_types = _clean_text(types_m.group(1)) if types_m else None
        reported_entity = _clean_text(name_m.group(1)) if name_m else None

        comments: List[Dict[str, Any]] = []
        sc_idx = html_text.find('id="singlecomments"')
        if sc_idx != -1:
            sc_section = html_text[sc_idx:sc_idx + 25000]
            for li_blk in re.findall(r'(?is)<li id="\d+"[^>]*>(.*?)</li>', sc_section)[:15]:
                msg_m = re.search(r'(?is)<p class="mb-0"[^>]*>(.*?)</p>', li_blk)
                lead_m = re.search(r'(?is)<p class="lead[^>]*>(.*?)</p>', li_blk)
                meta_m = re.search(r'(?is)<div class="comment-meta">(.*?)</div>', li_blk)
                msg = _clean_text(msg_m.group(1)) if msg_m else ""
                lead = _clean_text(lead_m.group(1)) if lead_m else ""
                if not msg and not lead:
                    continue
                date_match = re.search(r"\d{2}/\d{2}/\d{2}(?:\s+\d{2}:\d{2})?", _clean_text(meta_m.group(1)) if meta_m else "")
                comments.append({
                    "source": "Tellows ES",
                    "author": "Usuario Tellows",
                    "date": date_match.group(0) if date_match else "Reciente",
                    "category": call_types or "Reporte Tellows",
                    "text": msg if msg else lead,
                    "url": url,
                })

        total_hits = max(eval_count, len(comments))
        # Solo considerar el Score de Tellows si existen evaluaciones o comentarios reales (s5 por defecto = neutro sin votos)
        if total_hits > 0:
            if score_val >= 8:
                risk_level = "CRITICAL"
            elif score_val >= 6:
                risk_level = "HIGH"
            elif score_val == 5:
                risk_level = "MEDIUM"
            else:
                risk_level = "CLEAN"

            return _make_source_result(
                "Tellows ES",
                url,
                status="found",
                risk_level=risk_level,
                rating_label=f"Score {score_val}/9 ({total_hits} eval.)",
                reports_count=total_hits,
                reported_entity=reported_entity,
                categories=[call_types] if call_types else [],
                comments=comments,
                summary=f"Tellows Score {score_val}/9 con {total_hits} evaluación(es){f' · {call_types}' if call_types else ''}.",
            )

        return _make_source_result("Tellows ES", url, status="clean", risk_level="CLEAN", rating_label="0 evaluaciones", summary="Sin valoraciones de usuarios en Tellows.")
    except Exception:
        return _make_source_result("Tellows ES", url, status="unavailable", rating_label="Timeout / Error", summary="No se pudo consultar Tellows.")


async def _query_800notes(client: httpx.AsyncClient, clean_nat: str, country_code: str) -> Optional[Dict[str, Any]]:
    """Consulta reportes comunitarios en 800Notes para numeración Norteamérica (+1)."""
    if country_code not in ("US", "CA") or len(clean_nat) != 10:
        return None

    formatted = f"1-{clean_nat[:3]}-{clean_nat[3:6]}-{clean_nat[6:]}"
    url = f"https://800notes.com/Phone.aspx/{formatted}"
    try:
        r = await client.get(url)
        if r.status_code != 200:
            return _make_source_result("800Notes", url, status="unavailable", rating_label=f"HTTP {r.status_code}", summary="No accesible.")

        html_text = _decode_response(r)
        comments: List[Dict[str, Any]] = []
        for blk in re.findall(r'(?is)<div class="oos_msg"[^>]*>(.*?)</div>\s*<div class="oos_ftr"', html_text)[:12]:
            txt = _clean_text(blk)
            if txt and "post pending moderator approval" not in txt.lower():
                comments.append({
                    "source": "800Notes",
                    "author": "Comunidad US/CA",
                    "date": "Reporte registrado",
                    "category": "Community Report",
                    "text": txt,
                    "url": url,
                })

        if comments:
            return _make_source_result(
                "800Notes",
                url,
                status="found",
                risk_level="HIGH" if len(comments) >= 3 else "MEDIUM",
                rating_label=f"{len(comments)} comentarios",
                reports_count=len(comments),
                comments=comments,
                summary=f"{len(comments)} reporte(s) comunitarios en 800Notes.",
            )
        return _make_source_result("800Notes", url, status="clean", risk_level="CLEAN", rating_label="0 comentarios", summary="Sin comentarios en 800Notes.")
    except Exception:
        return _make_source_result("800Notes", url, status="unavailable", rating_label="Timeout", summary="No se pudo consultar 800Notes.")


async def _fetch_single_leakcheck(client: httpx.AsyncClient, query_val: str) -> Dict[str, Any]:
    """Ejecuta una consulta individual contra la API pública de LeakCheck."""
    try:
        r = await client.get(f"https://leakcheck.io/api/public?check={quote(query_val)}", timeout=4.0)
        if r.status_code == 200:
            data = r.json()
            if data.get("success") and data.get("found", 0) > 0:
                return {
                    "found": int(data.get("found", 0)),
                    "fields": list(data.get("fields", [])),
                    "sources": list(data.get("sources", [])),
                }
    except Exception:
        pass
    return {"found": 0, "fields": [], "sources": []}


async def _fetch_phone_breaches(
    client: httpx.AsyncClient,
    e164_digits: str,
    national_digits: str,
) -> Dict[str, Any]:
    """Comprueba filtraciones de datos en formato internacional y nacional simultáneamente."""
    queries = []
    if len(e164_digits) >= 7:
        queries.append(e164_digits)
    if len(national_digits) >= 7 and national_digits != e164_digits:
        queries.append(national_digits)

    if not queries:
        return {
            "exposed": False,
            "count": 0,
            "sources": [],
            "fields": [],
            "risk_level": "CLEAN",
            "status_label": "0 FILTRACIONES REGISTRADAS (NÚMERO NO EXPUESTO)",
        }

    results = await asyncio.gather(*(_fetch_single_leakcheck(client, q) for q in queries), return_exceptions=True)

    merged_sources: List[str] = []
    merged_fields: List[str] = []
    source_names_per_query: List[set] = []
    counts_per_query: List[int] = []

    for res in results:
        if not isinstance(res, dict) or res.get("found", 0) <= 0:
            continue
        counts_per_query.append(res["found"])
        q_names = set()
        for f in res.get("fields", []):
            if f not in merged_fields:
                merged_fields.append(f)
        for s in res.get("sources", [])[:20]:
            s_name = (s.get("name") if isinstance(s, dict) else str(s)) or "Filtración pública"
            s_date = s.get("date") if isinstance(s, dict) else None
            label = f"{s_name} ({s_date})" if s_date else s_name
            q_names.add(label)
            if label not in merged_sources:
                merged_sources.append(label)
        source_names_per_query.append(q_names)

    if not counts_per_query:
        return {
            "exposed": False,
            "count": 0,
            "sources": [],
            "fields": [],
            "risk_level": "CLEAN",
            "status_label": "0 FILTRACIONES REGISTRADAS (NÚMERO NO EXPUESTO)",
        }

    if len(counts_per_query) == 2 and source_names_per_query[0].isdisjoint(source_names_per_query[1]):
        total_count = counts_per_query[0] + counts_per_query[1]
    else:
        total_count = max(counts_per_query)

    risk_level = "CRITICAL" if ("password" in merged_fields or total_count >= 5) else "HIGH"
    return {
        "exposed": True,
        "count": total_count,
        "sources": merged_sources[:20],
        "fields": merged_fields,
        "risk_level": risk_level,
        "status_label": f"EXPUESTO EN {total_count} FILTRACIONES MASIVAS",
    }


async def _fetch_news_mentions(
    client: httpx.AsyncClient,
    variants: List[str],
    nat_digits: str,
    country_code: str,
) -> List[Dict[str, str]]:
    """Comprueba menciones en prensa y alertas policiales publicadas vía Google News RSS."""
    if not nat_digits:
        return []
    query = " OR ".join(f'"{v}"' for v in variants[:4])
    hl, gl = ("es", "ES") if country_code == "ES" else ("en", "US")
    rss_url = f"https://news.google.com/rss/search?q={quote(query)}&hl={hl}&gl={gl}&ceid={gl}:{hl}"

    items: List[Dict[str, str]] = []
    try:
        r = await client.get(rss_url, timeout=4.0)
        if r.status_code != 200 or "<item>" not in r.text:
            return []
        root = ET.fromstring(r.text)
        for item in root.findall(".//item")[:8]:
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date = (item.findtext("pubDate") or "").strip()
            desc = _clean_text(item.findtext("description") or "")
            digits_in_entry = re.sub(r"\D", "", f"{title} {desc}")
            # Verificar coincidencia real del número para evitar ruido
            if nat_digits in digits_in_entry:
                items.append({
                    "source": "Prensa / Google News",
                    "title": title,
                    "snippet": desc[:240],
                    "url": link,
                    "date": pub_date[:16],
                })
    except Exception:
        pass
    return items


async def _fetch_optional_web_search(
    client: httpx.AsyncClient,
    variants_query: str,
    nat_digits: str,
    country_code: str,
) -> Dict[str, Any]:
    """Consulta menciones en X/Twitter y Web mediante APIs opcionales (Serper o Brave Search)."""
    serper_key = os.getenv("SERPER_API_KEY", "").strip()
    brave_key = os.getenv("BRAVE_SEARCH_API_KEY", "").strip()
    items: List[Dict[str, str]] = []

    if serper_key:
        try:
            queries = [
                ("Google Web", f"({variants_query}) (estafa OR fraude OR timo OR denuncia OR estafador OR spam OR scam)"),
                ("X / Twitter", f"site:x.com OR site:twitter.com ({variants_query})"),
            ]

            async def _serper(label: str, q_str: str) -> None:
                resp = await client.post(
                    "https://google.serper.dev/search",
                    headers={"X-API-KEY": serper_key, "Content-Type": "application/json"},
                    json={"q": q_str, "gl": "es" if country_code == "ES" else "us", "hl": "es" if country_code == "ES" else "en", "num": 6},
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for row in data.get("organic", [])[:5]:
                        items.append({
                            "source": label,
                            "title": row.get("title") or "",
                            "snippet": row.get("snippet") or "",
                            "url": row.get("link") or "",
                            "date": row.get("date") or "",
                        })

            await asyncio.gather(*(_serper(lbl, q) for lbl, q in queries), return_exceptions=True)
            return {"api_configured": True, "provider": "Serper (Google Search + X)", "items": items}
        except Exception:
            pass

    if brave_key:
        try:
            q_str = f"({variants_query})"
            resp = await client.get(
                "https://api.search.brave.com/res/v1/web/search",
                params={"q": q_str, "count": 8},
                headers={"X-Subscription-Token": brave_key, "Accept": "application/json"},
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                for row in data.get("web", {}).get("results", [])[:8]:
                    url_val = row.get("url") or ""
                    src_lbl = "X / Twitter" if ("x.com/" in url_val or "twitter.com/" in url_val) else "Brave Web"
                    items.append({
                        "source": src_lbl,
                        "title": row.get("title") or "",
                        "snippet": _clean_text(row.get("description") or ""),
                        "url": url_val,
                        "date": row.get("age") or "",
                    })
            return {"api_configured": True, "provider": "Brave Search API", "items": items}
        except Exception:
            pass

    return {
        "api_configured": False,
        "provider": None,
        "items": [],
        "hint": (
            "X/Twitter y Google bloquean rastreos anónimos automatizados. Configura opcionalmente "
            "SERPER_API_KEY o BRAVE_SEARCH_API_KEY en backend/.env para extraer hilos sociales y menciones web automáticamente, "
            "o usa el enlace directo de búsqueda multiformato en X (Twitter)."
        ),
    }


def _consolidate_reputation(
    sources: List[Dict[str, Any]],
    news_items: List[Dict[str, str]],
    web_items: List[Dict[str, str]],
    tariff_warning: Optional[str],
) -> Dict[str, Any]:
    """Consolida puntuación, nivel de riesgo, palabras clave de fraude y feed cronológico."""
    comments_feed: List[Dict[str, Any]] = []
    reported_entities: List[str] = []
    reported_categories: List[str] = []
    detected_fraud_keywords: List[str] = []
    detected_spam_keywords: List[str] = []

    total_reports = 0
    total_searches = 0
    total_blocks = 0
    highest_risk = "CLEAN"
    positive_sources: List[str] = []

    for src in sources:
        if src.get("status") == "found":
            positive_sources.append(src["source"])
            if RISK_PRIORITY.get(src["risk_level"], 1) > RISK_PRIORITY.get(highest_risk, 1):
                highest_risk = src["risk_level"]

        total_reports += int(src.get("reports_count") or 0)
        total_searches = max(total_searches, int(src.get("searches_count") or 0))
        total_blocks += int(src.get("blocks_count") or 0)

        ent = src.get("reported_entity")
        if ent and ent not in reported_entities:
            reported_entities.append(ent)

        for cat in src.get("categories", []):
            if cat and cat not in reported_categories:
                reported_categories.append(cat)

        blob_src = f"{src.get('rating_label', '')} {' '.join(src.get('categories', []))}"
        for kw in _detect_keywords(blob_src, HIGH_FRAUD_KEYWORDS):
            if kw not in detected_fraud_keywords:
                detected_fraud_keywords.append(kw)
        for kw in _detect_keywords(blob_src, SPAM_COMMERCIAL_KEYWORDS):
            if kw not in detected_spam_keywords:
                detected_spam_keywords.append(kw)

        for c in src.get("comments", []):
            c_text = f"{c.get('category', '')} {c.get('text', '')}"
            fraud_kws = _detect_keywords(c_text, HIGH_FRAUD_KEYWORDS)
            spam_kws = _detect_keywords(c_text, SPAM_COMMERCIAL_KEYWORDS)
            for kw in fraud_kws:
                if kw not in detected_fraud_keywords:
                    detected_fraud_keywords.append(kw)
            for kw in spam_kws:
                if kw not in detected_spam_keywords:
                    detected_spam_keywords.append(kw)

            comments_feed.append({
                **c,
                "has_fraud_keyword": len(fraud_kws) > 0,
                "matched_keywords": fraud_kws[:4],
            })

    # Analizar también menciones en prensa/web por palabras clave de estafa
    for item in news_items + web_items:
        txt = f"{item.get('title', '')} {item.get('snippet', '')}"
        for kw in _detect_keywords(txt, HIGH_FRAUD_KEYWORDS):
            if kw not in detected_fraud_keywords:
                detected_fraud_keywords.append(kw)

    # Priorizar comentarios con palabras clave de fraude primero
    comments_feed.sort(key=lambda x: 0 if x.get("has_fraud_keyword") else 1)

    has_fraud_signals = len(detected_fraud_keywords) > 0
    if has_fraud_signals and (total_reports > 0 or comments_feed or news_items or web_items):
        highest_risk = "CRITICAL"
    elif tariff_warning and total_reports > 0:
        highest_risk = "CRITICAL"

    # Cálculo unificado de puntuación 1..9 y veredicto
    if highest_risk == "CRITICAL" or has_fraud_signals:
        score = 9 if has_fraud_signals else 8
        if has_fraud_signals:
            status = "PELIGROSO / POSIBLE ESTAFA REPORTADA"
            score_label = f"{score}/9 (Alerta Crítica: Indicadores de Estafa/Fraude)"
            detail = (
                f"Detectadas {total_reports} denuncia(s) en {', '.join(positive_sources) or 'fuentes OSINT'} "
                f"con palabras clave críticas de fraude ({', '.join(detected_fraud_keywords[:6])})."
            )
        else:
            status = "ALTO SPAM / PELIGROSO"
            score_label = f"{score}/9 (Spam Crítico / Denuncias Múltiples)"
            detail = f"Número marcado como peligroso con {total_reports} denuncias acumuladas en {', '.join(positive_sources)}."
        risk_level = "CRITICAL"
    elif highest_risk == "HIGH" or total_reports >= 3 or total_blocks >= 2:
        score = 7
        risk_level = "HIGH"
        status = "ALTO RIESGO / TELEMARKETING O ACOSO"
        score_label = f"{score}/9 (Múltiples Denuncias Comunitarias)"
        detail = f"Registra {total_reports} denuncia(s) y {total_blocks} bloqueo(s) en {', '.join(positive_sources)}."
    elif highest_risk == "MEDIUM" or total_reports >= 1 or total_blocks >= 1:
        score = 5
        risk_level = "MEDIUM"
        status = "SOSPECHOSO / REPORTES MODERADOS"
        score_label = f"{score}/9 (Reportes Recientes)"
        detail = f"Actividad reportada ({total_reports} denuncia(s)) en {', '.join(positive_sources)}. Revisar testimonios adjuntos."
    else:
        score = 1
        risk_level = "CLEAN"
        status = "SIN REPORTES EN BASES TELEFÓNICAS"
        score_label = "1/9 (Sin denuncias activas en bases consultadas)"
        detail = (
            f"No figuran denuncias activas en los directorios consultados"
            f"{f' (máximo {total_searches} búsquedas registradas)' if total_searches > 0 else ''}. "
            "Comprueba la búsqueda en vivo de X/Twitter si sospechas de una estafa muy reciente."
        )

    all_keywords = detected_fraud_keywords + [k for k in detected_spam_keywords if k not in detected_fraud_keywords]

    return {
        "status": status,
        "risk_level": risk_level,
        "score": score,
        "score_label": score_label,
        "searches": str(total_searches),
        "total_searches": total_searches,
        "total_reports": total_reports,
        "total_blocks": total_blocks,
        "comments": len(comments_feed),
        "detail": detail,
        "positive_sources": positive_sources,
        "detected_keywords": all_keywords[:12],
        "has_fraud_alert": has_fraud_signals,
        "reported_entities": reported_entities[:6],
        "reported_categories": reported_categories[:8],
        "sources_checked": sources,
        "comments_feed": comments_feed[:20],
    }


def _build_quick_checks(
    e164_format: str,
    national_number: str,
    clean_e164_digits: str,
    country_code: str,
    variants: Dict[str, Any],
) -> List[Dict[str, str]]:
    """Genera accesos directos útiles a X/Twitter (multiformato), bases telefónicas e identificadores."""
    cc_lower = country_code.lower() if country_code != "INTL" else "es"
    truecaller_target = national_number if country_code == "ES" else clean_e164_digits
    x_query = " OR ".join(f'"{v}"' for v in variants["formats"][:5])

    checks = [
        {
            "name": "X / Twitter (Hilos en Vivo)",
            "url": f"https://x.com/search?q={quote(x_query)}&src=typed_query&f=live",
            "label": "Buscar menciones recientes de estafas en X/Twitter (multiformato)",
        },
        {
            "name": "Truecaller",
            "url": f"https://www.truecaller.com/search/{cc_lower}/{quote(truecaller_target)}",
            "label": "Consultar nombre asociado en Truecaller",
        },
        {
            "name": "Sync.me",
            "url": f"https://sync.me/search/?number={quote(e164_format)}",
            "label": "Consultar identificador en Sync.me",
        },
        {
            "name": "ListaSpam",
            "url": f"https://www.listaspam.com/busca.php?Telefono={quote(national_number)}",
            "label": "Abrir ficha completa en ListaSpam",
        },
    ]
    if country_code == "ES":
        checks.append({
            "name": "TelefonoSpam",
            "url": f"https://www.telefonospam.com/{quote(national_number)}",
            "label": "Abrir ficha en TelefonoSpam",
        })
        checks.append({
            "name": "ResponderONo",
            "url": f"https://www.responderono.es/numero-de-telefono/{quote(national_number)}",
            "label": "Abrir ficha en ResponderONo",
        })
    return checks


async def analyze_phone_number(raw_phone: str) -> Dict[str, Any]:
    """Ejecuta el pipeline OSINT completo sobre un número de teléfono."""
    cleaned = raw_phone.strip()
    if not cleaned:
        return {"error": "Número de teléfono no proporcionado o inválido"}

    digits_only = re.sub(r"\D", "", cleaned)
    if len(digits_only) < 4:
        return {"error": "Número de teléfono con longitud insuficiente"}

    default_region = "ES" if (not cleaned.startswith("+") and len(digits_only) == 9 and digits_only[0] in "6789") else None

    if phonenumbers:
        try:
            parse_target = cleaned if cleaned.startswith("+") else (cleaned if default_region else f"+{cleaned}")
            parsed = phonenumbers.parse(parse_target, default_region)
        except Exception:
            try:
                parsed = phonenumbers.parse(f"+{cleaned}", None)
            except Exception as exc:
                return {"error": f"Formato telefónico no reconocido: {str(exc)}"}
    else:
        parsed = None

    if parsed and phonenumbers.is_possible_number(parsed):
        is_valid = phonenumbers.is_valid_number(parsed)
        c_code_str = phonenumbers.region_code_for_number(parsed) or "INTL"
        flag = FLAG_MAP.get(c_code_str, "🌐")
        dial_code = f"+{parsed.country_code}"
        national_number = str(parsed.national_number)

        type_code = phonenumbers.number_type(parsed)
        line_type = LINE_TYPE_MAP.get(type_code, "Telefonía General")

        geo_desc = (
            geocoder.description_for_number(parsed, "es")
            or geocoder.description_for_number(parsed, "en")
            or COUNTRY_NAME_FALLBACK.get(c_code_str)
            or "Internacional"
        )
        carrier_name = carrier.name_for_number(parsed, "es") or carrier.name_for_number(parsed, "en") or None
        tz_list = list(timezone.time_zones_for_number(parsed)) or ["UTC"]

        e164_format = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
        international_format = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
        national_format = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
    else:
        is_valid = len(digits_only) >= 8
        c_code_str = "ES" if len(digits_only) == 9 and digits_only[0] in "6789" else "INTL"
        flag = FLAG_MAP.get(c_code_str, "🌐")
        dial_code = "+34" if c_code_str == "ES" else "+?"
        national_number = digits_only
        line_type = "Móvil / Celular" if (c_code_str == "ES" and digits_only[0] in "67") else "Telefonía General"
        geo_desc = "España" if c_code_str == "ES" else "Internacional"
        carrier_name = None
        tz_list = ["Europe/Madrid"] if c_code_str == "ES" else ["UTC"]
        e164_format = f"+{digits_only}"
        international_format = f"+{digits_only}"
        national_format = digits_only

    clean_e164_digits = e164_format.replace("+", "")
    network_codes = _resolve_mcc_mnc(c_code_str, carrier_name)
    numbering_intel = _resolve_spain_numbering_intel(c_code_str, national_number, geo_desc)
    variants = _extract_number_variants(national_number, e164_format, international_format, national_format)

    outbound_proxy = os.getenv("OUTBOUND_PROXY", "").strip() or None
    client_kwargs: Dict[str, Any] = {
        "headers": {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        },
        "timeout": 5.5,
        "follow_redirects": True,
    }
    if outbound_proxy and is_proxy_reachable(outbound_proxy):
        client_kwargs["proxy"] = outbound_proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        tasks = [
            _query_listaspam(client, national_number),
            _query_telefonospam(client, national_number, c_code_str),
            _query_shouldianswer(client, national_number, clean_e164_digits, c_code_str),
            _query_cleverdialer(client, national_number, c_code_str),
            _query_tellows(client, national_number, c_code_str),
            _query_800notes(client, national_number, c_code_str),
            _fetch_phone_breaches(client, clean_e164_digits, national_number),
            _fetch_news_mentions(client, variants["formats"], national_number, c_code_str),
            _fetch_optional_web_search(client, variants["search_or_query"], national_number, c_code_str),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    source_results: List[Dict[str, Any]] = []
    for res in results[:6]:
        if isinstance(res, dict):
            source_results.append(res)

    breaches = results[6] if isinstance(results[6], dict) else {
        "exposed": False,
        "count": 0,
        "sources": [],
        "fields": [],
        "risk_level": "CLEAN",
        "status_label": "0 FILTRACIONES REGISTRADAS",
    }
    news_items = results[7] if isinstance(results[7], list) else []
    web_mentions = results[8] if isinstance(results[8], dict) else {"api_configured": False, "provider": None, "items": []}

    # Enriquecer el operador con lo reportado por ListaSpam si libphonenumber no trajo uno concreto
    resolved_carrier = carrier_name
    if not resolved_carrier:
        for src in source_results:
            if src.get("operator_detected"):
                resolved_carrier = src["operator_detected"]
                break

    reputation = _consolidate_reputation(
        sources=source_results,
        news_items=news_items,
        web_items=web_mentions.get("items", []),
        tariff_warning=numbering_intel.get("tariff_warning"),
    )

    direct_messaging = {
        "whatsapp_url": f"https://wa.me/{clean_e164_digits}",
        "whatsapp_label": "Abrir Chat WhatsApp Web (Directo sin guardar contacto)",
        "telegram_url": f"https://t.me/+{clean_e164_digits}",
        "telegram_label": "Abrir Perfil Telegram",
        "x_search_url": f"https://x.com/search?q={quote(variants['search_or_query'])}&src=typed_query&f=live",
        "x_search_label": "Buscar Hilos en X/Twitter (Multiformato)",
    }

    quick_checks = _build_quick_checks(
        e164_format=e164_format,
        national_number=national_number,
        clean_e164_digits=clean_e164_digits,
        country_code=c_code_str,
        variants=variants,
    )

    return {
        "raw_query": raw_phone,
        "is_valid": is_valid,
        "country": numbering_intel.get("geo_enriched") or geo_desc,
        "country_code": c_code_str,
        "flag": flag,
        "dial_code": dial_code,
        "national_number": national_number,
        "e164_format": e164_format,
        "international_format": international_format,
        "national_format": national_format,
        "variants": variants["formats"],
        "line_type": line_type,
        "tariff_info": {
            "tariff_class": numbering_intel["tariff_class"],
            "tariff_warning": numbering_intel["tariff_warning"],
            "special_risk": numbering_intel["special_risk"],
            "portability_note": numbering_intel["portability_note"],
        },
        "carrier": resolved_carrier or "Operador según asignación local / Portabilidad",
        "network_codes": network_codes,
        "timezones": tz_list[:2],
        "reputation": reputation,
        "breaches": breaches,
        "news_mentions": news_items,
        "web_mentions": web_mentions,
        "direct_messaging": direct_messaging,
        "quick_checks": quick_checks,
    }
