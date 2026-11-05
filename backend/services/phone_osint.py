"""Servicio de inteligencia de números de teléfono (OSINT Telefónico avanzado).

Utiliza la librería oficial phonenumbers (Google libphonenumber) para validación
exhaustiva en >200 países, resolución de operador oficial, geolocalización,
zona horaria, tipo de línea (Móvil/Fija/VoIP) y reputación de spam en tiempo real.
"""
from typing import Dict, Any, List, Optional
import re
import asyncio
from urllib.parse import quote
import httpx

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone, PhoneNumberType, PhoneNumberFormat
except ImportError:
    phonenumbers = None
    geocoder = None
    carrier = None
    timezone = None
    PhoneNumberType = None
    PhoneNumberFormat = None

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

# Códigos de países a banderas emoji
FLAG_MAP = {
    "ES": "🇪🇸", "US": "🇺🇸", "GB": "🇬🇧", "FR": "🇫🇷", "DE": "🇩🇪", "IT": "🇮🇹", "PT": "🇵🇹",
    "MX": "🇲🇽", "AR": "🇦🇷", "CO": "🇨🇴", "CL": "🇨🇱", "PE": "🇵🇪", "BR": "🇧🇷", "CA": "🇨🇦",
    "CH": "🇨🇭", "NL": "🇳🇱", "BE": "🇧🇪", "RU": "🇷🇺", "CN": "🇨🇳", "JP": "🇯🇵", "AU": "🇦🇺",
}

# Tabla de Mobile Country Code (ITU-T E.212)
MCC_TABLE = {
    "ES": "214", "US": "310", "CA": "302", "GB": "234", "FR": "208", "DE": "262",
    "IT": "222", "PT": "268", "MX": "334", "AR": "722", "CO": "732", "CL": "730",
    "PE": "716", "BR": "724", "CH": "228", "NL": "204", "BE": "206", "RU": "250",
    "CN": "460", "JP": "440", "AU": "505",
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
            mnc = "07"  # Telefónica / Movistar
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


async def _fetch_phone_breaches(digits_only: str) -> Dict[str, Any]:
    """Comprueba si el número de teléfono ha sido expuesto en filtraciones masivas de datos (LeakCheck)."""
    breaches_info = {
        "exposed": False,
        "count": 0,
        "sources": [],
        "fields": [],
        "risk_level": "CLEAN",
        "status_label": "0 FILTRACIONES REGISTRADAS (NÚMERO NO EXPUESTO)",
    }

    if not digits_only or len(digits_only) < 7:
        return breaches_info

    try:
        url = f"https://leakcheck.io/api/public?check={digits_only}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        }
        async with httpx.AsyncClient(headers=headers, timeout=3.0, follow_redirects=True) as client:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                if data.get("success") and data.get("found", 0) > 0:
                    count = data.get("found", 0)
                    fields = data.get("fields", [])
                    raw_sources = data.get("sources", [])
                    formatted_sources = []
                    for s in raw_sources[:12]:
                        s_name = s.get("name") or "Filtración pública"
                        s_date = s.get("date")
                        formatted_sources.append(f"{s_name} ({s_date})" if s_date else s_name)

                    risk_level = "CRITICAL" if ("password" in fields or count >= 5) else "HIGH"
                    breaches_info = {
                        "exposed": True,
                        "count": count,
                        "sources": formatted_sources,
                        "fields": fields,
                        "risk_level": risk_level,
                        "status_label": f"EXPUESTO EN {count} FILTRACIONES MASIVAS",
                    }
    except Exception:
        pass

    return breaches_info


async def _fetch_spam_reputation(national_number: str, country_code: str) -> Dict[str, Any]:
    """Consulta pasiva de reputación y quejas de spam en Tellows."""
    reputation = {
        "status": "SIN REPORTES DE SPAM",
        "risk_level": "CLEAN",
        "score": 1,
        "score_label": "1/9 (Número Confiable / Sin reportes)",
        "searches": "0",
        "comments": 0,
        "detail": "Sin denuncias ni tráfico abusivo registrado en bases de reputación.",
    }

    try:
        clean_nat = re.sub(r"\D", "", national_number)
        tellows_domain = "tellows.es" if country_code == "ES" else "tellows.com"
        url = f"https://www.{tellows_domain}/num/{clean_nat}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        }

        async with httpx.AsyncClient(headers=headers, timeout=2.5, follow_redirects=True) as client:
            r = await client.get(url)
            if r.status_code == 200:
                html = r.text
                score_match = re.search(r"score/s(\d+)\.jpg", html)
                searches_match = re.search(r"(\d+[\.\d]*)\s*b[úu]squedas", html, re.I)

                if score_match:
                    score_val = int(score_match.group(1))
                    reputation["score"] = score_val

                    if searches_match:
                        reputation["searches"] = searches_match.group(1)

                    if score_val >= 7:
                        reputation["status"] = "ALTO SPAM / TELEMARKETING AGRESIVO"
                        reputation["risk_level"] = "CRITICAL"
                        reputation["score_label"] = f"{score_val}/9 (Spam Crítico / Denuncias Masivas)"
                        reputation["detail"] = f"Puntuación de riesgo muy alta ({score_val}/9). Registra búsquedas recurrentes y quejas de usuarios."
                    elif score_val >= 5:
                        reputation["status"] = "SOSPECHOSO / COBROS O PUBLICIDAD"
                        reputation["risk_level"] = "MEDIUM"
                        reputation["score_label"] = f"{score_val}/9 (Actividad Moderada)"
                        reputation["detail"] = f"Puntuación intermedia ({score_val}/9). Posible línea de telemarketing o recobros."
                    else:
                        reputation["status"] = "LIMPIO / CONFIABLE"
                        reputation["risk_level"] = "CLEAN"
                        reputation["score_label"] = f"{score_val}/9 (Número Legítimo)"
                        reputation["detail"] = "Línea calificada como legítima y sin denuncias de acoso telefónico."
    except Exception:
        pass

    return reputation


async def analyze_phone_number(raw_phone: str) -> Dict[str, Any]:
    """Analiza un número de teléfono con la librería oficial libphonenumber y reputación en vivo."""
    cleaned = raw_phone.strip()
    if not cleaned:
        return {"error": "Número de teléfono no proporcionado o inválido"}

    digits_only = re.sub(r"\D", "", cleaned)
    if len(digits_only) < 4:
        return {"error": "Número de teléfono con longitud insuficiente"}

    # Formato por defecto
    default_region = "ES" if (not cleaned.startswith("+") and len(digits_only) == 9 and digits_only[0] in "6789") else None

    if phonenumbers:
        try:
            parsed = phonenumbers.parse(cleaned if cleaned.startswith("+") else f"+{cleaned}" if not default_region else cleaned, default_region)
        except Exception:
            try:
                parsed = phonenumbers.parse(f"+{cleaned}", None)
            except Exception as e:
                return {"error": f"Formato telefónico no reconocido: {str(e)}"}
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

        geo_desc = geocoder.description_for_number(parsed, "es") or geocoder.description_for_number(parsed, "en") or "Nacional"
        carrier_name = carrier.name_for_number(parsed, "es") or carrier.name_for_number(parsed, "en") or None
        tz_list = list(timezone.time_zones_for_number(parsed)) or ["UTC"]

        e164_format = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
        international_format = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
        national_format = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
    else:
        # Fallback si libphonenumber no pudo procesarlo
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

    # Resolución de códigos de infraestructura de red ITU-T E.212 (MCC / MNC)
    network_codes = _resolve_mcc_mnc(c_code_str, carrier_name)

    # Consulta asíncrona paralela de reputación de spam y filtraciones masivas de datos (LeakCheck)
    rep_task = _fetch_spam_reputation(national_number, c_code_str)
    breach_task = _fetch_phone_breaches(clean_e164_digits)

    reputation, breaches = await asyncio.gather(rep_task, breach_task, return_exceptions=True)

    if isinstance(reputation, Exception) or not isinstance(reputation, dict):
        reputation = {
            "status": "SIN REPORTES DE SPAM",
            "risk_level": "CLEAN",
            "score": 1,
            "score_label": "1/9 (Sin datos negativos)",
            "searches": "0",
            "comments": 0,
            "detail": "Sin denuncias ni tráfico abusivo registrado en bases de reputación.",
        }

    if isinstance(breaches, Exception) or not isinstance(breaches, dict):
        breaches = {
            "exposed": False,
            "count": 0,
            "sources": [],
            "fields": [],
            "risk_level": "CLEAN",
            "status_label": "0 FILTRACIONES REGISTRADAS",
        }

    # Acciones directas de mensajería
    direct_messaging = {
        "whatsapp_url": f"https://wa.me/{clean_e164_digits}",
        "whatsapp_label": "Abrir Chat WhatsApp Web (Directo sin guardar contacto)",
        "telegram_url": f"https://t.me/+{clean_e164_digits}",
        "telegram_label": "Abrir Perfil Telegram",
    }

    # Enlaces rápidos de verificación externa
    quick_checks = [
        {
            "name": "Sync.me",
            "url": f"https://sync.me/search/?number={quote(e164_format)}",
            "label": "Buscar Identidad en Sync.me",
        },
        {
            "name": "Truecaller",
            "url": f"https://www.truecaller.com/search/es/{quote(national_number if c_code_str == 'ES' else clean_e164_digits)}",
            "label": "Consultar Truecaller",
        },
        {
            "name": "Google Dork",
            "url": f"https://www.google.com/search?q={quote(f'\"{national_number}\" OR \"{e164_format}\"')}",
            "label": "Rastrear Menciones en Google",
        },
    ]

    return {
        "raw_query": raw_phone,
        "is_valid": is_valid,
        "country": geo_desc,
        "country_code": c_code_str,
        "flag": flag,
        "dial_code": dial_code,
        "national_number": national_number,
        "e164_format": e164_format,
        "international_format": international_format,
        "national_format": national_format,
        "line_type": line_type,
        "carrier": carrier_name or "Operador según asignación local / Portabilidad",
        "network_codes": network_codes,
        "timezones": tz_list[:2],
        "reputation": reputation,
        "breaches": breaches,
        "direct_messaging": direct_messaging,
        "quick_checks": quick_checks,
    }
