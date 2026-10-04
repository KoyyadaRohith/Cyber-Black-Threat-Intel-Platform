import csv
import ipaddress
import json
import logging
from datetime import datetime, timezone

from config import Config
from services import abuseipdb as abuse
from services import virustotal as vt
from services import whois_lookup as whois
from services import risk_scoring as risk
from services import recommendations as recs
from services import threat_summary as summary

logger = logging.getLogger(__name__)
CACHE_FILE = Config.DB_FOLDER / 'threat_intel_cache.csv'

CACHE_FIELDS = [
    'ip_address',
    'timestamp_utc',
    'abuse_json',
    'vt_json',
    'whois_json',
    'risk_score',
    'classification',
    'recommendations_json',
    'last_updated_utc',
    'source_status',
    'cache_age_hours'
]


def _read_csv_rows():
    cache_path = CACHE_FILE
    if not cache_path.exists():
        return []

    try:
        with cache_path.open(mode='r', encoding='utf-8', newline='') as cache_file:
            reader = csv.DictReader(cache_file)
            return list(reader)
    except OSError:
        logger.exception("Failed to read threat-intelligence cache")
        return []


def _write_csv_rows(rows):
    cache_path = CACHE_FILE
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with cache_path.open(mode='w', encoding='utf-8', newline='') as cache_file:
        writer = csv.DictWriter(cache_file, fieldnames=CACHE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _json_dumps_safe(value):
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return json.dumps({})


def _json_loads_safe(value, default=None):
    if default is None:
        default = {}
    try:
        if value is None or value == '':
            return default
        return json.loads(value)
    except Exception:
        return default


def _normalize_ip(ip: str) -> str:
    ip = (ip or '').strip()
    ipaddress.ip_address(ip)
    return str(ipaddress.ip_address(ip))


def _parse_time_utc(timestamp: str) -> datetime:
    if not timestamp:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        if timestamp.endswith('Z'):
            timestamp = timestamp[:-1] + '+00:00'
        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _cache_age_hours(now: datetime, then: datetime) -> float:
    delta = now - then
    return round(delta.total_seconds() / 3600.0, 3)


def _build_details(ip: str, abuse_data: dict, vt_data: dict, whois_data: dict, computed_meta: dict):
    risk_profile = risk.calculate_risk_score(abuse_data, vt_data, whois_data)
    threat_sum = summary.generate_threat_summary(
        ip,
        risk_profile['score'],
        risk_profile['classification'],
        abuse_data,
        vt_data,
        whois_data
    )
    recommendations = recs.get_recommendations(risk_profile['classification'])

    return {
        'ip': ip,
        'risk': risk_profile,
        'abuse': abuse_data,
        'vt': vt_data,
        'whois': whois_data,
        'summary': threat_sum,
        'recommendations': recommendations,
        'intel_meta': computed_meta
    }


def _refresh_from_sources(ip: str, cfg: dict):
    use_mock = cfg.get('mock_mode', True)

    if use_mock:
        abuse_data = abuse.get_mock_abuse_data(ip)
        vt_data = vt.get_mock_virustotal_data(ip)
        whois_data = whois.get_mock_whois_data(ip)
    else:
        abuse_key = cfg.get('abuseipdb_key') or Config.ABUSEIPDB_API_KEY
        virustotal_key = cfg.get('virustotal_key') or Config.VIRUSTOTAL_API_KEY
        abuse_data = abuse.check_ip_abuse(ip, abuse_key)
        vt_data = vt.check_ip_virustotal(ip, virustotal_key)
        whois_data = whois.get_whois_info(ip)

    computed_meta = {}
    return abuse_data, vt_data, whois_data, computed_meta


def _select_best_cached_row(ip: str):
    rows = _read_csv_rows()
    ip_rows = [row for row in rows if (row.get('ip_address') or '').strip() == ip]
    if not ip_rows:
        return None

    ip_rows.sort(
        key=lambda row: _parse_time_utc(row.get('timestamp_utc', '')),
        reverse=True
    )
    return ip_rows[0]


def get_cached_intel(ip: str, cfg: dict, ttl_hours: int = 24, force_refresh: bool = False):
    """Cache-first threat intel fetch."""
    normalized_ip = _normalize_ip(ip)
    now = datetime.now(timezone.utc)

    cached_row = None if force_refresh else _select_best_cached_row(normalized_ip)

    if cached_row:
        cached_time = _parse_time_utc(cached_row.get('timestamp_utc') or '')
        age_hours = _cache_age_hours(now, cached_time)
        if age_hours < ttl_hours:
            abuse_data = _json_loads_safe(cached_row.get('abuse_json'), default={})
            vt_data = _json_loads_safe(cached_row.get('vt_json'), default={})
            whois_data = _json_loads_safe(cached_row.get('whois_json'), default={})
            recommendations = _json_loads_safe(
                cached_row.get('recommendations_json'),
                default=[]
            )
            risk_profile = risk.calculate_risk_score(abuse_data, vt_data, whois_data)

            threat_sum = summary.generate_threat_summary(
                normalized_ip,
                risk_profile['score'],
                risk_profile['classification'],
                abuse_data,
                vt_data,
                whois_data
            )

            intel_meta = {
                'last_updated_utc': cached_row.get(
                    'last_updated_utc',
                    cached_row.get('timestamp_utc', '')
                ),
                'source_status': cached_row.get('source_status', 'Cached Result'),
                'cache_age_hours': age_hours,
                'cache_hit': True
            }

            recommendations_final = (
                recommendations
                if recommendations
                else recs.get_recommendations(risk_profile['classification'])
            )

            return {
                'ip': normalized_ip,
                'risk': risk_profile,
                'abuse': abuse_data,
                'vt': vt_data,
                'whois': whois_data,
                'summary': threat_sum,
                'recommendations': recommendations_final,
                'intel_meta': intel_meta
            }

    cfg_local = dict(cfg or {})
    cfg_local.setdefault('mock_mode', True)

    abuse_data, vt_data, whois_data, _ = _refresh_from_sources(normalized_ip, cfg_local)

    risk_profile = risk.calculate_risk_score(abuse_data, vt_data, whois_data)
    threat_sum = summary.generate_threat_summary(
        normalized_ip,
        risk_profile['score'],
        risk_profile['classification'],
        abuse_data,
        vt_data,
        whois_data
    )
    recommendations = recs.get_recommendations(risk_profile['classification'])

    timestamp_utc = now.isoformat().replace('+00:00', 'Z')
    intel_meta = {
        'last_updated_utc': timestamp_utc,
        'source_status': 'Refreshed Result' if not cached_row else 'Refreshed Result (Expired)',
        'cache_age_hours': 0.0,
        'cache_hit': False
    }

    new_row = {
        'ip_address': normalized_ip,
        'timestamp_utc': timestamp_utc,
        'abuse_json': _json_dumps_safe(abuse_data),
        'vt_json': _json_dumps_safe(vt_data),
        'whois_json': _json_dumps_safe(whois_data),
        'risk_score': str(risk_profile['score']),
        'classification': risk_profile['classification'],
        'recommendations_json': _json_dumps_safe(recommendations),
        'last_updated_utc': timestamp_utc,
        'source_status': intel_meta['source_status'],
        'cache_age_hours': str(int(intel_meta['cache_age_hours']))
    }

    rows = _read_csv_rows()
    rows = [row for row in rows if (row.get('ip_address') or '').strip() != normalized_ip]
    rows.append(new_row)
    try:
        _write_csv_rows(rows)
    except OSError:
        logger.exception("Failed to write threat-intelligence cache")

    return {
        'ip': normalized_ip,
        'risk': risk_profile,
        'abuse': abuse_data,
        'vt': vt_data,
        'whois': whois_data,
        'summary': threat_sum,
        'recommendations': recommendations,
        'intel_meta': intel_meta
    }
