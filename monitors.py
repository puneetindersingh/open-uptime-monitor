"""
Monitoring engine for open-uptime-monitor.

Self-contained: own SQLite DB, own scheduler thread, one external dependency
(requests). All alerting behaviour (grace window, reminder throttle,
shared-server events, WAF/platform false-positive guards, per-monitor mute)
lives here; app.py provides the web UI around it.

Monitor types: http, http_keyword, dns, ping.
Reason codes: up, dns_servfail, dns_nxdomain, dns_no_answer, ssl_invalid,
ssl_expired, timeout, connection_refused, http_4xx, http_5xx, http_other,
keyword_missing, ping_failed, unknown_error.
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)

# All state (SQLite DB + settings.json) lives in one data dir so backup and
# .gitignore are a single path. Override the dir with UPTIME_DATA_DIR, or the
# DB alone with MONITORS_DB.
DATA_DIR = os.environ.get('UPTIME_DATA_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data'))
DB_PATH = os.environ.get('MONITORS_DB', os.path.join(DATA_DIR, 'monitors.db'))
WORKER_COUNT = 20
TICK_SECONDS = 30
HEARTBEAT_RETENTION_DAYS = 30

# Tiered default intervals (minutes), per the UK pattern
DEFAULT_INTERVAL_MIN = {
    'http': 5,
    'http_keyword': 10,
    'dns': 1,
    'ping': 5,
}

# Shopify stores are never checked more often than this, regardless of the
# admin interval — their shared edge flags IPs on request frequency, and the
# whole false-positive saga (5xx pages, then refused connections) came from
# looking bot-like. 15 min per store, evenly spaced, is proven quiet.
SHOPIFY_MIN_INTERVAL_MIN = 15


def effective_interval_min(monitor: dict) -> int:
    """Per-monitor interval → admin/type default, clamped for Shopify."""
    iv = monitor.get('interval_min') or get_effective_default(monitor.get('type') or 'http')
    if monitor.get('platform') == 'shopify':
        iv = max(iv, SHOPIFY_MIN_INTERVAL_MIN)
    return iv

# Runtime override of the per-type defaults — set by app.py after reading
# Admin Settings → Uptime monitor intervals. Same shape as DEFAULT_INTERVAL_MIN
# but partial-fill is fine (missing keys fall back to the hardcoded defaults).
# Per-monitor `interval_min` overrides BOTH (lookup order: per-monitor → admin
# override → hardcoded default).
_admin_interval_overrides: dict | None = None


def set_default_intervals(overrides: dict | None) -> None:
    """Called by app.py whenever admin settings change. Pass None to clear."""
    global _admin_interval_overrides
    if not overrides or not isinstance(overrides, dict):
        _admin_interval_overrides = None
        return
    cleaned = {}
    for k in ('http', 'http_keyword', 'dns', 'ping'):
        v = overrides.get(k)
        try:
            iv = int(v)
            if 1 <= iv <= 1440:
                cleaned[k] = iv
        except (TypeError, ValueError):
            pass
    _admin_interval_overrides = cleaned or None


def get_effective_default(monitor_type: str) -> int:
    """Resolve the default interval for a monitor type. Admin override > hardcoded."""
    if _admin_interval_overrides and monitor_type in _admin_interval_overrides:
        return _admin_interval_overrides[monitor_type]
    return DEFAULT_INTERVAL_MIN.get(monitor_type, 5)

UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36'
REQUEST_TIMEOUT = 10

# Full Chrome-on-Linux header set. Cloudflare/Imperva look at Sec-Fetch-* and
# Sec-Ch-Ua-* — without them, default python-requests gets challenged. With
# them, ~85% of previously-blocked sites return 200.
# Cache-Control/Pragma ask CDNs/page caches to revalidate at origin so an edge
# cache can't keep serving a stale 200 while the origin is down. Browsers send
# the same pair on hard refresh, so it carries no bot-tell.
BROWSER_HEADERS = {
    'User-Agent': UA,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Ch-Ua': '"Chromium";v="147", "Not?A_Brand";v="24", "Google Chrome";v="147"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Linux"',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
}

REASON_LABELS = {
    'up': 'Up',
    'up_protected': 'Up (WAF)',
    'dns_servfail': 'DNS SERVFAIL',
    'dns_nxdomain': 'DNS NXDOMAIN',
    'dns_no_answer': 'DNS no answer',
    'ssl_invalid': 'SSL invalid',
    'ssl_expired': 'SSL expired',
    'timeout': 'Timeout',
    'connection_refused': 'Connection refused',
    'http_4xx': 'HTTP 4xx',
    'http_5xx': 'HTTP 5xx',
    'http_other': 'HTTP unexpected',
    'keyword_missing': 'Keyword missing',
    'ping_failed': 'Ping failed',
    'unknown_error': 'Unknown error',
}


def _is_waf_block(resp) -> str | None:
    """Detect when a 4xx response is really a WAF challenge rather than a site
    being down. Returns the WAF name if detected, or None.

    Same approach Uptime Kuma / UptimeRobot use: WAF challenge = server is up,
    edge is just blocking non-browser clients.
    """
    h = {k.lower(): v.lower() for k, v in resp.headers.items()}
    server = h.get('server', '')
    # Cloudflare — by far the most common. 'cf-ray' and 'cf-mitigated' are
    # the canonical signals; 'server: cloudflare' confirms.
    if 'cloudflare' in server or 'cf-ray' in h or 'cf-mitigated' in h:
        return 'cloudflare'
    # AWS WAF / CloudFront
    if 'x-amz-cf-id' in h or 'cloudfront' in server:
        return 'cloudfront'
    # Imperva Incapsula
    if 'x-iinfo' in h or 'x-cdn' in h and 'incapsula' in h.get('x-cdn', ''):
        return 'imperva'
    # Sucuri
    if 'x-sucuri-id' in h or 'sucuri' in server:
        return 'sucuri'
    # Akamai
    if 'akamaighost' in server or 'akamainetstorage' in server:
        return 'akamai'
    return None


def _is_shopify_edge(resp) -> bool:
    """True when the response came from Shopify's storefront platform.

    Shopify stores have no client-owned origin that can 5xx — the whole
    storefront is served by Shopify's edge. A 5xx that still carries Shopify
    identity headers is their bot protection screening our IP (observed
    July 2026: several Shopify clients flip 500/503 within the same few
    minutes, each "incident" lasting exactly one check interval), not the
    store being down. Trade-off: a platform-wide Shopify outage would also be
    classified as protected — acceptable, since that is global news and not
    client-actionable, whereas the false DOWN alerts page the chat weekly.
    """
    h = {k.lower(): v.lower() for k, v in resp.headers.items()}
    if 'shopify' in h.get('powered-by', ''):
        return True
    return any(
        k.startswith(('x-shopify-', 'shopify-'))
        or k in ('x-sorting-hat-podid', 'x-sorting-hat-shopid', 'x-shopid', 'x-shardid')
        for k in h
    )


# Strings that only appear on bot-challenge interstitials, never on a real
# error page: Cloudflare (cf-chl / challenge-platform / "Just a moment"),
# hCaptcha, Turnstile, DDoS-Guard, PerimeterX, Imperva.
_CHALLENGE_BODY_MARKERS = (
    'cf-chl', 'challenge-platform', 'just a moment', 'checking your browser',
    'hcaptcha', 'turnstile', 'captcha', 'ddos-guard', 'perimeterx', 'incapsula',
)


def _looks_like_challenge_page(resp) -> bool:
    try:
        body = (resp.text or '')[:5000].lower()
    except Exception:
        return False
    return any(m in body for m in _CHALLENGE_BODY_MARKERS)


def _http_5xx_detail(resp) -> str:
    """'HTTP 503' alone made false positives undiagnosable — keep the server
    header and page title so the next odd alert explains itself."""
    detail = f'HTTP {resp.status_code}'
    server = resp.headers.get('server')
    if server:
        detail += f' (server={server})'
    try:
        m = re.search(r'<title[^>]*>(.*?)</title>', (resp.text or '')[:5000], re.I | re.S)
        if m:
            title = re.sub(r'\s+', ' ', m.group(1)).strip()[:80]
            if title:
                detail += f' — "{title}"'
    except Exception:
        pass
    return detail


# ── Notifications (chat webhooks: Google Chat / Slack / Discord) ──────────

# Set by app.py (boot + settings save) via set_notify_config().
# Shape: {'enabled': bool, 'webhook_url': str, 'webhook_type': str,
#         'notify_recovery': bool, 'public_base_url': str}
_notify_config: dict | None = None

# Seconds to wait before re-checking a monitor that just flipped up→down.
# One transient timeout shouldn't open an incident or page the chat — this is
# the same idea as Uptime Kuma's "retries" setting.
CONFIRM_DELAY_S = 20


# Webhook payload formats. Google Chat and Slack both accept {'text': ...};
# Discord wants {'content': ...}; 'generic' posts {'text': ...} for anything
# else that speaks the de-facto standard.
WEBHOOK_TYPES = ('google_chat', 'slack', 'discord', 'generic')


def set_notify_config(cfg: dict | None) -> None:
    """Called by app.py whenever settings change. Pass None/empty to disable."""
    global _notify_config
    if not cfg or not isinstance(cfg, dict):
        _notify_config = None
        return
    url = (cfg.get('webhook_url') or '').strip()
    wtype = (cfg.get('webhook_type') or 'google_chat').strip().lower()
    _notify_config = {
        'enabled': bool(cfg.get('enabled')) and bool(url),
        'webhook_url': url,
        'webhook_type': wtype if wtype in WEBHOOK_TYPES else 'google_chat',
        'notify_recovery': cfg.get('notify_recovery') is not False,
        # Base URL of this service — when set, alerts carry a link to the
        # monitor's report / the dashboard / the mute page. Empty = no links.
        'public_base_url': (cfg.get('public_base_url') or '').strip().rstrip('/'),
    }


_display_tz_name = 'UTC'


def set_timezone(tz_name: str | None) -> None:
    """Display timezone for chat alerts and reports (IANA name, e.g.
    'Australia/Melbourne'). Invalid/empty names fall back to UTC."""
    global _display_tz_name
    _display_tz_name = (tz_name or 'UTC').strip() or 'UTC'


def get_display_tz():
    from zoneinfo import ZoneInfo
    try:
        return ZoneInfo(_display_tz_name)
    except Exception:
        return timezone.utc


def _report_link(monitor_id: int) -> str | None:
    base = (_notify_config or {}).get('public_base_url')
    return f'📊 {base}/monitors/{monitor_id}/report' if base else None


def _mute_link(monitor_id: int) -> str | None:
    base = (_notify_config or {}).get('public_base_url')
    return f'🔇 Mute alerts: {base}/monitors/{monitor_id}/mute' if base else None


def _dashboard_link() -> str | None:
    base = (_notify_config or {}).get('public_base_url')
    return f'📊 {base}/' if base else None


# Monitor ids whose DOWN alert was actually delivered — a recovery message is
# only sent for these, so a suppressed down (local internet outage) never
# produces an orphan 🟢. Mirrored to the settings table because the server
# restarts often enough that in-memory-only left 🔴s without their 🟢.
_alerted_down: set[int] = set()

# Per-monitor 🔴 throttle. One rule covers both directions: no monitor sends a 🔴 —
# whether a fresh down or a still-down reminder — within NOTIFY_MIN_GAP_S of
# its previous 🔴. Flapping sites collapse to one alert per half hour; sites
# that STAY down re-remind every half hour instead of going silent after the
# first message. 🟢 recovery messages are never throttled (they pair with a
# delivered 🔴). Kept across recoveries on purpose — clearing on 🟢 would let
# a 10-min flap cycle spam a full 🔴/🟢 pair every cycle.
NOTIFY_MIN_GAP_S = 30 * 60
_last_down_alert: dict[int, str] = {}  # monitor id → iso ts of last delivered 🔴

# Grace window: a confirmed up→down flip does NOT page the chat.
# The first 🔴 is sent by the still-down reminder loop once the outage has
# lasted ALERT_GRACE_S; an outage that recovers inside the window never
# messages the space at all — no 🔴, and the _alerted_down pairing rule keeps
# its 🟢 silent too. Net effect: at most two messages per hour per monitor,
# and only for outages a human could actually witness.
ALERT_GRACE_S = 30 * 60


def set_alert_windows(grace_min: int | None = None, reminder_min: int | None = None) -> None:
    """Settings hook: minutes an outage must last before the first 🔴 (grace)
    and minutes between repeat 🔴s for the same monitor (reminder). Clamped to
    sane bounds; None/invalid leaves the current value unchanged."""
    global ALERT_GRACE_S, NOTIFY_MIN_GAP_S
    try:
        if grace_min is not None:
            ALERT_GRACE_S = max(0, min(int(grace_min), 24 * 60)) * 60
    except (TypeError, ValueError):
        pass
    try:
        if reminder_min is not None:
            NOTIFY_MIN_GAP_S = max(5, min(int(reminder_min), 24 * 60)) * 60
    except (TypeError, ValueError):
        pass


# Shared-server events: a single site's short blip is
# noise, but 2+ monitored sites down on the SAME server IP at the same moment
# is a server incident — that pages IMMEDIATELY (no grace), as ONE ⚠️ message
# instead of N per-site 🔴s. While a server event is open, the per-site
# still-down alerts for that box are suppressed; the event closes (🟢) when
# the box is back below two down sites.
_server_events_open: dict[str, str] = {}  # server key → iso ts the event opened
_last_server_alert: dict[str, str] = {}   # server key → iso ts of last ⚠️

# Per-monitor alert mute (for known issues — e.g. an expired SSL cert the
# site owner already knows about). While muted, the 🔴 DOWN /
# STILL DOWN reminders for that monitor stay silent; the 🟢 RECOVERED still
# sends (only ever pairs with a delivered 🔴, and it's the one message that
# says the client actually fixed it). Server events are NOT muted — 2+ sites
# down on one box is a different incident than the known-broken site.
_muted: dict[int, dict] = {}  # monitor id → {'until': iso, 'by': name}


def mute_monitor(mid: int, hours: float = 24, by: str | None = None) -> str:
    """Silence 🔴 alerts for a monitor for `hours`. Returns the iso expiry."""
    until = iso(utcnow() + timedelta(hours=max(0.25, min(hours, 24 * 30))))
    _muted[int(mid)] = {'until': until, 'by': (by or '').strip() or None}
    _save_alert_state()
    log.info('[monitors] alerts MUTED for monitor %s until %s (by %s)', mid, until, by or '?')
    return until


def unmute_monitor(mid: int) -> bool:
    if _muted.pop(int(mid), None) is None:
        return False
    _save_alert_state()
    log.info('[monitors] alerts UNMUTED for monitor %s', mid)
    return True


def mute_info(mid: int, now: datetime | None = None) -> dict | None:
    """{'until': iso, 'by': name} while the mute is active, else None.
    Expired entries are dropped lazily (fails unmuted on a bad timestamp —
    a corrupt mute must never silence a real outage forever)."""
    entry = _muted.get(int(mid))
    if not entry:
        return None
    try:
        if (now or utcnow()) < parse_iso(entry['until']):
            return entry
    except Exception:
        pass
    _muted.pop(int(mid), None)
    _save_alert_state()
    return None


def muted_until(mid: int, now: datetime | None = None) -> str | None:
    entry = mute_info(mid, now)
    return entry['until'] if entry else None


def _save_alert_state() -> None:
    try:
        with _db_lock, db() as conn:
            for key, val in (('alerted_down', json.dumps(sorted(_alerted_down))),
                             ('last_down_alert', json.dumps({str(k): v for k, v in _last_down_alert.items()})),
                             ('server_events_open', json.dumps(_server_events_open)),
                             ('last_server_alert', json.dumps(_last_server_alert)),
                             ('muted_alerts', json.dumps({str(k): v for k, v in _muted.items()}))):
                conn.execute('INSERT INTO settings(key, value) VALUES (?, ?) '
                             'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, val))
    except Exception:
        log.exception('[monitors] failed to persist alert state')


def _load_alert_state() -> None:
    try:
        with db() as conn:
            rows = {r['key']: r['value'] for r in conn.execute(
                "SELECT key, value FROM settings WHERE key IN "
                "('alerted_down', 'last_down_alert', 'server_events_open', 'last_server_alert', 'muted_alerts')")}
        if rows.get('alerted_down'):
            _alerted_down.update(int(x) for x in json.loads(rows['alerted_down']))
            if _alerted_down:
                log.info('[monitors] restored %d open down-alert(s) from db: %s',
                         len(_alerted_down), sorted(_alerted_down))
        if rows.get('last_down_alert'):
            _last_down_alert.update({int(k): v for k, v in json.loads(rows['last_down_alert']).items()})
        if rows.get('server_events_open'):
            _server_events_open.update(json.loads(rows['server_events_open']))
            if _server_events_open:
                log.info('[monitors] restored %d open server event(s): %s',
                         len(_server_events_open), sorted(_server_events_open))
        if rows.get('last_server_alert'):
            _last_server_alert.update(json.loads(rows['last_server_alert']))
        if rows.get('muted_alerts'):
            _muted.update({int(k): v for k, v in json.loads(rows['muted_alerts']).items()})
            if _muted:
                log.info('[monitors] restored %d alert mute(s) from db: %s',
                         len(_muted), sorted(_muted))
    except Exception:
        log.exception('[monitors] failed to restore alert state')


def _down_alert_too_soon(monitor_id: int, now: datetime) -> bool:
    last = _last_down_alert.get(monitor_id)
    if not last:
        return False
    try:
        return (now - parse_iso(last)).total_seconds() < NOTIFY_MIN_GAP_S
    except Exception:
        return False

# Chat alerts are STRICTLY for sites that are actually down (hard rule).
# Only server-level failures alert; anything where the server answered —
# 4xx (including unknown-WAF blocks that slip past _is_waf_block),
# keyword_missing (JS-challenge pages return 200 without the keyword),
# http_other, unknown_error — shows red on the dashboard but never messages
# the space.
ALERT_REASONS = {
    'http_5xx', 'timeout', 'connection_refused',
    'dns_servfail', 'dns_nxdomain', 'dns_no_answer',
    'ssl_expired', 'ssl_invalid', 'ping_failed',
}

# The monitoring box is a desktop on a home/office connection: when ITS
# internet drops, every monitor flips down at once. Before any DOWN alert we
# probe well-known always-up endpoints — if none respond, the outage is ours,
# not the client's, and alerts are suppressed.
_CONNECTIVITY_PROBES = (
    'https://www.google.com/generate_204',
    'https://one.one.one.one/cdn-cgi/trace',
    'https://www.bing.com/favicon.ico',
)


def _internet_ok() -> bool:
    for url in _CONNECTIVITY_PROBES:
        try:
            requests.head(url, timeout=5, headers={'User-Agent': UA})
            return True
        except Exception:
            continue
    return False


def notify_enabled() -> bool:
    return bool(_notify_config and _notify_config.get('enabled'))


def send_chat_message(text: str, webhook_url: str | None = None,
                      thread_key: str | None = None,
                      webhook_type: str | None = None) -> tuple[bool, str | None]:
    """POST a text message to a chat webhook (Google Chat / Slack / Discord /
    generic). Returns (ok, error_message). thread_key groups related messages
    into one thread — Google Chat only, ignored elsewhere. Alerts are sent
    top-level on purpose: threaded replies hide from the space's main stream."""
    cfg = _notify_config or {}
    url = (webhook_url or cfg.get('webhook_url') or '').strip()
    if not url:
        return False, 'no webhook URL configured'
    wtype = (webhook_type or cfg.get('webhook_type') or 'google_chat').lower()
    params = {}
    if thread_key and wtype == 'google_chat':
        params = {'threadKey': thread_key,
                  'messageReplyOption': 'REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD'}
    if wtype == 'discord':
        # Discord ignores 'text'; *bold* becomes **bold** in its markdown.
        payload = {'content': text.replace('*', '**')}
    else:
        payload = {'text': text}
    try:
        resp = requests.post(url, params=params, json=payload, timeout=10)
        if resp.ok:
            return True, None
        return False, f'HTTP {resp.status_code}: {(resp.text or "")[:200]}'
    except Exception as e:
        return False, str(e)[:300]


def _fmt_duration(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 60:
        return f'{s}s'
    m, s = divmod(s, 60)
    if m < 60:
        return f'{m}m {s}s' if s else f'{m}m'
    h, m = divmod(m, 60)
    if h < 24:
        return f'{h}h {m}m' if m else f'{h}h'
    d, h = divmod(h, 24)
    return f'{d}d {h}h' if h else f'{d}d'


def _local_ts(dt: datetime) -> str:
    """Render a UTC datetime in the configured display timezone for chat
    messages. %Z renders the correct DST-aware label instead of a hardcoded
    one that would be wrong half the year."""
    try:
        return dt.astimezone(get_display_tz()).strftime('%d %b %H:%M %Z')
    except Exception:
        return iso(dt)


def _notify_transition(monitor: dict, result: dict, now: datetime) -> None:
    """Send a Google Chat alert for a confirmed state change. `monitor` holds the
    PRE-check row (current_status = previous state). Never raises.

    Down flips deliberately send NOTHING here — the 30-min grace window means
    the first 🔴 comes from _maybe_notify_still_down() once the outage has
    outlived ALERT_GRACE_S, so blips that recover inside the window are
    discarded entirely."""
    cfg = _notify_config
    if not cfg or not cfg.get('enabled'):
        return
    prev = monitor.get('current_status')
    status = result['status']
    name = monitor.get('name') or monitor.get('target')
    tag = monitor.get('client_tag')

    if status == 'down':
        if result['reason'] in ALERT_REASONS:
            log.info('[monitors] DOWN for %s — in %d-min grace window, alert deferred '
                     'to the still-down loop', monitor['target'], ALERT_GRACE_S // 60)
        else:
            log.info('[monitors] DOWN (%s) for %s is dashboard-only — not an alertable reason',
                     result['reason'], monitor['target'])
        return
    elif status == 'up' and prev == 'down':
        # Only pair a 🟢 with a 🔴 that was actually delivered — a suppressed
        # down (local outage) recovering must not flood the space.
        if monitor['id'] not in _alerted_down:
            return
        _alerted_down.discard(monitor['id'])
        _save_alert_state()
        if not cfg.get('notify_recovery', True):
            return
        lines = [f'🟢 *RECOVERED — {name}*']
        if tag and tag != name:
            lines.append(f'Client: {tag}')
        lines.append(f'Target: {monitor["target"]} ({monitor["type"]})')
        went_down = monitor.get('last_state_change_at')
        if went_down:
            try:
                lines.append(f'Downtime: ~{_fmt_duration((now - parse_iso(went_down)).total_seconds())}')
            except Exception:
                pass
        lines.append(f'Recovered: {_local_ts(now)}')
        link = _report_link(monitor['id'])
        if link:
            lines.append(link)
    else:
        # unknown→up (first check of a new monitor) — not alert-worthy
        return

    # Top-level message on purpose: with threadKey, Google Chat files the 🟢
    # RECOVERED as a *reply inside* the 🔴 thread — the space's main stream
    # never shows it and nobody gets notified, so recoveries looked missing.
    ok, err = send_chat_message('\n'.join(lines))
    if ok:
        log.info('[monitors] chat alert sent: %s %s', status, monitor['target'])
    else:
        log.warning('[monitors] chat alert FAILED for %s: %s', monitor['target'], err)


def _maybe_notify_still_down(monitor: dict, result: dict, now: datetime) -> None:
    """The ONLY sender of 🔴s. Called on every non-transition down check:
    - first alert: sent once the outage has outlived ALERT_GRACE_S (the down
      flip itself never pages — blips that recover inside the grace window
      are discarded entirely)
    - then a "STILL DOWN" reminder every NOTIFY_MIN_GAP_S while it stays down
      (one message then silence made ongoing outages look resolved).
    The throttle caps it at twice an hour. Also covers downs whose 🔴 was
    suppressed by the local-outage guard. Never raises."""
    try:
        cfg = _notify_config
        if not cfg or not cfg.get('enabled'):
            return
        if result['reason'] not in ALERT_REASONS:
            return
        # Muted (known issue, client informed): every 🔴 stays silent until the
        # mute expires, then the normal grace/throttle rules resume. The 🟢
        # RECOVERED is untouched — it only pairs with a delivered 🔴 and is the
        # message that says the client fixed it.
        if muted_until(monitor['id'], now):
            log.info('[monitors] 🔴 for %s suppressed — alerts muted until %s',
                     monitor['target'], _muted.get(monitor['id'], {}).get('until'))
            return
        # An open server event for this box already covers this site — one ⚠️
        # for the server beats N per-site 🔴s (suppression lifts when the
        # event closes, so a lone survivor still alerts individually).
        if monitor.get('server_ip') and monitor.get('server_ip') in _server_events_open:
            return
        first_alert = monitor['id'] not in _alerted_down
        if first_alert:
            # Grace window: fails OPEN on a missing/unparseable flip time — a
            # genuinely down site must never stay silent forever.
            try:
                down_secs = (now - parse_iso(monitor['last_state_change_at'])).total_seconds()
                if down_secs < ALERT_GRACE_S:
                    return
            except Exception:
                pass
        if _down_alert_too_soon(monitor['id'], now):
            return
        if not _internet_ok():
            return
        name = monitor.get('name') or monitor.get('target')
        tag = monitor.get('client_tag')
        lines = [f'🔴 *{"DOWN" if first_alert else "STILL DOWN"} — {name}*']
        if tag and tag != name:
            lines.append(f'Client: {tag}')
        lines.append(f'Target: {monitor["target"]} ({monitor["type"]})')
        if monitor.get('redirect_to'):
            lines.append(f'↪ Redirects to: {monitor["redirect_to"]} (different domain)')
        reason = REASON_LABELS.get(result['reason'], result['reason'])
        err = result.get('error_msg')
        lines.append(f'Reason: {reason}' + (f' — {err}' if err and err != reason else ''))
        went_down = monitor.get('last_state_change_at')
        if went_down:
            try:
                lines.append(f'Down for: ~{_fmt_duration((now - parse_iso(went_down)).total_seconds())}')
            except Exception:
                pass
        link = _report_link(monitor['id'])
        if link:
            lines.append(link)
        mute = _mute_link(monitor['id'])
        if mute:
            lines.append(mute)
        ok, err2 = send_chat_message('\n'.join(lines))
        if ok:
            _alerted_down.add(monitor['id'])
            _last_down_alert[monitor['id']] = iso(now)
            _save_alert_state()
            log.info('[monitors] chat alert sent: still-down %s', monitor['target'])
        else:
            log.warning('[monitors] still-down alert FAILED for %s: %s', monitor['target'], err2)
    except Exception:
        log.exception('[monitors] still-down notify failed for %s', monitor.get('target'))


# ── Shared-server events ───────────────────────────────────────────────────

def _resolve_server_key(target: str) -> str | None:
    """Grouping key for shared-server detection: the target's FULL sorted A-record
    set, comma-joined — not just the first record, so round-robin DNS (Cloudflare
    per-zone pairs etc.) yields a stable key instead of flapping between IPs.
    None on resolution failure (callers keep the last known key — a DNS-dead
    site should still count toward its box's event)."""
    try:
        host = urlparse(target if '://' in target else f'https://{target}').hostname
        if not host:
            return None
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
        return ','.join(ips) or None
    except Exception:
        return None


def _server_key_label(key: str) -> str:
    return key.split(',')[0] + (f' (+{key.count(",")} more)' if ',' in key else '')


def _down_peers(server_key: str) -> list[dict]:
    """All enabled http monitors on this server key that are currently down for
    an alertable reason (WAF blocks / keyword_missing etc. don't count)."""
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, target, current_reason FROM monitors "
            "WHERE server_ip=? AND enabled=1 AND current_status='down' "
            "AND type IN ('http','http_keyword')", (server_key,)).fetchall()
    return [dict(r) for r in rows if r['current_reason'] in ALERT_REASONS]


def _maybe_notify_server_event(monitor: dict, result: dict, now: datetime) -> None:
    """2+ sites down together on one server IP = server incident. Pages
    IMMEDIATELY — short-but-multiple outages on a shared box are worth
    knowing about even when each site's blip is under the grace window.
    One ⚠️ per box per NOTIFY_MIN_GAP_S; re-fires as "ongoing" while
    the condition holds. Never raises."""
    try:
        cfg = _notify_config
        if not cfg or not cfg.get('enabled'):
            return
        if result['reason'] not in ALERT_REASONS:
            return
        key = monitor.get('server_ip')
        if not key:
            return
        peers = _down_peers(key)
        if len(peers) < 2:
            return
        last = _last_server_alert.get(key)
        if last:
            try:
                if (now - parse_iso(last)).total_seconds() < NOTIFY_MIN_GAP_S:
                    return
            except Exception:
                pass
        if not _internet_ok():
            return
        ongoing = key in _server_events_open
        lines = [f'⚠️ *SERVER OUTAGE{" ongoing" if ongoing else ""} — '
                 f'{len(peers)} sites down together*',
                 f'Server IP: {_server_key_label(key)}']
        for p in sorted(peers, key=lambda x: (x.get('name') or x['target']).lower()):
            reason = REASON_LABELS.get(p['current_reason'], p['current_reason'])
            lines.append(f'• {p.get("name") or p["target"]} — {reason}')
        if ongoing:
            try:
                lines.append(f'Down for: ~{_fmt_duration((now - parse_iso(_server_events_open[key])).total_seconds())}')
            except Exception:
                pass
        lines.append(f'Detected: {_local_ts(now)}')
        link = _dashboard_link()
        if link:
            lines.append(link)
        ok, err = send_chat_message('\n'.join(lines))
        if ok:
            _server_events_open.setdefault(key, iso(now))
            _last_server_alert[key] = iso(now)
            _save_alert_state()
            log.info('[monitors] server-event alert sent for %s (%d sites down)', key, len(peers))
        else:
            log.warning('[monitors] server-event alert FAILED for %s: %s', key, err)
    except Exception:
        log.exception('[monitors] server-event notify failed for %s', monitor.get('target'))


def _maybe_close_server_event(monitor: dict, now: datetime) -> None:
    """Close an open server event once the box is back below two down sites.
    A single site still down afterwards falls back to the normal per-site
    rules (grace/throttle), so it can't get stuck silent behind a stale open
    event. Never raises."""
    try:
        key = monitor.get('server_ip')
        if not key or key not in _server_events_open:
            return
        peers = _down_peers(key)
        if len(peers) >= 2:
            return  # still a server event
        started = _server_events_open.pop(key)
        _save_alert_state()
        cfg = _notify_config
        if not cfg or not cfg.get('enabled') or not cfg.get('notify_recovery', True):
            return
        lines = ['🟢 *SERVER OUTAGE over*', f'Server IP: {_server_key_label(key)}']
        try:
            lines.append(f'Duration: ~{_fmt_duration((now - parse_iso(started)).total_seconds())}')
        except Exception:
            pass
        if peers:
            lines.append(f'Still down individually: {peers[0].get("name") or peers[0]["target"]} '
                         '(continues under normal per-site alerts)')
        lines.append(f'Recovered: {_local_ts(now)}')
        ok, err = send_chat_message('\n'.join(lines))
        if ok:
            log.info('[monitors] server-event recovery sent for %s', key)
        else:
            log.warning('[monitors] server-event recovery FAILED for %s: %s', key, err)
    except Exception:
        log.exception('[monitors] server-event close failed for %s', monitor.get('target'))


# ── DB ─────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS monitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK(type IN ('http','http_keyword','dns','ping')),
    target TEXT NOT NULL,
    name TEXT,
    client_tag TEXT,
    interval_min INTEGER,
    expected_keyword TEXT,
    dns_record_type TEXT,
    dns_expected_value TEXT,
    seeded INTEGER NOT NULL DEFAULT 0,
    platform TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    current_status TEXT,
    current_reason TEXT,
    last_state_change_at TEXT,
    last_checked_at TEXT,
    next_check_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_monitors_next ON monitors(enabled, next_check_at);
CREATE INDEX IF NOT EXISTS idx_monitors_tag ON monitors(client_tag);
CREATE UNIQUE INDEX IF NOT EXISTS uq_monitors_type_target ON monitors(type, target);

CREATE TABLE IF NOT EXISTS heartbeats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    checked_at TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    http_code INTEGER,
    response_ms INTEGER,
    error_msg TEXT,
    FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_heartbeats_monitor_time ON heartbeats(monitor_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS hourly_stats (
    monitor_id INTEGER NOT NULL,
    hour_start TEXT NOT NULL,
    up_count INTEGER NOT NULL DEFAULT 0,
    down_count INTEGER NOT NULL DEFAULT 0,
    avg_ms INTEGER,
    p95_ms INTEGER,
    PRIMARY KEY(monitor_id, hour_start)
);

CREATE TABLE IF NOT EXISTS daily_stats (
    monitor_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    up_count INTEGER NOT NULL DEFAULT 0,
    down_count INTEGER NOT NULL DEFAULT 0,
    avg_ms INTEGER,
    p95_ms INTEGER,
    incident_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(monitor_id, day)
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    reason TEXT NOT NULL,
    details TEXT,
    FOREIGN KEY(monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_incidents_monitor ON incidents(monitor_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_open ON incidents(monitor_id) WHERE ended_at IS NULL;

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


_db_lock = threading.Lock()

# Monitor ids with a check currently running — the scheduler tick (30s) is
# shorter than a worst-case check (~40s with the confirm re-check), so without
# this a slow check gets submitted twice and double-alerts. See _check_and_record.
_inflight_lock = threading.Lock()
_inflight: set[int] = set()

# ── Process-wide singletons ────────────────────────────────────────────────
# If the app module is ever imported under two names in one process (e.g. as
# __main__ AND re-imported as 'app'), module-level threads get duplicated.
# This module is in sys.modules exactly once, so guards here are truly
# process-wide. Use claim_singleton() around any module-level thread start.
_singleton_lock = threading.Lock()
_singletons: set[str] = set()


def claim_singleton(name: str) -> bool:
    """Returns True exactly once per process for each name."""
    with _singleton_lock:
        if name in _singletons:
            return False
        _singletons.add(name)
        return True


# Serialises client↔monitor syncs — a sync that finds this held must SKIP
# (its sibling is already doing the same work), never queue behind it.
client_sync_lock = threading.Lock()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA journal_mode = WAL')
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or '.', exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)
        # Migration for DBs created before the seeded column existed. Existing
        # rows default to 0 (= manually created); bulk imports may mark
        # theirs 1 to distinguish them later.
        try:
            conn.execute('ALTER TABLE monitors ADD COLUMN seeded INTEGER NOT NULL DEFAULT 0')
        except sqlite3.OperationalError:
            pass  # column already exists
        # Platform learned from successful checks ('shopify' or NULL). Needed
        # because Shopify's bot-block 5xx page strips every identity header
        # (observed 2026-07-11: 503, server=cloudflare, "Something went wrong",
        # nothing Shopify about it) — the block response alone is undetectable,
        # so we have to remember what the target IS from when it was healthy.
        try:
            conn.execute('ALTER TABLE monitors ADD COLUMN platform TEXT')
        except sqlite3.OperationalError:
            pass  # column already exists
        # Shared-server grouping key: sorted comma-joined A records, refreshed
        # on every http check. 2+ sites down on the same key = server event.
        try:
            conn.execute('ALTER TABLE monitors ADD COLUMN server_ip TEXT')
        except sqlite3.OperationalError:
            pass  # column already exists
        # Cross-domain redirect learned from healthy checks (a rebrand
        # redirect can otherwise surface only inside an SSL error string).
        # Same-domain/www canonicalisation is never recorded.
        try:
            conn.execute('ALTER TABLE monitors ADD COLUMN redirect_to TEXT')
        except sqlite3.OperationalError:
            pass  # column already exists
    log.info('[monitors] DB initialised at %s', DB_PATH)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_iso(s: str) -> datetime:
    return datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


# ── Domain helpers ────────────────────────────────────────────────────────

def registrable_domain(url_or_host: str) -> str:
    """Strip protocol, path, www — the bare registrable domain for comparisons."""
    s = (url_or_host or '').strip().lower()
    if '://' in s:
        s = urlparse(s).netloc or s
    s = s.split('/')[0].split('@')[-1]
    if s.startswith('www.'):
        s = s[4:]
    return s


def normalise_target(t: str, kind: str) -> str:
    t = (t or '').strip()
    if kind == 'http' or kind == 'http_keyword':
        if not t.startswith(('http://', 'https://')):
            t = 'https://' + t
    elif kind in ('dns', 'ping'):
        t = registrable_domain(t) or t
    return t


# ── Check functions ───────────────────────────────────────────────────────

def _classify_http_exception(e: Exception) -> tuple[str, str]:
    """Map a requests exception → (reason_code, error_msg)."""
    msg = str(e)
    low = msg.lower()
    if isinstance(e, requests.exceptions.SSLError):
        if 'expired' in low or 'certificate has expired' in low:
            return 'ssl_expired', msg
        return 'ssl_invalid', msg
    if isinstance(e, requests.exceptions.ConnectTimeout) or 'timed out' in low or 'timeout' in low:
        return 'timeout', msg
    if isinstance(e, requests.exceptions.ConnectionError):
        if 'name or service not known' in low or 'nodename nor servname' in low or 'temporary failure in name resolution' in low:
            return 'dns_nxdomain', msg
        if 'connection refused' in low:
            return 'connection_refused', msg
        if 'servfail' in low:
            return 'dns_servfail', msg
        return 'connection_refused', msg
    return 'unknown_error', msg


def _cross_domain_redirect(target: str, resp) -> str | None:
    """Final hostname when the redirect chain ended on a DIFFERENT domain than
    the target — a rebrand/migration signal worth surfacing (e.g.
    old-brand.com → www.new-brand.com). www stripping and
    subdomain moves within the same domain return None: canonicalisation is
    normal, not news."""
    try:
        t = registrable_domain(target)
        f = registrable_domain(str(resp.url))
        if t and f and t != f and not t.endswith('.' + f) and not f.endswith('.' + t):
            final_host = urlparse(str(resp.url)).hostname
            return final_host or f
    except Exception:
        pass
    return None


def check_http(target: str, expected_keyword: str | None = None,
               platform: str | None = None) -> dict:
    """Run HTTP(S) check. If expected_keyword given, also verify it appears in body.
    `platform` is the platform learned from earlier healthy checks (monitors.platform
    column) — used to classify otherwise-anonymous bot-block 5xx responses."""
    started = time.perf_counter()
    try:
        resp = requests.get(
            target,
            headers=BROWSER_HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        ms = int((time.perf_counter() - started) * 1000)
        code = resp.status_code
        if 200 <= code < 400:
            # Healthy response: (re-)learn the platform so future anonymous
            # bot-block 5xx can be classified. Only healthy responses may set
            # OR clear it — a block page stripped of headers must not unlearn.
            # Same rule for the cross-domain redirect signal.
            detected = 'shopify' if _is_shopify_edge(resp) else None
            redirect = _cross_domain_redirect(target, resp)
            if expected_keyword:
                body = resp.text or ''
                if expected_keyword.lower() in body.lower():
                    return {'status': 'up', 'reason': 'up', 'http_code': code, 'response_ms': ms,
                            'error_msg': None, 'platform_detected': detected, 'redirect_to': redirect}
                return {'status': 'down', 'reason': 'keyword_missing', 'http_code': code, 'response_ms': ms,
                        'error_msg': f'Keyword "{expected_keyword}" not in response'}
            return {'status': 'up', 'reason': 'up', 'http_code': code, 'response_ms': ms,
                    'error_msg': None, 'platform_detected': detected, 'redirect_to': redirect}
        if 400 <= code < 500:
            # 4xx from a known WAF is usually a challenge, not the site being
            # down. Real users get through; we just look like a bot.
            waf = _is_waf_block(resp)
            if waf:
                return {'status': 'up', 'reason': 'up_protected', 'http_code': code, 'response_ms': ms,
                        'error_msg': f'{waf.title()} challenge ({code}) — server is up, edge is blocking the check'}
            return {'status': 'down', 'reason': 'http_4xx', 'http_code': code, 'response_ms': ms, 'error_msg': f'HTTP {code}'}
        if 500 <= code < 600:
            # Bot-protection 5xx is NOT the site being down. Three explicit
            # signals count as up; a real origin 5xx behind Cloudflare also
            # carries cf-ray, so plain Cloudflare headers do NOT.
            # 1) Cloudflare "Under Attack" challenge: 503 + cf-mitigated.
            if 'challenge' in (resp.headers.get('cf-mitigated') or '').lower():
                return {'status': 'up', 'reason': 'up_protected', 'http_code': code, 'response_ms': ms,
                        'error_msg': f'Cloudflare challenge ({code}) — server is up, edge is blocking the check'}
            # 2) Shopify edge screening our IP. Two paths: the response still
            # identifies as Shopify (_is_shopify_edge), OR the target is a
            # KNOWN Shopify store from earlier healthy checks — their block
            # page strips every identity header (503, server=cloudflare,
            # "Something went wrong"), so the learned platform is the only
            # reliable signal. A Shopify storefront has no client-owned origin
            # that can 5xx; blocks show as one-check blips across stores.
            if _is_shopify_edge(resp) or platform == 'shopify':
                return {'status': 'up', 'reason': 'up_protected', 'http_code': code, 'response_ms': ms,
                        'error_msg': f'Shopify edge protection ({code}) — platform is serving, check was bot-screened'
                                     + ('' if _is_shopify_edge(resp) else f' [known-shopify target; {_http_5xx_detail(resp)}]')}
            # 3) Any other edge serving a challenge interstitial as a 5xx.
            if _looks_like_challenge_page(resp):
                return {'status': 'up', 'reason': 'up_protected', 'http_code': code, 'response_ms': ms,
                        'error_msg': f'Bot challenge page ({code}) — server is up, edge is blocking the check'}
            return {'status': 'down', 'reason': 'http_5xx', 'http_code': code, 'response_ms': ms,
                    'error_msg': _http_5xx_detail(resp)}
        return {'status': 'down', 'reason': 'http_other', 'http_code': code, 'response_ms': ms, 'error_msg': f'HTTP {code}'}
    except Exception as e:
        ms = int((time.perf_counter() - started) * 1000)
        reason, msg = _classify_http_exception(e)
        # Shopify escalates IP mitigation beyond 5xx pages: it drops/refuses
        # the TCP connection outright (observed: connection_refused, gone by
        # the next check). Shopify's anycast edge does not go down per
        # store — a connection-level failure on a known-shopify target is our
        # IP being screened. DNS and SSL reasons still alert: those are
        # client-controlled (domain/cert misconfig) and CAN genuinely break.
        if platform == 'shopify' and reason in ('timeout', 'connection_refused'):
            return {'status': 'up', 'reason': 'up_protected', 'http_code': None, 'response_ms': ms,
                    'error_msg': f'Shopify edge dropped the connection ({reason}) — IP screening, '
                                 f'not an outage: {msg[:200]}'}
        return {'status': 'down', 'reason': reason, 'http_code': None, 'response_ms': ms, 'error_msg': msg[:500]}


_DNS_RE_ANSWER = re.compile(r'^[^;\s].+', re.M)


def check_dns(host: str, record_type: str = 'A', expected: str | None = None) -> dict:
    """DNS check via `dig +short`. Returns up if at least one answer, optionally matches expected."""
    rt = (record_type or 'A').upper()
    started = time.perf_counter()
    try:
        out = subprocess.run(
            ['dig', '+short', '+time=5', '+tries=2', host, rt],
            capture_output=True, text=True, timeout=15,
        )
        ms = int((time.perf_counter() - started) * 1000)
        stderr = (out.stderr or '').lower()
        stdout = (out.stdout or '').strip()
        if 'servfail' in stderr or 'servfail' in stdout.lower():
            return {'status': 'down', 'reason': 'dns_servfail', 'http_code': None, 'response_ms': ms,
                    'error_msg': 'Authoritative DNS returned SERVFAIL'}
        if not stdout:
            # No answer — distinguish NXDOMAIN by running a status query
            status_out = subprocess.run(
                ['dig', host, rt, '+time=5', '+tries=1'],
                capture_output=True, text=True, timeout=15,
            )
            so = status_out.stdout or ''
            if 'NXDOMAIN' in so:
                return {'status': 'down', 'reason': 'dns_nxdomain', 'http_code': None, 'response_ms': ms,
                        'error_msg': 'NXDOMAIN'}
            if 'SERVFAIL' in so:
                return {'status': 'down', 'reason': 'dns_servfail', 'http_code': None, 'response_ms': ms,
                        'error_msg': 'SERVFAIL'}
            return {'status': 'down', 'reason': 'dns_no_answer', 'http_code': None, 'response_ms': ms,
                    'error_msg': f'No {rt} record returned'}
        if expected:
            if expected.lower() not in stdout.lower():
                return {'status': 'down', 'reason': 'dns_no_answer', 'http_code': None, 'response_ms': ms,
                        'error_msg': f'Expected "{expected}" not in answer: {stdout[:200]}'}
        return {'status': 'up', 'reason': 'up', 'http_code': None, 'response_ms': ms, 'error_msg': None}
    except subprocess.TimeoutExpired:
        ms = int((time.perf_counter() - started) * 1000)
        return {'status': 'down', 'reason': 'timeout', 'http_code': None, 'response_ms': ms, 'error_msg': 'dig timeout'}
    except Exception as e:
        ms = int((time.perf_counter() - started) * 1000)
        return {'status': 'down', 'reason': 'unknown_error', 'http_code': None, 'response_ms': ms, 'error_msg': str(e)[:500]}


def check_ping(host: str) -> dict:
    """ICMP ping via system `ping -c 1 -W 5`. Reports rtt in ms."""
    started = time.perf_counter()
    try:
        out = subprocess.run(
            ['ping', '-c', '1', '-W', '5', host],
            capture_output=True, text=True, timeout=10,
        )
        ms = int((time.perf_counter() - started) * 1000)
        if out.returncode == 0:
            m = re.search(r'time[=<]([\d.]+)\s*ms', out.stdout)
            rtt = int(float(m.group(1))) if m else ms
            return {'status': 'up', 'reason': 'up', 'http_code': None, 'response_ms': rtt, 'error_msg': None}
        stderr = (out.stderr or '').lower()
        if 'name or service not known' in stderr or 'unknown host' in stderr or 'temporary failure in name resolution' in stderr:
            return {'status': 'down', 'reason': 'dns_nxdomain', 'http_code': None, 'response_ms': ms, 'error_msg': stderr[:500]}
        return {'status': 'down', 'reason': 'ping_failed', 'http_code': None, 'response_ms': ms, 'error_msg': (out.stderr or out.stdout or 'unreachable')[:500]}
    except subprocess.TimeoutExpired:
        ms = int((time.perf_counter() - started) * 1000)
        return {'status': 'down', 'reason': 'timeout', 'http_code': None, 'response_ms': ms, 'error_msg': 'ping timeout'}
    except Exception as e:
        ms = int((time.perf_counter() - started) * 1000)
        return {'status': 'down', 'reason': 'unknown_error', 'http_code': None, 'response_ms': ms, 'error_msg': str(e)[:500]}


def run_check(monitor: sqlite3.Row | dict) -> dict:
    m = dict(monitor)
    t = m['type']
    if t == 'http':
        return check_http(m['target'], platform=m.get('platform'))
    if t == 'http_keyword':
        return check_http(m['target'], expected_keyword=m.get('expected_keyword'),
                          platform=m.get('platform'))
    if t == 'dns':
        return check_dns(m['target'], record_type=m.get('dns_record_type') or 'A', expected=m.get('dns_expected_value'))
    if t == 'ping':
        return check_ping(m['target'])
    return {'status': 'down', 'reason': 'unknown_error', 'http_code': None, 'response_ms': 0, 'error_msg': f'unsupported type {t}'}


# ── Persistence helpers ───────────────────────────────────────────────────

def _record_heartbeat(conn: sqlite3.Connection, monitor: dict, result: dict, now: datetime) -> bool:
    """Persist one check result. Returns True when the monitor's status flipped
    (up→down or down→up) so callers can fire notifications after commit."""
    conn.execute(
        'INSERT INTO heartbeats(monitor_id, checked_at, status, reason, http_code, response_ms, error_msg) '
        'VALUES (?,?,?,?,?,?,?)',
        (monitor['id'], iso(now), result['status'], result['reason'],
         result['http_code'], result['response_ms'], result['error_msg']),
    )

    # Healthy checks (re-)learn the target's platform (see check_http). The key
    # is only present on healthy responses, so block pages never unlearn it.
    if 'platform_detected' in result and result['platform_detected'] != monitor.get('platform'):
        conn.execute('UPDATE monitors SET platform=? WHERE id=?',
                     (result['platform_detected'], monitor['id']))

    # Cross-domain redirect: learned AND cleared by healthy checks only (key
    # present = knowledge). A failed check can't tell where the site points.
    if 'redirect_to' in result and result['redirect_to'] != monitor.get('redirect_to'):
        conn.execute('UPDATE monitors SET redirect_to=? WHERE id=?',
                     (result['redirect_to'], monitor['id']))

    # Learned platform may have just changed in this txn — clamp with the
    # freshest value so a newly-identified Shopify store slows down immediately.
    plat = result.get('platform_detected') if 'platform_detected' in result else monitor.get('platform')
    next_at = now + timedelta(minutes=effective_interval_min({**monitor, 'platform': plat}))
    state_changed = monitor.get('current_status') != result['status']

    conn.execute(
        'UPDATE monitors SET current_status=?, current_reason=?, last_checked_at=?, next_check_at=?, '
        'last_state_change_at = CASE WHEN ? THEN ? ELSE last_state_change_at END '
        'WHERE id=?',
        (result['status'], result['reason'], iso(now), iso(next_at),
         1 if state_changed else 0, iso(now), monitor['id']),
    )

    if state_changed:
        if result['status'] == 'down':
            conn.execute(
                'INSERT INTO incidents(monitor_id, started_at, reason, details) VALUES (?,?,?,?)',
                (monitor['id'], iso(now), result['reason'], result['error_msg']),
            )
        else:
            conn.execute(
                'UPDATE incidents SET ended_at=? WHERE monitor_id=? AND ended_at IS NULL',
                (iso(now), monitor['id']),
            )
    return state_changed


def _check_and_record(monitor_id: int):
    # A slow check (10s timeout + 20s confirm sleep + 10s re-check ≈ 40s)
    # outlives the 30s scheduler tick, and next_check_at only advances after
    # recording — so the next tick re-submitted the same monitor. Both checks
    # then compared against the same stale "up" snapshot and BOTH opened an
    # incident + paged the chat (every 🔴 delivered twice). The in-flight
    # set drops the duplicate submit at the door.
    with _inflight_lock:
        if monitor_id in _inflight:
            return
        _inflight.add(monitor_id)
    try:
        with db() as conn:
            row = conn.execute('SELECT * FROM monitors WHERE id=?', (monitor_id,)).fetchone()
            if not row or not row['enabled']:
                return
            monitor = dict(row)
        result = run_check(monitor)
        if result['status'] == 'down' and monitor.get('current_status') != 'down':
            # Would flip up→down: re-check once before recording so a single
            # transient blip doesn't open an incident (or ping the chat).
            time.sleep(CONFIRM_DELAY_S)
            result = run_check(monitor)
        now = utcnow()
        # Refresh the shared-server grouping key (http types only); a failed
        # resolution keeps the last known key so a DNS-dead site still counts
        # toward its box's server event.
        server_key = (_resolve_server_key(monitor['target'])
                      if monitor['type'] in ('http', 'http_keyword') else None)
        if server_key:
            monitor['server_ip'] = server_key
        # The monitor can be deleted while the (slow) check above runs — its
        # heartbeats cascade away, so the insert would hit a FOREIGN KEY error.
        # BEGIN IMMEDIATE + an existence re-check makes skip-vs-insert atomic
        # against a concurrent delete_monitor().
        state_changed = False
        with _db_lock, db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            try:
                still_there = conn.execute(
                    'SELECT current_status FROM monitors WHERE id=?', (monitor_id,)).fetchone()
                if still_there:
                    # Second layer against double alerts: judge the transition
                    # against the CURRENT db state, not the pre-check snapshot
                    # (run_now or another worker may have recorded meanwhile).
                    monitor['current_status'] = still_there['current_status']
                    state_changed = _record_heartbeat(conn, monitor, result, now)
                    if server_key:
                        conn.execute('UPDATE monitors SET server_ip=? WHERE id=?',
                                     (server_key, monitor_id))
                conn.execute('COMMIT')
            except Exception:
                conn.execute('ROLLBACK')
                raise
        if not still_there:
            log.debug('[monitors] monitor %s deleted mid-check; heartbeat skipped', monitor_id)
        elif state_changed:
            _notify_transition(monitor, result, now)
            if result['status'] == 'down':
                _maybe_notify_server_event(monitor, result, now)
            else:
                _maybe_close_server_event(monitor, now)
        elif result['status'] == 'down':
            # No transition, still down — server-event check first (it may
            # open the event that suppresses the per-site reminder below).
            _maybe_notify_server_event(monitor, result, now)
            # The 30-min reminder loop.
            _maybe_notify_still_down(monitor, result, now)
        else:
            # Steady up — self-heal: close a stale open event for this box.
            _maybe_close_server_event(monitor, now)
    except Exception:
        log.exception('[monitors] check failed for monitor_id=%s', monitor_id)
    finally:
        with _inflight_lock:
            _inflight.discard(monitor_id)


# ── Scheduler ─────────────────────────────────────────────────────────────

_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()
_executor: ThreadPoolExecutor | None = None


def _scheduler_loop():
    global _executor
    _executor = ThreadPoolExecutor(max_workers=WORKER_COUNT, thread_name_prefix='monitor-check')
    log.info('[monitors] scheduler started (tick=%ss, workers=%s)', TICK_SECONDS, WORKER_COUNT)
    last_hourly = datetime.min.replace(tzinfo=timezone.utc)
    last_daily = datetime.min.replace(tzinfo=timezone.utc)
    last_purge = datetime.min.replace(tzinfo=timezone.utc)
    while not _scheduler_stop.is_set():
        try:
            now = utcnow()
            with db() as conn:
                due = conn.execute(
                    'SELECT id FROM monitors WHERE enabled=1 AND (next_check_at IS NULL OR next_check_at <= ?)',
                    (iso(now),),
                ).fetchall()
            for row in due:
                _executor.submit(_check_and_record, row['id'])

            # Rollups (cheap; only run on the hour / day boundary)
            if (now - last_hourly).total_seconds() > 600 and now.minute >= 5:
                rollup_hourly(now)
                last_hourly = now
            if (now - last_daily).total_seconds() > 3600 and now.hour == 0 and now.minute >= 10:
                rollup_daily(now)
                last_daily = now
            if (now - last_purge).total_seconds() > 3600 * 6 and now.hour == 3:
                purge_old(now)
                last_purge = now
        except Exception:
            log.exception('[monitors] scheduler tick error')
        _scheduler_stop.wait(TICK_SECONDS)
    log.info('[monitors] scheduler stopping')


def spread_check_phases() -> None:
    """De-cluster check times (runs at every boot; phases then stay stable
    because each check reschedules itself +interval).

    Batch-seeded monitors used to fire every check within the same seconds —
    ~80 http checks at once, including every Shopify store hitting Shopify's
    shared edge simultaneously from one IP. That burst is exactly the pattern
    their bot protection scores (false 5xx/connection-refused blocks).

    Shopify monitors get EVEN spacing across the interval; everything else
    gets stable per-target jitter."""
    now = utcnow()
    with db() as conn:
        rows = conn.execute("SELECT id, type, target, interval_min, platform FROM monitors "
                            "WHERE enabled=1").fetchall()
        shopify = sorted((r for r in rows if r['platform'] == 'shopify'
                          and r['type'] in ('http', 'http_keyword')), key=lambda r: r['id'])
        for i, r in enumerate(shopify):
            interval_s = effective_interval_min(dict(r)) * 60
            offset = int(i * interval_s / max(1, len(shopify)))
            conn.execute('UPDATE monitors SET next_check_at=? WHERE id=?',
                         (iso(now + timedelta(seconds=offset)), r['id']))
        shopify_ids = {r['id'] for r in shopify}
        for r in rows:
            if r['id'] in shopify_ids:
                continue
            interval_s = effective_interval_min(dict(r)) * 60
            offset = zlib.crc32(r['target'].encode()) % interval_s
            conn.execute('UPDATE monitors SET next_check_at=? WHERE id=?',
                         (iso(now + timedelta(seconds=offset)), r['id']))
    if shopify:
        gap = effective_interval_min(dict(shopify[0])) * 60 / len(shopify)
        log.info('[monitors] check phases spread: %d shopify monitors ~%ds apart, %d others jittered',
                 len(shopify), int(gap), len(rows) - len(shopify))


def start_scheduler():
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    init_db()
    _load_alert_state()
    spread_check_phases()
    _scheduler_stop.clear()
    _scheduler_thread = threading.Thread(target=_scheduler_loop, name='monitors-scheduler', daemon=True)
    _scheduler_thread.start()


def stop_scheduler():
    _scheduler_stop.set()


# ── Rollups + retention ───────────────────────────────────────────────────

def rollup_hourly(now: datetime):
    """Aggregate heartbeats into hourly_stats for the just-completed hour."""
    hour_end = now.replace(minute=0, second=0, microsecond=0)
    hour_start = hour_end - timedelta(hours=1)
    with db() as conn:
        rows = conn.execute(
            "SELECT monitor_id, "
            "SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) AS up_count, "
            "SUM(CASE WHEN status='down' THEN 1 ELSE 0 END) AS down_count, "
            "AVG(response_ms) AS avg_ms "
            "FROM heartbeats WHERE checked_at >= ? AND checked_at < ? GROUP BY monitor_id",
            (iso(hour_start), iso(hour_end)),
        ).fetchall()
        for r in rows:
            # p95 via window over the same range
            p95_row = conn.execute(
                "SELECT response_ms FROM heartbeats WHERE monitor_id=? AND checked_at >= ? AND checked_at < ? "
                "AND response_ms IS NOT NULL ORDER BY response_ms LIMIT 1 OFFSET "
                "(SELECT MAX(0, CAST(0.95 * COUNT(*) AS INTEGER) - 1) FROM heartbeats WHERE monitor_id=? "
                "AND checked_at >= ? AND checked_at < ? AND response_ms IS NOT NULL)",
                (r['monitor_id'], iso(hour_start), iso(hour_end),
                 r['monitor_id'], iso(hour_start), iso(hour_end)),
            ).fetchone()
            p95 = p95_row['response_ms'] if p95_row else None
            conn.execute(
                'INSERT OR REPLACE INTO hourly_stats(monitor_id, hour_start, up_count, down_count, avg_ms, p95_ms) '
                'VALUES (?,?,?,?,?,?)',
                (r['monitor_id'], iso(hour_start), r['up_count'], r['down_count'],
                 int(r['avg_ms']) if r['avg_ms'] is not None else None, p95),
            )


def rollup_daily(now: datetime):
    """Aggregate hourly_stats into daily_stats for yesterday (UTC)."""
    day_end = now.replace(hour=0, minute=0, second=0, microsecond=0)
    day_start = day_end - timedelta(days=1)
    day_label = day_start.strftime('%Y-%m-%d')
    with db() as conn:
        rows = conn.execute(
            "SELECT monitor_id, SUM(up_count) AS up_count, SUM(down_count) AS down_count, "
            "AVG(avg_ms) AS avg_ms, MAX(p95_ms) AS p95_ms "
            "FROM hourly_stats WHERE hour_start >= ? AND hour_start < ? GROUP BY monitor_id",
            (iso(day_start), iso(day_end)),
        ).fetchall()
        for r in rows:
            inc = conn.execute(
                'SELECT COUNT(*) AS c FROM incidents WHERE monitor_id=? AND started_at >= ? AND started_at < ?',
                (r['monitor_id'], iso(day_start), iso(day_end)),
            ).fetchone()['c']
            conn.execute(
                'INSERT OR REPLACE INTO daily_stats(monitor_id, day, up_count, down_count, avg_ms, p95_ms, incident_count) '
                'VALUES (?,?,?,?,?,?,?)',
                (r['monitor_id'], day_label, r['up_count'], r['down_count'],
                 int(r['avg_ms']) if r['avg_ms'] is not None else None, r['p95_ms'], inc),
            )


def purge_old(now: datetime):
    """Drop raw heartbeats older than retention window."""
    cutoff = now - timedelta(days=HEARTBEAT_RETENTION_DAYS)
    with db() as conn:
        deleted = conn.execute('DELETE FROM heartbeats WHERE checked_at < ?', (iso(cutoff),)).rowcount
        if deleted:
            log.info('[monitors] purged %s heartbeats older than %s', deleted, iso(cutoff))


# ── CRUD ──────────────────────────────────────────────────────────────────

def list_monitors(client_tag: str | None = None) -> list[dict]:
    with db() as conn:
        if client_tag:
            rows = conn.execute('SELECT * FROM monitors WHERE client_tag=? ORDER BY name, target', (client_tag,)).fetchall()
        else:
            rows = conn.execute('SELECT * FROM monitors ORDER BY client_tag, name, target').fetchall()
        return [dict(r) for r in rows]


def get_monitor(mid: int) -> dict | None:
    with db() as conn:
        row = conn.execute('SELECT * FROM monitors WHERE id=?', (mid,)).fetchone()
        return dict(row) if row else None


def create_monitor(*, type: str, target: str, name: str | None = None, client_tag: str | None = None,
                   interval_min: int | None = None, expected_keyword: str | None = None,
                   dns_record_type: str | None = None, dns_expected_value: str | None = None,
                   enabled: bool = True, seeded: bool = False) -> int:
    if type not in DEFAULT_INTERVAL_MIN:
        raise ValueError(f'unknown type {type}')
    target = normalise_target(target, type)
    if not target:
        raise ValueError('target required')
    iv = interval_min if interval_min else None
    # Deterministic per-target jitter so batch-seeded monitors don't all come
    # due in the same scheduler tick (and then stay phase-locked forever —
    # the resulting every-15-min burst from one IP trips Shopify's bot
    # protection). crc32(target) keeps the phase stable across re-seeds.
    interval_s = (iv or get_effective_default(type)) * 60
    first_check = utcnow() + timedelta(seconds=zlib.crc32(target.encode()) % interval_s)
    with db() as conn:
        cur = conn.execute(
            'INSERT INTO monitors(type, target, name, client_tag, interval_min, expected_keyword, '
            'dns_record_type, dns_expected_value, enabled, seeded, next_check_at) '
            'VALUES (?,?,?,?,?,?,?,?,?,?,?) '
            'ON CONFLICT(type, target) DO UPDATE SET '
            'name=excluded.name, client_tag=excluded.client_tag, interval_min=excluded.interval_min, '
            'expected_keyword=excluded.expected_keyword, dns_record_type=excluded.dns_record_type, '
            'dns_expected_value=excluded.dns_expected_value, enabled=excluded.enabled, '
            'seeded=MAX(seeded, excluded.seeded)',
            (type, target, name, client_tag, iv, expected_keyword, dns_record_type,
             dns_expected_value, 1 if enabled else 0, 1 if seeded else 0, iso(first_check)),
        )
        if cur.lastrowid:
            return cur.lastrowid
        row = conn.execute('SELECT id FROM monitors WHERE type=? AND target=?', (type, target)).fetchone()
        return row['id'] if row else 0


def update_monitor(mid: int, **fields) -> bool:
    allowed = {'name', 'client_tag', 'interval_min', 'expected_keyword',
               'dns_record_type', 'dns_expected_value', 'enabled'}
    sets, vals = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f'{k}=?')
            vals.append(v)
    if not sets:
        return False
    vals.append(mid)
    with db() as conn:
        cur = conn.execute(f'UPDATE monitors SET {", ".join(sets)} WHERE id=?', vals)
        return cur.rowcount > 0


def delete_monitor(mid: int) -> bool:
    with db() as conn:
        cur = conn.execute('DELETE FROM monitors WHERE id=?', (mid,))
        return cur.rowcount > 0


def reset_history(mid: int) -> bool:
    """Wipe all heartbeats/incidents/rollups for a monitor so uptime starts from 0 again.
    The monitor row itself (config + current_status) is preserved."""
    with db() as conn:
        exists = conn.execute('SELECT 1 FROM monitors WHERE id=?', (mid,)).fetchone()
        if not exists:
            return False
        conn.execute('DELETE FROM heartbeats WHERE monitor_id=?', (mid,))
        conn.execute('DELETE FROM hourly_stats WHERE monitor_id=?', (mid,))
        conn.execute('DELETE FROM daily_stats WHERE monitor_id=?', (mid,))
        conn.execute('DELETE FROM incidents WHERE monitor_id=?', (mid,))
        # Null next_check_at so the scheduler treats it as due on the next tick;
        # otherwise the monitor stays on its old cadence and looks frozen.
        conn.execute(
            "UPDATE monitors SET current_status=NULL, current_reason=NULL, "
            "last_checked_at=NULL, last_state_change_at=NULL, next_check_at=NULL WHERE id=?",
            (mid,),
        )
        return True


# ── Read views ────────────────────────────────────────────────────────────

def overview(window_days: int = 1) -> list[dict]:
    """Summary row per monitor for the dashboard grid."""
    since = utcnow() - timedelta(days=window_days)
    with db() as conn:
        monitors = conn.execute('SELECT * FROM monitors ORDER BY client_tag, name, target').fetchall()
        out = []
        for m in monitors:
            agg = conn.execute(
                "SELECT SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) AS up, "
                "SUM(CASE WHEN status='down' THEN 1 ELSE 0 END) AS down, "
                "AVG(response_ms) AS avg_ms "
                "FROM heartbeats WHERE monitor_id=? AND checked_at >= ?",
                (m['id'], iso(since)),
            ).fetchone()
            up = agg['up'] or 0
            down = agg['down'] or 0
            total = up + down
            uptime_pct = round(100 * up / total, 2) if total else None
            d = dict(m)
            d['uptime_pct'] = uptime_pct
            d['checks_window'] = total
            d['avg_ms'] = int(agg['avg_ms']) if agg['avg_ms'] is not None else None
            d['reason_label'] = REASON_LABELS.get(d.get('current_reason') or '', d.get('current_reason'))
            d['muted_until'] = muted_until(m['id'])
            out.append(d)
        return out


def _bucket_heartbeats(raw: list[dict], since: datetime, hours: int, bucket_min: int) -> list[dict]:
    """Group raw heartbeats into fixed-width time buckets so 7d/30d views don't return
    thousands of rows. Each output row covers `bucket_min` minutes starting at `since`,
    and carries down_count/total_count so the FE can shade partial-down buckets amber."""
    bucket_s = bucket_min * 60
    n_buckets = max(1, (hours * 60 + bucket_min - 1) // bucket_min)
    start_ts = since.timestamp()
    # Index by bucket -> list of heartbeats
    grouped: list[list[dict]] = [[] for _ in range(n_buckets)]
    for hb in raw:
        # checked_at is ISO; parse fast via fromisoformat (handles 'Z' since 3.11+, fall back)
        ts_str = hb['checked_at'].replace('Z', '+00:00') if hb['checked_at'].endswith('Z') else hb['checked_at']
        try:
            ts = datetime.fromisoformat(ts_str).timestamp()
        except ValueError:
            continue
        idx = int((ts - start_ts) // bucket_s)
        if 0 <= idx < n_buckets:
            grouped[idx].append(hb)
    out = []
    for i, bucket in enumerate(grouped):
        bucket_start = since + timedelta(seconds=i * bucket_s)
        if not bucket:
            out.append({
                'checked_at': iso(bucket_start),
                'status': 'unknown',
                'reason': '',
                'http_code': None,
                'response_ms': None,
                'down_count': 0,
                'total_count': 0,
            })
            continue
        down = [h for h in bucket if h['status'] == 'down']
        ups = [h for h in bucket if h['status'] == 'up']
        ms_vals = [h['response_ms'] for h in bucket if h['response_ms'] is not None]
        # Status field stays binary for back-compat; FE uses count fields for shading.
        status = 'down' if down else ('up' if ups else 'unknown')
        # Surface a representative down reason for tooltips/legends.
        reason = down[0]['reason'] if down else (ups[0]['reason'] if ups else '')
        out.append({
            'checked_at': iso(bucket_start),
            'status': status,
            'reason': reason,
            'http_code': (down[0] if down else bucket[-1]).get('http_code'),
            'response_ms': int(sum(ms_vals) / len(ms_vals)) if ms_vals else None,
            'down_count': len(down),
            'total_count': len(bucket),
        })
    return out


def detail(mid: int, hb_window: str = '24h') -> dict | None:
    """Full detail for a single monitor: monitor row, recent heartbeats, open + recent incidents,
    uptime over 1d/7d/30d, response-time series.

    `hb_window` controls the status-grid + response-chart timeframe: '24h' returns raw
    heartbeats; '7d' buckets into hourly aggregates (168 bars); '30d' buckets into
    4-hour aggregates (180 bars). Bucketed rows carry `down_count`/`total_count` so
    the FE can colour partial-down buckets amber instead of red.
    """
    m = get_monitor(mid)
    if not m:
        return None
    now = utcnow()

    # Normalise + map window → (hours, bucket_minutes). bucket_minutes=None means raw.
    hb_spec = {
        '24h': (24, None),
        '7d':  (24 * 7, 60),
        '30d': (24 * 30, 240),
    }
    hours, bucket_min = hb_spec.get(hb_window, hb_spec['24h'])
    with db() as conn:
        # Window aggregates
        windows = {}
        for label, days in (('1d', 1), ('7d', 7), ('30d', 30)):
            since = now - timedelta(days=days)
            agg = conn.execute(
                "SELECT SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) AS up, "
                "SUM(CASE WHEN status='down' THEN 1 ELSE 0 END) AS down, "
                "AVG(response_ms) AS avg_ms "
                "FROM heartbeats WHERE monitor_id=? AND checked_at >= ?",
                (mid, iso(since)),
            ).fetchone()
            up = agg['up'] or 0
            down = agg['down'] or 0
            total = up + down
            windows[label] = {
                'uptime_pct': round(100 * up / total, 2) if total else None,
                'checks': total,
                'avg_ms': int(agg['avg_ms']) if agg['avg_ms'] is not None else None,
            }

        # Heartbeats for the requested window (status grid + chart)
        hb_since = now - timedelta(hours=hours)
        raw = [dict(r) for r in conn.execute(
            'SELECT checked_at, status, reason, http_code, response_ms FROM heartbeats '
            'WHERE monitor_id=? AND checked_at >= ? ORDER BY checked_at',
            (mid, iso(hb_since)),
        ).fetchall()]
        if bucket_min is None:
            heartbeats = raw
        else:
            heartbeats = _bucket_heartbeats(raw, hb_since, hours, bucket_min)

        # Incidents (last 30d)
        inc_since = now - timedelta(days=30)
        incidents = [dict(r) for r in conn.execute(
            'SELECT id, started_at, ended_at, reason, details FROM incidents '
            'WHERE monitor_id=? AND started_at >= ? ORDER BY started_at DESC',
            (mid, iso(inc_since)),
        ).fetchall()]
        for inc in incidents:
            inc['reason_label'] = REASON_LABELS.get(inc['reason'], inc['reason'])

        # Reason breakdown (down events, last 7d)
        breakdown = [dict(r) for r in conn.execute(
            "SELECT reason, COUNT(*) AS c FROM heartbeats "
            "WHERE monitor_id=? AND status='down' AND checked_at >= ? GROUP BY reason ORDER BY c DESC",
            (mid, iso(now - timedelta(days=7))),
        ).fetchall()]
        for b in breakdown:
            b['reason_label'] = REASON_LABELS.get(b['reason'], b['reason'])

    m['windows'] = windows
    m['heartbeats'] = heartbeats
    m['incidents'] = incidents
    m['reason_breakdown'] = breakdown
    m['reason_label'] = REASON_LABELS.get(m.get('current_reason') or '', m.get('current_reason'))
    mute = mute_info(mid)
    m['muted_until'] = mute['until'] if mute else None
    m['muted_by'] = (mute or {}).get('by')
    return m


def run_now(mid: int) -> dict | None:
    """On-demand check, bypasses the scheduler."""
    m = get_monitor(mid)
    if not m:
        return None
    result = run_check(m)
    now = utcnow()
    server_key = (_resolve_server_key(m['target'])
                  if m['type'] in ('http', 'http_keyword') else None)
    if server_key:
        m['server_ip'] = server_key
    with _db_lock, db() as conn:
        # Same stale-snapshot guard as _check_and_record: a scheduler check may
        # have recorded while ours ran — judge the flip against current state.
        fresh = conn.execute('SELECT current_status FROM monitors WHERE id=?', (mid,)).fetchone()
        if not fresh:
            return result
        m['current_status'] = fresh['current_status']
        state_changed = _record_heartbeat(conn, m, result, now)
        if server_key:
            conn.execute('UPDATE monitors SET server_ip=? WHERE id=?', (server_key, mid))
    if state_changed:
        _notify_transition(m, result, now)
        if result['status'] == 'down':
            _maybe_notify_server_event(m, result, now)
        else:
            _maybe_close_server_event(m, now)
    elif result['status'] == 'down':
        # Manual check of a still-down monitor goes through the same grace +
        # throttle guards as the scheduler — no extra messages from clicking.
        _maybe_notify_server_event(m, result, now)
        _maybe_notify_still_down(m, result, now)
    else:
        _maybe_close_server_event(m, now)
    return result


# ── Aggregates ────────────────────────────────────────────────────────────

def list_clients() -> list[dict]:
    """Distinct client tags with monitor counts and aggregate uptime (24h)."""
    since = utcnow() - timedelta(days=1)
    with db() as conn:
        tags = conn.execute(
            "SELECT client_tag, COUNT(*) AS monitors, "
            "SUM(CASE WHEN current_status='up' THEN 1 ELSE 0 END) AS up_now, "
            "SUM(CASE WHEN current_status='down' THEN 1 ELSE 0 END) AS down_now "
            "FROM monitors WHERE client_tag IS NOT NULL AND client_tag != '' "
            "GROUP BY client_tag ORDER BY client_tag"
        ).fetchall()
        return [dict(r) for r in tags]
