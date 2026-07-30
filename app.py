"""open-uptime-monitor — self-hosted uptime monitoring with sane alerts.

Single Flask process: a scheduler thread runs the checks (monitors.py), this
app serves the dashboard, settings, mute pages and shareable reports.

    python app.py                # http://0.0.0.0:8080
    UPTIME_PORT=9000 python app.py

All state lives in ./data (SQLite DB + settings.json) — override the location
with UPTIME_DATA_DIR. There is no built-in auth: bind to localhost or put a
reverse proxy with auth in front if the network isn't trusted.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading

from flask import Flask, Response, jsonify, redirect, request

import monitors
import monitor_report

HOST = os.environ.get('UPTIME_HOST', '0.0.0.0')
PORT = int(os.environ.get('UPTIME_PORT', '8080'))
SETTINGS_PATH = os.path.join(monitors.DATA_DIR, 'settings.json')

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s')
log = logging.getLogger('uptime')

app = Flask(__name__)

DEFAULT_SETTINGS = {
    'intervals': {'http': 5, 'http_keyword': 10, 'dns': 15, 'ping': 5},
    'notify': {
        'enabled': False,
        'webhook_url': '',
        'webhook_type': 'google_chat',   # google_chat | slack | discord | generic
        'notify_recovery': True,
        'public_base_url': '',           # e.g. http://192.0.2.10:8080 — enables links in alerts
        'grace_min': 30,                 # outage must last this long before the first 🔴
        'reminder_min': 30,              # minutes between repeat 🔴s per monitor
    },
    'timezone': 'UTC',                   # IANA name, e.g. Europe/Berlin
    'branding': {'name': '', 'color': '#dc2626', 'url': '', 'logo_b64': ''},
}


def _merged(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merged(out[k], v)
        else:
            out[k] = v
    return out


def load_settings() -> dict:
    try:
        with open(SETTINGS_PATH) as f:
            return _merged(DEFAULT_SETTINGS, json.load(f) or {})
    except FileNotFoundError:
        return json.loads(json.dumps(DEFAULT_SETTINGS))
    except Exception:
        log.exception('settings read failed — using defaults')
        return json.loads(json.dumps(DEFAULT_SETTINGS))


def save_settings(s: dict) -> None:
    os.makedirs(monitors.DATA_DIR, exist_ok=True)
    tmp = SETTINGS_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(s, f, indent=1)
    os.replace(tmp, SETTINGS_PATH)


def apply_settings(s: dict | None = None) -> None:
    """Push settings into the engine + report module. Called at boot and after
    every save, so changes apply without a restart."""
    s = s or load_settings()
    monitors.set_default_intervals(s.get('intervals'))
    monitors.set_notify_config(s.get('notify'))
    n = s.get('notify') or {}
    monitors.set_alert_windows(n.get('grace_min'), n.get('reminder_min'))
    monitors.set_timezone(s.get('timezone'))
    monitor_report.set_branding(s.get('branding'))


# ── JSON API ────────────────────────────────────────────────────────────────

@app.route('/monitors/overview')
def monitors_overview():
    return jsonify({'monitors': monitors.overview(window_days=1),
                    'clients': monitors.list_clients()})


@app.route('/monitors/<int:mid>')
def monitors_detail(mid):
    window = request.args.get('window', '24h')
    d = monitors.detail(mid, hb_window=window if window in ('24h', '7d', '30d') else '24h')
    if not d:
        return jsonify({'error': 'not found'}), 404
    return jsonify(d)


@app.route('/monitors', methods=['POST'])
def monitors_create():
    body = request.get_json(silent=True) or {}
    try:
        mid = monitors.create_monitor(
            type=body.get('type', 'http'),
            target=body.get('target', ''),
            name=(body.get('name') or '').strip() or None,
            client_tag=(body.get('client_tag') or '').strip() or None,
            interval_min=body.get('interval_min') or None,
            expected_keyword=(body.get('expected_keyword') or '').strip() or None,
            dns_record_type=(body.get('dns_record_type') or '').strip() or None,
            dns_expected_value=(body.get('dns_expected_value') or '').strip() or None,
            enabled=bool(body.get('enabled', True)),
        )
        return jsonify({'id': mid})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/monitors/<int:mid>', methods=['PATCH'])
def monitors_update(mid):
    return jsonify({'ok': bool(monitors.update_monitor(mid, **(request.get_json(silent=True) or {})))})


@app.route('/monitors/<int:mid>', methods=['DELETE'])
def monitors_delete(mid):
    return jsonify({'ok': bool(monitors.delete_monitor(mid))})


@app.route('/monitors/<int:mid>/run', methods=['POST'])
def monitors_run_now(mid):
    r = monitors.run_now(mid)
    if r is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify(r)


@app.route('/monitors/<int:mid>/reset', methods=['POST'])
def monitors_reset(mid):
    if not monitors.reset_history(mid):
        return jsonify({'error': 'not found'}), 404
    return jsonify({'ok': True})


# ── Settings ────────────────────────────────────────────────────────────────

@app.route('/settings', methods=['GET'])
def settings_get():
    return jsonify(load_settings())


@app.route('/settings', methods=['POST'])
def settings_save():
    body = request.get_json(silent=True) or {}
    s = _merged(load_settings(), body)
    # Light validation — never let a broken value take the scheduler down.
    n = s['notify']
    url = (n.get('webhook_url') or '').strip()
    if url and not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'webhook URL must start with http(s)://'}), 400
    if n.get('enabled') and not url:
        return jsonify({'error': 'enable alerts requires a webhook URL'}), 400
    if (n.get('webhook_type') or 'google_chat') not in monitors.WEBHOOK_TYPES:
        return jsonify({'error': f'webhook_type must be one of {", ".join(monitors.WEBHOOK_TYPES)}'}), 400
    logo = (s['branding'].get('logo_b64') or '')
    if len(logo) > 400_000:
        return jsonify({'error': 'logo too large — keep it under ~300 KB'}), 400
    save_settings(s)
    apply_settings(s)
    return jsonify({'ok': True})


@app.route('/settings/test-webhook', methods=['POST'])
def settings_test_webhook():
    body = request.get_json(silent=True) or {}
    ok, err = monitors.send_chat_message(
        '✅ Test message from open-uptime-monitor — alerts will arrive here.',
        webhook_url=(body.get('webhook_url') or '').strip() or None,
        webhook_type=(body.get('webhook_type') or '').strip() or None)
    return jsonify({'ok': ok, 'error': err})


# ── Mute page (linked from every 🔴 alert) ─────────────────────────────────
# GET shows a confirm page — the link in a chat message must never mutate
# state on open (previews, prefetches, mis-clicks). The mute is the POST.

_MUTE_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Mute alerts — {name}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 *{{box-sizing:border-box;margin:0;padding:0}}
 body{{font-family:Inter,system-ui,sans-serif;background:#f6f7f8;color:#111}}
 header{{padding:12px 22px;background:#1f2125;color:#fff}}
 h1{{font-size:15px;margin:0;font-weight:700}}
 main{{max-width:560px;margin:40px auto;padding:0 20px}}
 .card{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:22px;box-shadow:0 1px 3px rgba(0,0,0,0.04)}}
 .dot{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px}}
 .up{{background:#16a34a}}.down{{background:#dc2626}}.unknown{{background:#9ca3af}}.up_protected{{background:#f1c40f}}
 .grey{{color:#6b7280}}.row{{margin:6px 0;font-size:14px}}
 .banner{{border-radius:8px;padding:10px 14px;margin-bottom:16px;font-size:14px}}
 .ok{{background:#f0fdf4;border:1px solid #16a34a;color:#14532d}}
 .muted-b{{background:#fffbeb;border:1px solid #f1c40f;color:#7c5e00}}
 form{{display:inline}}
 button{{font:inherit;font-size:13.5px;border:0;border-radius:6px;padding:10px 16px;margin:14px 8px 0 0;cursor:pointer;font-weight:600}}
 .primary{{background:#dc2626;color:#fff}}
 .secondary{{background:#fff;color:#111;border:1px solid #ccc}}
 .unmute{{background:#16a34a;color:#fff}}
 a{{color:#2563eb;text-decoration:none}}
</style></head><body>
<header><h1>🔇 Mute uptime alerts</h1></header>
<main><div class="card">
{banner}
<div class="row"><span class="dot {st}"></span><b>{name}</b> <span class="grey">({st})</span></div>
<div class="row grey">{target}</div>
{reason_row}
{mute_row}
<div class="row grey" style="margin-top:14px">Muting silences the 🔴 DOWN / STILL DOWN messages for this
site only — for when the issue is already known (e.g. an expired SSL certificate) and there's nothing
more to do right now. A 🟢 RECOVERED message still sends when it comes back, and alerts resume
automatically when the mute expires.</div>
{buttons}
<div class="row" style="margin-top:16px"><a href="/monitors/{mid}/report">📊 View report</a> ·
<a href="/">Dashboard</a></div>
</div></main></body></html>"""


def _mute_page(mid: int, done: str | None = None):
    import html as html_mod
    m = monitors.get_monitor(mid)
    if not m:
        return jsonify({'error': 'not found'}), 404
    esc = html_mod.escape
    name = esc(m.get('name') or m.get('target') or f'monitor {mid}')
    info = monitors.mute_info(mid)
    banner = ''
    if done == 'muted':
        banner = '<div class="banner ok">Done — alerts for this site are muted.</div>'
    elif done == 'unmuted':
        banner = '<div class="banner ok">Alerts are back on for this site.</div>'
    mute_row = ''
    if info:
        until_local = monitors._local_ts(monitors.parse_iso(info['until']))
        by = f' by {esc(info["by"])}' if info.get('by') else ''
        mute_row = (f'<div class="banner muted-b" style="margin-top:12px">🔇 Muted{by} '
                    f'until <b>{esc(until_local)}</b></div>')
    reason = m.get('current_reason')
    reason_row = ''
    if m.get('current_status') == 'down' and reason:
        label = monitors.REASON_LABELS.get(reason, reason)
        reason_row = f'<div class="row">Reason: <b>{esc(label)}</b></div>'

    def btn(label, hours, cls):
        return (f'<form method="post"><input type="hidden" name="hours" value="{hours}">'
                f'<button class="{cls}" type="submit">{label}</button></form>')
    buttons = btn('Mute for 1 day', 24, 'primary') + btn('Mute for 3 days', 72, 'secondary')
    if info:
        buttons += ('<form method="post"><input type="hidden" name="action" value="unmute">'
                    '<button class="unmute" type="submit">Unmute now</button></form>')
    page = _MUTE_HTML.format(mid=mid, name=name, st=m.get('current_status') or 'unknown',
                             banner=banner, mute_row=mute_row, reason_row=reason_row,
                             target=esc(m.get('target') or ''), buttons=buttons)
    return Response(page, mimetype='text/html')


@app.route('/monitors/<int:mid>/mute', methods=['GET'])
def monitors_mute_page(mid):
    return _mute_page(mid, done=request.args.get('done'))


@app.route('/monitors/<int:mid>/mute', methods=['POST'])
def monitors_mute_apply(mid):
    m = monitors.get_monitor(mid)
    if not m:
        return jsonify({'error': 'not found'}), 404
    is_json = request.is_json
    body = request.form if request.form else (request.get_json(silent=True) or {})
    who = request.remote_addr or ''
    if (body.get('action') or '').strip() == 'unmute':
        monitors.unmute_monitor(mid)
        if is_json:
            return jsonify({'ok': True, 'muted_until': None})
        return redirect(f'/monitors/{mid}/mute?done=unmuted')
    try:
        hours = float(body.get('hours') or 24)
    except (TypeError, ValueError):
        hours = 24
    until = monitors.mute_monitor(mid, hours=hours, by=who)
    if is_json:
        return jsonify({'ok': True, 'muted_until': until, 'muted_by': who})
    return redirect(f'/monitors/{mid}/mute?done=muted')


# ── Reports ─────────────────────────────────────────────────────────────────

@app.route('/monitors/<int:mid>/report')
def monitors_report(mid):
    if not monitors.get_monitor(mid):
        return jsonify({'error': 'not found'}), 404
    try:
        days = min(90, max(7, int(request.args.get('days', 30))))
    except (TypeError, ValueError):
        days = 30
    html = monitor_report.build_html(mid, days, bare=request.args.get('bare') == '1')
    return Response(html, mimetype='text/html')


@app.route('/monitors/<int:mid>/report.png')
def monitors_report_png(mid):
    m = monitors.get_monitor(mid)
    if not m:
        return jsonify({'error': 'not found'}), 404
    try:
        days = min(90, max(7, int(request.args.get('days', 30))))
    except (TypeError, ValueError):
        days = 30
    try:
        png = monitor_report.render_png(mid, days, base_url=f'http://127.0.0.1:{PORT}')
    except Exception as e:
        log.exception('report.png render failed for %s', mid)
        return jsonify({'error': f'PNG render failed: {e}. The HTML report still works — '
                                 'use Print / save as PDF, or install playwright.'}), 500
    slug = re.sub(r'[^a-z0-9]+', '-', (m.get('name') or 'site').lower()).strip('-')
    stamp = monitors.utcnow().strftime('%Y%m%d')
    return Response(png, mimetype='image/png',
                    headers={'Content-Disposition': f'attachment; filename="uptime-report-{slug}-{stamp}.png"'})


# ── Dashboard (single page: Monitors + Settings tabs) ──────────────────────

_PAGE_HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Uptime Monitor</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 *{box-sizing:border-box;margin:0;padding:0}
 body{font-family:Inter,system-ui,sans-serif;background:#f6f7f8;color:#111}
 header{background:#1f2125;color:#fff;padding:11px 24px;display:flex;align-items:center;gap:18px}
 header b{font-size:14.5px;font-weight:700}
 header nav{display:flex;gap:4px}
 header nav button{background:none;border:none;color:#9aa1ac;font:inherit;font-size:13px;font-weight:600;padding:6px 12px;border-radius:6px;cursor:pointer}
 header nav button.on{background:#33363c;color:#fff}
 header small{color:#9aa1ac;margin-left:auto;font-size:12px}
 main{max-width:1240px;margin:0 auto;padding:26px 24px 60px}
 h1{font-family:Georgia,serif;font-size:26px;margin-bottom:4px}
 .sub{color:#6b7280;font-size:13px;margin-bottom:18px}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:16px}
 .card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:14px 18px;min-width:170px;flex:1}
 .card .lbl{font-size:11px;font-weight:700;letter-spacing:.6px;color:#6b7280;text-transform:uppercase}
 .card .num{font-size:26px;font-weight:800;margin-top:2px}
 .num.ok{color:#16a34a}.num.bad{color:#dc2626}
 .bar{display:flex;gap:10px;margin-bottom:14px}
 #q{flex:1;padding:10px 14px;border:1px solid #e5e7eb;border-radius:8px;font:inherit;font-size:13.5px;background:#fff}
 .btn{font:inherit;font-size:13px;font-weight:600;border:none;border-radius:8px;padding:10px 16px;cursor:pointer}
 .btn.red{background:#dc2626;color:#fff}
 .btn.plain{background:#fff;color:#111;border:1px solid #ccc}
 .btn.green{background:#16a34a;color:#fff}
 #wrap{background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow-x:auto}
 table{width:100%;border-collapse:collapse;font-size:13.5px}
 th,td{padding:10px 14px;text-align:left;border-bottom:1px solid #f0f1f3;white-space:nowrap}
 th{color:#6b7280;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
 tbody tr:last-child td{border-bottom:none}
 tbody tr:hover td{background:#fafafa;cursor:pointer}
 .dot{display:inline-block;width:9px;height:9px;border-radius:50%}
 .up{background:#16a34a}.down{background:#dc2626}.unknown{background:#9ca3af}.up_protected{background:#f1c40f}
 .nm{font-weight:600}
 .url{color:#6b7280;font-size:12px;font-family:ui-monospace,Menlo,monospace}
 .pill{display:inline-flex;align-items:center;gap:5px;border:1px solid #e5e7eb;border-radius:999px;padding:2px 9px;font-size:11px;font-weight:600;color:#374151}
 .pill .dot{width:6px;height:6px}
 .grey{color:#6b7280}
 .pct{font-weight:700}.pct.g{color:#16a34a}.pct.a{color:#d97706}.pct.r{color:#dc2626}
 .act{background:none;border:none;cursor:pointer;font-size:14px;padding:2px 5px;opacity:.55}
 .act:hover{opacity:1}
 a.mute{text-decoration:none;opacity:.35;font-size:14px}a.mute.on{opacity:1}
 .overlay{position:fixed;inset:0;background:rgba(17,17,17,0.45);z-index:100;display:none;align-items:center;justify-content:center}
 .overlay.show{display:flex}
 .modal{background:#fff;border-radius:10px;box-shadow:0 20px 60px rgba(0,0,0,0.25);width:min(480px,92vw);padding:22px;max-height:90vh;overflow-y:auto}
 .modal h3{font-size:16px;margin-bottom:14px}
 .f{margin-bottom:12px}
 .f label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:4px}
 .f input,.f select{width:100%;padding:9px 12px;border:1px solid #d1d5db;border-radius:6px;font:inherit;font-size:13.5px;background:#fff}
 .f input[type=checkbox]{width:auto}
 .f .hint{font-size:11.5px;color:#6b7280;margin-top:3px;line-height:1.45}
 .frow{display:flex;gap:10px}.frow .f{flex:1}
 fieldset{border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:18px;background:#fff}
 legend{font-size:12px;font-weight:700;color:#374151;text-transform:uppercase;letter-spacing:.5px;padding:0 6px}
 #msg{position:fixed;bottom:20px;right:20px;background:#1f2125;color:#fff;padding:10px 18px;border-radius:8px;font-size:13px;display:none;z-index:200}
</style></head><body>
<header>
  <b>🛰️ Uptime Monitor</b>
  <nav>
    <button id="tab-mon" class="on" onclick="showTab('mon')">Monitors</button>
    <button id="tab-set" onclick="showTab('set')">Settings</button>
  </nav>
  <small id="meta">loading…</small>
</header>
<main>
<div id="view-mon">
  <h1>Uptime Monitor</h1>
  <div class="sub">Checks run on their own scheduler · this page refreshes every 30s</div>
  <div class="cards">
   <div class="card"><div class="lbl">Sites</div><div class="num" id="c-sites">—</div></div>
   <div class="card"><div class="lbl">Up now</div><div class="num ok" id="c-up">—</div></div>
   <div class="card"><div class="lbl">Down now</div><div class="num bad" id="c-down">—</div></div>
  </div>
  <div class="bar">
    <input id="q" placeholder="Search by name, URL, or tag…">
    <button class="btn red" onclick="openAdd()">+ Add monitor</button>
  </div>
  <div id="wrap"><table id="t"><thead><tr>
  <th></th><th>Site</th><th>Check</th><th>Reason</th><th>Uptime 24h</th><th>Response</th><th>Last check</th><th style="text-align:right">Actions</th>
  </tr></thead><tbody></tbody></table></div>
</div>

<div id="view-set" style="display:none">
  <h1>Settings</h1>
  <div class="sub">Applied live on save — no restart needed</div>

  <fieldset><legend>Check intervals (minutes)</legend>
    <div class="frow">
      <div class="f"><label>HTTP</label><input id="iv-http" type="number" min="1" max="1440"></div>
      <div class="f"><label>HTTP + keyword</label><input id="iv-http_keyword" type="number" min="1" max="1440"></div>
      <div class="f"><label>DNS</label><input id="iv-dns" type="number" min="1" max="1440"></div>
      <div class="f"><label>Ping</label><input id="iv-ping" type="number" min="1" max="1440"></div>
    </div>
    <div class="f"><div class="hint">Per-monitor intervals (set when adding a monitor) override these defaults.
    Monitors detected as Shopify are never checked more than once per 15 minutes — faster checks trip
    Shopify's bot protection and cause false downs.</div></div>
  </fieldset>

  <fieldset><legend>Alerts</legend>
    <div class="f"><label><input id="n-enabled" type="checkbox"> Send chat alerts when a site goes down</label></div>
    <div class="frow">
      <div class="f"><label>Webhook type</label>
        <select id="n-type"><option value="google_chat">Google Chat</option><option value="slack">Slack</option>
        <option value="discord">Discord</option><option value="generic">Generic JSON</option></select></div>
      <div class="f" style="flex:2"><label>Webhook URL</label><input id="n-url" placeholder="https://…"></div>
    </div>
    <div class="f"><label><input id="n-recovery" type="checkbox"> Also send 🟢 recovery messages</label></div>
    <div class="frow">
      <div class="f"><label>Grace window (min)</label><input id="n-grace" type="number" min="0" max="1440">
        <div class="hint">An outage must last this long before the first 🔴 — short blips send nothing.</div></div>
      <div class="f"><label>Reminder every (min)</label><input id="n-reminder" type="number" min="5" max="1440">
        <div class="hint">While a site stays down, one "STILL DOWN" reminder per this many minutes.</div></div>
    </div>
    <div class="f"><label>Public base URL of this app</label><input id="n-base" placeholder="http://192.0.2.10:8080">
      <div class="hint">When set, every alert carries links to the report and the mute page. Leave empty for no links.</div></div>
    <button class="btn plain" onclick="testWebhook()">Send test message</button>
  </fieldset>

  <fieldset><legend>Display</legend>
    <div class="f"><label>Timezone (IANA name)</label><input id="d-tz" list="tzlist" placeholder="UTC">
      <datalist id="tzlist"><option>UTC</option><option>Europe/London</option><option>Europe/Berlin</option>
      <option>America/New_York</option><option>America/Chicago</option><option>America/Los_Angeles</option>
      <option>Asia/Kolkata</option><option>Asia/Singapore</option><option>Australia/Sydney</option><option>Australia/Melbourne</option></datalist>
      <div class="hint">Used for timestamps in alerts and reports.</div></div>
  </fieldset>

  <fieldset><legend>Report branding</legend>
    <div class="frow">
      <div class="f"><label>Name shown on reports</label><input id="b-name" placeholder="Your company"></div>
      <div class="f"><label>Accent colour</label><input id="b-color" type="color"></div>
    </div>
    <div class="f"><label>Website URL (report footer)</label><input id="b-url" placeholder="example.com"></div>
    <div class="f"><label>Logo (PNG, shown on reports)</label><input id="b-logo" type="file" accept="image/png">
      <div class="hint" id="b-logo-state"></div></div>
  </fieldset>

  <button class="btn red" onclick="saveSettings()">Save settings</button>
</div>
</main>

<div class="overlay" id="add-ov" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <h3>Add monitor</h3>
    <div class="f"><label>Type</label>
      <select id="a-type" onchange="addTypeChanged()">
        <option value="http">HTTP — page loads OK</option>
        <option value="http_keyword">HTTP + keyword — page loads AND contains text</option>
        <option value="dns">DNS — domain resolves</option>
        <option value="ping">Ping — host answers ICMP</option>
      </select></div>
    <div class="f"><label>Target</label><input id="a-target" placeholder="https://example.com">
      <div class="hint">URL for HTTP checks; bare domain/host for DNS and ping.</div></div>
    <div class="f"><label>Name (optional)</label><input id="a-name" placeholder="Example site"></div>
    <div class="f" id="a-kw-row" style="display:none"><label>Expected keyword</label><input id="a-kw" placeholder='"db":"ok"'>
      <div class="hint">Case-insensitive substring the response body must contain.</div></div>
    <div class="frow" id="a-dns-row" style="display:none">
      <div class="f"><label>Record type</label>
        <select id="a-dnstype"><option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>TXT</option><option>NS</option></select></div>
      <div class="f"><label>Expected value (optional)</label><input id="a-dnsval"></div>
    </div>
    <div class="f"><label>Interval (min, optional — falls back to the type default)</label><input id="a-iv" type="number" min="1" max="1440"></div>
    <div style="display:flex;gap:8px;margin-top:6px">
      <button class="btn red" onclick="submitAdd()">Add monitor</button>
      <button class="btn plain" onclick="document.getElementById('add-ov').classList.remove('show')">Cancel</button>
    </div>
  </div>
</div>
<div id="msg"></div>

<script>
let DATA=[];
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toast(t){const m=$('msg');m.textContent=t;m.style.display='block';clearTimeout(m._t);m._t=setTimeout(()=>m.style.display='none',3500)}
async function api(path,opts){const r=await fetch(path,opts);const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||r.status);return j}

function showTab(t){
  $('view-mon').style.display=t==='mon'?'':'none';
  $('view-set').style.display=t==='set'?'':'none';
  $('tab-mon').classList.toggle('on',t==='mon');
  $('tab-set').classList.toggle('on',t==='set');
  if(t==='set')loadSettings();
}

function pctCls(p){return p==null?'grey':(p>=99.5?'pct g':(p>=97?'pct a':'pct r'))}
function render(){
  const q=($('q').value||'').toLowerCase();
  const tb=document.querySelector('#t tbody');tb.innerHTML='';
  const rows=DATA.filter(m=>!q||(`${m.name||''} ${m.target||''} ${m.client_tag||''}`).toLowerCase().includes(q));
  for(const m of rows){
    const st=m.current_status||'unknown';
    const tr=document.createElement('tr');
    const up=(m.uptime_pct==null?'—':m.uptime_pct.toFixed(2)+'%');
    const paused=!m.enabled;
    tr.innerHTML=`<td><span class="dot ${st}" title="${st}"></span></td>
     <td><div class="nm">${esc(m.name)||esc(m.target)}${paused?' <span class="grey" style="font-weight:400">(paused)</span>':''}</div><div class="url">${esc(m.target)}</div></td>
     <td><span class="pill"><span class="dot ${st}"></span>${esc((m.type||'').replace('http_keyword','HTTP+KW').toUpperCase())}</span></td>
     <td class="grey">${esc(m.reason_label||m.current_reason||'')}</td>
     <td><span class="${pctCls(m.uptime_pct)}">${up}</span></td>
     <td class="grey">${m.avg_ms!=null?m.avg_ms+' ms':'—'}</td>
     <td class="grey">${esc((m.last_checked_at||'').replace('T',' ').slice(0,16))}</td>
     <td style="text-align:right;white-space:nowrap">
       <button class="act" title="run check now" onclick="event.stopPropagation();runNow(${m.id},this)">▶</button>
       <button class="act" title="${paused?'resume':'pause'}" onclick="event.stopPropagation();togglePause(${m.id},${paused})">${paused?'⏵':'⏸'}</button>
       <a class="mute ${m.muted_until?'on':''}" href="/monitors/${m.id}/mute" onclick="event.stopPropagation()"
          title="${m.muted_until?'alerts muted — view/unmute':'mute alerts for this site'}">🔇</a>
       <button class="act" title="delete" onclick="event.stopPropagation();del(${m.id},'${esc(m.name||m.target).replace(/'/g,'')}')">🗑</button>
     </td>`;
    tr.onclick=()=>location.href='/monitors/'+m.id+'/report';
    tb.appendChild(tr);
  }
}
async function load(){
  try{
    const j=await api('/monitors/overview');
    DATA=(j.monitors||[]).slice().sort((a,b)=>
      (a.current_status==='down'?0:1)-(b.current_status==='down'?0:1)||
      String(a.name||a.target).localeCompare(String(b.name||b.target)));
    const key=m=>m.client_tag||m.name||m.target;
    const sites=new Set(DATA.map(key));
    const downSites=new Set(DATA.filter(m=>m.current_status==='down').map(key));
    $('c-sites').textContent=sites.size;
    $('c-up').textContent=sites.size-downSites.size;
    $('c-down').textContent=downSites.size;
    $('meta').textContent=DATA.length+' checks · '+downSites.size+' down · refreshed '+new Date().toLocaleTimeString();
    render();
  }catch(e){$('meta').textContent='load failed: '+e.message}
}

function openAdd(){$('add-ov').classList.add('show');$('a-target').focus()}
function addTypeChanged(){
  const t=$('a-type').value;
  $('a-kw-row').style.display=t==='http_keyword'?'':'none';
  $('a-dns-row').style.display=t==='dns'?'':'none';
}
async function submitAdd(){
  try{
    await api('/monitors',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      type:$('a-type').value,target:$('a-target').value,name:$('a-name').value,
      expected_keyword:$('a-kw').value,dns_record_type:$('a-dnstype').value,dns_expected_value:$('a-dnsval').value,
      interval_min:parseInt($('a-iv').value)||null})});
    $('add-ov').classList.remove('show');
    $('a-target').value='';$('a-name').value='';$('a-kw').value='';$('a-iv').value='';
    toast('Monitor added — first check runs shortly');load();
  }catch(e){toast('Error: '+e.message)}
}
async function runNow(id,btn){btn.textContent='…';try{await api('/monitors/'+id+'/run',{method:'POST'})}catch(e){}btn.textContent='▶';load()}
async function togglePause(id,resume){try{await api('/monitors/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:resume?1:0})})}catch(e){}load()}
async function del(id,name){if(!confirm('Delete monitor "'+name+'" and its history?'))return;try{await api('/monitors/'+id,{method:'DELETE'})}catch(e){}load()}

async function loadSettings(){
  try{
    const s=await api('/settings');
    for(const k of ['http','http_keyword','dns','ping'])$('iv-'+k).value=s.intervals[k];
    $('n-enabled').checked=!!s.notify.enabled;$('n-type').value=s.notify.webhook_type;
    $('n-url').value=s.notify.webhook_url;$('n-recovery').checked=s.notify.notify_recovery!==false;
    $('n-grace').value=s.notify.grace_min;$('n-reminder').value=s.notify.reminder_min;
    $('n-base').value=s.notify.public_base_url;
    $('d-tz').value=s.timezone||'UTC';
    $('b-name').value=s.branding.name||'';$('b-color').value=s.branding.color||'#dc2626';
    $('b-url').value=s.branding.url||'';
    $('b-logo-state').textContent=s.branding.logo_b64?'Logo uploaded ✓ (choose a file to replace)':'No logo — reports show the name as text.';
    window._logoB64=s.branding.logo_b64||'';
  }catch(e){toast('Could not load settings: '+e.message)}
}
$('b-logo')&&($('b-logo').onchange=e=>{
  const f=e.target.files[0];if(!f)return;
  if(f.size>300000){toast('Logo too large — keep it under 300 KB');e.target.value='';return}
  const r=new FileReader();
  r.onload=()=>{window._logoB64=String(r.result).split(',')[1]||'';$('b-logo-state').textContent='New logo ready — save settings to apply.'};
  r.readAsDataURL(f);
});
async function saveSettings(){
  try{
    await api('/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      intervals:{http:+$('iv-http').value||5,http_keyword:+$('iv-http_keyword').value||10,dns:+$('iv-dns').value||15,ping:+$('iv-ping').value||5},
      notify:{enabled:$('n-enabled').checked,webhook_type:$('n-type').value,webhook_url:$('n-url').value.trim(),
        notify_recovery:$('n-recovery').checked,grace_min:+$('n-grace').value||30,reminder_min:+$('n-reminder').value||30,
        public_base_url:$('n-base').value.trim()},
      timezone:$('d-tz').value.trim()||'UTC',
      branding:{name:$('b-name').value.trim(),color:$('b-color').value,url:$('b-url').value.trim(),logo_b64:window._logoB64||''}})});
    toast('Settings saved and applied');
  }catch(e){toast('Error: '+e.message)}
}
async function testWebhook(){
  try{
    const j=await api('/settings/test-webhook',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({webhook_url:$('n-url').value.trim(),webhook_type:$('n-type').value})});
    toast(j.ok?'Test message delivered ✓':'Failed: '+(j.error||'unknown'));
  }catch(e){toast('Failed: '+e.message)}
}

$('q').addEventListener('input',render);
load();setInterval(load,30000);
</script></body></html>"""


@app.route('/')
def dashboard():
    return Response(_PAGE_HTML, mimetype='text/html')


@app.route('/favicon.ico')
def favicon():
    return ('', 204)


# ── Boot ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    os.makedirs(monitors.DATA_DIR, exist_ok=True)
    apply_settings()
    monitors.start_scheduler()
    log.info('scheduler started; dashboard on http://%s:%s', HOST, PORT)
    # threaded=True: report.png does a loopback fetch of the report page from
    # inside a request handler — a single-threaded server would deadlock.
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
