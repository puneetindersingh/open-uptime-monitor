"""
Shareable uptime report for a monitor — a self-contained, print-ready HTML
page you can send to a site owner; /monitors/<id>/report.png screenshots it
with headless Playwright (optional dependency) for a drop-into-an-email PNG.

The report is white-labelled from Settings: your name/company, accent colour,
optional logo and website URL. Content is deliberately factual: checks,
incidents, durations, availability — no promises, no blame. The 99.9% line is
the standard hosting-industry baseline, stated as context.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import monitors
from monitors import db, get_monitor, iso, parse_iso, utcnow, REASON_LABELS

# Neutral report palette; the accent colour comes from branding settings.
INK = '#1F1F1F'
MID = '#595959'
LIGHT = '#9A9A9A'
BORDER = '#E0E0E0'
PANEL = '#F5F5F5'
GREEN = '#16a34a'
AMBER = '#f59e0b'
RED = '#dc2626'

# White-label branding, set by app.py from Settings via set_branding().
_branding: dict = {}


def set_branding(cfg: dict | None) -> None:
    """{'name': str, 'color': '#hex', 'url': str, 'logo_b64': str|None} —
    all optional; sensible neutral defaults apply."""
    global _branding
    _branding = dict(cfg or {})


def _brand() -> dict:
    return {
        'name': (_branding.get('name') or '').strip() or 'Uptime Monitor',
        'color': (_branding.get('color') or '').strip() or '#dc2626',
        'url': (_branding.get('url') or '').strip(),
        'logo_b64': (_branding.get('logo_b64') or '').strip() or None,
    }


def _fmt_local(ts: str, with_year: bool = False) -> str:
    try:
        dt = parse_iso(ts).astimezone(monitors.get_display_tz())
        return dt.strftime('%d %b %Y, %I:%M %p' if with_year else '%d %b, %I:%M %p').replace(' 0', ' ')
    except Exception:
        return ts or '—'


def _fmt_dur(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 3600:
        return f'{max(1, seconds // 60)} min'
    h, m = divmod(seconds // 60, 60)
    return f'{h}h {m:02d}m'


def gather(mid: int, days: int = 30) -> dict | None:
    """All report data for one monitor over the trailing window."""
    m = get_monitor(mid)
    if not m:
        return None
    now = utcnow()
    since = now - timedelta(days=days)
    with db() as conn:
        hbs = [dict(r) for r in conn.execute(
            'SELECT checked_at, status, reason, response_ms FROM heartbeats '
            'WHERE monitor_id=? AND checked_at >= ? ORDER BY checked_at',
            (mid, iso(since)))]
        incidents = [dict(r) for r in conn.execute(
            'SELECT started_at, ended_at, reason, details FROM incidents '
            'WHERE monitor_id=? AND started_at >= ? ORDER BY started_at',
            (mid, iso(since)))]

    up = sum(1 for h in hbs if h['status'] == 'up')
    total = len(hbs)
    ms_vals = [h['response_ms'] for h in hbs if h['response_ms'] is not None and h['status'] == 'up']

    # Daily strip: bucket heartbeats by calendar day in the display timezone.
    daily: dict[str, dict] = {}
    for i in range(days):
        d = (now.astimezone(monitors.get_display_tz()) - timedelta(days=days - 1 - i)).date()
        daily[d.isoformat()] = {'date': d, 'total': 0, 'down': 0}
    for h in hbs:
        try:
            key = parse_iso(h['checked_at']).astimezone(monitors.get_display_tz()).date().isoformat()
        except Exception:
            continue
        if key in daily:
            daily[key]['total'] += 1
            if h['status'] == 'down':
                daily[key]['down'] += 1

    # Downtime is measured from OBSERVED down checks, not incident wall-clock.
    # If the monitoring box itself was off mid-incident, the incident spans
    # the gap but nobody observed the site down for those hours — a report
    # someone else will read must only claim what we can prove.
    # Each down check contributes its gap to the next check, capped so a
    # monitoring pause can never inflate the number; capped incidents get
    # flagged and footnoted.
    times = [parse_iso(h['checked_at']) for h in hbs]
    gaps = [(times[j + 1] - times[j]).total_seconds() for j in range(len(times) - 1)]
    med = sorted(gaps)[len(gaps) // 2] if gaps else 300.0
    cap = max(3 * med, 1800.0)

    inc_rows, downtime_s = [], 0.0
    for i in incidents:
        try:
            start = parse_iso(i['started_at'])
            end = parse_iso(i['ended_at']) if i['ended_at'] else now
        except Exception:
            continue
        obs, gapped = 0.0, False
        for j, h in enumerate(hbs):
            if h['status'] != 'down' or not (start <= times[j] < end):
                continue
            gap = (times[j + 1] - times[j]).total_seconds() if j + 1 < len(times) \
                else (now - times[j]).total_seconds()
            if gap > cap:
                gapped = True
            obs += min(gap, cap)
        downtime_s += obs
        inc_rows.append({
            'started': _fmt_local(i['started_at']),
            'ended': _fmt_local(i['ended_at']) if i['ended_at'] else 'ongoing',
            'dur': (_fmt_dur(obs) + (' †' if gapped else '')) if i['ended_at'] else 'ongoing',
            'gapped': gapped,
            'label': REASON_LABELS.get(i['reason'], i['reason']),
            'details': (i['details'] or '')[:140],
        })

    return {
        'monitor': m,
        'days': days,
        'since': since,
        'now': now,
        'uptime_pct': round(100 * up / total, 2) if total else None,
        'checks': total,
        'avg_ms': int(sum(ms_vals) / len(ms_vals)) if ms_vals else None,
        'peak_ms': max(ms_vals) if ms_vals else None,
        'daily': list(daily.values()),
        'incidents': inc_rows,
        'downtime_s': downtime_s,
        'heartbeats': hbs,
    }


def _chart_svg(hbs: list[dict], days: int) -> str:
    """Response-time line, bucketed server-side — mirrors the dashboard chart
    (renderResponseChart in script.js) so AMs recognise it: full-height
    red/amber bands mark down / partly-down buckets. Height encodes "how
    fast", the band encodes "was it down" — a dot at response-time height
    hides fast failures (a 503 served in 200ms sits inside the green
    baseline), and refused/DNS buckets have no response_ms to plot at all."""
    now = utcnow()
    hours = days * 24
    bucket_min = 60 if days <= 7 else 240
    buckets = monitors._bucket_heartbeats(hbs, now - timedelta(hours=hours), hours, bucket_min)
    series = [b for b in buckets if b.get('response_ms') is not None and b.get('total_count')]
    if not series:
        return f'<div style="color:{LIGHT};font-size:13px;padding:14px;">No response-time data in this period.</div>'
    w, h, pad = 840, 150, 12
    all_ts = [parse_iso(b['checked_at']).timestamp() for b in buckets]
    ts = [parse_iso(b['checked_at']).timestamp() for b in series]
    t0, t1 = min(all_ts), max(all_ts)
    span = max(1.0, t1 - t0)
    max_ms = max(max(b['response_ms'] for b in series), 100)

    def x_of(t: float) -> float:
        return pad + (w - 2 * pad) * ((t - t0) / span)

    slot = (w - 2 * pad) / max(1, len(buckets))
    band_w = max(2.5, min(10.0, slot))
    bands = []
    for b, t in zip(buckets, all_ts):
        if not b.get('total_count'):
            continue  # empty bucket: no data ≠ down
        is_down = b.get('down_count') == b.get('total_count')
        partial = not is_down and bool(b.get('down_count'))
        if not is_down and not partial:
            continue
        bands.append(f'<rect x="{x_of(t) - band_w / 2:.1f}" y="0" width="{band_w:.1f}" height="{h}" '
                     f'fill="{RED if is_down else AMBER}" fill-opacity="0.22"/>')
    pts, up_dots, down_dots = [], [], []
    for b, t in zip(series, ts):
        x = x_of(t)
        y = h - pad - (h - 2 * pad) * (b['response_ms'] / max_ms)
        pts.append(f'{x:.1f},{y:.1f}')
        # Red/amber dots go in a later layer (and slightly bigger) so a fast
        # failure isn't painted over by the surrounding green baseline dots.
        if b.get('down_count'):
            c = RED if b['down_count'] == b['total_count'] else AMBER
            down_dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.2" fill="{c}"/>')
        else:
            up_dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.2" fill="{GREEN}"/>')
    peak = f'{max_ms}ms' if max_ms < 1000 else f'{max_ms / 1000:.2f}s'
    return (f'<svg width="100%" viewBox="0 0 {w} {h}" preserveAspectRatio="none" '
            f'style="background:#fff;border:1px solid {BORDER};border-radius:6px;">'
            f'{"".join(bands)}'
            f'<polyline fill="none" stroke="{INK}" stroke-width="1.2" stroke-opacity="0.45" '
            f'points="{" ".join(pts)}"/>{"".join(up_dots)}{"".join(down_dots)}'
            f'<text x="{w - 8}" y="18" text-anchor="end" font-size="11" fill="{LIGHT}">peak {peak}</text></svg>')


def build_html(mid: int, days: int = 30, bare: bool = False) -> str | None:
    d = gather(mid, days)
    if not d:
        return None
    m = d['monitor']
    name = m.get('client_tag') or m.get('name') or m['target']
    target = m['target']
    local_now = d['now'].astimezone(monitors.get_display_tz())
    period = (f'{d["since"].astimezone(monitors.get_display_tz()).strftime("%d %b %Y")} — '
              f'{local_now.strftime("%d %b %Y")}')

    n_inc = len(d['incidents'])
    pct = d['uptime_pct']
    pct_color = GREEN if (pct or 0) >= 99.9 else AMBER if (pct or 0) >= 99 else RED
    avg = f'{d["avg_ms"]}ms' if (d['avg_ms'] or 0) < 1000 else f'{d["avg_ms"] / 1000:.2f}s'

    # Daily availability strip
    cells, labels = [], []
    for i, day in enumerate(d['daily']):
        if day['total'] == 0:
            c, tip = '#e5e5e5', 'no checks'
        elif day['down'] == 0:
            c, tip = GREEN, '100% up'
        else:
            day_pct = 100 * (day['total'] - day['down']) / day['total']
            c = RED if day_pct < 95 else AMBER
            tip = f'{day_pct:.1f}% up'
        cells.append(f'<div title="{day["date"].strftime("%d %b")} — {tip}" '
                     f'style="flex:1;height:34px;background:{c};border-radius:2px;"></div>')
        show = i == 0 or i == len(d['daily']) - 1 or day['date'].day == 1 or i % 7 == 0
        labels.append(f'<div style="flex:1;font-size:9px;color:{LIGHT};text-align:center;">'
                      f'{day["date"].strftime("%d %b") if show else ""}</div>')

    if n_inc:
        inc_html = ''.join(
            f'<tr>'
            f'<td style="padding:8px 10px;border-bottom:1px solid {BORDER};white-space:nowrap;">{r["started"]}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid {BORDER};white-space:nowrap;">{r["ended"]}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid {BORDER};font-weight:700;white-space:nowrap;">{r["dur"]}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid {BORDER};color:{_brand()['color']};font-weight:600;white-space:nowrap;">{r["label"]}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid {BORDER};color:{MID};'
            f'font-family:ui-monospace,monospace;font-size:11px;">{r["details"]}</td></tr>'
            for r in d['incidents'])
        incidents_block = f'''
      <table style="width:100%;border-collapse:collapse;font-size:12.5px;background:#fff;border:1px solid {BORDER};border-radius:6px;">
        <thead><tr style="background:{PANEL};text-align:left;">
          <th style="padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:0.6px;color:{MID};">Went down</th>
          <th style="padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:0.6px;color:{MID};">Back up</th>
          <th style="padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:0.6px;color:{MID};">Duration</th>
          <th style="padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:0.6px;color:{MID};">Type</th>
          <th style="padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:0.6px;color:{MID};">Detail</th>
        </tr></thead><tbody>{inc_html}</tbody>
      </table>'''
        if any(r['gapped'] for r in d['incidents']):
            incidents_block += (f'<div style="font-size:11px;color:{MID};margin-top:6px;">'
                                f'† Monitoring was interrupted for part of this incident — the duration counts '
                                f'confirmed observations only, so the actual outage may have been longer.</div>')
        summary = (f'Between {period}, <strong>{target}</strong> was checked '
                   f'<strong>{d["checks"]:,} times</strong>. It was unreachable during '
                   f'<strong>{n_inc} separate incident{"s" if n_inc != 1 else ""}</strong>, '
                   f'totalling <strong>~{_fmt_dur(d["downtime_s"])}</strong> of downtime. '
                   f'Overall availability for the period was <strong>{pct}%</strong>.')
    else:
        incidents_block = (f'<div style="padding:14px;border:1px solid {BORDER};border-radius:6px;'
                           f'background:#fff;color:{MID};font-size:13px;">No outages recorded in this period.</div>')
        summary = (f'Between {period}, <strong>{target}</strong> was checked '
                   f'<strong>{d["checks"]:,} times</strong> with no outages recorded. '
                   f'Availability for the period was <strong>{pct}%</strong>.')

    brand = _brand()
    logo_html = (f'<img src="data:image/png;base64,{brand["logo_b64"]}" alt="{brand["name"]}" style="height:44px;">'
                 if brand['logo_b64'] else
                 f'<div style="color:{brand["color"]};font-size:24px;font-weight:700;font-style:italic;">{brand["name"]}</div>')

    toolbar = '' if bare else f'''
  <div class="no-print" style="max-width:920px;margin:0 auto 14px;display:flex;gap:8px;justify-content:flex-end;">
    <a href="report.png?days={days}" style="background:{INK};color:#fff;text-decoration:none;padding:9px 16px;border-radius:5px;font-size:13px;font-weight:600;">Download PNG</a>
    <button onclick="window.print()" style="background:#fff;border:1px solid {BORDER};color:{INK};padding:9px 16px;border-radius:5px;font-size:13px;cursor:pointer;">Print / save PDF</button>
  </div>'''

    return f'''<!doctype html><html><head><meta charset="utf-8">
<title>Uptime report — {name}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  * {{ box-sizing: border-box; margin: 0; }}
  body {{ font-family: Inter, -apple-system, 'Segoe UI', Arial, sans-serif; background: #ececec; color: {INK}; padding: 24px 16px; }}
  @media print {{ .no-print {{ display: none !important; }} body {{ background: #fff; padding: 0; }} .page {{ box-shadow: none !important; }} }}
</style></head><body>
{toolbar}
<div class="page" style="max-width:920px;margin:0 auto;background:#fff;box-shadow:0 2px 16px rgba(0,0,0,0.12);">

  <div style="background:{INK};padding:30px 40px;display:flex;justify-content:space-between;align-items:center;">
    <div>
      <div style="font-size:10px;letter-spacing:2px;text-transform:uppercase;color:{LIGHT};font-weight:700;">Website availability report</div>
      <div style="font-size:28px;font-weight:800;color:#fff;margin-top:6px;">{name}</div>
      <div style="font-size:13px;color:#cfcfcf;margin-top:4px;">{target} &nbsp;·&nbsp; {period}</div>
    </div>
    {logo_html}
  </div>

  <div style="padding:28px 40px 36px;">
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;">
      <div style="background:{PANEL};border-radius:6px;padding:14px 16px;">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:{MID};font-weight:700;">Availability</div>
        <div style="font-size:26px;font-weight:800;color:{pct_color};margin-top:4px;">{pct if pct is not None else "—"}%</div>
      </div>
      <div style="background:{PANEL};border-radius:6px;padding:14px 16px;">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:{MID};font-weight:700;">Outages</div>
        <div style="font-size:26px;font-weight:800;color:{RED if n_inc else GREEN};margin-top:4px;">{n_inc}</div>
      </div>
      <div style="background:{PANEL};border-radius:6px;padding:14px 16px;">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:{MID};font-weight:700;">Total downtime</div>
        <div style="font-size:26px;font-weight:800;color:{RED if d["downtime_s"] else GREEN};margin-top:4px;">{_fmt_dur(d["downtime_s"]) if d["downtime_s"] else "0 min"}</div>
      </div>
      <div style="background:{PANEL};border-radius:6px;padding:14px 16px;">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:{MID};font-weight:700;">Avg response</div>
        <div style="font-size:26px;font-weight:800;color:{INK};margin-top:4px;">{avg if d["avg_ms"] else "—"}</div>
      </div>
    </div>

    <div style="margin:22px 0 26px;background:{PANEL};border-left:4px solid {_brand()['color']};border-radius:4px;padding:14px 18px;font-size:14px;line-height:1.55;color:{INK};">
      {summary}
      <div style="font-size:12px;color:{MID};margin-top:8px;">For context: the standard availability target for business
      hosting is 99.9%, which allows for roughly 43 minutes of downtime per month.</div>
    </div>

    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:{MID};font-weight:700;margin-bottom:8px;">Daily availability — last {days} days</div>
    <div style="display:flex;gap:2px;margin-bottom:3px;">{''.join(cells)}</div>
    <div style="display:flex;gap:2px;">{''.join(labels)}</div>
    <div style="display:flex;gap:14px;font-size:10px;color:{MID};margin:6px 0 24px;">
      <span><span style="display:inline-block;width:9px;height:9px;background:{GREEN};border-radius:2px;margin-right:4px;"></span>Up all day</span>
      <span><span style="display:inline-block;width:9px;height:9px;background:{AMBER};border-radius:2px;margin-right:4px;"></span>Partial outage</span>
      <span><span style="display:inline-block;width:9px;height:9px;background:{RED};border-radius:2px;margin-right:4px;"></span>Major outage</span>
      <span><span style="display:inline-block;width:9px;height:9px;background:#e5e5e5;border-radius:2px;margin-right:4px;"></span>Not monitored</span>
    </div>

    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:{MID};font-weight:700;margin-bottom:8px;">Response time</div>
    {_chart_svg(d['heartbeats'], days)}

    <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:{MID};font-weight:700;margin:24px 0 8px;">Outage log</div>
    {incidents_block}
  </div>

  <div style="border-top:1px solid {BORDER};padding:14px 40px;display:flex;justify-content:space-between;font-size:11px;color:{LIGHT};">
    <span>Automated uptime monitoring by {brand['name']}</span>
    <span>Generated {local_now.strftime('%d %b %Y, %I:%M %p').replace(' 0', ' ')} {local_now.strftime('%Z')}{(' · ' + brand['url']) if brand['url'] else ''}</span>
  </div>
</div>
</body></html>'''


def render_png(mid: int, days: int, base_url: str = 'http://127.0.0.1:8080') -> bytes | None:
    """Headless-chromium screenshot of the report page (requires the optional
    playwright dependency + `playwright install chromium`)."""
    from playwright.sync_api import sync_playwright
    url = f'{base_url}/monitors/{mid}/report?days={days}&bare=1'
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={'width': 980, 'height': 900}, device_scale_factor=2)
            page.goto(url, wait_until='networkidle', timeout=30000)
            return page.screenshot(full_page=True, type='png')
        finally:
            browser.close()
