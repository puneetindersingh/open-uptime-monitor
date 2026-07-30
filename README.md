# open-uptime-monitor

Self-hosted website uptime monitoring with **alerts that don't cry wolf**.

One Python process, one SQLite file, a clean dashboard, and a set of alerting
rules refined by running hundreds of production checks: no 3 a.m. pages for a
two-minute blip, no false DOWNs because a bot-protection edge challenged the
checker, and a mute link right in the alert for the outage you already know
about.

## Features

- **Check types**: HTTP(S), HTTP + keyword (page must contain a string), DNS
  (via `dig`), ICMP ping.
- **Dashboard**: live status, 24 h uptime, response times, search, add/pause/
  run-now/delete — plus a **Settings tab** that applies changes without a
  restart.
- **Chat alerts**: Google Chat, Slack, Discord, or any generic JSON webhook.
- **Shareable reports**: a white-label, print-ready availability report per
  monitor (your name, colour and logo from Settings), with an optional PNG
  export for dropping into an email.
- **Per-monitor mute**: every 🔴 alert carries a mute link — one click opens a
  confirm page, mute for 1 or 3 days, alerts resume automatically. A 🟢
  recovery message still sends, so you know when it's fixed.
- **Zero infrastructure**: Flask + SQLite. No accounts, no queue, no Docker
  required (works fine in one if you prefer).

## The alerting rules

Most monitors treat every failed check as an emergency. This one encodes what
an outage actually has to prove before a human gets paged:

| Rule | Behaviour |
|---|---|
| **Confirm re-check** | An up→down flip is re-checked once after 20 s before anything is recorded. One transient timeout opens no incident. |
| **Grace window** | The first 🔴 only sends once the outage has lasted N minutes (default 30, configurable). A blip that recovers inside the window sends *nothing* — no 🔴, no orphan 🟢. |
| **Reminder throttle** | While a site stays down, one "STILL DOWN" reminder per N minutes (default 30). A flapping site can't spam the channel. |
| **Recovery pairing** | A 🟢 RECOVERED is only sent if its 🔴 was actually delivered. |
| **Local-outage suppression** | Before any alert, well-known endpoints are probed. If none respond, it's *your* connection that died — everything is suppressed instead of paging you about 200 "down" sites. |
| **WAF / bot-protection awareness** | A 4xx/5xx that is really a Cloudflare/Akamai/Imperva/Sucuri challenge, or a Shopify edge screening the checker's IP, is classified `up (WAF)` — the site is fine, the checker got challenged. Shopify stores are identified from *healthy* responses and remembered, because their block pages strip every identifying header. |
| **Shared-server events** | 2+ monitors down together on the same server IP collapse into one ⚠️ SERVER OUTAGE message (sent immediately) instead of N separate pages; per-site alerts are suppressed while the event is open. |
| **Per-monitor mute** | Known issue, nothing to do right now? Mute it for a day from the link in the alert. Expires on its own — a mute can never be forgotten. |
| **Check phase spreading** | Checks are de-clustered so batches never fire as one burst from your IP (which is exactly the pattern bot protection scores). |

Reports are honest too: downtime is computed from **observed** down checks,
capped per gap — if the monitoring box itself was offline mid-incident, the
report says so in a footnote instead of inflating the number.

## Quickstart

Requires Python 3.10+, and `dig` (package `dnsutils`/`bind-utils`) if you use
DNS checks.

```bash
git clone https://github.com/puneetindersingh/open-uptime-monitor.git
cd open-uptime-monitor
pip install -r requirements.txt
python app.py                      # dashboard on http://0.0.0.0:8080
```

Add your first monitor from the dashboard, then open **Settings** to point
alerts at a webhook:

- **Google Chat**: space → Apps & integrations → Webhooks
- **Slack**: create an *Incoming Webhook* app
- **Discord**: channel settings → Integrations → Webhooks

Use *Send test message* to verify, set the **public base URL** so alerts carry
report/mute links, and save.

Optional PNG report export:

```bash
pip install playwright && playwright install chromium
```

## Configuration

Everything lives in the Settings tab (stored in `data/settings.json`,
hot-applied on save):

| Setting | What it does |
|---|---|
| Check intervals | Default minutes between checks per type; per-monitor override when adding. |
| Webhook type + URL | Where alerts go. |
| Recovery messages | Toggle 🟢s. |
| Grace window / reminder | The two timing rules above. |
| Public base URL | Enables report + mute links inside alerts. |
| Timezone | IANA name; used in alerts and reports. |
| Report branding | Name, accent colour, website, logo for the shareable report. |

Environment variables: `UPTIME_PORT` (default 8080), `UPTIME_HOST` (default
0.0.0.0), `UPTIME_DATA_DIR` (default `./data`).

## Deployment

There is **no built-in auth** — run it on a trusted network, bind it to
localhost, or put a reverse proxy with auth in front.

A systemd unit is included:

```bash
cp deploy/open-uptime-monitor.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now open-uptime-monitor
```

## Tests

```bash
python3 tests/test_alerts.py    # no pytest needed; network fully stubbed
```

## License

MIT — see [LICENSE](LICENSE).
