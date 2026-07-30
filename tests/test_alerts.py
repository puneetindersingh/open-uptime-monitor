"""Alerting behaviour tests — WAF/Shopify 5xx classification, chat notify
behaviour (grace window, throttle, recovery pairing, mute), shared-server
events and the duplicate check/alert race. Run directly, no pytest needed:

    python3 tests/test_alerts.py

No network: requests.get/post/head are stubbed — nothing is ever posted to
a real webhook.
"""
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests as real_requests

import monitors

PASS = 0


def check(cond, label):
    global PASS
    assert cond, f'FAIL: {label}'
    PASS += 1
    print(f'  ok — {label}')


class FakeResp:
    def __init__(self, status_code=200, headers=None, text='', ok=None, url='https://example.com'):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.ok = ok if ok is not None else (200 <= status_code < 400)
        self.url = url


# ── stubbed requests ───────────────────────────────────────────────────────

_next_get_resp = FakeResp()
_posts = []


def fake_get(url, **kw):
    return _next_get_resp


def fake_post(url, **kw):
    _posts.append({'url': url, 'params': kw.get('params'), 'json': kw.get('json')})
    return FakeResp(200, ok=True)


def fake_head(url, **kw):
    return FakeResp(200)


real_requests.get = fake_get
real_requests.post = fake_post
real_requests.head = fake_head


def http_result(resp):
    global _next_get_resp
    _next_get_resp = resp
    return monitors.check_http('https://example.com')


SHOPIFY_HDRS = {'powered-by': 'Shopify', 'server': 'cloudflare', 'cf-ray': 'abc-MEL'}


def test_5xx_classification():
    print('check_http 5xx classification:')
    r = http_result(FakeResp(503, SHOPIFY_HDRS))
    check(r['status'] == 'up' and r['reason'] == 'up_protected', 'Shopify 503 (powered-by) → up_protected')
    check('Shopify' in r['error_msg'], 'Shopify 503 error_msg names Shopify')

    r = http_result(FakeResp(500, {'x-shopify-request-id': 'x', 'server': 'cloudflare'}))
    check(r['status'] == 'up' and r['reason'] == 'up_protected', 'Shopify 500 (x-shopify-*) → up_protected')

    r = http_result(FakeResp(503, {'shopify-complexity-score': '1'}))
    check(r['reason'] == 'up_protected', 'Shopify 503 (shopify-* header) → up_protected')

    r = http_result(FakeResp(503, {'x-sorting-hat-podid': '42'}))
    check(r['reason'] == 'up_protected', 'Shopify 503 (sorting-hat) → up_protected')

    r = http_result(FakeResp(503, {'server': 'cloudflare', 'cf-mitigated': 'challenge'}))
    check(r['reason'] == 'up_protected', 'Cloudflare cf-mitigated challenge 503 → up_protected (regression)')

    r = http_result(FakeResp(503, {'server': 'ddos-guard'}, text='<html>solve this hCaptcha to continue</html>'))
    check(r['reason'] == 'up_protected', 'challenge body sniff on 5xx → up_protected')

    r = http_result(FakeResp(503, {'server': 'cloudflare', 'cf-ray': 'x'}, text='<title>Origin error</title>'))
    check(r['status'] == 'down' and r['reason'] == 'http_5xx',
          'plain Cloudflare-proxied origin 503 (no challenge marker) → still DOWN')

    # The 2026-07-11 escape: Shopify's block page strips ALL identity headers.
    # A monitor whose platform was learned as shopify must classify it as
    # protected anyway; an unknown-platform monitor must not.
    global _next_get_resp
    _next_get_resp = FakeResp(503, {'server': 'cloudflare'}, text='<title>Something went wrong</title>')
    r = monitors.check_http('https://example.com', platform='shopify')
    check(r['status'] == 'up' and r['reason'] == 'up_protected',
          'anonymous 503 on KNOWN-shopify target → up_protected (header-stripped block page)')
    check('known-shopify' in r['error_msg'], 'known-shopify suppression is labelled in error_msg')

    # Shopify escalation beyond 5xx: dropped/refused connections (2026-07-12).
    def raise_conn(url, **kw):
        raise real_requests.exceptions.ConnectionError(
            'Max retries exceeded: Failed to establish a new connection: [Errno 111] Connection refused')
    real_requests.get = raise_conn
    r = monitors.check_http('https://example.com', platform='shopify')
    check(r['status'] == 'up' and r['reason'] == 'up_protected',
          'connection refused on KNOWN-shopify target → up_protected (IP screening)')
    r = monitors.check_http('https://example.com')
    check(r['status'] == 'down' and r['reason'] == 'connection_refused',
          'connection refused on unknown-platform target → still DOWN')

    def raise_ssl(url, **kw):
        raise real_requests.exceptions.SSLError('certificate verify failed: Hostname mismatch')
    real_requests.get = raise_ssl
    r = monitors.check_http('https://example.com', platform='shopify')
    check(r['status'] == 'down' and r['reason'] == 'ssl_invalid',
          'SSL failure on shopify target still alerts (client-controlled DNS/cert)')
    real_requests.get = fake_get

    r = http_result(FakeResp(200, SHOPIFY_HDRS, text='ok'))
    check(r.get('platform_detected') == 'shopify', 'healthy Shopify 200 reports platform_detected')
    r = http_result(FakeResp(200, {'server': 'nginx'}, text='ok'))
    check(r.get('platform_detected') is None, 'healthy non-Shopify 200 reports platform_detected=None')
    r = http_result(FakeResp(503, SHOPIFY_HDRS))
    check('platform_detected' not in r, '5xx result never carries platform_detected (blocks must not unlearn)')

    r = http_result(FakeResp(503, {'server': 'nginx'}, text='<html><title>503 Service  Unavailable</title></html>'))
    check(r['status'] == 'down' and r['reason'] == 'http_5xx', 'plain origin 503 → down http_5xx')
    check('server=nginx' in r['error_msg'] and '503 Service Unavailable' in r['error_msg'],
          '5xx error_msg carries server header + page title')

    r = http_result(FakeResp(500))
    check(r['status'] == 'down' and r['error_msg'] == 'HTTP 500', 'bare 500, no headers/body → down')

    r = http_result(FakeResp(200, SHOPIFY_HDRS, text='<html>store</html>'))
    check(r['status'] == 'up' and r['reason'] == 'up', 'Shopify 200 → plain up (regression)')

    r = http_result(FakeResp(403, {'server': 'cloudflare'}))
    check(r['reason'] == 'up_protected', 'Cloudflare 403 WAF → up_protected (regression)')

    r = http_result(FakeResp(430, SHOPIFY_HDRS))
    check(r['reason'] == 'up_protected', 'Shopify 430 security rejection → up_protected (via WAF path)')

    r = http_result(FakeResp(404, {'server': 'apache'}))
    check(r['status'] == 'down' and r['reason'] == 'http_4xx', 'plain 404 → down http_4xx (regression)')


def test_notify():
    print('notify behaviour:')
    tmp = tempfile.mktemp(suffix='.db')
    old_db = monitors.DB_PATH
    monitors.DB_PATH = tmp
    monitors.init_db()
    monitors.set_notify_config({'enabled': True, 'webhook_url': 'https://chat.googleapis.com/v1/fake', 'notify_recovery': True})
    monitors._alerted_down.clear()
    monitors._last_down_alert.clear()
    from datetime import timedelta
    mon = {'id': 9001, 'name': 'Test Site', 'target': 'https://t.example', 'type': 'http',
           'client_tag': 'Test Site', 'current_status': 'up', 'last_state_change_at': None}
    now = monitors.utcnow()
    down_5xx = {'status': 'down', 'reason': 'http_5xx', 'http_code': 503,
                'response_ms': 1, 'error_msg': 'HTTP 503 (server=nginx)'}

    try:
        # ── 30-min grace: the down FLIP never pages ──
        _posts.clear()
        monitors._notify_transition(mon, down_5xx, now)
        check(len(_posts) == 0, 'confirmed down flip → SILENT (30-min grace window)')
        check(9001 not in monitors._alerted_down, 'grace-deferred down opens no recovery pairing')

        mon_down = dict(mon, current_status='down', last_state_change_at=monitors.iso(now))
        monitors._notify_transition(mon_down, {'status': 'up', 'reason': 'up', 'http_code': 200,
                                               'response_ms': 1, 'error_msg': None}, now + timedelta(minutes=5))
        check(len(_posts) == 0, 'blip that recovers inside the grace window → discarded entirely (no 🔴, no 🟢)')

        # still down but grace not yet outlived → still silent
        monitors._maybe_notify_still_down(mon_down, down_5xx, now + timedelta(minutes=10))
        check(len(_posts) == 0, 'still down 10 min in → grace holds, no 🔴 yet')

        # outage outlives the grace window → FIRST 🔴, worded as DOWN with duration
        monitors._maybe_notify_still_down(mon_down, down_5xx, now + timedelta(minutes=31))
        check(len(_posts) == 1 and '🔴' in _posts[0]['json']['text'] and 'DOWN —' in _posts[0]['json']['text']
              and 'STILL DOWN' not in _posts[0]['json']['text'] and 'Down for' in _posts[0]['json']['text'],
              'outage outlives 30-min grace → first 🔴 sent (DOWN + duration)')
        check(not _posts[0]['params'], 'DOWN message is top-level (no threadKey)')
        check(9001 in monitors._alerted_down, 'delivered 🔴 recorded for recovery pairing')

        # throttle: reminder within 30 min of the first 🔴 stays silent
        _posts.clear()
        monitors._maybe_notify_still_down(mon_down, down_5xx, now + timedelta(minutes=45))
        check(len(_posts) == 0, 'still-down within 30 min of last 🔴 → no reminder yet (max twice hourly)')
        monitors._maybe_notify_still_down(mon_down, down_5xx, now + timedelta(minutes=62))
        check(len(_posts) == 1 and 'STILL DOWN' in _posts[0]['json']['text'] and 'Down for' in _posts[0]['json']['text'],
              'still down 30+ min after last 🔴 → STILL DOWN reminder with duration')

        # recovery after an alerted (30+ min) outage → 🟢
        _posts.clear()
        monitors._notify_transition(mon_down, {'status': 'up', 'reason': 'up', 'http_code': 200,
                                               'response_ms': 1, 'error_msg': None}, now + timedelta(minutes=70))
        check(len(_posts) == 1 and '🟢' in _posts[0]['json']['text'], 'recovery after alerted down → 🟢 sent')
        check(not _posts[0]['params'], 'RECOVERED message is top-level (no threadKey) — fixes invisible 🟢')
        check(9001 not in monitors._alerted_down, 'recovery clears the alerted-down pairing')

        monitors._notify_transition(mon_down, {'status': 'up', 'reason': 'up', 'http_code': 200,
                                               'response_ms': 1, 'error_msg': None}, now + timedelta(minutes=71))
        check(len(_posts) == 1, 'recovery without a delivered 🔴 stays silent (orphan guard)')

        _posts.clear()
        monitors._maybe_notify_still_down(mon_down, dict(down_5xx, reason='http_4xx'), now + timedelta(minutes=99))
        check(len(_posts) == 0, 'reminder respects the ALERT_REASONS whitelist')
        monitors._notify_transition(mon, {'status': 'down', 'reason': 'keyword_missing', 'http_code': 200,
                                          'response_ms': 1, 'error_msg': 'kw'}, now)
        check(len(_posts) == 0, 'non-alertable reason (keyword_missing) → dashboard-only, no chat')

        check('http_5xx' in monitors.ALERT_REASONS and 'http_4xx' not in monitors.ALERT_REASONS,
              'ALERT_REASONS whitelist unchanged')

        # missing flip time fails OPEN — a real outage must never stay silent
        monitors._alerted_down.clear()
        monitors._last_down_alert.clear()
        mon_noflip = dict(mon, current_status='down', last_state_change_at=None)
        _posts.clear()
        monitors._maybe_notify_still_down(mon_noflip, down_5xx, now)
        check(len(_posts) == 1, 'unparseable/missing flip time → grace fails open, 🔴 still sent')

        # persistence round-trip of the throttle timestamps
        monitors._save_alert_state()
        saved = dict(monitors._last_down_alert)
        monitors._last_down_alert.clear()
        monitors._load_alert_state()
        check(monitors._last_down_alert == saved, 'last_down_alert survives a restart (db round-trip)')
    finally:
        monitors.DB_PATH = old_db
        monitors._alerted_down.clear()
        monitors._last_down_alert.clear()
        monitors.set_notify_config(None)
        if os.path.exists(tmp):
            os.unlink(tmp)


def test_redirect_detection():
    print('cross-domain redirect detection:')
    r = http_result(FakeResp(200, text='ok', url='https://www.new-brand.example.net/'))
    check(r['redirect_to'] == 'www.new-brand.example.net',
          'healthy check ending on another domain → redirect_to learned (rebrand case)')
    r = http_result(FakeResp(200, text='ok', url='https://www.example.com/'))
    check(r['redirect_to'] is None, 'www canonicalisation on the same domain → not a redirect')
    r = http_result(FakeResp(200, text='ok', url='https://shop.example.com/'))
    check(r['redirect_to'] is None, 'subdomain move within the same domain → not a redirect')
    r = http_result(FakeResp(503, url='https://elsewhere.com/'))
    check('redirect_to' not in r, 'failed check never carries redirect_to (cannot unlearn)')

    tmp = tempfile.mktemp(suffix='.db')
    old_db = monitors.DB_PATH
    monitors.DB_PATH = tmp
    try:
        monitors.init_db()
        with monitors.db() as conn:
            conn.execute("INSERT INTO monitors(id,type,target,name,current_status) "
                         "VALUES (1,'http','https://old.example','O','up')")
        now = monitors.utcnow()
        up_redir = {'status': 'up', 'reason': 'up', 'http_code': 200, 'response_ms': 1,
                    'error_msg': None, 'redirect_to': 'www.new.example'}
        with monitors.db() as conn:
            monitors._record_heartbeat(conn, {'id': 1, 'type': 'http', 'current_status': 'up',
                                              'redirect_to': None}, up_redir, now)
        with monitors.db() as conn:
            row = conn.execute('SELECT redirect_to FROM monitors WHERE id=1').fetchone()
        check(row['redirect_to'] == 'www.new.example', 'healthy check persists learned redirect to db')
        up_clean = dict(up_redir, redirect_to=None)
        with monitors.db() as conn:
            monitors._record_heartbeat(conn, {'id': 1, 'type': 'http', 'current_status': 'up',
                                              'redirect_to': 'www.new.example'}, up_clean, now)
        with monitors.db() as conn:
            row = conn.execute('SELECT redirect_to FROM monitors WHERE id=1').fetchone()
        check(row['redirect_to'] is None, 'redirect removed → healthy check clears it')

        # alert line carries the redirect
        monitors.set_notify_config({'enabled': True, 'webhook_url': 'https://chat.googleapis.com/v1/fake', 'notify_recovery': True})
        monitors._alerted_down.clear()
        monitors._last_down_alert.clear()
        from datetime import timedelta
        mon = {'id': 1, 'name': 'O', 'target': 'https://old.example', 'type': 'http',
               'client_tag': 'O', 'current_status': 'down', 'redirect_to': 'www.new.example',
               'last_state_change_at': monitors.iso(now - timedelta(minutes=40))}
        _posts.clear()
        monitors._maybe_notify_still_down(mon, {'status': 'down', 'reason': 'ssl_invalid', 'http_code': None,
                                                'response_ms': 1, 'error_msg': 'cert'}, now)
        check(len(_posts) == 1 and 'Redirects to: www.new.example' in _posts[0]['json']['text'],
              '🔴 alert includes the learned cross-domain redirect')
    finally:
        monitors.DB_PATH = old_db
        monitors._alerted_down.clear()
        monitors._last_down_alert.clear()
        monitors.set_notify_config(None)
        if os.path.exists(tmp):
            os.unlink(tmp)


def test_server_events():
    print('shared-server events:')
    from datetime import timedelta
    tmp = tempfile.mktemp(suffix='.db')
    old_db = monitors.DB_PATH
    monitors.DB_PATH = tmp
    monitors.set_notify_config({'enabled': True, 'webhook_url': 'https://chat.googleapis.com/v1/fake', 'notify_recovery': True})
    monitors._alerted_down.clear()
    monitors._last_down_alert.clear()
    monitors._server_events_open.clear()
    monitors._last_server_alert.clear()
    now = monitors.utcnow()
    down_5xx = {'status': 'down', 'reason': 'http_5xx', 'http_code': 500,
                'response_ms': 1, 'error_msg': 'HTTP 500'}
    try:
        monitors.init_db()
        with monitors.db() as conn:
            for mid, name, status, reason, key in (
                    (1, 'Site A', 'down', 'http_5xx', 'X'),
                    (2, 'Site B', 'down', 'timeout', 'X'),
                    (3, 'Site C', 'up', 'up', 'X'),
                    (4, 'Site D', 'down', 'http_5xx', 'Y'),
                    (5, 'Site E', 'down', 'http_4xx', 'Y')):
                conn.execute("INSERT INTO monitors(id,type,target,name,current_status,current_reason,server_ip) "
                             "VALUES (?,?,?,?,?,?,?)",
                             (mid, 'http', f'https://{name.replace(" ", "").lower()}.example', name, status, reason, key))
        mon_b = {'id': 2, 'name': 'Site B', 'target': 'https://siteb.example', 'type': 'http',
                 'client_tag': 'Site B', 'current_status': 'down', 'server_ip': 'X',
                 'last_state_change_at': monitors.iso(now - timedelta(minutes=40))}

        _posts.clear()
        monitors._maybe_notify_server_event(mon_b, down_5xx, now)
        txt = _posts[0]['json']['text'] if _posts else ''
        check(len(_posts) == 1 and 'SERVER OUTAGE' in txt and '2 sites down together' in txt
              and 'Site A' in txt and 'Site B' in txt,
              '2 sites down on one server IP → immediate ⚠️ SERVER OUTAGE (no grace)')
        check('X' in monitors._server_events_open, 'server event recorded as open')

        monitors._maybe_notify_server_event(mon_b, down_5xx, now + timedelta(minutes=5))
        check(len(_posts) == 1, 'second ⚠️ within 30 min → throttled per server')

        _posts.clear()
        mon_a = dict(mon_b, id=1, name='Site A', target='https://sitea.example')
        monitors._maybe_notify_still_down(mon_a, down_5xx, now + timedelta(minutes=45))
        check(len(_posts) == 0, 'per-site 🔴 suppressed while its server event is open')

        monitors._maybe_notify_server_event(mon_b, down_5xx, now + timedelta(minutes=31))
        check(len(_posts) == 1 and 'ongoing' in _posts[0]['json']['text']
              and 'Down for' in _posts[0]['json']['text'],
              'server outage persisting 30+ min → "ongoing" reminder with duration')

        # a lone down site (http_5xx) + a non-alertable one (http_4xx) on Y
        # never open an event — alertable peers on Y = 1
        _posts.clear()
        mon_d = dict(mon_b, id=4, name='Site D', target='https://sited.example', server_ip='Y')
        monitors._maybe_notify_server_event(mon_d, down_5xx, now)
        check(len(_posts) == 0 and 'Y' not in monitors._server_events_open,
              'single alertable down (4xx peer ignored) → no server event')

        # persistence round-trip
        monitors._save_alert_state()
        saved = dict(monitors._server_events_open)
        monitors._server_events_open.clear()
        monitors._load_alert_state()
        check(monitors._server_events_open == saved, 'open server events survive a restart (db round-trip)')

        # Site A recovers → only Site B left down (<2) → event closes with 🟢
        with monitors.db() as conn:
            conn.execute("UPDATE monitors SET current_status='up', current_reason='up' WHERE id=1")
        _posts.clear()
        monitors._maybe_close_server_event(dict(mon_a, current_status='up'), now + timedelta(minutes=50))
        txt = _posts[0]['json']['text'] if _posts else ''
        check(len(_posts) == 1 and 'SERVER OUTAGE over' in txt and 'Site B' in txt,
              'box back below 2 down sites → 🟢 SERVER OUTAGE over (survivor named)')
        check('X' not in monitors._server_events_open, 'closed event removed from open set')

        # suppression lifted: the survivor now alerts individually
        _posts.clear()
        monitors._maybe_notify_still_down(mon_b, down_5xx, now + timedelta(minutes=55))
        check(len(_posts) == 1 and 'DOWN —' in _posts[0]['json']['text'],
              'after the event closes, the lone survivor gets its per-site 🔴')
    finally:
        monitors.DB_PATH = old_db
        monitors._alerted_down.clear()
        monitors._last_down_alert.clear()
        monitors._server_events_open.clear()
        monitors._last_server_alert.clear()
        monitors.set_notify_config(None)
        if os.path.exists(tmp):
            os.unlink(tmp)


def test_check_and_record_dedup():
    print('duplicate check/alert race:')
    tmp = tempfile.mktemp(suffix='.db')
    old_db, old_delay = monitors.DB_PATH, monitors.CONFIRM_DELAY_S
    monitors.DB_PATH = tmp
    monitors.CONFIRM_DELAY_S = 0
    old_resolve = monitors._resolve_server_key
    monitors._resolve_server_key = lambda t: None  # no real DNS in tests
    monitors.set_notify_config({'enabled': True, 'webhook_url': 'https://chat.googleapis.com/v1/fake', 'notify_recovery': True})
    monitors._alerted_down.clear()
    monitors._last_down_alert.clear()
    try:
        monitors.init_db()
        with monitors.db() as conn:
            conn.execute("INSERT INTO monitors(id,type,target,name,current_status) "
                         "VALUES (1,'http','https://t.example','T','up')")
        down = {'status': 'down', 'reason': 'http_5xx', 'http_code': 503, 'response_ms': 1, 'error_msg': 'HTTP 503'}

        # in-flight guard: 2nd submit while a check runs is dropped at the door
        started, release = threading.Event(), threading.Event()

        def slow_check(m):
            started.set()
            release.wait(5)
            return dict(down)

        old_run_check = monitors.run_check
        monitors.run_check = slow_check
        _posts.clear()
        t = threading.Thread(target=monitors._check_and_record, args=(1,))
        t.start()
        started.wait(5)
        monitors._check_and_record(1)   # duplicate submit — must return instantly
        release.set()
        t.join(10)
        monitors.run_check = old_run_check
        with monitors.db() as conn:
            hb = conn.execute('SELECT COUNT(*) c FROM heartbeats').fetchone()['c']
            inc = conn.execute('SELECT COUNT(*) c FROM incidents').fetchone()['c']
        check(hb == 1, 'concurrent duplicate submit records ONE heartbeat, not two')
        check(inc == 1, 'one incident opened')
        check(len(_posts) == 0, 'down flip sends NO 🔴 (30-min grace, scheduler path)')

        # stale-snapshot guard: sequential still-down check must not re-alert,
        # and grace still holds (outage seconds old)
        monitors.run_check = lambda m: dict(down)
        monitors._check_and_record(1)
        with monitors.db() as conn:
            inc = conn.execute('SELECT COUNT(*) c FROM incidents').fetchone()['c']
        check(inc == 1, 'still-down follow-up check opens no second incident')
        check(len(_posts) == 0, 'still-down follow-up inside grace sends no 🔴')

        # backdate the flip 31 min → the next scheduler check delivers the first 🔴
        with monitors.db() as conn:
            conn.execute("UPDATE monitors SET last_state_change_at=? WHERE id=1",
                         (monitors.iso(monitors.utcnow() - __import__('datetime').timedelta(minutes=31)),))
        monitors._check_and_record(1)
        monitors.run_check = old_run_check
        check(len(_posts) == 1 and 'DOWN —' in _posts[0]['json']['text']
              and 'STILL DOWN' not in _posts[0]['json']['text'],
              'outage past the grace window → scheduler path sends the first 🔴')
        check(not monitors._inflight, 'in-flight set drains back to empty')
    finally:
        monitors.DB_PATH, monitors.CONFIRM_DELAY_S = old_db, old_delay
        monitors._resolve_server_key = old_resolve
        monitors._alerted_down.clear()
        monitors._last_down_alert.clear()
        monitors.set_notify_config(None)
        if os.path.exists(tmp):
            os.unlink(tmp)


def test_shopify_interval_clamp():
    print('shopify check-interval clamp:')
    m_shop = {'type': 'http', 'platform': 'shopify', 'interval_min': None}
    m_norm = {'type': 'http', 'platform': None, 'interval_min': None}
    old = monitors._admin_interval_overrides
    monitors.set_default_intervals({'http': 5})
    try:
        check(monitors.effective_interval_min(m_norm) == 5, 'normal site follows the 5-min admin interval')
        check(monitors.effective_interval_min(m_shop) == monitors.SHOPIFY_MIN_INTERVAL_MIN,
              f'shopify site clamped to {monitors.SHOPIFY_MIN_INTERVAL_MIN} min regardless (no false-positive bait)')
        monitors.set_default_intervals({'http': 30})
        check(monitors.effective_interval_min(m_shop) == 30, 'clamp is a floor, not a ceiling (30-min admin interval respected)')
    finally:
        monitors._admin_interval_overrides = old


def test_platform_learning_and_alerted_down_persistence():
    print('platform learning + alerted_down persistence:')
    tmp = tempfile.mktemp(suffix='.db')
    old_db = monitors.DB_PATH
    monitors.DB_PATH = tmp
    try:
        monitors.init_db()
        with monitors.db() as conn:
            conn.execute("INSERT INTO monitors(id,type,target,name,current_status) "
                         "VALUES (1,'http','https://s.example','S','up')")
        now = monitors.utcnow()
        up_shopify = {'status': 'up', 'reason': 'up', 'http_code': 200, 'response_ms': 1,
                      'error_msg': None, 'platform_detected': 'shopify'}
        with monitors.db() as conn:
            monitors._record_heartbeat(conn, {'id': 1, 'type': 'http', 'current_status': 'up',
                                              'platform': None}, up_shopify, now)
        with monitors.db() as conn:
            row = conn.execute('SELECT platform FROM monitors WHERE id=1').fetchone()
        check(row['platform'] == 'shopify', 'healthy check persists learned platform to db')

        monitors._alerted_down.clear()
        monitors._alerted_down.update({7, 42})
        monitors._save_alert_state()
        monitors._alerted_down.clear()
        monitors._load_alert_state()
        check(monitors._alerted_down == {7, 42}, 'alerted_down survives a restart (db round-trip)')
    finally:
        monitors.DB_PATH = old_db
        monitors._alerted_down.clear()
        if os.path.exists(tmp):
            os.unlink(tmp)


def test_singleton_guard():
    print('process-wide singleton guard:')
    check(monitors.claim_singleton('test-thing') is True, 'claim_singleton grants first claim')
    check(monitors.claim_singleton('test-thing') is False, 'claim_singleton denies the duplicate')


def test_check_phase_spreading():
    print('check phase spreading (anti-burst):')
    tmp = tempfile.mktemp(suffix='.db')
    old_db = monitors.DB_PATH
    monitors.DB_PATH = tmp
    try:
        monitors.init_db()
        with monitors.db() as conn:
            for i in range(1, 5):
                conn.execute("INSERT INTO monitors(id,type,target,name,platform) "
                             f"VALUES ({i},'http','https://shop{i}.example','S{i}','shopify')")
            for i in range(5, 15):
                conn.execute("INSERT INTO monitors(id,type,target,name) "
                             f"VALUES ({i},'http','https://site{i}.example','P{i}')")
        monitors.spread_check_phases()
        with monitors.db() as conn:
            shop = [monitors.parse_iso(r['next_check_at']) for r in conn.execute(
                "SELECT next_check_at FROM monitors WHERE platform='shopify' ORDER BY id")]
            others = {r['next_check_at'] for r in conn.execute(
                "SELECT next_check_at FROM monitors WHERE platform IS NULL")}
        gaps = [(shop[i+1] - shop[i]).total_seconds() for i in range(len(shop)-1)]
        interval_s = max(monitors.get_effective_default('http'), monitors.SHOPIFY_MIN_INTERVAL_MIN) * 60
        expect = interval_s / 4
        check(all(abs(g - expect) < 2 for g in gaps),
              f'4 shopify monitors evenly spaced ~{int(expect)}s apart over the CLAMPED interval (gaps={[int(g) for g in gaps]})')
        check(len(others) > 5, 'non-shopify monitors jittered to distinct phases, not one burst')

        # new monitors must not come due in the same tick as each other
        ids = [monitors.create_monitor(type='http', target=f'https://new{i}.example', seeded=True)
               for i in range(6)]
        with monitors.db() as conn:
            fresh = {r['next_check_at'] for r in conn.execute(
                f"SELECT next_check_at FROM monitors WHERE id IN ({','.join(map(str, ids))})")}
        check(len(fresh) >= 5, 'newly seeded monitors get per-target jitter, not due-now')
    finally:
        monitors.DB_PATH = old_db
        if os.path.exists(tmp):
            os.unlink(tmp)


def test_mute():
    """Per-monitor alert mute (for known issues, e.g. an expired SSL cert
    the site owner already knows about). Muted monitors send no
    🔴 DOWN / STILL DOWN; 🟢 RECOVERED still pairs with a delivered 🔴; the
    mute expires on its own and survives a restart."""
    print('alert mute:')
    tmp = tempfile.mktemp(suffix='.db')
    old_db = monitors.DB_PATH
    monitors.DB_PATH = tmp
    monitors.init_db()
    monitors.set_notify_config({'enabled': True, 'webhook_url': 'https://chat.googleapis.com/v1/fake',
                                'notify_recovery': True, 'public_base_url': 'http://192.0.2.10:8080'})
    monitors._alerted_down.clear()
    monitors._last_down_alert.clear()
    monitors._muted.clear()
    from datetime import timedelta
    now = monitors.utcnow()
    down_ssl = {'status': 'down', 'reason': 'ssl_expired', 'http_code': None,
                'response_ms': 1, 'error_msg': 'certificate has expired'}
    mon_down = {'id': 9101, 'name': 'Cert Site', 'target': 'https://cert.example', 'type': 'http',
                'client_tag': 'Cert Site', 'current_status': 'down',
                'last_state_change_at': monitors.iso(now)}

    try:
        # un-muted baseline: outage past grace sends the 🔴 and it carries the mute link
        _posts.clear()
        monitors._maybe_notify_still_down(mon_down, down_ssl, now + timedelta(minutes=31))
        check(len(_posts) == 1, 'baseline: 30+ min outage pages as before')
        check('🔇 Mute alerts: http://192.0.2.10:8080/monitors/9101/mute' in _posts[0]['json']['text'],
              '🔴 message carries the mute link')

        # mute → the next reminder window stays silent
        until = monitors.mute_monitor(9101, hours=24, by='alice')
        check(monitors.muted_until(9101) == until, 'mute_monitor records the expiry')
        _posts.clear()
        monitors._maybe_notify_still_down(mon_down, down_ssl, now + timedelta(minutes=62))
        check(len(_posts) == 0, 'muted monitor sends no STILL DOWN reminder')

        # 🟢 still pairs with the 🔴 that was delivered before the mute
        monitors._notify_transition(mon_down, {'status': 'up', 'reason': 'up', 'http_code': 200,
                                               'response_ms': 1, 'error_msg': None}, now + timedelta(minutes=70))
        check(len(_posts) == 1 and '🟢' in _posts[0]['json']['text'],
              'muted monitor still sends 🟢 RECOVERED (client fixed it)')

        # persistence round-trip (restart-safe like the other alert state)
        monitors._save_alert_state()
        monitors._muted.clear()
        monitors._load_alert_state()
        info = monitors.mute_info(9101)
        check(info and info['until'] == until and info['by'] == 'alice',
              'mute survives a restart (db round-trip, incl. who muted)')

        # expiry: alerts resume on their own
        monitors._muted[9101] = {'until': monitors.iso(now - timedelta(minutes=1)), 'by': 'alice'}
        check(monitors.muted_until(9101) is None, 'expired mute reads as un-muted (lazy cleanup)')
        monitors._alerted_down.clear()
        monitors._last_down_alert.clear()
        _posts.clear()
        monitors._maybe_notify_still_down(mon_down, down_ssl, now + timedelta(hours=25))
        check(len(_posts) == 1, 'after expiry the 🔴s resume under normal grace/throttle rules')

        # unmute + corrupt-timestamp fail-open
        monitors.mute_monitor(9101, hours=24)
        check(monitors.unmute_monitor(9101) and monitors.muted_until(9101) is None,
              'unmute_monitor clears the mute')
        monitors._muted[9101] = {'until': 'not-a-date', 'by': None}
        check(monitors.muted_until(9101) is None, 'corrupt mute timestamp fails OPEN (never silences forever)')
    finally:
        monitors.DB_PATH = old_db
        monitors._alerted_down.clear()
        monitors._last_down_alert.clear()
        monitors._muted.clear()
        monitors.set_notify_config(None)
        if os.path.exists(tmp):
            os.unlink(tmp)


if __name__ == '__main__':
    test_5xx_classification()
    test_notify()
    test_redirect_detection()
    test_server_events()
    test_check_and_record_dedup()
    test_platform_learning_and_alerted_down_persistence()
    test_singleton_guard()
    test_check_phase_spreading()
    test_shopify_interval_clamp()
    test_mute()
    print(f'\nALL PASS — {PASS} assertions')
