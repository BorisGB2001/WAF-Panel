# Architecture

```
SafeLine A ─┐  /api/open/records, /api/stat/*, /api/open/site, ...
SafeLine B ─┼── X-SLCE-API-TOKEN, pinned TLS ──┐
            │                                  ├─ collector ──► rules ──► Telegram / email / webhook
            │                                  │      └──────► syslog (CEF / JSON) ──► SIEM
            │                                  └─ web panel :12443 (statistics, log, apps, WAF control)
```

One process (`wafpanel`) runs the collectors, the alert pipeline, the SIEM forwarders and the web panel.

## SafeLine

SafeLine CE runs as docker compose: `mgt` (API and console), `detector` (detection engine), `tengine` (reverse proxy), `luigi` (log and statistics collector), `fvm` (rule compiler), `chaos` (challenges) and PostgreSQL. The open-source `management` code in the SafeLine repository is an old version; the current `mgt` is closed. The panel therefore works only through the OpenAPI and never writes to the SafeLine database: `mgt` pushes configuration to the detector and tengine, and a write past it would leave them out of sync.

## Collector

Every `poll_interval` the collector reads `/api/open/records?start=<newest − lookback>` and compares `event_id`s with those already seen. Records reach the API late (`created_at` lags `timestamp` by seconds), so each poll re-reads a window (`lookback`, 2 minutes by default). The newest timestamp and the event ids inside the window are kept in `state_file`, so a restart neither loses nor repeats events. On the first start existing events are skipped unless `backfill` is on.

## Alert pipeline

A single goroutine owns the rule engine: filters (instances, hosts with `*.mask`, attack types, actions, minimal risk), a threshold of events per window per group (`src_ip`, `host`, `instance`, `none`) and a cooldown per group. Rules saved in the UI replace the engine without a restart. Each channel has its own queue with retries, so a broken channel never delays the others. Fired alerts and their delivery results are kept in the alert history.

## Web panel

Server-rendered HTML (`html/template`), embedded assets, no build step. Charts are inline SVG generated in Go (monotone cubic curves, rings, sparklines); `charts.js` adds the crosshair tooltips, tabs and "copy as cURL". The CSP allows only same-origin scripts and styles.

Sessions are HMAC-signed cookies that carry the user's password version, so changing a password or role ends every other session. Every form carries a CSRF token; POSTs also check `Origin`.

## SafeLine APIs used

| Area | Calls |
|---|---|
| Attack log | `GET /api/open/records`, `GET /api/open/record/{event_id}` |
| Statistics | `GET /api/stat/advance/{access,attack,error_status_code,status_code,location,client,domain,page}`, `GET /api/stat/advance/trend/{access,intercept}`, `GET /api/stat/qps` |
| Sites | `GET/POST/PUT/DELETE /api/open/site`, `GET /api/open/site/{id}`, `PUT /api/open/site/mode`, `PUT /api/open/site/enabled` |
| Certificates | `GET /api/open/cert`, `POST /api/open/cert`, `DELETE /api/open/cert/{id}` (the panel never reads a key back) |
| Blocklist | `GET/POST/PUT /api/open/ipgroup`, `GET /api/open/ipgroup/detail`, `POST /api/open/ipgroup/append`, `GET/POST /api/open/policy`, `PUT /api/open/policy/switch` |
| Health | `GET /api/open/health` |

The full list of console routes of SafeLine 9.4.3 is in [research/ui-api-routes-v9.4.3.txt](research/ui-api-routes-v9.4.3.txt) and its database schema in [research/safeline-v9.4.3-schema.sql](research/safeline-v9.4.3-schema.sql).
