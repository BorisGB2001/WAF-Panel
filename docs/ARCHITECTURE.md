# Architecture

```
SafeLine A ─┐  /api/open/records, /api/stat/*, /api/open/site, ...
SafeLine B ─┼── X-SLCE-API-TOKEN, pinned TLS ──┐
            │                                  ├─ collector ──► rules ──► Telegram / email / webhook
            │                                  │      └──────► syslog (CEF / JSON) ──► SIEM
            │                                  │      └──────► auto-ban ──► blocklist (IP group + deny rule)
            │                                  └─ web panel :12443 (statistics, log, apps, WAF control)
```

One process (`wafpanel`) runs the collectors, the alert pipeline, the SIEM forwarders and the web panel.

## SafeLine

SafeLine CE runs as docker compose: `mgt` (API and console), `detector` (detection engine), `tengine` (reverse proxy), `luigi` (log and statistics collector), `fvm` (rule compiler), `chaos` (challenges) and PostgreSQL. The open-source `management` code in the SafeLine repository is an old version; the current `mgt` is closed. The panel therefore works only through the OpenAPI and never writes to the SafeLine database: `mgt` pushes configuration to the detector and tengine, and a write past it would leave them out of sync.

## Collector

Every `poll_interval` the collector reads `/api/open/records?start=<newest − lookback>` and compares `event_id`s with those already seen. Records reach the API late (`created_at` lags `timestamp` by seconds), so each poll re-reads a window (`lookback`, 2 minutes by default). The newest timestamp and the event ids inside the window are kept in `state_file`, so a restart neither loses nor repeats events. On the first start existing events are skipped unless `backfill` is on.

## Traffic analytics

SafeLine CE keeps 24 hours of statistics and leaves locations, clients, response codes, referrers and pages empty. When the panel runs on the SafeLine host it reads tengine's logs instead: `accesslog_<site id>` of every application with the access log on, and `error.log` for upstream failures. The collector follows the files like `tail -f`, notices rotation by inode, and on the first start also reads the rotated files still on disk. Lines are counted into hourly buckets per site — status codes, methods, hosts, countries and cities (GeoLite2), operating systems, browsers and apps, bots, referrers, endpoints with ids folded into `:id`, client addresses, and upstream errors by kind and upstream — and the distinct addresses and visitors as HyperLogLog sketches, so they add up correctly over days. Hours of the last three days stay in memory; every day is kept as a rollup in `data_dir/analytics/<instance>/<site>/<date>.json.gz` for the retention (90 days).

## Blocking, allow list, auto-ban and traps

The panel owns two IP groups in SafeLine with a rule each: "WAF Panel blocklist" with a deny rule and "WAF Panel allow list" with an allow rule, both created on first use and placed first. SafeLine keeps the addresses; the panel keeps who added each one, why, by which rule and until when (`blocklist-<instance>.json`, `allowlist-<instance>.json`), and removes expired blocks every minute.

Nothing is blocked that is the requester's own address, the WAF host, in `block.protected` or on the allow list. Blocking a private address by hand needs a confirmation, and nothing automatic ever blocks one: behind a proxy without `X-Forwarded-For` SafeLine sees the proxy's private address for every visitor.

The auto-ban (`autoban.json`) reads every attack record the collector brings and, when the panel runs on the SafeLine host, every line of the access logs:

- N denied requests from one address within a window, or one denied request of a dangerous type (backdoor, deserialization, code execution, command injection) with a minimal risk;
- from the access logs: too many 404s on pages (not images or styles), POSTs to login pages, or requests a minute; known search engines are never banned;
- traps: any request to a trap path, whether the auto-ban is on or not, at most once an hour per address and trap. Every trap also has a deny rule in SafeLine (`uri_no_query` prefix or contains, and the host for a one-site trap), so the request gets 403 and appears in the attack log even when the detector finds nothing; in dry run that rule only records (`monitor`).

A repeat offender gets the next duration of the list (a day, a week, then for good by default). Each kind of rule has its own dry run, in which decisions are only recorded. Decisions are applied by one goroutine of the web panel, which owns the blocklists, and the last 500 are kept with their result.

## Analysis and ban by attack

The analysis reads up to 5000 records of the period from SafeLine and ranks attackers, rules, paths, types and countries. Possible false positives are groups of (site, rule, path) ranked by how many *focused* addresses hit them: addresses that touched at most three paths in the period. A scanner tries hundreds of URLs and drops out; a form the WAF breaks is hit by every visitor who uses it.

The ban by attack lists every address that triggered the same attack type, path or rule in a period, marks the ones that cannot be blocked, warns when the list looks like ordinary visitors (most let through or seen once), and blocks the chosen ones in one call.

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
| Allow & Deny | `GET/POST/PUT/DELETE /api/open/policy`, `PUT /api/open/policy/switch`, `PUT /api/open/policy/orders` |
| Blocklist and allow list | `GET/POST/PUT /api/open/ipgroup`, `GET /api/open/ipgroup/detail`, `POST /api/open/ipgroup/append`, `GET/POST /api/open/policy`, `PUT /api/open/policy/switch` |
| Traps | `GET/POST/PUT/DELETE /api/open/policy` |
| Health | `GET /api/open/health` |

The full list of console routes of SafeLine 9.4.3 is in [research/ui-api-routes-v9.4.3.txt](research/ui-api-routes-v9.4.3.txt) and its database schema in [research/safeline-v9.4.3-schema.sql](research/safeline-v9.4.3-schema.sql).
