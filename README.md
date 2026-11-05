# WAF Panel

An enterprise panel for [SafeLine WAF](https://github.com/chaitin/SafeLine) Community Edition.

SafeLine CE has one administrator, no alerting, no SIEM export and its statistics live only in its own console. WAF Panel is a single Go binary that sits next to one or more SafeLine instances. It talks only to their OpenAPI and adds what a security team needs:

- **Statistics** like the SafeLine console: requests, PV/UV, unique and attacking IPs, 4xx/5xx of the application and of the WAF, live QPS, hourly trends, what was blocked. Charts are server-rendered SVG with crosshair tooltips; no external scripts.
- **Traffic analytics from tengine's logs** when the panel runs on the SafeLine host, for 7, 30 and 90 days: countries and cities, devices, operating systems, browsers and desktop apps, bots, where visitors come from (search engines, social networks, other sites, direct), pages not found, response codes, endpoints with their error rates and traffic, referrers, top addresses and upstream errors (timeouts, refused connections, TLS failures) by kind and upstream — everything SafeLine CE leaves empty or keeps for 24 hours only.
- **Address page and search**: type an IP, a site or a path in the menu. One page shows everything about an address: its attacks over 30 days by type, site and path, its traffic from the logs, whether it is blocked or allowed, by whom and why, and the auto-ban's decisions. Every address in a table carries its country code.
- **Analysis**: possible false positives (the same rule on the same site and path hit by many ordinary visitors rather than scanners), top attackers, rules, paths, types and countries.
- **Blocking**: one-click "day" / "for good" next to every address; ban by attack — everyone who triggered the same attack type, path or rule, reviewed before blocking; change the term or move a blocked address to the allow list.
- **Allow list** of trusted addresses: SafeLine lets them through and the panel never blocks them. `block.protected` addresses and private networks are never blocked automatically, so a front proxy is safe.
- **Auto-ban** of addresses that keep attacking (N denied requests in a window, or one request of a dangerous type), and from the access logs of those that hit many missing pages, keep posting to login pages or flood; longer blocks for repeat offenders; dry run first.
- **Traps**: a path no visitor asks for (`/.env`, `/.git/`, …) bans whoever requests it; a SafeLine deny rule per trap returns 403 and records the request. Default traps come in dry run.
- **Allow & Deny** rules: allow and deny lists with their own order, an editor for AND/OR conditions with values checked before saving, reordering, and a guard against rules that would block your own address.
- **Attack log** with filters (period, IP, site, URL, type, action), CSV export and an attack card with the highlighted request and response, a deny/pass stamp and "copy as cURL".
- **Applications**: list with upstream health, certificates and protections; create, edit, enable/disable and delete sites; upload, replace and delete certificates; warnings 30 days before a certificate expires.
- **WAF control**: switch protection modes; an IP blocklist with durations and automatic expiry, kept in SafeLine as an IP group and a deny rule.
- **Alerts** to Telegram, email and webhooks by rules (thresholds per window, grouping, cooldown), editable in the UI and applied without a restart.
- **SIEM forwarding** of every event over syslog (UDP/TCP/TLS) as CEF or JSON, with ready-made Wazuh rules.
- **Users and audit**: local users with `admin` and `viewer` roles, bcrypt, login throttling, CSRF protection, an audit log of every action, `web.allow_from` to limit who may open the panel.
- **Tables**: drag a column edge to resize it; the widths and the chosen periods are remembered.
- **English and Russian** UI (English by default).

## Quick start

Requirements: Go 1.25+, a SafeLine CE 9.x instance and an API token created in its console (System settings → API Token).

```bash
make test
make linux VERSION=0.6.0          # bin/wafpanel-linux-amd64
cp deploy/wafpanel.example.yaml wafpanel.yaml
```

Edit `wafpanel.yaml`, put the token into `secrets/<instance>.token`, then on the host:

```bash
sudo sh deploy/install.sh wafpanel.yaml secrets
```

The installer creates the `wafpanel` system user, installs the binary and the systemd unit, checks the new config against SafeLine (`-check`) before switching over and starts the service. The first password of `admin` is in `/var/lib/wafpanel/initial-admin-password`; change it after the first sign-in.

Open `https://<host>:12443`.

## Command line

| Flag | Purpose |
|---|---|
| `-config path` | config file, `/etc/wafpanel/wafpanel.yaml` by default |
| `-check` | validate the config, read the latest records from every instance and exit |
| `-test-channel name` | send a test alert to one channel and exit |
| `-dry-run` | log alerts instead of sending them, send nothing to SIEM |
| `-reset-password user` | set a random password and print it (run as the `wafpanel` user) |
| `-version` | print the version |

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — how the panel works and which SafeLine APIs it uses
- [Alerts and SIEM](docs/ALERTS-SIEM.md) — rules, channels, CEF/JSON, Wazuh
- [Deployment](docs/DEPLOYMENT.md) — install, upgrade, data on disk, security
- [SafeLine notes](docs/SAFELINE-NOTES.md) — API quirks and known issues of SafeLine CE 9.4

## Status

Built against SafeLine CE 9.4.3. The SafeLine OpenAPI is not versioned; the panel parses responses loosely, and every write call mirrors a request of the SafeLine console itself.
