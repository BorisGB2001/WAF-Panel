# Alerts and SIEM

## Rules

A rule turns attack events into alerts:

| Field | Meaning |
|---|---|
| `name` | unique name |
| `severity` | `info`, `warning` or `critical` |
| `disabled` | `true` switches the rule off |
| `instances`, `hosts`, `attack_types`, `actions`, `min_risk` | filters; an empty filter matches everything; hosts accept `*.example.com`; actions are `deny` and `pass` |
| `threshold`, `window` | N events of one group within the window fire an alert; `threshold: 1` alerts on every event |
| `group_by` | `src_ip`, `host`, `instance` or `none` |
| `cooldown` | pause between alerts of one group, the window by default |
| `channels` | where to send |

Rules come from the config file until an administrator saves them in the panel; from then on `data_dir/rules.yaml` is used and changes apply without a restart.

## Channels

- **Telegram**: `chat_id`, optional `thread_id` for a forum topic, optional `api_url` for a local Bot API server or a proxy. `retry_after` of the Bot API is respected. If Telegram is blocked for the host, set `HTTPS_PROXY` in the systemd unit.
- **Email**: SMTP with STARTTLS, implicit TLS or plain.
- **Webhook**: a JSON payload (rule, severity, counts, hosts, types, sample events) or `format: slack` for Slack, Mattermost and Rocket.Chat; `secret_file` adds `X-WAFPanel-Signature: sha256=<hmac of the body>`.

Alert texts are in English; set `language: ru` for Russian.

## SIEM

Every event, not only alerts, is forwarded to each `siem` target:

- transports: UDP, TCP or TLS; framing `newline` or `octet` (RFC 6587);
- `header: rfc5424` (default) or `none`;
- formats: **CEF** (`CEF:0|Chaitin|SafeLine|9|<type>|<name>|8 for deny, 5 for pass|rt src dhost dpt request act cat externalId ...`) or **JSON** (normalized fields plus `product: "safeline"`; `json_raw: true` adds the whole SafeLine record);
- a queue of 10 000 events per target; when it overflows events are dropped and counted in `siem_dropped_total` instead of blocking alerts.

### Wazuh

Wazuh 4.x does not pre-decode RFC 5424 and decodes JSON only without a syslog header, so use `format: json` with `header: none`. Install [deploy/wazuh/safeline_rules.xml](../deploy/wazuh/safeline_rules.xml):

| ID | Level | When |
|---|---|---|
| 100700 | 3 | any SafeLine event |
| 100701 | 5 | blocked |
| 100702 | 6 | passed |
| 100703 | 10 | dangerous type: 5, 7, 8, 9, 17, 20, 36 |
| 100704 | 10 | 20+ events from one `src_ip` in 5 minutes |

`action` and `url` are static Wazuh fields: match them with `<action>`, never `<field name="action">` — the manager refuses to load such a rule. Always run `wazuh-analysisd -t` before restarting the manager. The syslog source must be listed in `<allowed-ips>` of the `<remote>` block.

## Monitoring

`GET 127.0.0.1:9188/healthz` answers 503 when an instance has not been polled successfully for three poll intervals plus a minute; `/metrics` exposes Prometheus counters (`wafpanel_events_total`, `wafpanel_poll_errors_total`, `wafpanel_alerts_sent_total`, `wafpanel_siem_sent_total`, ...).
