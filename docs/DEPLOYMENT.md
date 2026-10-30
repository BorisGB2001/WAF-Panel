# Deployment

## Where to run it

On the SafeLine host or on a separate host that reaches the console (`:9443`). It needs outbound access to the console, to the alert channels and to the SIEM; inbound only on the panel port (`:12443`).

Ports 22, 9188, 9443, 12443 and 65443 cannot be used by sites created in the panel, because they belong to SSH, the panel metrics, the SafeLine console, the panel and SafeLine itself.

## Install and upgrade

```bash
make test && make linux VERSION=x.y.z
sudo sh deploy/install.sh wafpanel.yaml secrets   # first install
sudo sh deploy/install.sh                          # upgrade: binary and unit only
```

The installer checks the new binary with the new config (`-check`) before switching over and keeps the previous config as `wafpanel.yaml.bak-<date>`.

## TLS

Without `tls_cert`/`tls_key` the panel creates a self-signed certificate in `data_dir/tls`. It can reuse the certificate SafeLine serves for your sites (`/data/safeline/resources/nginx/certs/cert_N.crt|key`); the file is re-read when it changes, so a renewal in SafeLine needs no restart. `plain_http` is allowed only on a loopback address.

When the console certificate is issued for a name but `base_url` uses an IP, set `tls_server_name`.

## Data on disk

| Path | Content |
|---|---|
| `/etc/wafpanel/wafpanel.yaml` | config |
| `/etc/wafpanel/secrets/` | SafeLine and channel secrets |
| `/var/lib/wafpanel/state.json` | collector position |
| `/var/lib/wafpanel/rules.yaml` | rules saved in the panel |
| `/var/lib/wafpanel/users.json` | users (bcrypt) |
| `/var/lib/wafpanel/session.key` | session signing key; deleting it ends every session |
| `/var/lib/wafpanel/alerts-history.jsonl` | alert history |
| `/var/lib/wafpanel/audit.log` | audit log |
| `/var/lib/wafpanel/blocklist-<instance>.json` | who blocked an IP, why and until when |

## Security

- HTTPS only (TLS 1.2+), HSTS, a CSP without external sources, `X-Frame-Options: DENY`.
- Passwords in bcrypt, at least 10 characters; 5 failed sign-ins lock the IP and the username for 15 minutes.
- Sessions: HMAC-signed `HttpOnly; Secure; SameSite=Strict` cookies, 12 hours; a password or role change ends every other session of that user.
- CSRF token and `Origin` check on every POST.
- Every change in SafeLine needs a reason; changing a site's mode, disabling or deleting a site needs the site name typed in. All of it goes to the audit log, failures included.
- The blocklist refuses the requester's own address, the WAF host, loopback and subnets wider than /16 (IPv6 /48).
- The service runs as an unprivileged user with a read-only file system except `/var/lib/wafpanel` and no capabilities.

To reset a password: `sudo -u wafpanel wafpanel -config /etc/wafpanel/wafpanel.yaml -reset-password admin` (as `wafpanel`, not root, so the users file stays readable by the service).
