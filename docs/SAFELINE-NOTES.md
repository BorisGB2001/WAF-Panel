# SafeLine CE notes

What we learned about SafeLine CE 9.4.x while building the panel.

## API quirks

- Every response is `{"err": null|"...", "msg": "...", "data": ...}`; HTTP 200 does not mean success.
- `GET /api/open/records`: newest first by `timestamp`, no numeric `id`; the key is `event_id` (`EventId` is always empty). `timestamp` is in seconds, while the `start`/`end` filters are in **milliseconds** and inclusive. In the list `req_*`, `rsp_*`, `payload` and `method` are empty; `GET /api/open/record/{event_id}` has them, with numbers as strings.
- `page_size` is at most 100 for policies and records; larger values fail with "Error occurred when extracting params".
- `GET /api/open/ipgroup/detail` wraps the group once more: `{"data": {"data": {...}}}`.
- `POST /api/open/policy` needs `insert_position` (`"first"`, `"last"`); without it the call fails with "Error occurred when extracting params".
- Statistics: `/api/stat/advance/*` take `begin_time`, `end_time` (seconds) and `time_preset`. In CE only the last 24 hours work: `today` answers "license required" and 7 or 30 days silently fall back to 24 hours. Locations, clients, response codes, referrers and pages stay empty unless the edition or the application has advanced statistics. `error_status_code` counts the application's errors with `upstream=true` and the WAF's own 4xx with `upstream=false`.
- `GET /api/stat/qps?count=N` returns five-second buckets; divide by five for requests per second.
- Site modes: `0` defense, `1` offline, `2` monitoring (detect only).
- `GET /api/open/cert/{id}` returns the private key; the panel never calls it.
- A site's `title` is not a name: `mgt` fills it from the `<title>` of the upstream's home page and overwrites what is sent. The name typed in the console is `comment`.
- Upstreams on loopback and other special-use addresses are refused ("special-use address is not allowed").
- Allow & Deny rules (`/api/open/policy`): `action` 0 allow, 1 deny; `log` writes allowed requests to the log, `monitor` makes a deny rule record only. `pattern` is OR of AND groups of `{k, op, v[], sub_k}`; `sub_k` is the header or parameter name. Update is `PUT` with the create body plus `id` (without `insert_position` the rule keeps its place); delete is `DELETE` with the body `{"id": N}`. The operators each target accepts are listed in `internal/safeline/policies.go`; geo operators need a license and JA4 the commercial fingerprint database.

## Known issue: empty attack log after updating to images of 2026-10-23

**Symptoms.** The console shows no new attacks and empty QPS; the detector logs `reject detector management request without valid token` every few seconds for `luigi` and `fvm`, `luigi` logs `request qps failed: 401`, and `mgt` logs `push fsl failed: 401 unauthorized` every hour, so the detector also runs without current rules.

**Cause.** From these images the detector management proxy requires a shared token (`DETECTOR_MGMT_TOKEN`, sent as `X-Safeline-Internal-Token`), but the `compose.yaml` of that time does not pass it to any container.

**Fix.** Add a random token to `.env` and pass it to `detect`, `luigi` and `fvm`:

```bash
echo "DETECTOR_MGMT_TOKEN=$(openssl rand -hex 32)" >> /data/safeline/.env
```

```yaml
# in services.detect.environment, services.luigi.environment and a new services.fvm.environment:
      - DETECTOR_MGMT_TOKEN=${DETECTOR_MGMT_TOKEN:?DETECTOR_MGMT_TOKEN required}
```

```bash
cd /data/safeline && docker compose up -d --no-deps --pull never detect luigi fvm
```

The next hourly rule push (`:04`) reports `Push FSL success` in `fvm`, and new attacks appear again. If `.env` is managed by configuration management, make the change there, otherwise the next run reverts it. Pin `IMAGE_TAG` instead of `latest` to avoid such surprises.
