#!/bin/sh
# boris.gb 2026-10-30 11:37 - installs wafpanel on a Debian host: system user, directories, binary, config, secrets, systemd unit
# boris.gb 2026-10-30 15:06 - the service is called wafpanel now; an older wafpanel-alerts unit is stopped and removed, state in /var/lib/wafpanel is kept
# Run from the project root: sudo sh deploy/install.sh [wafpanel.yaml secrets-dir]
# Without arguments it only updates the binary and the unit. From the secrets dir it takes *.token, *.password, *.secret, *.pem.
set -eu

CFG=${1:-}
SECRETS=${2:-}
BIN=bin/wafpanel-linux-amd64

[ -f "$BIN" ] || { echo "no $BIN, run make linux" >&2; exit 1; }

id wafpanel >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin wafpanel
install -d -m 0750 -o root -g wafpanel /etc/wafpanel /etc/wafpanel/secrets
install -d -m 0700 -o wafpanel -g wafpanel /var/lib/wafpanel
install -m 0755 "$BIN" /usr/local/bin/wafpanel.new
install -m 0644 deploy/wafpanel.service /etc/systemd/system/wafpanel.service

if [ -n "$CFG" ]; then
    install -m 0640 -o root -g wafpanel "$CFG" /etc/wafpanel/wafpanel.yaml.new
fi
if [ -n "$SECRETS" ]; then
    for f in "$SECRETS"/*.token "$SECRETS"/*.password "$SECRETS"/*.secret "$SECRETS"/*.pem; do
        [ -f "$f" ] && install -m 0640 -o root -g wafpanel "$f" /etc/wafpanel/secrets/
    done
fi

# Check the new binary with the new config before switching over.
NEWCFG=/etc/wafpanel/wafpanel.yaml
[ -f /etc/wafpanel/wafpanel.yaml.new ] && NEWCFG=/etc/wafpanel/wafpanel.yaml.new
runuser -u wafpanel -- /usr/local/bin/wafpanel.new -config "$NEWCFG" -check

[ -f /etc/wafpanel/wafpanel.yaml ] && cp -p /etc/wafpanel/wafpanel.yaml "/etc/wafpanel/wafpanel.yaml.bak-$(date +%Y%m%d%H%M)"
[ -f /etc/wafpanel/wafpanel.yaml.new ] && mv /etc/wafpanel/wafpanel.yaml.new /etc/wafpanel/wafpanel.yaml
mv /usr/local/bin/wafpanel.new /usr/local/bin/wafpanel

# Migrate from the old wafpanel-alerts service.
if [ -f /etc/systemd/system/wafpanel-alerts.service ]; then
    systemctl disable --now wafpanel-alerts || true
    rm -f /etc/systemd/system/wafpanel-alerts.service /usr/local/bin/wafpanel-alerts
fi

systemctl daemon-reload
systemctl enable wafpanel
systemctl restart wafpanel
sleep 3
systemctl --no-pager status wafpanel | head -5
curl -s 127.0.0.1:9188/healthz; echo
[ -f /var/lib/wafpanel/initial-admin-password ] && echo "First sign-in password of admin: /var/lib/wafpanel/initial-admin-password (sudo cat); change it in the panel"
exit 0
