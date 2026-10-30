# boris.gb 2026-10-30 10:04 - build and test; linux-amd64 for Debian servers
# boris.gb 2026-10-30 15:06 - the service is wafpanel (alerts + SIEM + web panel); the version is stamped into the binary
# boris.gb 2026-10-30 16:22 - 0.6.1: site name goes to comment (SafeLine owns title), row menu no longer clipped
# boris.gb 2026-10-30 16:38 - 0.7.0: Allow & Deny rules editor
# boris.gb 2026-10-30 16:42 - 0.7.1: header names in rule conditions, rules sharing a position are marked
# boris.gb 2026-10-30 16:54 - 0.8.0: allow and deny lists with their own order, reordering
VERSION ?= 0.8.0
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: build linux test

build:
	go build -ldflags '-X main.version=$(VERSION)-dev' -o bin/wafpanel ./cmd/wafpanel

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='$(LDFLAGS)' -o bin/wafpanel-linux-amd64 ./cmd/wafpanel

test:
	go vet ./cmd/... ./internal/...
	go test ./cmd/... ./internal/...
