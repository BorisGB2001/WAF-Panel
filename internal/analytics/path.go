package analytics

import (
	"regexp"
	"strings"
)

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe  = regexp.MustCompile(`^[0-9a-fA-F]{12,}$`)
	// Ids like Mattermost's: 26 lowercase letters and digits.
	idRe  = regexp.MustCompile(`^[a-z0-9]{20,}$`)
	numRe = regexp.MustCompile(`^\d+$`)
)

// maxSegments keeps endpoint keys short; deeper paths end in "/…".
const maxSegments = 6

// NormalizePath turns a URL path into an endpoint: ids, numbers, hashes
// and UUIDs become ":id" so /api/v4/users/abc…/status and the same call
// for another user count as one endpoint. File names keep their
// extension: /static/files/9ea8….png → /static/files/:id.png.
func NormalizePath(p string) string {
	if p == "" || p[0] != '/' {
		return "(invalid)"
	}
	segs := strings.Split(p[1:], "/")
	cut := false
	if len(segs) > maxSegments {
		segs, cut = segs[:maxSegments], true
	}
	for i, s := range segs {
		name, ext := s, ""
		if j := strings.LastIndexByte(s, '.'); j > 0 && len(s)-j <= 6 {
			name, ext = s[:j], s[j:]
		}
		if isID(name) {
			segs[i] = ":id" + ext
		} else if len(s) > 48 {
			segs[i] = ":long"
		}
	}
	out := "/" + strings.Join(segs, "/")
	if cut {
		out += "/…"
	}
	return out
}

func isID(s string) bool {
	if numRe.MatchString(s) || uuidRe.MatchString(s) || hexRe.MatchString(s) {
		return true
	}
	if idRe.MatchString(s) {
		// A word like "notifications" is not an id: ids mix in digits.
		return strings.ContainsAny(s, "0123456789")
	}
	return false
}
