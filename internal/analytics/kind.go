package analytics

import (
	"path"
	"strings"
)

var assetExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".svg": true,
	".ico": true, ".css": true, ".js": true, ".map": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".webm": true, ".mp3": true}

// IsAsset reports whether a path is an image, style, script or font.
func IsAsset(p string) bool { return assetExt[strings.ToLower(path.Ext(p))] }

// Device is the kind of client: Desktop, Phone, Tablet, Bot or Script
// (an HTTP library or tool).
func Device(ua string, c Client) string {
	switch {
	case c.Bot != "":
		return "Bot"
	case ua == "":
		return "Script"
	case strings.Contains(ua, "iPad"), strings.Contains(ua, "Tablet"),
		strings.Contains(ua, "Android") && !strings.Contains(ua, "Mobile"):
		return "Tablet"
	case strings.Contains(ua, "Mobi"), strings.Contains(ua, "iPhone"), strings.Contains(ua, "Android"),
		strings.HasPrefix(ua, "Mattermost-Mobile"), strings.HasPrefix(ua, "okhttp/"), strings.HasPrefix(ua, "Dart/"):
		return "Phone"
	case !strings.HasPrefix(ua, "Mozilla/"):
		return "Script"
	}
	return "Desktop"
}

var searchEngines = []string{"google.", "yandex.", "ya.ru", "bing.com", "duckduckgo.com", "go.mail.ru", "search.yahoo.",
	"baidu.com", "ecosia.org", "rambler.ru", "startpage.com", "qwant.com", "msn.com"}

var socialNetworks = []string{"facebook.com", "fb.com", "vk.com", "vk.ru", "ok.ru", "t.me", "telegram.", "twitter.com", "x.com",
	"t.co", "instagram.com", "linkedin.com", "lnkd.in", "youtube.com", "reddit.com", "pinterest.", "tiktok.com", "dzen.ru",
	"zen.yandex.ru", "habr.com", "whatsapp.com"}

func matches(host string, list []string) bool {
	for _, s := range list {
		if strings.HasSuffix(s, ".") {
			if strings.HasPrefix(host, s) || strings.Contains(host, "."+s) {
				return true
			}
		} else if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// Source groups a referrer host: Search engines, Social networks, Other
// sites, or Direct when there is none.
func Source(refHost string) string {
	switch {
	case refHost == "":
		return "Direct"
	case matches(refHost, searchEngines):
		return "Search engines"
	case matches(refHost, socialNetworks):
		return "Social networks"
	}
	return "Other sites"
}
