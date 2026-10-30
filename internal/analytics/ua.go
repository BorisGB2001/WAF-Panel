package analytics

import (
	"regexp"
	"strings"
)

// Client is what a User-Agent tells about the visitor.
type Client struct {
	OS     string
	Client string // browser, app or tool
	Bot    string // crawler or scanner name, empty for people
}

var (
	botRe     = regexp.MustCompile(`(?i)(googlebot|bingbot|yandex(?:bot|images|metrika|direct)|baiduspider|duckduckbot|applebot|petalbot|ahrefsbot|semrushbot|mj12bot|dotbot|bytespider|gptbot|claudebot|ccbot|facebookexternalhit|telegrambot|slackbot|twitterbot|linkedinbot|uptimerobot|pingdom|zabbix|prometheus|nuclei|sqlmap|nikto|nmap|masscan|zgrab|wpscan|dirbuster|gobuster|ffuf|censys|shodan|[a-z]*bot\b|crawler|spider)`)
	versionRe = regexp.MustCompile(`^[\d.]+`)
)

// tools are non-browser clients, matched as prefixes of the User-Agent.
var tools = []struct{ prefix, name string }{
	{"curl/", "curl"}, {"Wget/", "Wget"}, {"python-requests/", "Python requests"}, {"Python-urllib/", "Python urllib"},
	{"python-httpx/", "Python httpx"}, {"aiohttp/", "Python aiohttp"}, {"Go-http-client/", "Go HTTP client"},
	{"okhttp/", "OkHttp"}, {"Java/", "Java"}, {"Apache-HttpClient/", "Apache HttpClient"}, {"axios/", "axios"},
	{"node-fetch", "node-fetch"}, {"PostmanRuntime/", "Postman"}, {"insomnia/", "Insomnia"}, {"Dart/", "Dart"},
	{"Mattermost-Mobile", "Mattermost Mobile"}, {"Mattermost", "Mattermost"},
}

// ParseUA classifies a User-Agent string. It knows the common browsers
// and operating systems, desktop apps built on Electron (named by their
// own token, e.g. "Mattermost Desktop 6.0"), HTTP libraries and bots.
func ParseUA(ua string) Client {
	var c Client
	if strings.TrimSpace(ua) == "" {
		return Client{OS: "Unknown", Client: "No User-Agent"}
	}
	if m := botRe.FindString(ua); m != "" {
		c.Bot = botName(m)
	}
	c.OS = parseOS(ua)
	for _, t := range tools {
		if strings.HasPrefix(ua, t.prefix) {
			c.Client = t.name
			return c
		}
	}
	c.Client = parseBrowser(ua)
	if c.Bot != "" && c.Client == "Other client" {
		c.Client = c.Bot
	}
	return c
}

func botName(m string) string {
	l := strings.ToLower(m)
	switch {
	case strings.HasPrefix(l, "yandex"):
		return "YandexBot"
	case l == "crawler" || l == "spider" || l == "bot":
		return "Other bot"
	}
	return strings.ToUpper(m[:1]) + m[1:]
}

func parseOS(ua string) string {
	switch {
	case strings.Contains(ua, "Windows NT 10.0"), strings.Contains(ua, "Windows NT 11"):
		return "Windows 10/11"
	case strings.Contains(ua, "Windows NT 6.1"):
		return "Windows 7"
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"), strings.Contains(ua, "iOS"):
		return "iOS"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "CrOS"):
		return "ChromeOS"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"), strings.Contains(ua, "Darwin"):
		return "macOS"
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		return "Linux"
	}
	return "Other OS"
}

// token returns the version after name/ in ua, major.minor only.
func token(ua, name string) (string, bool) {
	i := strings.Index(ua, name+"/")
	if i < 0 {
		return "", false
	}
	v := versionRe.FindString(ua[i+len(name)+1:])
	if p := strings.SplitN(v, ".", 3); len(p) >= 2 {
		v = p[0] + "." + p[1]
	}
	return v, true
}

func parseBrowser(ua string) string {
	// Electron apps name themselves next to the Electron token.
	if _, ok := token(ua, "Electron"); ok {
		for _, app := range []string{"Mattermost", "Slack", "Teams", "Discord", "Figma", "Notion", "Obsidian"} {
			if v, ok := token(ua, app); ok {
				return app + " Desktop " + v
			}
		}
		return "Electron app"
	}
	for _, b := range []struct{ tok, name string }{
		{"YaBrowser", "Yandex Browser"}, {"Edg", "Edge"}, {"OPR", "Opera"}, {"SamsungBrowser", "Samsung Internet"},
		{"Firefox", "Firefox"}, {"FxiOS", "Firefox"}, {"CriOS", "Chrome"},
	} {
		if v, ok := token(ua, b.tok); ok {
			return b.name + " " + major(v)
		}
	}
	if v, ok := token(ua, "Chrome"); ok {
		return "Chrome " + major(v)
	}
	if strings.Contains(ua, "Safari/") && strings.Contains(ua, "Version/") {
		v, _ := token(ua, "Version")
		return "Safari " + major(v)
	}
	if strings.HasPrefix(ua, "Mozilla/") {
		return "Other browser"
	}
	return "Other client"
}

func major(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}

// Family drops the version: "Chrome 140" → "Chrome".
func Family(client string) string {
	if i := strings.LastIndexByte(client, ' '); i > 0 && client[i+1] >= '0' && client[i+1] <= '9' {
		return client[:i]
	}
	return client
}
