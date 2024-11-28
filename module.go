package ipmark

import (
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(MarkIP{})
	caddy.RegisterModule(IPMatcher{})
	httpcaddyfile.RegisterHandlerDirective("mark_ip", parseCaddyfileMarkIP)
	httpcaddyfile.RegisterMatcherDirective("match_ip", parseCaddyfileMatchIP)
}

// IPStore is a global store for IPs
var (
	ipStore     = make(map[string]struct{})
	ipStoreLock sync.RWMutex
)

// MarkIP implements an HTTP handler that stores IPs
type MarkIP struct{}

// IPMatcher implements a request matcher for stored IPs
type IPMatcher struct{}

// CaddyModule returns the Caddy module information.
func (MarkIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.mark_ip",
		New: func() caddy.Module { return new(MarkIP) },
	}
}

func (IPMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.match_ip",
		New: func() caddy.Module { return new(IPMatcher) },
	}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m MarkIP) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := getRealIP(r)
	if ip != "" {
		ipStoreLock.Lock()
		ipStore[ip] = struct{}{}
		ipStoreLock.Unlock()
	}
	return next.ServeHTTP(w, r)
}

// Match implements caddyhttp.RequestMatcher
func (m IPMatcher) Match(r *http.Request) bool {
	ip := getRealIP(r)
	if ip == "" {
		return false
	}

	ipStoreLock.RLock()
	_, exists := ipStore[ip]
	ipStoreLock.RUnlock()

	return exists
}

// getRealIP implements the IP resolution logic
func getRealIP(r *http.Request) string {
	// Try Cloudflare IP
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}
	// Try X-Forwarded-For
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	// Try X-Real-Ip
	if ip := r.Header.Get("X-Real-Ip"); ip != "" {
		return ip
	}
	// Use Remote Address
	return r.RemoteAddr
}

// parseCaddyfileMarkIP unmarshals tokens from h into a new middleware handler
func parseCaddyfileMarkIP(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m MarkIP
	return m, nil
}

// parseCaddyfileMatchIP unmarshals tokens from h into a new matcher
func parseCaddyfileMatchIP(h httpcaddyfile.Helper) (caddyhttp.RequestMatcher, error) {
	var m IPMatcher
	return m, nil
}

// Interface guards
var (
	_ caddy.Module                = (*MarkIP)(nil)
	_ caddy.Module                = (*IPMatcher)(nil)
	_ caddyhttp.MiddlewareHandler = (*MarkIP)(nil)
	_ caddyhttp.RequestMatcher    = (*IPMatcher)(nil)
)
