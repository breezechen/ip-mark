package ipmark

import (
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MarkIP{})
	caddy.RegisterModule(IPMatcher{})
	httpcaddyfile.RegisterHandlerDirective("mark_ip", parseCaddyfileMarkIP)
}

var ipStore = sync.Map{}

// MarkIP implements an HTTP handler that stores IPs
type MarkIP struct {
	logger *zap.Logger
}

// IPMatcher implements a request matcher for stored IPs
type IPMatcher struct {
	logger *zap.Logger
}

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

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *IPMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// match_ip 指令不需要任何参数，所以直接返回 nil
	return nil
}

// Provision sets up the module
func (m *MarkIP) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

// Provision sets up the module
func (m *IPMatcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

// Optimized MarkIP.ServeHTTP with minimal logging
func (m *MarkIP) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if ip := getRealIP(r); ip != "" {
		// Keep only essential logging for new IP additions
		if _, loaded := ipStore.LoadOrStore(ip, struct{}{}); !loaded {
			m.logger.Info("new ip marked", zap.String("ip", ip))
		}
	}
	return next.ServeHTTP(w, r)
}

// Optimized IPMatcher.Match with minimal logging
func (m *IPMatcher) Match(r *http.Request) bool {
	ip := getRealIP(r)
	if ip == "" {
		return false
	}
	_, exists := ipStore.Load(ip)
	return exists
}

func getRealIP(r *http.Request) string {
	// Direct header checks without allocation
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-Ip"); ip != "" {
		return ip
	}

	// Parse RemoteAddr
	if addr := r.RemoteAddr; addr != "" {
		if idx := strings.IndexByte(addr, ':'); idx != -1 {
			return addr[:idx]
		}
		return addr
	}
	return ""
}

// parseCaddyfileMarkIP unmarshals tokens from h into a new middleware handler
func parseCaddyfileMarkIP(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m MarkIP
	return &m, nil
}

// Interface guards
var (
	_ caddy.Module                = (*MarkIP)(nil)
	_ caddy.Module                = (*IPMatcher)(nil)
	_ caddyhttp.MiddlewareHandler = (*MarkIP)(nil)
	_ caddyhttp.RequestMatcher    = (*IPMatcher)(nil)
	_ caddy.Provisioner           = (*MarkIP)(nil)
	_ caddy.Provisioner           = (*IPMatcher)(nil)
	_ caddyfile.Unmarshaler       = (*IPMatcher)(nil) // 添加这个接口检查
)
