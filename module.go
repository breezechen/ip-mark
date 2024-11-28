package ipmark

import (
    "fmt"
    "net/http"
    "sync"

    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
    "github.com/caddyserver/caddy/v2/modules/caddyhttp"
    "go.uber.org/zap"
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

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *MarkIP) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    ip := getRealIP(r)
    if ip != "" {
        ipStoreLock.Lock()
        ipStore[ip] = struct{}{}
        ipStoreLock.Unlock()
        m.logger.Info("marked ip",
            zap.String("ip", ip),
            zap.String("path", r.URL.Path),
            zap.String("method", r.Method))
    } else {
        m.logger.Warn("could not determine real IP",
            zap.String("path", r.URL.Path),
            zap.String("method", r.Method))
    }
    return next.ServeHTTP(w, r)
}

// Match implements caddyhttp.RequestMatcher
func (m *IPMatcher) Match(r *http.Request) bool {
    ip := getRealIP(r)
    if ip == "" {
        m.logger.Debug("no IP found in request",
            zap.String("path", r.URL.Path),
            zap.String("method", r.Method))
        return false
    }

    ipStoreLock.RLock()
    _, exists := ipStore[ip]
    ipStoreLock.RUnlock()

    m.logger.Debug("checking IP match",
        zap.String("ip", ip),
        zap.String("path", r.URL.Path),
        zap.String("method", r.Method),
        zap.Bool("matched", exists))

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
    return &m, nil
}

// parseCaddyfileMatchIP unmarshals tokens from h into a new matcher
func parseCaddyfileMatchIP(h httpcaddyfile.Helper) (caddyhttp.RequestMatcher, error) {
    var m IPMatcher
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
)