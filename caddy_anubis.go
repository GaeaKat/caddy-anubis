package caddyanubis

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/TecharoHQ/anubis"
	libanubis "github.com/TecharoHQ/anubis/lib"
	"github.com/TecharoHQ/anubis/lib/policy"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(AnubisMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("anubis", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("anubis", httpcaddyfile.After, "templates")
}

type AnubisMiddleware struct {
	Target       *string `json:"target,omitempty"`
	AnubisPolicy *policy.ParsedConfig
	AnubisServer *libanubis.Server

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (AnubisMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.anubis",
		New: func() caddy.Module {
			return new(AnubisMiddleware)
		},
	}
}

// Provision implements caddy.Provisioner.
func (m *AnubisMiddleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger().Named("anubis")
	m.logger.Info("Anubis middleware provisioning")

	p, err := libanubis.LoadPoliciesOrDefault(
		context.Background(),
		"",
		anubis.DefaultDifficulty,
		"info",
		true,
	)
	if err != nil {
		return err
	}

	m.AnubisPolicy = p

	// We deliberately don't set Next here.
	//
	// The actual Caddy next handler is request-specific and is supplied
	// when ServeHTTP is called. Keeping it on the module would introduce
	// a data race between simultaneous requests.
	m.logger.Info("Anubis middleware provisioned")

	return nil
}

// Validate implements caddy.Validator.
func (m *AnubisMiddleware) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *AnubisMiddleware) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
	next caddyhttp.Handler,
) error {
	m.logger.Info("Anubis middleware processing request")

	// Anubis v1.27 expects X-Real-IP to be present.
	//
	// At the moment Caddy is directly exposed to the Internet, so
	// RemoteAddr is the actual client connection. SplitHostPort removes
	// the ephemeral source port and also handles IPv6 correctly.
	if r.Header.Get("X-Real-IP") == "" {
		clientIP := r.RemoteAddr

		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			clientIP = host
		}

		r.Header.Set("X-Real-IP", clientIP)
	}

	m.logger.Info(
		"Anubis middleware sending request",
		"remote_addr", r.RemoteAddr,
		"x_real_ip", r.Header.Get("X-Real-IP"),
	)

	// The Anubis library calls Next when the request passes the
	// challenge/policy checks. Capture this request's Caddy handler in
	// the closure rather than storing it on the shared middleware object.
	anubisServer, err := libanubis.New(libanubis.Options{
		Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.logger.Info("Anubis middleware calling next")

			if m.Target != nil {
				http.Redirect(w, r, *m.Target, http.StatusTemporaryRedirect)
				return
			}

			if err := next.ServeHTTP(w, r); err != nil {
				m.logger.Error(
					"next handler returned an error",
					"error", err,
				)
			}
		}),
		Policy:         m.AnubisPolicy,
		ServeRobotsTXT: true,
	})
	if err != nil {
		return err
	}

	anubisServer.ServeHTTP(w, r)

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *AnubisMiddleware) UnmarshalCaddyfile(
	d *caddyfile.Dispenser,
) error {
	d.Next()

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "target":
			if d.NextArg() {
				val := d.Val()
				m.Target = &val
			}
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(
	h httpcaddyfile.Helper,
) (caddyhttp.MiddlewareHandler, error) {
	var m AnubisMiddleware

	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*AnubisMiddleware)(nil)
	_ caddy.Validator             = (*AnubisMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AnubisMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*AnubisMiddleware)(nil)
)
