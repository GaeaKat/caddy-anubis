package caddyanubis

import (
	"context"
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

type nextHandlerKey struct{}

func init() {
	caddy.RegisterModule(AnubisMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("anubis", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("anubis", httpcaddyfile.After, "templates")
}

type AnubisMiddleware struct {
	Target       *string             `json:"target,omitempty"`
	AnubisPolicy *policy.ParsedConfig
	AnubisServer *libanubis.Server

	logger *zap.Logger
}

func (AnubisMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.anubis",
		New: func() caddy.Module {
			return new(AnubisMiddleware)
		},
	}
}

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

	m.AnubisServer, err = libanubis.New(libanubis.Options{
		Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next, ok := r.Context().Value(nextHandlerKey{}).(caddyhttp.Handler)
			if !ok || next == nil {
				m.logger.Error("Anubis could not find Caddy next handler")
				http.Error(
					w,
					"Anubis middleware is misconfigured",
					http.StatusInternalServerError,
				)
				return
			}

			if m.Target != nil {
				http.Redirect(w, r, *m.Target, http.StatusTemporaryRedirect)
				return
			}

			if err := next.ServeHTTP(w, r); err != nil {
				m.logger.Error(
					"next handler returned an error",
					zap.Error(err),
				)
			}
		}),
		Policy:         m.AnubisPolicy,
		ServeRobotsTXT: true,
	})
	if err != nil {
		return err
	}

	m.logger.Info("Anubis middleware provisioned")
	return nil
}

func (m *AnubisMiddleware) Validate() error {
	return nil
}

func (m *AnubisMiddleware) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
	next caddyhttp.Handler,
) error {
	m.logger.Info("Anubis middleware processing request")

	// Always overwrite X-Real-IP so a client cannot spoof it.
	//
	// When directly connected, RemoteAddr is the client.
	// When Caddy is configured with trusted proxies (e.g. Cloudflare),
	// Caddy's RemoteAddr/client handling can be used here accordingly.
	clientIP := r.RemoteAddr

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	}

	r.Header.Set("X-Real-IP", clientIP)

	m.logger.Info(
		"Anubis middleware sending request",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("x_real_ip", clientIP),
	)

	r = r.WithContext(
		context.WithValue(r.Context(), nextHandlerKey{}, next),
	)

	m.AnubisServer.ServeHTTP(w, r)

	return nil
}

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

func parseCaddyfile(
	h httpcaddyfile.Helper,
) (caddyhttp.MiddlewareHandler, error) {
	var m AnubisMiddleware

	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

var (
	_ caddy.Provisioner         = (*AnubisMiddleware)(nil)
	_ caddy.Validator           = (*AnubisMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AnubisMiddleware)(nil)
	_ caddyfile.Unmarshaler      = (*AnubisMiddleware)(nil)
)
