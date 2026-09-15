// Package logctx carries request-scoped log attributes through a context and
// adds them to every slog record written with that context.
//
// zitadel/oidc logs protocol failures through slog.Default() with the request
// context ("request error" at WARN). Without this package those lines name
// only the OIDC error, so an operator cannot tell which client failed or
// correlate the line with the ingress access log.
package logctx

import (
	"context"
	"log/slog"
)

type contextKey struct{}

// With returns a copy of ctx whose log records also carry attrs. Attributes
// added by an outer call are kept; a later call appends after them.
func With(ctx context.Context, attrs ...slog.Attr) context.Context {
	if len(attrs) == 0 {
		return ctx
	}
	prev := attrsFrom(ctx)
	merged := make([]slog.Attr, 0, len(prev)+len(attrs))
	merged = append(merged, prev...)
	merged = append(merged, attrs...)
	return context.WithValue(ctx, contextKey{}, merged)
}

func attrsFrom(ctx context.Context) []slog.Attr {
	if ctx == nil {
		return nil
	}
	attrs, _ := ctx.Value(contextKey{}).([]slog.Attr)
	return attrs
}

// Handler adds the attributes stored in a record's context to the record
// before passing it to the wrapped handler.
type Handler struct {
	inner slog.Handler
}

// NewHandler wraps inner. Do not wrap slog.Default().Handler() and then install
// the result with slog.SetDefault: the stock default handler writes through the
// log package, which SetDefault redirects back into slog.
func NewHandler(inner slog.Handler) *Handler {
	return &Handler{inner: inner}
}

func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if attrs := attrsFrom(ctx); len(attrs) > 0 {
		r = r.Clone()
		r.AddAttrs(attrs...)
	}
	return h.inner.Handle(ctx, r)
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{inner: h.inner.WithAttrs(attrs)}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{inner: h.inner.WithGroup(name)}
}
