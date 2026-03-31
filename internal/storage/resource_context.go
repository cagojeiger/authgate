package storage

import (
	"context"
	"net/http"
	"strings"
)

type resourceContextKey struct{}

func WithResource(ctx context.Context, resource string) context.Context {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return ctx
	}
	return context.WithValue(ctx, resourceContextKey{}, resource)
}

func ResourceFromContext(ctx context.Context) string {
	resource, _ := ctx.Value(resourceContextKey{}).(string)
	return strings.TrimSpace(resource)
}

func ResourceFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if err := r.ParseForm(); err != nil {
		return ""
	}
	values := r.Form["resource"]
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}
