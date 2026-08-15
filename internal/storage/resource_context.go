package storage

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type resourceContextKey struct{}

// ErrMultipleResourceParams is returned by ResourceFromRequestStrict when
// more than one `resource` value is present on the request. RFC 8707 §2
// permits multiple resource parameters in principle, but RFC 8707 §2.2
// explicitly allows the AS to apply its own restrictive policy via
// `invalid_target`. authgate enforces single-audience policy: a request
// may bind to at most one MCP resource server.
var ErrMultipleResourceParams = errors.New("multiple resource parameters not permitted")

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

// ResourceFromRequestStrict enforces the single-audience policy at the
// HTTP boundary: any request carrying more than one `resource` parameter
// is rejected with ErrMultipleResourceParams before the auth_request is
// stored. Returns the (possibly empty) resource string and nil on the
// zero-or-one-value path.
func ResourceFromRequestStrict(r *http.Request) (string, error) {
	if r == nil {
		return "", nil
	}
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	values := r.Form["resource"]
	if len(values) > 1 {
		return "", ErrMultipleResourceParams
	}
	if len(values) == 0 {
		return "", nil
	}
	return strings.TrimSpace(values[0]), nil
}
