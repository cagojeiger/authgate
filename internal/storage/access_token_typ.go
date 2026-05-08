package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

// WrapAccessTokenJWTType wraps the OIDC token endpoint and rewrites the
// JOSE `typ` header of the JWT access token to `at+jwt` per RFC 9068
// §2.1. zitadel/oidc's signer is hardcoded to `typ=JWT` for both access
// tokens and id_tokens (pkg/op/signer.go SignerFromKey), and the library
// exposes no public hook to override this for a single token type. This
// middleware captures the JSON response on the way out, re-signs the
// access_token JWT with our same key but the correct profile typ, and
// passes the response on. The id_token is left untouched per OIDC Core
// 1.0 (§2 keeps `typ=JWT` for id_tokens).
//
// On any error during the rewrite, the original response body is
// preserved unchanged so the rewrite cannot make the endpoint less
// available than it would be otherwise.
func WrapAccessTokenJWTType(inner http.Handler, store *Storage) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := newCaptureRW(w)
		inner.ServeHTTP(rec, r)

		body := rec.body.Bytes()
		if rec.code == http.StatusOK && len(body) > 0 {
			upgraded, err := upgradeAccessTokenTyp(r.Context(), store, body)
			switch {
			case err == nil:
				body = upgraded
			case errors.Is(err, errSkipUpgrade):
				// Response is not eligible (no access_token, not a JWS).
				// Forward the original body unchanged.
			default:
				// A real error means we'd be serving a typ=JWT access token
				// despite the fix. Preserve availability (forward original
				// body) but log loudly so the regression is visible.
				slog.ErrorContext(r.Context(), "at+jwt typ rewrite failed; serving typ=JWT access token",
					"error", err,
				)
			}
		}

		for k, vs := range rec.Header() {
			w.Header()[k] = vs
		}
		// Strip any content-integrity headers zitadel may have set against
		// the original body — they would now be inconsistent.
		w.Header().Del("ETag")
		w.Header().Del("Content-Digest")
		w.Header().Del("Repr-Digest")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(rec.code)
		_, _ = w.Write(body)
	})
}

// upgradeAccessTokenTyp parses a token-endpoint JSON response, locates
// the `access_token` field, and if it is a compact JWS with typ=JWT,
// re-signs the same payload with typ=at+jwt using the storage's signing
// key. Returns the (possibly modified) body. A non-nil error means the
// caller should keep the original body — callers MUST treat error as a
// signal to fall back, not propagate.
func upgradeAccessTokenTyp(ctx context.Context, store *Storage, body []byte) ([]byte, error) {
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	rawAT, ok := resp["access_token"]
	if !ok {
		return nil, errSkipUpgrade
	}
	var token string
	if err := json.Unmarshal(rawAT, &token); err != nil {
		return nil, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errSkipUpgrade
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, err
	}
	if typ, _ := header["typ"].(string); typ == "at+jwt" {
		return body, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	sk, err := store.SigningKey(ctx)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: sk.SignatureAlgorithm(),
		Key: &jose.JSONWebKey{
			Key:   sk.Key(),
			KeyID: sk.ID(),
		},
	}, (&jose.SignerOptions{}).WithType("at+jwt"))
	if err != nil {
		return nil, err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	rewritten, err := signed.CompactSerialize()
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(rewritten)
	if err != nil {
		return nil, err
	}
	resp["access_token"] = encoded
	return json.Marshal(resp)
}

// errSkipUpgrade signals that the response is not eligible for typ
// rewriting (e.g. no access_token field, or not a compact JWS). It is a
// non-failure condition.
var errSkipUpgrade = &jwtUpgradeSkip{}

type jwtUpgradeSkip struct{}

func (*jwtUpgradeSkip) Error() string { return "access_token typ upgrade skipped" }

// captureRW buffers the entire response so the middleware can inspect
// and rewrite it before flushing to the real ResponseWriter.
type captureRW struct {
	http.ResponseWriter
	header http.Header
	body   *bytes.Buffer
	code   int
	wrote  bool
}

func newCaptureRW(w http.ResponseWriter) *captureRW {
	return &captureRW{
		ResponseWriter: w,
		header:         http.Header{},
		body:           &bytes.Buffer{},
		code:           http.StatusOK,
	}
}

func (c *captureRW) Header() http.Header { return c.header }

func (c *captureRW) WriteHeader(code int) {
	if c.wrote {
		return
	}
	c.code = code
	c.wrote = true
}

func (c *captureRW) Write(b []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	return c.body.Write(b)
}
