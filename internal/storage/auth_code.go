package storage

import (
	"context"
	"database/sql"

	"github.com/kangheeyong/authgate/internal/db/storeq"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// consumeAuthCode runs only at issuance, after zitadel's client, redirect and
// PKCE validation. With a refresh token, the caller supplies the same transaction
// that inserts the grant. The provider's subsequent DeleteAuthRequest is an
// idempotent cleanup. A failed signing/HTTP response after commit never restores
// the credential: at-most-once issuance takes precedence over retry availability.
func (s *Storage) consumeAuthCode(ctx context.Context, q *storeq.Queries, request op.TokenRequest) error {
	ar, ok := request.(*AuthRequestModel)
	if !ok {
		return nil
	}
	if ar.Code == nil || *ar.Code == "" {
		return oidc.ErrInvalidGrant()
	}
	n, err := q.ConsumeAuthCode(ctx, storeq.ConsumeAuthCodeParams{
		ID: ar.ID, ClientID: ar.ClientID,
		Code: sql.NullString{String: s.codeAtRest(*ar.Code), Valid: true},
		Now:  s.clock.Now(),
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return oidc.ErrInvalidGrant()
	}
	return nil
}
