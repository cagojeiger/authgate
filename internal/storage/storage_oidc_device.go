package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	if s.signingKey == nil {
		return nil, errors.New("no signing key configured")
	}
	return &signingKeyModel{
		id:        s.signingKeyID,
		algorithm: jose.RS256,
		key:       s.signingKey,
	}, nil
}

func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	if s.signingKey == nil {
		return nil, nil
	}
	keys := []op.Key{
		&publicKeyModel{
			id:        s.signingKeyID,
			algorithm: jose.RS256,
			key:       &s.signingKey.PublicKey,
		},
	}
	// 2-slot rotation: include previous key if set
	if s.previousKey != nil {
		keys = append(keys, &publicKeyModel{
			id:        s.previousKeyID,
			algorithm: jose.RS256,
			key:       &s.previousKey.PublicKey,
		})
	}
	return keys, nil
}

// --- op.Storage: OPStorage ---

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	client, err := s.resolveClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, err := s.resolveClient(ctx, clientID)
	if err != nil {
		return ErrNotFound
	}
	if client.SecretHash == nil {
		return errors.New("public client cannot use client_secret")
	}
	return verifyBcrypt(*client.SecretHash, clientSecret)
}

func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, userID, scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	return s.setUserinfo(ctx, userinfo, subject, []string{"openid", "profile", "email"})
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	var ui oidc.UserInfo
	if err := s.setUserinfo(ctx, &ui, subject, []string{"openid", "profile", "email"}); err != nil {
		return err
	}
	introspection.SetUserInfo(&ui)
	return nil
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return nil, nil
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, ErrNotFound
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// --- Health ---

func (s *Storage) Health(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// --- DeviceAuthorizationStorage ---

func (s *Storage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	return storeq.New(s.db).InsertDeviceCode(ctx, storeq.InsertDeviceCodeParams{
		ID:         s.idgen.NewUUID(),
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     scopes,
		ExpiresAt:  expires,
		CreatedAt:  s.clock.Now(),
	})
}

func (s *Storage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	qtx := storeq.New(tx)

	dc, err := loadDeviceAuthorizationForUpdate(ctx, qtx, clientID, deviceCode)
	if err != nil {
		return nil, err
	}

	return resolveDeviceAuthorizationState(ctx, tx, qtx, dc, s.clock.Now())
}

// --- Device code business operations (called by service, not by zitadel) ---

// GetDeviceCodeByUserCode looks up a device code by user_code for the approval page.
func (s *Storage) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCodeModel, error) {
	row, err := storeq.New(s.db).GetDeviceCodeByUserCode(ctx, userCode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &DeviceCodeModel{
		ID:         row.ID,
		DeviceCode: row.DeviceCode,
		UserCode:   row.UserCode,
		ClientID:   row.ClientID,
		Scopes:     StringArray(row.Scopes),
		State:      row.State,
		Subject:    nullStringToPtr(row.Subject),
		ExpiresAt:  row.ExpiresAt,
		AuthTime:   nullTimePtr(row.AuthTime),
	}, nil
}

// ApproveDeviceCode sets a device code to approved state with subject and auth_time.
func (s *Storage) ApproveDeviceCode(ctx context.Context, userCode, subject string) error {
	now := s.clock.Now()
	rows, err := storeq.New(s.db).ApproveDeviceCodeByUserCode(ctx, storeq.ApproveDeviceCodeByUserCodeParams{
		Subject:  sql.NullString{String: subject, Valid: true},
		AuthTime: sql.NullTime{Time: now, Valid: true},
		UserCode: userCode,
	})
	if err != nil {
		return err
	}
	return ensureDeviceCodeApproved(rows)
}

func (s *Storage) DenyDeviceCode(ctx context.Context, userCode string) error {
	rows, err := storeq.New(s.db).DenyDeviceCodeByUserCode(ctx, storeq.DenyDeviceCodeByUserCodeParams{
		UserCode: userCode,
		Now:      s.clock.Now(),
	})
	if err != nil {
		return err
	}
	// No row means the user_code is expired, invalid, or already processed; service maps it to the same user-facing denial failure.
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// Compile-time interface checks
var (
	_ op.Storage                    = (*Storage)(nil)
	_ op.DeviceAuthorizationStorage = (*Storage)(nil)
)

func loadDeviceAuthorizationForUpdate(ctx context.Context, qtx *storeq.Queries, clientID, deviceCode string) (*DeviceCodeModel, error) {
	row, err := qtx.GetDeviceAuthorizationForUpdate(ctx, storeq.GetDeviceAuthorizationForUpdateParams{
		DeviceCode: deviceCode,
		ClientID:   clientID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &DeviceCodeModel{
		ID:        row.ID,
		ClientID:  row.ClientID,
		Scopes:    StringArray(row.Scopes),
		State:     row.State,
		Subject:   nullStringToPtr(row.Subject),
		ExpiresAt: row.ExpiresAt,
		AuthTime:  nullTimePtr(row.AuthTime),
	}, nil
}

func resolveDeviceAuthorizationState(ctx context.Context, tx *sql.Tx, qtx *storeq.Queries, dc *DeviceCodeModel, now time.Time) (*op.DeviceAuthorizationState, error) {
	// Expired
	if now.After(dc.ExpiresAt) {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &op.DeviceAuthorizationState{Expires: dc.ExpiresAt}, nil
	}

	// Denied
	if dc.State == "denied" {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &op.DeviceAuthorizationState{Denied: true, Expires: dc.ExpiresAt}, nil
	}

	// Approved -> atomically transition to consumed
	if dc.State == "approved" {
		if err := qtx.UpdateDeviceCodeStateConsumedByID(ctx, dc.ID); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return toApprovedDeviceAuthorizationState(dc), nil
	}

	// Consumed -> already issued
	if dc.State == "consumed" {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, &oidc.Error{ErrorType: "invalid_grant", Description: "device code already consumed"}
	}

	// Pending
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &op.DeviceAuthorizationState{
		ClientID: dc.ClientID,
		Scopes:   dc.Scopes,
		Expires:  dc.ExpiresAt,
	}, nil
}

func toApprovedDeviceAuthorizationState(dc *DeviceCodeModel) *op.DeviceAuthorizationState {
	subject := ""
	if dc.Subject != nil {
		subject = *dc.Subject
	}

	var authTime time.Time
	if dc.AuthTime != nil {
		authTime = *dc.AuthTime
	}

	return &op.DeviceAuthorizationState{
		ClientID: dc.ClientID,
		Scopes:   dc.Scopes,
		Expires:  dc.ExpiresAt,
		Done:     true,
		Subject:  subject,
		AuthTime: authTime,
	}
}

func ensureDeviceCodeApproved(rows int64) error {
	if rows == 0 {
		return errors.New("device code not found, expired, or already processed")
	}
	return nil
}
