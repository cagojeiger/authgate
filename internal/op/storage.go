package op

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	zop "github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/bcrypt"

	"authgate/internal/storage"
)

var (
	_ zop.Storage                    = &Storage{}
	_ zop.DeviceAuthorizationStorage = &Storage{}
)

type Storage struct {
	db              *storage.DB
	signingKey      *rsa.PrivateKey
	keyID           string
	accessTokenTTL  int
	refreshTokenTTL int
	devMode         bool
}

func NewStorage(db *storage.DB, key *rsa.PrivateKey, accessTokenTTL, refreshTokenTTL int, devMode bool) *Storage {
	return &Storage{db: db, signingKey: key, keyID: "key-1", accessTokenTTL: accessTokenTTL, refreshTokenTTL: refreshTokenTTL, devMode: devMode}
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- AuthStorage ---

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, _ string) (zop.AuthRequest, error) {
	id := uuid.New()
	expiresAt := time.Now().Add(10 * time.Minute)

	challenge := ""
	challengeMethod := "S256"
	if req.CodeChallenge != "" {
		challenge = req.CodeChallenge
		challengeMethod = string(req.CodeChallengeMethod)
	}

	err := s.db.Exec(ctx,
		`INSERT INTO auth_requests (id, client_id, redirect_uri, scopes, state, nonce, code_challenge, code_challenge_method, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, req.ClientID, req.RedirectURI, req.Scopes, req.State, req.Nonce, challenge, challengeMethod, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create auth request: %w", err)
	}

	return &AuthRequest{
		ID:                  id,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scopes:              req.Scopes,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       challenge,
		CodeChallengeMethod: challengeMethod,
		ExpiresAt:           expiresAt,
		CreatedAt:           time.Now(),
	}, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (zop.AuthRequest, error) {
	reqID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid auth request id: %w", err)
	}
	return s.getAuthRequest(ctx, "id", reqID)
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (zop.AuthRequest, error) {
	return s.getAuthRequest(ctx, "code", code)
}

func (s *Storage) getAuthRequest(ctx context.Context, field string, value any) (*AuthRequest, error) {
	allowedFields := map[string]bool{"id": true, "code": true}
	if !allowedFields[field] {
		return nil, fmt.Errorf("invalid query field: %s", field)
	}
	query := fmt.Sprintf(
		`SELECT id, client_id, redirect_uri, scopes, state, nonce, code_challenge, code_challenge_method,
		        subject, auth_time, done, code, expires_at, created_at
		 FROM auth_requests WHERE %s = $1`, field)

	row := s.db.QueryRow(ctx, query, value)
	ar := &AuthRequest{}
	var subject *string
	var authTime *time.Time
	var code *string

	err := row.Scan(&ar.ID, &ar.ClientID, &ar.RedirectURI, &ar.Scopes, &ar.State, &ar.Nonce,
		&ar.CodeChallenge, &ar.CodeChallengeMethod, &subject, &authTime, &ar.Done_, &code, &ar.ExpiresAt, &ar.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get auth request by %s: %w", field, err)
	}

	if subject != nil {
		ar.Subject = *subject
	}
	if authTime != nil {
		ar.AuthTime = *authTime
	}
	if code != nil {
		ar.Code = *code
	}
	return ar, nil
}

func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	return s.db.Exec(ctx, `UPDATE auth_requests SET code = $2 WHERE id = $1`, id, code)
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.db.Exec(ctx, `DELETE FROM auth_requests WHERE id = $1`, id)
}

func (s *Storage) CreateAccessToken(ctx context.Context, req zop.TokenRequest) (string, time.Time, error) {
	return uuid.New().String(), time.Now().Add(time.Duration(s.accessTokenTTL) * time.Second), nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req zop.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	accessTokenID := uuid.New().String()
	newRefreshToken := uuid.New().String()
	newTokenHash := hashToken(newRefreshToken)
	familyID := uuid.New()
	expiration := time.Now().Add(time.Duration(s.accessTokenTTL) * time.Second)
	refreshExpiry := time.Now().Add(time.Duration(s.refreshTokenTTL) * time.Second)

	if currentRefreshToken != "" {
		// Rotation: revoke old token, inherit family_id
		oldHash := hashToken(currentRefreshToken)
		row := s.db.QueryRow(ctx, `SELECT family_id FROM refresh_tokens WHERE token_hash = $1 AND revoked_at IS NULL`, oldHash)
		if err := row.Scan(&familyID); err != nil {
			return "", "", time.Time{}, fmt.Errorf("old refresh token not found: %w", err)
		}
		if err := s.db.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW(), used_at = NOW() WHERE token_hash = $1`, oldHash); err != nil {
			return "", "", time.Time{}, fmt.Errorf("revoke old refresh token: %w", err)
		}
	}

	err := s.db.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, family_id, user_id, session_id, client_id, scopes, expires_at)
		 VALUES ($1, $2, $3, (SELECT id FROM sessions WHERE user_id = $3 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1), $4, $5, $6)`,
		newTokenHash, familyID, req.GetSubject(), req.GetAudience()[0], req.GetScopes(), refreshExpiry,
	)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("create refresh token: %w", err)
	}

	return accessTokenID, newRefreshToken, expiration, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (zop.RefreshTokenRequest, error) {
	tokenHash := hashToken(refreshToken)
	row := s.db.QueryRow(ctx,
		`SELECT rt.user_id, rt.client_id, rt.scopes, rt.created_at
		 FROM refresh_tokens rt
		 WHERE rt.token_hash = $1 AND rt.revoked_at IS NULL AND rt.expires_at > NOW()`,
		tokenHash)

	var userID uuid.UUID
	var clientID string
	var scopes []string
	var createdAt time.Time

	if err := row.Scan(&userID, &clientID, &scopes, &createdAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("invalid refresh token")
		}
		return nil, fmt.Errorf("get refresh token: %w", err)
	}

	return &refreshTokenRequest{
		subject:  userID.String(),
		clientID: clientID,
		scopes:   scopes,
		authTime: createdAt,
	}, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	return s.db.Exec(ctx, `UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *oidc.Error {
	tokenHash := hashToken(tokenOrTokenID)
	err := s.db.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return oidc.ErrServerError()
	}
	return nil
}


func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	tokenHash := hashToken(token)
	row := s.db.QueryRow(ctx,
		`SELECT user_id, id FROM refresh_tokens WHERE token_hash = $1 AND client_id = $2 AND revoked_at IS NULL`,
		tokenHash, clientID)
	var userID uuid.UUID
	var tokenID uuid.UUID
	if err := row.Scan(&userID, &tokenID); err != nil {
		return "", "", fmt.Errorf("get refresh token info: %w", err)
	}
	return userID.String(), tokenID.String(), nil
}

func (s *Storage) SigningKey(ctx context.Context) (zop.SigningKey, error) {
	return &signingKey{id: s.keyID, key: s.signingKey}, nil
}

func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]zop.Key, error) {
	return []zop.Key{&publicKey{id: s.keyID, key: &s.signingKey.PublicKey}}, nil
}

// --- OPStorage ---

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (zop.Client, error) {
	row := s.db.QueryRow(ctx,
		`SELECT client_id, client_secret_hash, client_type, name, redirect_uris, allowed_scopes
		 FROM oauth_clients WHERE client_id = $1`, clientID)

	c := &Client{}
	var secretHash *string
	if err := row.Scan(&c.ID, &secretHash, &c.ClientType, &c.Name, &c.RedirectURIs_, &c.AllowedScopes_); err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}
	if secretHash != nil {
		c.SecretHash = *secretHash
	}
	c.DevMode_ = s.devMode
	return c, nil
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, err := s.GetClientByClientID(ctx, clientID)
	if err != nil {
		return err
	}
	c := client.(*Client)
	if c.ClientType == "public" {
		return nil
	}
	return bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(clientSecret))
}

func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, subject, clientID string, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, subject, scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	return s.setUserinfo(ctx, userinfo, subject, []string{"openid", "profile", "email"})
}

func (s *Storage) setUserinfo(ctx context.Context, userinfo *oidc.UserInfo, subject string, scopes []string) error {
	userID, err := uuid.Parse(subject)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}

	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	userinfo.Subject = subject
	for _, scope := range scopes {
		switch scope {
		case "email":
			userinfo.Email = user.PrimaryEmail
			userinfo.EmailVerified = oidc.Bool(user.EmailVerified)
		case "profile":
			userinfo.Name = user.Name
			userinfo.PreferredUsername = user.Name
			if user.AvatarURL != "" {
				userinfo.Picture = user.AvatarURL
			}
		}
	}
	return nil
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	userinfo := new(oidc.UserInfo)
	if err := s.setUserinfo(ctx, userinfo, subject, []string{"openid", "profile", "email"}); err != nil {
		return err
	}
	introspection.Subject = userinfo.Subject
	introspection.Username = userinfo.PreferredUsername
	return nil
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, errors.New("not supported")
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// --- DeviceAuthorizationStorage ---

func (s *Storage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	return s.db.Exec(ctx,
		`INSERT INTO device_codes (device_code, user_code, client_id, scopes, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		deviceCode, userCode, clientID, scopes, expires)
}

func (s *Storage) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*zop.DeviceAuthorizationState, error) {
	row := s.db.QueryRow(ctx,
		`SELECT client_id, scopes, expires_at, subject, state, auth_time
		 FROM device_codes WHERE device_code = $1 AND client_id = $2`,
		deviceCode, clientID)

	var cID string
	var scopes []string
	var expiresAt time.Time
	var subject *string
	var state string
	var authTime *time.Time

	if err := row.Scan(&cID, &scopes, &expiresAt, &subject, &state, &authTime); err != nil {
		return nil, fmt.Errorf("device code not found: %w", err)
	}

	das := &zop.DeviceAuthorizationState{
		ClientID: cID,
		Scopes:   scopes,
		Expires:  expiresAt,
	}

	switch state {
	case "approved":
		das.Done = true
		if subject != nil {
			das.Subject = *subject
		}
		if authTime != nil {
			das.AuthTime = *authTime
		}
	case "denied":
		das.Denied = true
	}

	return das, nil
}

// --- Health ---

func (s *Storage) Health(ctx context.Context) error {
	return s.db.Ping(ctx)
}

// --- Custom methods (called by login UI, not part of zitadel interfaces) ---

func (s *Storage) CompleteAuthRequest(ctx context.Context, authRequestID, subject string) error {
	return s.db.Exec(ctx,
		`UPDATE auth_requests SET subject = $2, auth_time = NOW(), done = true
		 WHERE id = $1 AND expires_at > NOW()`,
		authRequestID, subject)
}

func (s *Storage) CompleteDeviceAuthorization(ctx context.Context, userCode, subject string) error {
	return s.db.Exec(ctx,
		`UPDATE device_codes SET subject = $2, state = 'approved', auth_time = NOW()
		 WHERE user_code = $1 AND state = 'pending' AND expires_at > NOW()`,
		userCode, subject)
}

func (s *Storage) DenyDeviceAuthorization(ctx context.Context, userCode string) error {
	return s.db.Exec(ctx,
		`UPDATE device_codes SET state = 'denied'
		 WHERE user_code = $1 AND state = 'pending' AND expires_at > NOW()`,
		userCode)
}

// --- RefreshTokenRequest implementation ---

type refreshTokenRequest struct {
	subject  string
	clientID string
	scopes   []string
	authTime time.Time
}

func (r *refreshTokenRequest) GetAMR() []string       { return nil }
func (r *refreshTokenRequest) GetAudience() []string   { return []string{r.clientID} }
func (r *refreshTokenRequest) GetAuthTime() time.Time  { return r.authTime }
func (r *refreshTokenRequest) GetClientID() string     { return r.clientID }
func (r *refreshTokenRequest) GetScopes() []string     { return r.scopes }
func (r *refreshTokenRequest) GetSubject() string      { return r.subject }
func (r *refreshTokenRequest) SetCurrentScopes(scopes []string) { r.scopes = scopes }
