package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"authgate/internal/storage"
	"authgate/internal/upstream"
)

// --- Stubs ---

type stubUserStore struct {
	user    *storage.User
	session *storage.Session
	findErr error
	terms   bool
	events  []string
}

func (s *stubUserStore) GetUserByProviderIdentity(_ context.Context, _, _ string) (*storage.User, error) {
	if s.findErr != nil {
		return nil, s.findErr
	}
	return s.user, nil
}
func (s *stubUserStore) CreateUserWithIdentity(_ context.Context, email, name, avatar string, verified bool, _, _, _ string) (*storage.User, error) {
	s.user = &storage.User{ID: uuid.New(), PrimaryEmail: email, Name: name, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	return s.user, nil
}
func (s *stubUserStore) GetUserByID(_ context.Context, _ uuid.UUID) (*storage.User, error) {
	return s.user, nil
}
func (s *stubUserStore) GetSession(_ context.Context, _ uuid.UUID) (*storage.Session, error) {
	return s.session, nil
}
func (s *stubUserStore) CreateSession(_ context.Context, userID uuid.UUID, _ int) (*storage.Session, error) {
	s.session = &storage.Session{ID: uuid.New(), UserID: userID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	return s.session, nil
}
func (s *stubUserStore) HasAcceptedTerms(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	return s.terms, nil
}
func (s *stubUserStore) AcceptTerms(_ context.Context, _ uuid.UUID, _, _ string) error {
	s.terms = true
	return nil
}
func (s *stubUserStore) RequestDeletion(_ context.Context, _ uuid.UUID) error { return nil }
func (s *stubUserStore) CancelDeletion(_ context.Context, _ uuid.UUID) error  { return nil }
func (s *stubUserStore) LogEvent(_ context.Context, _ *uuid.UUID, event, _, _ string, _ map[string]any) {
	s.events = append(s.events, event)
}

type stubAuthCompleter struct {
	completed bool
}

func (s *stubAuthCompleter) CompleteAuthRequest(_ context.Context, _, _ string) error {
	s.completed = true
	return nil
}
func (s *stubAuthCompleter) CompleteDeviceAuthorization(_ context.Context, _, _ string) error {
	return nil
}
func (s *stubAuthCompleter) DenyDeviceAuthorization(_ context.Context, _ string) error { return nil }

type stubUpstream struct{}

func (s stubUpstream) AuthURL(state string) string { return "/mock-login?state=" + state }
func (s stubUpstream) Exchange(_ context.Context, _ string) (*upstream.UserInfo, error) {
	return &upstream.UserInfo{
		ProviderUserID: "google-123",
		Email:          "test@example.com",
		EmailVerified:  true,
		Name:           "Test User",
	}, nil
}

// --- Tests ---

func TestHandleLogin_NoSession_RedirectsToUpstream(t *testing.T) {
	h := &Handler{
		users:    &stubUserStore{},
		upstream: stubUpstream{},
	}

	r := httptest.NewRequest("GET", "/?authRequestID=req-1", nil)
	w := httptest.NewRecorder()
	h.handleLogin(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusFound)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "mock-login") {
		t.Errorf("Location = %q, want upstream redirect", loc)
	}
}

func TestHandleLogin_WithSession_SkipsUpstream(t *testing.T) {
	user := &storage.User{ID: uuid.New(), Status: "active"}
	session := &storage.Session{ID: uuid.New(), UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}
	auth := &stubAuthCompleter{}

	h := &Handler{
		users:        &stubUserStore{user: user, session: session, terms: true},
		auth:         auth,
		callbackURL:  func(_ context.Context, id string) string { return "/callback?id=" + id },
		termsVersion: "v1",
	}

	r := httptest.NewRequest("GET", "/?authRequestID=req-1", nil)
	r.AddCookie(&http.Cookie{Name: "authgate_session", Value: session.ID.String()})
	w := httptest.NewRecorder()
	h.handleLogin(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want redirect", w.Code)
	}
	if !auth.completed {
		t.Error("auth request should be completed (auto-approve)")
	}
}

func TestHandleCallback_NewUser_SignupAndApprove(t *testing.T) {
	users := &stubUserStore{findErr: storage.ErrNotFound, terms: true}
	auth := &stubAuthCompleter{}

	h := &Handler{
		users:        users,
		auth:         auth,
		upstream:     stubUpstream{},
		callbackURL:  func(_ context.Context, id string) string { return "/callback?id=" + id },
		provider:     "google",
		sessionTTL:   3600,
		termsVersion: "v1",
		devMode:      true,
	}

	r := httptest.NewRequest("GET", "/callback?code=abc&state=req-1", nil)
	w := httptest.NewRecorder()
	h.handleCallback(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want redirect", w.Code)
	}
	if !auth.completed {
		t.Error("auth request should be completed after signup")
	}
	if users.user == nil {
		t.Error("user should be created")
	}
	if !contains(users.events, "signup") {
		t.Errorf("events = %v, want 'signup'", users.events)
	}
}

func TestHandleCallback_ExistingUser_LoginAndApprove(t *testing.T) {
	user := &storage.User{ID: uuid.New(), Status: "active"}
	users := &stubUserStore{user: user, terms: true}
	auth := &stubAuthCompleter{}

	h := &Handler{
		users:        users,
		auth:         auth,
		upstream:     stubUpstream{},
		callbackURL:  func(_ context.Context, id string) string { return "/callback?id=" + id },
		provider:     "google",
		sessionTTL:   3600,
		termsVersion: "v1",
		devMode:      true,
	}

	r := httptest.NewRequest("GET", "/callback?code=abc&state=req-1", nil)
	w := httptest.NewRecorder()
	h.handleCallback(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want redirect", w.Code)
	}
	if !contains(users.events, "login") {
		t.Errorf("events = %v, want 'login'", users.events)
	}
}

func TestHandleCallback_InactiveUser_Forbidden(t *testing.T) {
	user := &storage.User{ID: uuid.New(), Status: "disabled"}
	users := &stubUserStore{user: user}

	h := &Handler{
		users:      users,
		upstream:   stubUpstream{},
		provider:   "google",
		sessionTTL: 3600,
		devMode:    true,
	}

	r := httptest.NewRequest("GET", "/callback?code=abc&state=req-1", nil)
	w := httptest.NewRecorder()
	h.handleCallback(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestHandleCallback_DBError_Returns500(t *testing.T) {
	users := &stubUserStore{findErr: storage.ErrNotFound}
	// CreateUserWithIdentity will succeed, but we override findErr to simulate a non-ErrNotFound error
	users.findErr = context.DeadlineExceeded

	h := &Handler{
		users:    users,
		upstream: stubUpstream{},
		provider: "google",
	}

	r := httptest.NewRequest("GET", "/callback?code=abc&state=req-1", nil)
	w := httptest.NewRecorder()
	h.handleCallback(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleTermsAccept_Happy(t *testing.T) {
	user := &storage.User{ID: uuid.New(), Status: "active"}
	session := &storage.Session{ID: uuid.New(), UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}
	users := &stubUserStore{user: user, session: session}
	auth := &stubAuthCompleter{}

	h := &Handler{
		users:          users,
		auth:           auth,
		callbackURL:    func(_ context.Context, id string) string { return "/callback?id=" + id },
		termsVersion:   "v1",
		privacyVersion: "v1",
	}

	form := url.Values{"authRequestID": {"req-1"}, "age_confirm": {"on"}}
	r := httptest.NewRequest("POST", "/terms", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "authgate_session", Value: session.ID.String()})
	w := httptest.NewRecorder()
	h.handleTermsAccept(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want redirect", w.Code)
	}
	if !users.terms {
		t.Error("terms should be accepted")
	}
	if !auth.completed {
		t.Error("auth should be completed after terms")
	}
}

func TestHandleTermsAccept_MissingAge_BadRequest(t *testing.T) {
	h := &Handler{}

	form := url.Values{"authRequestID": {"req-1"}}
	r := httptest.NewRequest("POST", "/terms", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.handleTermsAccept(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
