package login

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"authgate/internal/storage"
	"authgate/internal/upstream"
)

// UserStore is the interface that handlers need from the data layer.
// Defined here (consumer), not in storage (producer).
type UserStore interface {
	GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	CreateUserWithIdentity(ctx context.Context, email, name, avatar string, verified bool, provider, providerUID, providerEmail string) (*storage.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error)
	GetSession(ctx context.Context, id uuid.UUID) (*storage.Session, error)
	CreateSession(ctx context.Context, userID uuid.UUID, ttl int) (*storage.Session, error)
	HasAcceptedTerms(ctx context.Context, userID uuid.UUID, version string) (bool, error)
	AcceptTerms(ctx context.Context, userID uuid.UUID, terms, privacy string) error
	RequestDeletion(ctx context.Context, userID uuid.UUID) error
	CancelDeletion(ctx context.Context, userID uuid.UUID) error
	LogEvent(ctx context.Context, userID *uuid.UUID, event, ip, ua string, meta map[string]any)
}

// AuthCompleter is the interface for completing auth/device flows.
type AuthCompleter interface {
	CompleteAuthRequest(ctx context.Context, id, subject string) error
	CompleteDeviceAuthorization(ctx context.Context, userCode, subject string) error
	DenyDeviceAuthorization(ctx context.Context, userCode string) error
}

type Handler struct {
	users          UserStore
	auth           AuthCompleter
	upstream       upstream.Provider
	callbackURL    func(context.Context, string) string
	templates      *template.Template
	provider       string
	sessionTTL     int
	termsVersion   string
	privacyVersion string
	devMode        bool
}

func NewHandler(users UserStore, auth AuthCompleter, up upstream.Provider, callbackURL func(context.Context, string) string, provider string, sessionTTL int, termsVersion, privacyVersion string, devMode bool) http.Handler {
	h := &Handler{
		users:          users,
		auth:           auth,
		upstream:       up,
		callbackURL:    callbackURL,
		provider:       provider,
		sessionTTL:     sessionTTL,
		termsVersion:   termsVersion,
		privacyVersion: privacyVersion,
		devMode:        devMode,
	}
	h.templates = template.Must(template.ParseGlob("internal/login/templates/*.html"))

	r := chi.NewRouter()
	r.Get("/", h.handleLogin)
	r.Get("/callback", h.handleCallback)
	r.Post("/terms", h.handleTermsAccept)
	return r
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	authRequestID := r.URL.Query().Get("authRequestID")
	if authRequestID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Missing authRequestID")
		return
	}

	session, user, err := getSessionUser(h.users, r)
	if err != nil {
		slog.Error("auth.db_error", "err", err, "request_id", RequestID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	if session != nil && user != nil && user.IsActive() {
		slog.Info("auth.login", "event", "session_reuse", "user_id", user.ID, "request_id", RequestID(r.Context()))
		h.approveOrTerms(w, r, authRequestID, user)
		return
	}

	http.Redirect(w, r, h.upstream.AuthURL(authRequestID), http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	authRequestID := r.URL.Query().Get("state")

	if code == "" || authRequestID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Missing code or state")
		return
	}

	userInfo, err := h.upstream.Exchange(r.Context(), code)
	if err != nil {
		slog.Error("auth.upstream_error", "err", err, "request_id", RequestID(r.Context()))
		writeError(w, http.StatusInternalServerError, "upstream_error", "Login provider is unavailable")
		return
	}

	ctx := r.Context()

	user, err := h.users.GetUserByProviderIdentity(ctx, h.provider, userInfo.ProviderUserID)
	if errors.Is(err, storage.ErrNotFound) {
		user, err = h.users.CreateUserWithIdentity(ctx, userInfo.Email, userInfo.Name, userInfo.Picture, userInfo.EmailVerified, h.provider, userInfo.ProviderUserID, userInfo.Email)
		if err != nil {
			slog.Error("auth.signup_failed", "err", err, "request_id", RequestID(r.Context()))
			writeError(w, http.StatusInternalServerError, "internal_error", "Failed to create account")
			return
		}
		slog.Info("auth.signup", "user_id", user.ID, "ip", r.RemoteAddr, "request_id", RequestID(r.Context()))
		h.users.LogEvent(ctx, &user.ID, "signup", r.RemoteAddr, r.UserAgent(), nil)
	} else if err != nil {
		slog.Error("auth.db_error", "err", err, "request_id", RequestID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	} else {
		slog.Info("auth.login", "user_id", user.ID, "ip", r.RemoteAddr, "request_id", RequestID(r.Context()))
		h.users.LogEvent(ctx, &user.ID, "login", r.RemoteAddr, r.UserAgent(), nil)
	}

	if user.Status == "pending_deletion" {
		if err := h.users.CancelDeletion(ctx, user.ID); err != nil {
			slog.Error("auth.db_error", "err", err, "action", "cancel_deletion", "user_id", user.ID, "request_id", RequestID(r.Context()))
			writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
			return
		}
		user.Status = "active"
		slog.Info("auth.deletion_cancelled", "user_id", user.ID, "request_id", RequestID(r.Context()))
		h.users.LogEvent(ctx, &user.ID, "deletion_cancelled_by_login", r.RemoteAddr, r.UserAgent(), nil)
	}
	if !user.IsActive() {
		slog.Warn("auth.inactive_user", "user_id", user.ID, "status", user.Status, "request_id", RequestID(r.Context()))
		writeError(w, http.StatusForbidden, "account_inactive", "Account is not active")
		return
	}

	session, err := h.users.CreateSession(ctx, user.ID, h.sessionTTL)
	if err != nil {
		slog.Error("auth.session_failed", "err", err, "user_id", user.ID, "request_id", RequestID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "authgate_session",
		Value:    session.ID.String(),
		Path:     "/",
		HttpOnly: true,
		Secure:   !h.devMode,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.sessionTTL,
	})

	h.approveOrTerms(w, r, authRequestID, user)
}

func (h *Handler) approveOrTerms(w http.ResponseWriter, r *http.Request, authRequestID string, user *storage.User) {
	accepted, err := h.users.HasAcceptedTerms(r.Context(), user.ID, h.termsVersion)
	if err != nil {
		slog.Error("auth.db_error", "err", err, "action", "check_terms", "user_id", user.ID, "request_id", RequestID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	if !accepted {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		h.templates.ExecuteTemplate(w, "terms.html", map[string]string{
			"AuthRequestID":  authRequestID,
			"TermsVersion":   h.termsVersion,
			"PrivacyVersion": h.privacyVersion,
		})
		return
	}
	h.autoApprove(w, r, authRequestID, user.ID.String())
}

func (h *Handler) handleTermsAccept(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	authRequestID := r.FormValue("authRequestID")
	ageConfirm := r.FormValue("age_confirm")

	if authRequestID == "" || ageConfirm != "on" {
		writeError(w, http.StatusBadRequest, "invalid_request", "Must confirm age requirement")
		return
	}

	session, user, err := getSessionUser(h.users, r)
	if err != nil {
		slog.Error("auth.db_error", "err", err, "request_id", RequestID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	if session == nil || user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Login required")
		return
	}

	if err := h.users.AcceptTerms(r.Context(), user.ID, h.termsVersion, h.privacyVersion); err != nil {
		slog.Error("auth.db_error", "err", err, "action", "accept_terms", "user_id", user.ID, "request_id", RequestID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}

	slog.Info("auth.terms_accepted", "user_id", user.ID, "terms_version", h.termsVersion, "request_id", RequestID(r.Context()))
	h.users.LogEvent(r.Context(), &user.ID, "terms_accepted", r.RemoteAddr, r.UserAgent(), map[string]any{
		"terms_version":   h.termsVersion,
		"privacy_version": h.privacyVersion,
	})

	h.autoApprove(w, r, authRequestID, user.ID.String())
}

func (h *Handler) autoApprove(w http.ResponseWriter, r *http.Request, authRequestID, subject string) {
	if err := h.auth.CompleteAuthRequest(r.Context(), authRequestID, subject); err != nil {
		slog.Error("auth.db_error", "err", err, "action", "complete_auth_request", "request_id", RequestID(r.Context()))
		writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	http.Redirect(w, r, h.callbackURL(r.Context(), authRequestID), http.StatusFound)
}

// --- Account Handler ---

func NewAccountHandler(users UserStore) http.Handler {
	r := chi.NewRouter()

	r.Delete("/", func(w http.ResponseWriter, r *http.Request) {
		session, _, err := getSessionUser(users, r)
		if err != nil {
			slog.Error("auth.db_error", "err", err, "request_id", RequestID(r.Context()))
			writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
			return
		}
		if session == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Login required")
			return
		}

		if err := users.RequestDeletion(r.Context(), session.UserID); err != nil {
			slog.Error("auth.db_error", "err", err, "action", "request_deletion", "user_id", session.UserID, "request_id", RequestID(r.Context()))
			writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
			return
		}

		slog.Info("auth.deletion_requested", "user_id", session.UserID, "request_id", RequestID(r.Context()))
		users.LogEvent(r.Context(), &session.UserID, "deletion_requested", r.RemoteAddr, r.UserAgent(), nil)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "pending_deletion",
			"message": "Account will be deleted in 30 days. Login again to cancel.",
		})
	})

	return r
}

// --- Device Handler ---

func NewDeviceHandler(auth AuthCompleter, users UserStore, tmpl *template.Template) http.Handler {
	r := chi.NewRouter()

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		userCode := r.URL.Query().Get("user_code")
		if userCode == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tmpl.ExecuteTemplate(w, "device_entry.html", nil)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.ExecuteTemplate(w, "device_approve.html", map[string]string{"UserCode": userCode})
	})

	r.Post("/approve", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		userCode := r.FormValue("user_code")
		action := r.FormValue("action")

		if userCode == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "Missing user_code")
			return
		}

		session, _, err := getSessionUser(users, r)
		if err != nil {
			slog.Error("auth.db_error", "err", err, "request_id", RequestID(r.Context()))
			writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
			return
		}
		if session == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Login required")
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if action == "approve" {
			if err := auth.CompleteDeviceAuthorization(r.Context(), userCode, session.UserID.String()); err != nil {
				slog.Error("auth.db_error", "err", err, "action", "device_approve", "request_id", RequestID(r.Context()))
				writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")
				return
			}
			slog.Info("auth.device_approved", "user_id", session.UserID, "request_id", RequestID(r.Context()))
			users.LogEvent(r.Context(), &session.UserID, "device_approved", r.RemoteAddr, r.UserAgent(), nil)
			tmpl.ExecuteTemplate(w, "success.html", map[string]string{
				"Title":   "Access Approved",
				"Message": "You have successfully authorized the CLI application. You can close this window.",
			})
		} else {
			if err := auth.DenyDeviceAuthorization(r.Context(), userCode); err != nil {
				slog.Warn("auth.device_deny_failed", "err", err, "request_id", RequestID(r.Context()))
			}
			tmpl.ExecuteTemplate(w, "success.html", map[string]string{
				"Title":   "Access Denied",
				"Message": "You have denied access to the application.",
			})
		}
	})

	return r
}
