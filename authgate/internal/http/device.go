package http

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"authgate/internal/domain"
	"authgate/internal/pages"
	"authgate/internal/storage"
	"github.com/google/uuid"
)

var (
	deviceCodes    = make(map[string]*DeviceRequest)
	deviceReqMutex sync.RWMutex
)

type DeviceRequest struct {
	DeviceCode   string
	UserCode     string
	ClientID     string
	Scope        string
	UserID       uuid.UUID
	SessionID    uuid.UUID
	Status       string
	ExpiresAt    time.Time
	LastPolledAt time.Time
	PollInterval int
	CreatedAt    time.Time
}

func (s *Server) handleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form")
		return
	}

	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")

	if clientID == "" {
		s.writeJSONError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	if scope == "" {
		scope = "openid profile email"
	}

	deviceCode := domain.GenerateDeviceCode()
	userCode := domain.GenerateUserCode()

	deviceReq := &DeviceRequest{
		DeviceCode:   deviceCode,
		UserCode:     userCode,
		ClientID:     clientID,
		Scope:        scope,
		Status:       "pending",
		ExpiresAt:    time.Now().Add(30 * time.Minute),
		PollInterval: 5,
		CreatedAt:    time.Now(),
	}

	deviceReqMutex.Lock()
	deviceCodes[deviceCode] = deviceReq
	deviceReqMutex.Unlock()

	response := map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          s.config.PublicURL + "/device",
		"verification_uri_complete": s.config.PublicURL + "/device?user_code=" + userCode,
		"expires_in":                1800,
		"interval":                  5,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if userCode == "" {
		s.pages.RenderDeviceEntry(w)
		return
	}

	deviceReqMutex.RLock()
	var deviceReq *DeviceRequest
	for _, dr := range deviceCodes {
		if dr.UserCode == userCode && time.Now().Before(dr.ExpiresAt) {
			deviceReq = dr
			break
		}
	}
	deviceReqMutex.RUnlock()

	if deviceReq == nil {
		s.pages.RenderError(w, pages.ErrorData{Message: "Invalid or expired user code"})
		return
	}

	s.pages.RenderDeviceApproval(w, pages.DeviceApprovalData{UserCode: deviceReq.UserCode})
}

func (s *Server) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.pages.RenderError(w, pages.ErrorData{Message: "Invalid form"})
		return
	}

	userCode := r.FormValue("user_code")
	action := r.FormValue("action")

	deviceReqMutex.Lock()
	defer deviceReqMutex.Unlock()

	var deviceReq *DeviceRequest
	for _, dr := range deviceCodes {
		if dr.UserCode == userCode && time.Now().Before(dr.ExpiresAt) {
			deviceReq = dr
			break
		}
	}

	if deviceReq == nil {
		s.pages.RenderError(w, pages.ErrorData{Message: "Invalid or expired user code"})
		return
	}

	if action != "approve" {
		deviceReq.Status = "denied"
		s.pages.RenderSuccess(w, pages.SuccessData{Title: "Access Denied", Message: "You have denied access to the application."})
		return
	}

	cookie, err := r.Cookie("authgate_session")
	var user *storage.User
	var session *storage.Session

	if err == nil && cookie.Value != "" {
		sessionID, _ := uuid.Parse(cookie.Value)
		if sessionID != uuid.Nil {
			session, _ = s.store.GetSession(r.Context(), sessionID)
			if session != nil {
				user, _ = s.store.GetUserByID(r.Context(), session.UserID)
			}
		}
	}

	if user == nil {
		upstreamState := generateState("device_"+deviceReq.DeviceCode, "", "", "", "", "")
		loginURL := s.upstream.GetAuthorizeURL(upstreamState, "", s.config.PublicURL+"/oauth/callback")

		authReqMutex.Lock()
		authRequests[upstreamState] = &AuthRequest{
			State:     "device_" + deviceReq.DeviceCode,
			CreatedAt: time.Now(),
		}
		authReqMutex.Unlock()

		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	deviceReq.UserID = user.ID
	deviceReq.SessionID = session.ID
	deviceReq.Status = "approved"

	s.pages.RenderSuccess(w, pages.SuccessData{Title: "Access Approved", Message: "You have successfully authorized the CLI application. You can close this window."})
}
