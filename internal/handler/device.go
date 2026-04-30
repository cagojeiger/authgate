package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/pages"
	"github.com/kangheeyong/authgate/internal/service"
)

type DeviceHandler struct {
	deviceService *service.DeviceService
	devMode       bool
	brandName     string
}

func NewDeviceHandler(deviceService *service.DeviceService, devMode bool, brandName string) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
		devMode:       devMode,
		brandName:     brandName,
	}
}

// HandleDevicePage handles GET /device and GET /device?user_code=XXXX
func (h *DeviceHandler) HandleDevicePage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	sessionID := getSessionCookie(r)

	result := h.deviceService.HandleDevicePage(r.Context(), userCode, sessionID)

	switch result.Action {
	case service.DeviceShowEntry:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pages.RenderDeviceEntry(w, pages.DeviceEntryData{
			BrandName: h.brandName,
			UserCode:  userCode,
			Error:     result.Error,
		})

	case service.DeviceShowApprove:
		csrfToken := generateCSRFToken()
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    csrfToken,
			Path:     "/device",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   !h.devMode,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		pages.RenderDeviceApprove(w, pages.DeviceApproveData{
			BrandName: h.brandName,
			UserCode:  result.UserCode,
			CSRFToken: csrfToken,
		})

	case service.DeviceRedirectIdP:
		http.Redirect(w, r, result.UserCode, http.StatusFound) // UserCode holds the auth URL

	case service.DeviceError:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(result.ErrorCode)
		pages.RenderError(w, pages.ErrorData{BrandName: h.brandName, Code: result.ErrorCode, Message: result.Error})
	}
}

// HandleDeviceCallback handles GET /device/auth/callback?code=xxx&state=user_code
func (h *DeviceHandler) HandleDeviceCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	userCode := r.URL.Query().Get("state")
	info := clientinfo.FromContext(r.Context())

	result := h.deviceService.HandleDeviceCallback(r.Context(), code, userCode, info.IP, info.UserAgent)

	switch result.Action {
	case service.DeviceRedirectBack:
		if result.SessionID != "" {
			setSessionCookie(w, result.SessionID, h.devMode)
		}
		http.Redirect(w, r, "/device?user_code="+result.UserCode, http.StatusFound)

	case service.DeviceError:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(result.ErrorCode)
		pages.RenderError(w, pages.ErrorData{BrandName: h.brandName, Code: result.ErrorCode, Message: result.Error})
	}
}

// HandleDeviceApprove handles POST /device/approve
func (h *DeviceHandler) HandleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		pages.RenderError(w, pages.ErrorData{BrandName: h.brandName, Code: 400, Message: "invalid form"})
		return
	}

	// CSRF check
	formToken := r.FormValue("csrf_token")
	cookieToken := ""
	if c, err := r.Cookie("csrf_token"); err == nil {
		cookieToken = c.Value
	}
	if formToken == "" || formToken != cookieToken {
		w.WriteHeader(http.StatusForbidden)
		pages.RenderError(w, pages.ErrorData{BrandName: h.brandName, Code: 403, Message: "CSRF validation failed"})
		return
	}

	userCode := r.FormValue("user_code")
	action := r.FormValue("action")
	sessionID := getSessionCookie(r)
	info := clientinfo.FromContext(r.Context())

	result := h.deviceService.HandleDeviceApprove(r.Context(), userCode, action, sessionID, info.IP, info.UserAgent)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !result.Success && result.ErrorCode != 0 {
		w.WriteHeader(result.ErrorCode)
	}
	pages.RenderResult(w, pages.ResultData{
		BrandName: h.brandName,
		Success:   result.Success,
		Message:   result.Message,
	})
}

func generateCSRFToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
