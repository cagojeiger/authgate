package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
)

type Server struct {
	router *mux.Router
	codes  map[string]CodeData
}

type CodeData struct {
	State       string
	RedirectURI string
	UserID      string
	Expiry      time.Time
}

func NewServer() *Server {
	s := &Server{
		router: mux.NewRouter(),
		codes:  make(map[string]CodeData),
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.router.HandleFunc("/authorize", s.handleAuthorize).Methods("GET")
	s.router.HandleFunc("/login", s.handleLoginPage).Methods("GET")
	s.router.HandleFunc("/login", s.handleLoginSubmit).Methods("POST")
	s.router.HandleFunc("/token", s.handleToken).Methods("POST")
	s.router.HandleFunc("/userinfo", s.handleUserInfo).Methods("GET")
	s.router.HandleFunc("/.well-known/jwks.json", s.handleJWKS).Methods("GET")
	s.router.HandleFunc("/", s.handleHome).Methods("GET")
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Mock IDP</title></head>
<body>
<h1>Mock Identity Provider</h1>
<p>This is a development-only mock OAuth provider.</p>
</body>
</html>`)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	if state == "" || redirectURI == "" {
		http.Error(w, "Missing state or redirect_uri", http.StatusBadRequest)
		return
	}

	// Redirect to login page
	loginURL := fmt.Sprintf("/login?state=%s&redirect_uri=%s", url.QueryEscape(state), url.QueryEscape(redirectURI))
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<title>Mock Login</title>
<style>
body { font-family: sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
form { display: flex; flex-direction: column; gap: 10px; }
input, button { padding: 10px; font-size: 16px; }
button { background: #0066cc; color: white; border: none; cursor: pointer; }
button:hover { background: #0055aa; }
.user-option { 
  border: 1px solid #ddd; 
  padding: 15px; 
  margin: 10px 0; 
  cursor: pointer;
  border-radius: 5px;
}
.user-option:hover { background: #f5f5f5; }
</style>
</head>
<body>
<h1>Mock Login</h1>
<p>Choose a test user:</p>
<form method="POST" action="/login">
<input type="hidden" name="state" value="%s">
<input type="hidden" name="redirect_uri" value="%s">

<div class="user-option" onclick="selectUser('alice', 'alice@example.com', 'Alice')">
<input type="radio" name="user_id" value="alice" id="alice" checked>
<label for="alice"><strong>Alice</strong> (alice@example.com)</label>
</div>

<div class="user-option" onclick="selectUser('bob', 'bob@example.com', 'Bob')">
<input type="radio" name="user_id" value="bob" id="bob">
<label for="bob"><strong>Bob</strong> (bob@example.com)</label>
</div>

<button type="submit">Sign In</button>
</form>

<script>
function selectUser(id, email, name) {
  document.getElementById(id).checked = true;
}
</script>
</body>
</html>`, r.URL.Query().Get("state"), r.URL.Query().Get("redirect_uri"))
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	state := r.FormValue("state")
	redirectURI := r.FormValue("redirect_uri")
	userID := r.FormValue("user_id")

	code := generateCode()
	s.codes[code] = CodeData{
		State:       state,
		RedirectURI: redirectURI,
		UserID:      userID,
		Expiry:      time.Now().Add(5 * time.Minute),
	}

	redirectURL, _ := url.Parse(redirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	code := r.FormValue("code")

	data, ok := s.codes[code]
	if !ok || time.Now().After(data.Expiry) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}

	delete(s.codes, code)

	user := getUserInfo(data.UserID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": generateCode(),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"user_info":    user,
	})
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getUserInfo("alice"))
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []map[string]interface{}{},
	})
}

func generateCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func getUserInfo(userID string) map[string]interface{} {
	if userID == "bob" {
		return map[string]interface{}{
			"sub":            "user_bob_123",
			"email":          "bob@example.com",
			"email_verified": true,
			"name":           "Bob",
			"picture":        "",
		}
	}
	return map[string]interface{}{
		"sub":            "user_alice_123",
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice",
		"picture":        "",
	}
}

func main() {
	server := NewServer()
	httpServer := &http.Server{
		Addr:    ":8082",
		Handler: server,
	}

	fmt.Println("Mock IDP server starting on :8082")
	if err := httpServer.ListenAndServe(); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
