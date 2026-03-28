package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	authgateURL       = getEnv("AUTHGATE_URL", "http://localhost:8080")
	authgatePublicURL = getEnv("AUTHGATE_PUBLIC_URL", "http://localhost:8080")
	clientID          = getEnv("CLIENT_ID", "service-a-web")
	clientSecret      = getEnv("CLIENT_SECRET", "dev-secret")
	baseURL           = getEnv("BASE_URL", "http://localhost:8081")

	store = sessions.NewCookieStore([]byte(getEnv("SESSION_SECRET", "service-a-secret")))
)

type Server struct {
	router    *mux.Router
	templates *template.Template
}

func main() {
	server := NewServer()
	httpServer := &http.Server{
		Addr:    ":8081",
		Handler: server,
	}

	fmt.Println("Service A starting on :8081")
	fmt.Printf("Authgate URL: %s\n", authgateURL)

	if err := httpServer.ListenAndServe(); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

func NewServer() *Server {
	s := &Server{
		router: mux.NewRouter(),
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.router.HandleFunc("/", s.handleHome).Methods("GET")
	s.router.HandleFunc("/login", s.handleLogin).Methods("GET")
	s.router.HandleFunc("/auth/callback", s.handleCallback).Methods("GET")
	s.router.HandleFunc("/protected", s.handleProtected).Methods("GET")
	s.router.HandleFunc("/logout", s.handleLogout).Methods("GET")
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "service-a-session")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Service A</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
.header { background: #0066cc; color: white; padding: 20px; border-radius: 5px; }
.content { margin-top: 20px; }
.button { 
  display: inline-block; 
  padding: 10px 20px; 
  background: #0066cc; 
  color: white; 
  text-decoration: none; 
  border-radius: 5px;
  margin: 5px;
}
.button:hover { background: #0055aa; }
</style>
</head>
<body>
<div class="header">
<h1>Service A</h1>
<p>A demo service protected by authgate</p>
</div>
<div class="content">
%s
</div>
</body>
</html>`, s.getHomeContent(session))
}

func (s *Server) getHomeContent(session *sessions.Session) string {
	if session.Values["user_id"] != nil {
		return fmt.Sprintf(`
<p>Welcome back! You are signed in.</p>
<p><a href="/protected" class="button">View Protected Content</a></p>
<p><a href="/logout" class="button">Sign Out</a></p>
`)
	}
	return `
<p>You are not signed in.</p>
<p><a href="/login" class="button">Sign In with authgate</a></p>
`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	codeChallenge := generateCodeChallenge()

	session, _ := store.Get(r, "service-a-session")
	session.Values["oauth_state"] = state
	session.Values["code_verifier"] = codeChallenge.verifier
	session.Save(r, w)

	authorizeURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&state=%s&code_challenge=%s&code_challenge_method=S256",
		authgatePublicURL,
		clientID,
		url.QueryEscape(baseURL+"/auth/callback"),
		state,
		codeChallenge.challenge,
	)

	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	errorCode := q.Get("error")

	session, _ := store.Get(r, "service-a-session")

	if errorCode != "" {
		http.Error(w, "Auth error: "+errorCode, http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	if state != session.Values["oauth_state"] {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	codeVerifier := session.Values["code_verifier"].(string)

	tokenResp, err := exchangeCode(code, codeVerifier)
	if err != nil {
		http.Error(w, "Token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["user_id"] = tokenResp.UserID
	session.Values["email"] = tokenResp.Email
	session.Values["name"] = tokenResp.Name
	session.Values["access_token"] = tokenResp.AccessToken
	session.Save(r, w)

	http.Redirect(w, r, "/protected", http.StatusFound)
}

func (s *Server) handleProtected(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "service-a-session")

	if session.Values["user_id"] == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Protected Content - Service A</title>
<style>
body { font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
.header { background: #28a745; color: white; padding: 20px; border-radius: 5px; }
.card { 
  border: 1px solid #ddd; 
  padding: 20px; 
  margin: 20px 0; 
  border-radius: 5px;
  background: #f8f9fa;
}
.card h3 { margin-top: 0; }
.button { 
  display: inline-block; 
  padding: 10px 20px; 
  background: #6c757d; 
  color: white; 
  text-decoration: none; 
  border-radius: 5px;
}
</style>
</head>
<body>
<div class="header">
<h1>Protected Content</h1>
<p>This page requires authentication via authgate</p>
</div>

<div class="card">
<h3>Identity from authgate</h3>
<p><strong>User ID:</strong> %s</p>
<p><strong>Email:</strong> %s</p>
<p><strong>Name:</strong> %s</p>
</div>

<div class="card" style="border-left: 4px solid #ffc107;">
<h3>🎭 Service-A Local State (DEMO DATA)</h3>
<p style="color: #856404; background: #fff3cd; padding: 10px; border-radius: 4px; margin-bottom: 15px;">
<strong>⚠️ Demo Only:</strong> This section shows hardcoded demo data to illustrate that Service A 
manages its own state independently of authgate. In production, this would come from Service A's database.
</p>
<p><strong>Membership Status:</strong> <span style="color: #28a745;">Active</span> ✓</p>
<p><strong>Service Terms:</strong> <span style="color: #28a745;">Accepted</span> ✓</p>
<p><strong>Role:</strong> User</p>
<p style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #ddd; font-size: 13px; color: #666;">
<strong>Key Point:</strong> authgate provides identity (who you are).<br>
Service A decides authorization (what you can do here).
</p>
</div>

<p><a href="/" class="button">Back to Home</a></p>
</body>
</html>`,
		session.Values["user_id"],
		session.Values["email"],
		session.Values["name"],
	)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "service-a-session")
	session.Options.MaxAge = -1
	session.Save(r, w)

	logoutURL := fmt.Sprintf("%s/oauth/logout?post_logout_redirect_uri=%s",
		authgatePublicURL,
		url.QueryEscape(baseURL+"/"),
	)

	http.Redirect(w, r, logoutURL, http.StatusFound)
}

type TokenResponse struct {
	AccessToken string
	UserID      string
	Email       string
	Name        string
}

func exchangeCode(code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", baseURL+"/auth/callback")
	data.Set("code_verifier", codeVerifier)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	resp, err := http.PostForm(authgateURL+"/oauth/token", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Parse ID token to get user info (in real app, validate signature)
	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(result.IDToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims := token.Claims.(jwt.MapClaims)

	return &TokenResponse{
		AccessToken: result.AccessToken,
		UserID:      claims["sub"].(string),
		Email:       claims["email"].(string),
		Name:        claims["name"].(string),
	}, nil
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

type PKCE struct {
	verifier  string
	challenge string
}

func generateCodeChallenge() PKCE {
	verifierBytes := make([]byte, 32)
	rand.Read(verifierBytes)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return PKCE{verifier: verifier, challenge: challenge}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
