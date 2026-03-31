package main

import (
	"encoding/json"
	"net/http"
	"time"
)

func HandleMe(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Use session data for email/name (fetched from /userinfo at login)
	email := claims.Email
	name := claims.Name
	if sess := GetSession(r.Context()); sess != nil {
		if sess.Email != "" {
			email = sess.Email
		}
		if sess.Name != "" {
			name = sess.Name
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sub":   claims.Sub,
		"email": email,
		"name":  name,
	})
}

func HandleData(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r.Context())
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"message":   "Hello from sample-app!",
		"timestamp": time.Now().Format(time.RFC3339),
		"user":      claims.Sub,
		"items": []map[string]any{
			{"id": 1, "title": "First item", "status": "active"},
			{"id": 2, "title": "Second item", "status": "pending"},
			{"id": 3, "title": "Third item", "status": "completed"},
		},
	})
}
