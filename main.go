package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	
	"github.com/setya-rgb/authtoken"
)

var tokenManager *authtoken.Manager

type LoginRequest struct {
	Username string   `json:"username"`
	Scopes   []string `json:"scopes"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func main() {
	// Initialize token manager
	var err error
	tokenManager, err = authtoken.NewManager(authtoken.Config{
		SecretKey:     "your-secret-key-change-in-production",
		TokenDuration: 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create token manager:", err)
	}

	// Setup routes
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/protected", authMiddleware(protectedHandler))
	http.HandleFunc("/admin", authMiddleware(adminHandler))

	// Start server
	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Generate token
	token, err := tokenManager.Generate(req.Username, req.Scopes)
	if err != nil {
		sendError(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	sendJSON(w, LoginResponse{Token: token}, http.StatusOK)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Context().Value("token").(*authtoken.Token)
	
	response := map[string]interface{}{
		"message":  "Access granted to protected endpoint",
		"user_id":  token.UserID,
		"scopes":   token.Scopes,
		"time":     time.Now().Format(time.RFC1123),
	}
	
	sendJSON(w, response, http.StatusOK)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Context().Value("token").(*authtoken.Token)
	
	// Check for admin scope
	if !token.HasScope("admin") {
		sendError(w, "Admin scope required", http.StatusForbidden)
		return
	}
	
	response := map[string]interface{}{
		"message": "Welcome to admin panel",
		"user_id": token.UserID,
		"level":   "administrator",
	}
	
	sendJSON(w, response, http.StatusOK)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendError(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		// Check Bearer prefix
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			sendError(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]
		
		// Validate token
		token, err := tokenManager.Validate(tokenString)
		if err != nil {
			sendError(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Store token in context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "token", token)
		
		// Call next handler
		next(w, r.WithContext(ctx))
	}
}

func sendJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func sendError(w http.ResponseWriter, message string, status int) {
	sendJSON(w, ErrorResponse{Error: message}, status)
}
