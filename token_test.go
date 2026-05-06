package authtoken

import (
    "testing"
    "time"
)

func TestManager(t *testing.T) {
    // Initialize token manager
    m, err := NewManager(Config{
        SecretKey:     "test-secret-key-12345",
        TokenDuration: 1 * time.Hour,
    })
    
    if err != nil {
        t.Fatalf("Failed to create manager: %v", err)
    }
    
    // Generate token
    token, err := m.Generate("user123", []string{"read", "write"})
    if err != nil {
        t.Fatalf("Failed to generate token: %v", err)
    }
    
    // Validate token
    validated, err := m.Validate(token)
    if err != nil {
        t.Fatalf("Failed to validate token: %v", err)
    }
    
    if validated.UserID != "user123" {
        t.Errorf("Expected user123, got %s", validated.UserID)
    }
    
    // Check scope
    if !validated.HasScope("read") {
        t.Error("Token should have read scope")
    }
    
    // Revoke token
    err = m.Revoke(token)
    if err != nil {
        t.Fatalf("Failed to revoke token: %v", err)
    }
    
    // Try validate revoked token
    _, err = m.Validate(token)
    if err == nil {
        t.Error("Expected error for revoked token")
    }
}

func TestHasScope(t *testing.T) {
    token := &Token{
        Scopes: []string{"read", "write"},
    }
    
    if !token.HasScope("read") {
        t.Error("Should have read scope")
    }
    
    if token.HasScope("delete") {
        t.Error("Should not have delete scope")
    }
}
