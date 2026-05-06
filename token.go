package authtoken

import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "sync"
    "time"
)

// Manager handles API token operations
type Manager struct {
    mu          sync.RWMutex
    tokens      map[string]*Token
    secretKey   []byte
}

// Token represents an authentication token
type Token struct {
    Value     string
    UserID    string
    CreatedAt time.Time
    ExpiresAt time.Time
    Scopes    []string
}

// Config holds package configuration
type Config struct {
    SecretKey     string
    TokenDuration time.Duration
}

// NewManager creates a new token manager
func NewManager(config Config) (*Manager, error) {
    if config.SecretKey == "" {
        return nil, errors.New("secret key is required")
    }
    
    if config.TokenDuration == 0 {
        config.TokenDuration = 24 * time.Hour
    }
    
    return &Manager{
        tokens:    make(map[string]*Token),
        secretKey: []byte(config.SecretKey),
    }, nil
}

// Generate creates a new token for a user
func (m *Manager) Generate(userID string, scopes []string) (string, error) {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // Create secure random token
    tokenValue, err := generateSecureToken()
    if err != nil {
        return "", err
    }
    
    token := &Token{
        Value:     tokenValue,
        UserID:    userID,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(24 * time.Hour),
        Scopes:    scopes,
    }
    
    // Sign the token
    signed, err := m.signToken(token)
    if err != nil {
        return "", err
    }
    
    m.tokens[tokenValue] = token
    return signed, nil
}

// Validate checks if a token is valid
func (m *Manager) Validate(tokenString string) (*Token, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    // Verify signature
    tokenValue, err := m.verifySignature(tokenString)
    if err != nil {
        return nil, errors.New("invalid token signature")
    }
    
    token, exists := m.tokens[tokenValue]
    if !exists {
        return nil, errors.New("token not found")
    }
    
    // Check expiration
    if time.Now().After(token.ExpiresAt) {
        return nil, errors.New("token expired")
    }
    
    return token, nil
}

// Revoke invalidates a token
func (m *Manager) Revoke(tokenString string) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    tokenValue, err := m.verifySignature(tokenString)
    if err != nil {
        return err
    }
    
    delete(m.tokens, tokenValue)
    return nil
}

// HasScope checks if token has a specific scope
func (t *Token) HasScope(scope string) bool {
    for _, s := range t.Scopes {
        if s == scope {
            return true
        }
    }
    return false
}

// Helper functions
func generateSecureToken() (string, error) {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}

func (m *Manager) signToken(token *Token) (string, error) {
    h := hmac.New(sha256.New, m.secretKey)
    h.Write([]byte(token.Value))
    h.Write([]byte(token.UserID))
    signature := hex.EncodeToString(h.Sum(nil))
    
    return token.Value + "." + signature, nil
}

func (m *Manager) verifySignature(signedToken string) (string, error) {
    // Split token and signature
    for i := len(signedToken) - 1; i >= 0; i-- {
        if signedToken[i] == '.' {
            tokenValue := signedToken[:i]
            providedSig := signedToken[i+1:]
            
            // Recreate signature
            h := hmac.New(sha256.New, m.secretKey)
            h.Write([]byte(tokenValue))
            expectedSig := hex.EncodeToString(h.Sum(nil))
            
            if hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
                return tokenValue, nil
            }
            return "", errors.New("signature mismatch")
        }
    }
    return "", errors.New("invalid token format")
}
