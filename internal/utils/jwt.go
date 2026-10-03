package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTCustomClaims defines the payload structure stored inside the JWT Access Token.
type JWTCustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateAccessToken builds and signs a short-lived JWT Access Token using HMAC-SHA256.
func GenerateAccessToken(userID, email, role, secret string, expiryMinutes int) (string, int64, error) {
	expirationTime := time.Now().Add(time.Duration(expiryMinutes) * time.Minute)
	expiresInSeconds := int64(expiryMinutes * 60)

	// Generate a unique JWT ID (JTI) for instant token revocation/blacklisting
	rawJTI, _, err := GenerateCryptoToken()
	if err != nil {
		return "", 0, fmt.Errorf("failed to generate JTI for access token: %w", err)
	}

	claims := &JWTCustomClaims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        rawJTI,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenString, expiresInSeconds, nil
}

// ValidateAccessToken parses and validates a JWT token string against the secret key.
func ValidateAccessToken(tokenString, secret string) (*JWTCustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure signing method is HMAC (HS256)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid or expired token: %w", err)
	}

	claims, ok := token.Claims.(*JWTCustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// GenerateCryptoToken generates a cryptographically secure 32-byte random token string.
// Returns: (rawToken, tokenHash, error)
// The rawToken is sent to the client. The SHA-256 tokenHash is stored in MongoDB for security.
func GenerateCryptoToken() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	rawToken := hex.EncodeToString(bytes)
	tokenHash := HashSHA256(rawToken)

	return rawToken, tokenHash, nil
}

// HashSHA256 calculates a SHA-256 hash string for a given text input.
func HashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}
