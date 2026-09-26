package utils

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword converts a plain text password into a secure bcrypt hash string.
// Bcrypt uses a salt internally to prevent rainbow table attacks.
// Cost factor 12 is the current industry recommendation balancing CPU time and brute-force protection.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(bytes), nil
}

// CheckPasswordHash compares a plain text password against a stored bcrypt hash string.
// Returns true if the password matches, false otherwise.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
