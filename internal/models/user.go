package models

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// User represents a user document stored in MongoDB.
// In Go, struct tags (like `bson:"..."` or `json:"..."`) tell drivers and parsers how to map fields.
// `bson:"_id,omitempty"` maps to Mongo's primary key `_id`.
// `json:"-"` ensures sensitive fields like PasswordHash are NEVER returned in JSON API responses.
type User struct {
	ID           bson.ObjectID `bson:"_id,omitempty" json:"id"`
	Email        string        `bson:"email" json:"email"`
	PasswordHash string        `bson:"password_hash" json:"-"` // Hidden from JSON output for security
	FirstName    string        `bson:"first_name" json:"first_name"`
	LastName     string        `bson:"last_name" json:"last_name"`
	Role         string        `bson:"role" json:"role"` // e.g. "user", "admin"
	IsActive     bool          `bson:"is_active" json:"is_active"`
	CreatedAt    time.Time     `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time     `bson:"updated_at" json:"updated_at"`
}

// RefreshToken represents a active or revoked refresh token session in MongoDB.
type RefreshToken struct {
	ID        bson.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    bson.ObjectID `bson:"user_id" json:"user_id"`
	TokenHash string        `bson:"token_hash" json:"-"` // Hashed refresh token
	ExpiresAt time.Time     `bson:"expires_at" json:"expires_at"`
	Revoked   bool          `bson:"revoked" json:"revoked"`
	IPAddress string        `bson:"ip_address" json:"ip_address"`
	UserAgent string        `bson:"user_agent" json:"user_agent"`
	CreatedAt time.Time     `bson:"created_at" json:"created_at"`
}

// PasswordResetToken represents a single-use token generated when a user requests a password reset.
type PasswordResetToken struct {
	ID        bson.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    bson.ObjectID `bson:"user_id" json:"user_id"`
	TokenHash string        `bson:"token_hash" json:"-"` // Hashed reset token
	ExpiresAt time.Time     `bson:"expires_at" json:"expires_at"`
	Used      bool          `bson:"used" json:"used"`
	CreatedAt time.Time     `bson:"created_at" json:"created_at"`
}

// --- DTOs (Data Transfer Objects) for Input Request Validation ---
// The `binding:"..."` tags enforce Fail-Fast validation at the HTTP layer via Gin.
// If input fails validation, Gin instantly returns HTTP 400 without touching MongoDB.

type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8,max=64"`
	FirstName string `json:"first_name" binding:"required,min=1,max=50"`
	LastName  string `json:"last_name" binding:"required,min=1,max=50"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=64"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=64"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required,min=8,max=64"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=64"`
}

// --- Output Response DTOs ---

type UserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"` // "Bearer"
	ExpiresIn    int64  `json:"expires_in"` // Access token expiration in seconds
}

// Standard API JSON Envelope
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Details string `json:"details"`
}
