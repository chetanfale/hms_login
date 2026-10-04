package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"hms_login/internal/config"
	"hms_login/internal/db"
	"hms_login/internal/models"
	"hms_login/internal/repository"
	"hms_login/internal/utils"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Common domain errors returned by the Service layer
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrTokenRevoked       = errors.New("token has been revoked")
	ErrSamePassword       = errors.New("new password cannot be identical to the old password")
)

// AuthService contains all business logic for user registration, authentication, session management, and password recovery.
type AuthService struct {
	repo  *repository.UserRepository
	redis *db.RedisClient
	cfg   *config.Config
}

// NewAuthService creates a new instance of AuthService.
func NewAuthService(repo *repository.UserRepository, redisClient *db.RedisClient, cfg *config.Config) *AuthService {
	return &AuthService{
		repo:  repo,
		redis: redisClient,
		cfg:   cfg,
	}
}

// Register handles user registration, password hashing, and database storage.
func (s *AuthService) Register(ctx context.Context, req *models.RegisterRequest) (*models.UserResponse, error) {
	// 1. Check if user already exists with this email
	existingUser, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, repository.ErrUserAlreadyExists
	}

	// 2. Hash the plain text password using Bcrypt (cost factor 12)
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// 3. Construct User entity
	user := &models.User{
		Email:        req.Email,
		PasswordHash: hashedPassword,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         "user",
		IsActive:     true,
	}

	// 4. Save User to MongoDB
	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return s.toUserResponse(user), nil
}

// Login authenticates user credentials and returns Access & Refresh tokens.
func (s *AuthService) Login(ctx context.Context, req *models.LoginRequest, ipAddress, userAgent string) (*models.TokenResponse, error) {
	// 1. Fetch user by email
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// 2. Verify password match
	if !utils.CheckPasswordHash(req.Password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, errors.New("user account is deactivated")
	}

	// 3. Generate tokens
	return s.generateTokenPair(ctx, user, ipAddress, userAgent)
}

// RefreshToken exchanges an existing valid Refresh Token for a fresh Access Token AND fresh Refresh Token (Rotation).
func (s *AuthService) RefreshToken(ctx context.Context, rawRefreshToken, oldAccessToken, ipAddress, userAgent string) (*models.TokenResponse, error) {
	// 1. Compute SHA-256 hash of raw token to query MongoDB
	tokenHash := utils.HashSHA256(rawRefreshToken)

	tokenDoc, err := s.repo.FindRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	// 2. Security Check: Detect Revocation or Expiration
	if tokenDoc.Revoked {
		log.Printf("[SECURITY WARN] Attempted reuse of revoked refresh token for UserID: %s. Revoking all user sessions.\n", tokenDoc.UserID.Hex())
		_ = s.repo.RevokeAllUserTokens(ctx, tokenDoc.UserID)
		if s.redis != nil {
			_ = s.redis.BlacklistUser(ctx, tokenDoc.UserID.Hex(), 24*time.Hour)
			_ = s.redis.PublishRevocation(ctx, &models.RevocationEvent{
				UserID: tokenDoc.UserID.Hex(),
				All:    true,
				Action: "token_reuse",
			})
		}
		return nil, ErrTokenRevoked
	}

	if time.Now().After(tokenDoc.ExpiresAt) {
		return nil, ErrInvalidToken
	}

	// 3. Revoke the old refresh token (Rotation)
	if err := s.repo.RevokeRefreshToken(ctx, tokenHash); err != nil {
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	// 4. Invalidate old access token if provided in header
	if oldAccessToken != "" {
		claims, err := utils.ValidateAccessToken(oldAccessToken, s.cfg.JWTAccessSecret)
		if err == nil && claims.ID != "" {
			var exp time.Time
			if claims.ExpiresAt != nil {
				exp = claims.ExpiresAt.Time
			} else {
				exp = time.Now().Add(time.Duration(s.cfg.JWTAccessExpiryMinutes) * time.Minute)
			}
			_ = s.repo.BlacklistAccessToken(ctx, claims.ID, tokenDoc.UserID, exp)
			if s.redis != nil {
				ttl := time.Until(exp)
				if ttl <= 0 {
					ttl = time.Duration(s.cfg.JWTAccessExpiryMinutes) * time.Minute
				}
				_ = s.redis.BlacklistToken(ctx, claims.ID, ttl)
			}
		}
	}

	// 5. Fetch User details
	user, err := s.repo.GetUserByID(ctx, tokenDoc.UserID)
	if err != nil {
		return nil, err
	}

	// 6. Generate new token pair
	return s.generateTokenPair(ctx, user, ipAddress, userAgent)
}

// ForgotPassword generates a 15-minute single-use password reset token.
func (s *AuthService) ForgotPassword(ctx context.Context, req *models.ForgotPasswordRequest) (string, error) {
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Security practice: Return success even if user not found to prevent Email Enumeration attacks
		if errors.Is(err, repository.ErrUserNotFound) {
			log.Printf("[INFO] Forgot password requested for non-existent email: %s\n", req.Email)
			return "If an account with this email exists, a password reset token has been issued.", nil
		}
		return "", err
	}

	// Generate random reset token & SHA-256 hash
	rawToken, tokenHash, err := utils.GenerateCryptoToken()
	if err != nil {
		return "", err
	}

	expiresAt := time.Now().Add(time.Duration(s.cfg.ResetTokenExpiryMinutes) * time.Minute)

	resetTokenDoc := &models.PasswordResetToken{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}

	if err := s.repo.SavePasswordResetToken(ctx, resetTokenDoc); err != nil {
		return "", err
	}

	log.Printf("[INFO] Password reset token generated for %s: %s (expires in %d mins)\n", user.Email, rawToken, s.cfg.ResetTokenExpiryMinutes)

	return rawToken, nil
}

// ResetPassword verifies the reset token and updates the user's password.
func (s *AuthService) ResetPassword(ctx context.Context, req *models.ResetPasswordRequest) error {
	tokenHash := utils.HashSHA256(req.Token)

	tokenDoc, err := s.repo.FindPasswordResetTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return ErrInvalidToken
		}
		return err
	}

	if tokenDoc.Used {
		return errors.New("this password reset token has already been used")
	}

	if time.Now().After(tokenDoc.ExpiresAt) {
		return errors.New("password reset token has expired")
	}

	// Hash new password
	newPasswordHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update user password in MongoDB
	if err := s.repo.UpdatePassword(ctx, tokenDoc.UserID, newPasswordHash); err != nil {
		return err
	}

	// Mark token as used
	_ = s.repo.MarkPasswordResetTokenUsed(ctx, tokenHash)

	// Revoke all existing sessions to force user to log in with new password
	_ = s.repo.RevokeAllUserTokens(ctx, tokenDoc.UserID)
	if s.redis != nil {
		_ = s.redis.BlacklistUser(ctx, tokenDoc.UserID.Hex(), 24*time.Hour)
		_ = s.redis.PublishRevocation(ctx, &models.RevocationEvent{
			UserID: tokenDoc.UserID.Hex(),
			All:    true,
			Action: "reset_password",
		})
	}

	return nil
}

// ChangePassword updates password for a currently logged-in user.
func (s *AuthService) ChangePassword(ctx context.Context, userIDStr string, req *models.ChangePasswordRequest) error {
	oid, err := bson.ObjectIDFromHex(userIDStr)
	if err != nil {
		return errors.New("invalid user ID")
	}

	user, err := s.repo.GetUserByID(ctx, oid)
	if err != nil {
		return err
	}

	// Verify old password
	if !utils.CheckPasswordHash(req.OldPassword, user.PasswordHash) {
		return errors.New("old password is incorrect")
	}

	if req.OldPassword == req.NewPassword {
		return ErrSamePassword
	}

	// Hash new password
	newPasswordHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return err
	}

	if err := s.repo.UpdatePassword(ctx, oid, newPasswordHash); err != nil {
		return err
	}

	// Revoke all existing sessions
	_ = s.repo.RevokeAllUserTokens(ctx, oid)
	if s.redis != nil {
		_ = s.redis.BlacklistUser(ctx, userIDStr, 24*time.Hour)
		_ = s.redis.PublishRevocation(ctx, &models.RevocationEvent{
			UserID: userIDStr,
			All:    true,
			Action: "change_password",
		})
	}

	return nil
}

// GetProfile retrieves public profile info for the logged-in user.
func (s *AuthService) GetProfile(ctx context.Context, userIDStr string) (*models.UserResponse, error) {
	oid, err := bson.ObjectIDFromHex(userIDStr)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	user, err := s.repo.GetUserByID(ctx, oid)
	if err != nil {
		return nil, err
	}

	return s.toUserResponse(user), nil
}

// Logout revokes the given refresh token session and blacklists the active Access Token JTI.
func (s *AuthService) Logout(ctx context.Context, tokenID string, userIDStr string, tokenExpiresAt time.Time, rawRefreshToken string) error {
	// 1. Blacklist the current JWT Access Token JTI if present
	if tokenID != "" && userIDStr != "" {
		oid, err := bson.ObjectIDFromHex(userIDStr)
		if err == nil {
			if tokenExpiresAt.IsZero() {
				tokenExpiresAt = time.Now().Add(time.Duration(s.cfg.JWTAccessExpiryMinutes) * time.Minute)
			}
			_ = s.repo.BlacklistAccessToken(ctx, tokenID, oid, tokenExpiresAt)
		}
		if s.redis != nil {
			ttl := time.Until(tokenExpiresAt)
			if ttl <= 0 {
				ttl = time.Duration(s.cfg.JWTAccessExpiryMinutes) * time.Minute
			}
			_ = s.redis.BlacklistToken(ctx, tokenID, ttl)
			_ = s.redis.PublishRevocation(ctx, &models.RevocationEvent{
				UserID:  userIDStr,
				TokenID: tokenID,
				Action:  "logout",
			})
		}
	}

	// 2. Revoke Refresh Token if provided
	if rawRefreshToken != "" {
		tokenHash := utils.HashSHA256(rawRefreshToken)
		_ = s.repo.RevokeRefreshToken(ctx, tokenHash)
	}

	return nil
}

// --- Helper Functions ---

func (s *AuthService) generateTokenPair(ctx context.Context, user *models.User, ipAddress, userAgent string) (*models.TokenResponse, error) {
	// 1. Create Access Token (JWT)
	accessToken, expiresIn, err := utils.GenerateAccessToken(
		user.ID.Hex(),
		user.Email,
		user.Role,
		s.cfg.JWTAccessSecret,
		s.cfg.JWTAccessExpiryMinutes,
	)
	if err != nil {
		return nil, err
	}

	// 2. Create Refresh Token (Random Crypto String)
	rawRefreshToken, refreshHash, err := utils.GenerateCryptoToken()
	if err != nil {
		return nil, err
	}

	refreshExpiry := time.Now().AddDate(0, 0, s.cfg.JWTRefreshExpiryDays)

	refreshTokenDoc := &models.RefreshToken{
		UserID:    user.ID,
		TokenHash: refreshHash,
		ExpiresAt: refreshExpiry,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.repo.SaveRefreshToken(ctx, refreshTokenDoc); err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	}, nil
}

func (s *AuthService) toUserResponse(u *models.User) *models.UserResponse {
	return &models.UserResponse{
		ID:        u.ID.Hex(),
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Role:      u.Role,
		IsActive:  u.IsActive,
		CreatedAt: u.CreatedAt,
	}
}
