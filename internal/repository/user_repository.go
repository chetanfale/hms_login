package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"hms_login/internal/db"
	"hms_login/internal/models"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Common errors returned by repository layer
var (
	ErrUserAlreadyExists = errors.New("a user with this email address already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrTokenNotFound     = errors.New("token not found or invalid")
)

// UserRepository handles all database queries for users, refresh tokens, and password reset tokens.
type UserRepository struct {
	db *db.MongoDB
}

// NewUserRepository returns a new instance of UserRepository.
func NewUserRepository(database *db.MongoDB) *UserRepository {
	return &UserRepository{
		db: database,
	}
}

// --- USER COLLECTION OPERATIONS ---

// CreateUser inserts a new user document into the 'users' collection.
func (r *UserRepository) CreateUser(ctx context.Context, user *models.User) error {
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	user.IsActive = true
	if user.Role == "" {
		user.Role = "user"
	}

	coll := r.db.Database.Collection("users")
	res, err := coll.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to insert user into mongodb: %w", err)
	}

	// Assign the generated MongoDB _id back to the struct
	if oid, ok := res.InsertedID.(bson.ObjectID); ok {
		user.ID = oid
	}

	return nil
}

// GetUserByEmail searches for a user by email address.
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	coll := r.db.Database.Collection("users")

	var user models.User
	err := coll.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to fetch user by email: %w", err)
	}

	return &user, nil
}

// GetUserByID searches for a user by MongoDB ObjectID.
func (r *UserRepository) GetUserByID(ctx context.Context, id bson.ObjectID) (*models.User, error) {
	coll := r.db.Database.Collection("users")

	var user models.User
	err := coll.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to fetch user by id: %w", err)
	}

	return &user, nil
}

// UpdatePassword updates the user's password hash in MongoDB.
func (r *UserRepository) UpdatePassword(ctx context.Context, userID bson.ObjectID, newPasswordHash string) error {
	coll := r.db.Database.Collection("users")

	filter := bson.M{"_id": userID}
	update := bson.M{
		"$set": bson.M{
			"password_hash": newPasswordHash,
			"updated_at":    time.Now(),
		},
	}

	res, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update user password: %w", err)
	}

	if res.MatchedCount == 0 {
		return ErrUserNotFound
	}

	return nil
}

// --- REFRESH TOKEN OPERATIONS ---

// SaveRefreshToken stores a new refresh token record in the 'refresh_tokens' collection.
func (r *UserRepository) SaveRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	token.CreatedAt = time.Now()
	token.Revoked = false

	coll := r.db.Database.Collection("refresh_tokens")
	res, err := coll.InsertOne(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to save refresh token: %w", err)
	}

	if oid, ok := res.InsertedID.(bson.ObjectID); ok {
		token.ID = oid
	}

	return nil
}

// FindRefreshTokenByHash fetches a refresh token document by its SHA-256 hash.
func (r *UserRepository) FindRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	coll := r.db.Database.Collection("refresh_tokens")

	var token models.RefreshToken
	err := coll.FindOne(ctx, bson.M{"token_hash": tokenHash}).Decode(&token)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to find refresh token: %w", err)
	}

	return &token, nil
}

// RevokeRefreshToken marks a specific refresh token as revoked.
func (r *UserRepository) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	coll := r.db.Database.Collection("refresh_tokens")

	filter := bson.M{"token_hash": tokenHash}
	update := bson.M{"$set": bson.M{"revoked": true}}

	_, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

// RevokeAllUserTokens invalidates all active sessions for a user (e.g. after password change).
func (r *UserRepository) RevokeAllUserTokens(ctx context.Context, userID bson.ObjectID) error {
	coll := r.db.Database.Collection("refresh_tokens")

	filter := bson.M{"user_id": userID, "revoked": false}
	update := bson.M{"$set": bson.M{"revoked": true}}

	_, err := coll.UpdateMany(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to revoke user tokens: %w", err)
	}

	return nil
}

// --- PASSWORD RESET TOKEN OPERATIONS ---

// SavePasswordResetToken stores a one-time password reset token in MongoDB.
func (r *UserRepository) SavePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	token.CreatedAt = time.Now()
	token.Used = false

	coll := r.db.Database.Collection("password_resets")
	res, err := coll.InsertOne(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to save password reset token: %w", err)
	}

	if oid, ok := res.InsertedID.(bson.ObjectID); ok {
		token.ID = oid
	}

	return nil
}

// FindPasswordResetTokenByHash retrieves a reset token by SHA-256 hash.
func (r *UserRepository) FindPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	coll := r.db.Database.Collection("password_resets")

	var token models.PasswordResetToken
	err := coll.FindOne(ctx, bson.M{"token_hash": tokenHash}).Decode(&token)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to find password reset token: %w", err)
	}

	return &token, nil
}

// MarkPasswordResetTokenUsed flags a reset token as used so it cannot be replayed.
func (r *UserRepository) MarkPasswordResetTokenUsed(ctx context.Context, tokenHash string) error {
	coll := r.db.Database.Collection("password_resets")

	filter := bson.M{"token_hash": tokenHash}
	update := bson.M{"$set": bson.M{"used": true}}

	_, err := coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to mark reset token as used: %w", err)
	}

	return nil
}

// --- BLACKLISTED ACCESS TOKEN OPERATIONS ---

// BlacklistAccessToken stores a revoked JWT Access Token ID (JTI) in MongoDB.
func (r *UserRepository) BlacklistAccessToken(ctx context.Context, tokenID string, userID bson.ObjectID, expiresAt time.Time) error {
	if tokenID == "" {
		return nil
	}

	doc := models.BlacklistedToken{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	coll := r.db.Database.Collection("blacklisted_tokens")
	_, err := coll.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("failed to blacklist access token: %w", err)
	}

	return nil
}

// IsAccessTokenBlacklisted checks if a JWT Access Token ID (JTI) has been revoked.
func (r *UserRepository) IsAccessTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	if tokenID == "" {
		return false, nil
	}

	coll := r.db.Database.Collection("blacklisted_tokens")
	count, err := coll.CountDocuments(ctx, bson.M{"token_id": tokenID})
	if err != nil {
		return false, fmt.Errorf("failed to check blacklisted access token: %w", err)
	}

	return count > 0, nil
}

