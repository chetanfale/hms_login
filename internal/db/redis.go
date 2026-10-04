package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"

	"hms_login/internal/config"
	"hms_login/internal/models"
)

// RedisClient wraps redis.Client for auth token blacklisting and pubsub events
type RedisClient struct {
	rdb *redis.Client
}

// ConnectRedis initializes connection pool to Redis
func ConnectRedis(cfg *config.Config) (*RedisClient, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis at %s: %w", cfg.RedisAddr, err)
	}

	log.Printf("[INFO] Successfully connected to Redis at %s\n", cfg.RedisAddr)
	return &RedisClient{rdb: rdb}, nil
}

// Close disconnects the Redis client
func (r *RedisClient) Close() error {
	if r != nil && r.rdb != nil {
		return r.rdb.Close()
	}
	return nil
}

// BlacklistToken stores a revoked JWT ID (JTI) in Redis with a TTL
func (r *RedisClient) BlacklistToken(ctx context.Context, tokenID string, ttl time.Duration) error {
	if r == nil || r.rdb == nil || tokenID == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	key := fmt.Sprintf("blacklist:token:%s", tokenID)
	return r.rdb.Set(ctx, key, "revoked", ttl).Err()
}

// BlacklistUser records the revocation timestamp for a user so older tokens are invalidated
func (r *RedisClient) BlacklistUser(ctx context.Context, userID string, ttl time.Duration) error {
	if r == nil || r.rdb == nil || userID == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	key := fmt.Sprintf("blacklist:user:%s", userID)
	return r.rdb.Set(ctx, key, time.Now().Unix(), ttl).Err()
}

// PublishRevocation broadcasts a token revocation event over Redis Pub/Sub
func (r *RedisClient) PublishRevocation(ctx context.Context, event *models.RevocationEvent) error {
	if r == nil || r.rdb == nil || event == nil {
		return nil
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal revocation event: %w", err)
	}
	return r.rdb.Publish(ctx, "auth:revocations", data).Err()
}

// IsTokenBlacklisted checks if an access token JTI is blacklisted in Redis
func (r *RedisClient) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	if r == nil || r.rdb == nil || tokenID == "" {
		return false, nil
	}
	key := fmt.Sprintf("blacklist:token:%s", tokenID)
	val, err := r.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return val > 0, nil
}
