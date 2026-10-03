package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"hms_login/internal/config"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Client holds references to the connected MongoDB client and target database.
type MongoDB struct {
	Client   *mongo.Client
	Database *mongo.Database
}

// ConnectMongoDB initializes a connection pool to MongoDB and sets up required unique indexes.
func ConnectMongoDB(cfg *config.Config) (*MongoDB, error) {
	// In Go, context controls call deadlines, timeouts, and cancellations.
	// We set a 10-second timeout for establishing the initial DB connection.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel() // 'defer' ensures cancel() is executed when ConnectMongoDB returns

	clientOpts := options.Client().ApplyURI(cfg.MongoURI)
	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create mongodb client: %w", err)
	}

	// Ping the database to verify the connection is live and active
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping mongodb at %s: %w", cfg.MongoURI, err)
	}

	database := client.Database(cfg.MongoDBName)
	log.Printf("[INFO] Successfully connected to MongoDB database '%s'\n", cfg.MongoDBName)

	mongoDB := &MongoDB{
		Client:   client,
		Database: database,
	}

	// Ensure database indexes exist (e.g., unique email constraint)
	if err := mongoDB.createIndexes(ctx); err != nil {
		log.Printf("[WARN] Failed to create database indexes: %v\n", err)
	}

	return mongoDB, nil
}

// createIndexes sets up MongoDB database indexes (Unique Email constraint & TTL indexes).
func (db *MongoDB) createIndexes(ctx context.Context) error {
	usersColl := db.Database.Collection("users")

	// 1. Unique index on Email in 'users' collection to guarantee no duplicate registration
	emailIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	_, err := usersColl.Indexes().CreateOne(ctx, emailIndex)
	if err != nil {
		return fmt.Errorf("failed to create unique index on users.email: %w", err)
	}
	log.Println("[INFO] Unique index on 'users.email' verified.")

	// 2. Index on user_id in 'refresh_tokens' collection for fast session lookup
	refreshColl := db.Database.Collection("refresh_tokens")
	refreshUserIndex := mongo.IndexModel{
		Keys: bson.D{{Key: "user_id", Value: 1}},
	}
	_, err = refreshColl.Indexes().CreateOne(ctx, refreshUserIndex)
	if err != nil {
		return fmt.Errorf("failed to create index on refresh_tokens.user_id: %w", err)
	}

	// 3. TTL Index on 'blacklisted_tokens.expires_at' so MongoDB automatically purges expired tokens
	blacklistColl := db.Database.Collection("blacklisted_tokens")
	blacklistIndex := mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(0), // Automatically delete when current time >= expires_at
	}
	_, err = blacklistColl.Indexes().CreateOne(ctx, blacklistIndex)
	if err != nil {
		return fmt.Errorf("failed to create TTL index on blacklisted_tokens.expires_at: %w", err)
	}

	return nil
}

// Close gracefully disconnects the MongoDB client connection pool.
func (db *MongoDB) Close(ctx context.Context) error {
	if db.Client != nil {
		log.Println("[INFO] Closing MongoDB connection pool...")
		return db.Client.Disconnect(ctx)
	}
	return nil
}
