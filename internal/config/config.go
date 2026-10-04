package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds all application configuration settings loaded from environment variables or .env file.
// In Go, a 'struct' is a collection of fields. We use it to group our config data together cleanly.
type Config struct {
	Port                    string
	Env                     string
	MongoURI                string
	MongoDBName             string
	RedisAddr               string
	RedisPassword           string
	JWTAccessSecret         string
	JWTRefreshSecret        string
	JWTAccessExpiryMinutes  int
	JWTRefreshExpiryDays    int
	ResetTokenExpiryMinutes int
	EnableHTTPS             bool
	SSLCertPath             string
	SSLKeyPath              string
}

// LoadConfig reads the .env file (if present) and parses environment variables into a Config struct.
// Returns a pointer (*Config) to avoid copying the struct in memory.
func LoadConfig() *Config {
	// Attempt to load .env file. In production, environment variables are usually injected directly by Docker/Kubernetes.
	if err := godotenv.Load(); err != nil {
		log.Println("[INFO] No .env file found or error loading it. Falling back to system environment variables.")
	}

	cfg := &Config{
		Port:                    getEnv("PORT", "8080"),
		Env:                     getEnv("ENV", "development"),
		MongoURI:                getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDBName:             getEnv("MONGO_DB_NAME", "hms_auth_db"),
		RedisAddr:               getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:           getEnv("REDIS_PASSWORD", ""),
		JWTAccessSecret:         getEnv("JWT_ACCESS_SECRET", "default_access_secret_change_me_in_prod"),
		JWTRefreshSecret:        getEnv("JWT_REFRESH_SECRET", "default_refresh_secret_change_me_in_prod"),
		JWTAccessExpiryMinutes:  getEnvAsInt("JWT_ACCESS_EXPIRY_MINUTES", 15),
		JWTRefreshExpiryDays:    getEnvAsInt("JWT_REFRESH_EXPIRY_DAYS", 7),
		ResetTokenExpiryMinutes: getEnvAsInt("RESET_TOKEN_EXPIRY_MINUTES", 15),
		EnableHTTPS:             getEnvAsBool("ENABLE_HTTPS", false),
		SSLCertPath:             getEnv("SSL_CERT_PATH", "certs/server.crt"),
		SSLKeyPath:              getEnv("SSL_KEY_PATH", "certs/server.key"),
	}

	return cfg
}

// getEnv is a helper function to read an environment variable or return a fallback default string.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	return fallback
}

// getEnvAsInt reads an environment variable and converts it from string to int.
func getEnvAsInt(key string, fallback int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return fallback
	}
	val, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Printf("[WARN] Invalid integer for env key %s: %v. Using default: %d\n", key, err, fallback)
		return fallback
	}
	return val
}

// getEnvAsBool reads an environment variable and converts it to a boolean value.
func getEnvAsBool(key string, fallback bool) bool {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return fallback
	}
	val, err := strconv.ParseBool(valueStr)
	if err != nil {
		log.Printf("[WARN] Invalid boolean for env key %s: %v. Using default: %t\n", key, err, fallback)
		return fallback
	}
	return val
}
