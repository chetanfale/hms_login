package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"hms_login/internal/config"
	"hms_login/internal/db"
	"hms_login/internal/handlers"
	"hms_login/internal/middleware"
	"hms_login/internal/repository"
	"hms_login/internal/service"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

func main() {
	log.Println("[INFO] Starting Authentication Service...")

	// 1. Load Application Configuration from .env or environment
	cfg := config.LoadConfig()

	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// 2. Initialize MongoDB Connection
	mongoDB, err := db.ConnectMongoDB(cfg)
	if err != nil {
		log.Fatalf("[FATAL] Database connection failed: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mongoDB.Close(ctx); err != nil {
			log.Printf("[ERROR] Error closing MongoDB connection: %v\n", err)
		}
	}()

	// 3. Initialize Architecture Layers (Repository -> Service -> Handler)
	userRepo := repository.NewUserRepository(mongoDB)
	authService := service.NewAuthService(userRepo, cfg)
	authHandler := handlers.NewAuthHandler(authService)

	// 4. Initialize Gin Router & Middlewares
	router := gin.Default()

	// Attach Security Headers Middleware (HSTS, X-Frame-Options, XSS Protection)
	router.Use(middleware.SecurityHeadersMiddleware())

	// Configure Rate Limiters
	var strictLimiter *middleware.IPRateLimiter
	var generalLimiter *middleware.IPRateLimiter

	if cfg.Env == "development" {
		// Development mode: relaxed limits for smooth API / Postman testing
		strictLimiter = middleware.NewIPRateLimiter(rate.Every(time.Second/5), 30)
		generalLimiter = middleware.NewIPRateLimiter(rate.Every(time.Second/10), 60)
	} else {
		// Production mode: Strict 5 req/min burst 5 for sensitive routes, 60 req/min for general
		strictLimiter = middleware.NewIPRateLimiter(rate.Every(time.Minute/5), 5)
		generalLimiter = middleware.NewIPRateLimiter(rate.Every(time.Minute/60), 10)
	}

	// Serve OpenAPI Spec and Static Documentation
	router.StaticFile("/docs/openapi.json", "./docs/openapi.json")

	// Public Auth API Routes (Unprotected)
	apiGroup := router.Group("/api/v1/auth")
	{
		apiGroup.POST("/register", middleware.RateLimitMiddleware(strictLimiter), authHandler.Register)
		apiGroup.POST("/login", middleware.RateLimitMiddleware(strictLimiter), authHandler.Login)
		apiGroup.POST("/refresh", middleware.RateLimitMiddleware(generalLimiter), authHandler.RefreshToken)
		apiGroup.POST("/forgot-password", middleware.RateLimitMiddleware(strictLimiter), authHandler.ForgotPassword)
		apiGroup.POST("/reset-password", middleware.RateLimitMiddleware(strictLimiter), authHandler.ResetPassword)
	}

	// Protected Auth API Routes (Requires valid JWT Access Token)
	protectedGroup := router.Group("/api/v1/auth")
	protectedGroup.Use(middleware.AuthMiddleware(cfg, userRepo))
	{
		protectedGroup.GET("/me", authHandler.GetMe)
		protectedGroup.POST("/change-password", middleware.RateLimitMiddleware(strictLimiter), authHandler.ChangePassword)
		protectedGroup.POST("/logout", authHandler.Logout)
	}

	// 5. Setup HTTP / HTTPS Server with Graceful Shutdown
	serverAddr := fmt.Sprintf(":%s", cfg.Port)
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to listen for OS interrupt signals (Ctrl+C or SIGTERM)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if cfg.EnableHTTPS {
			log.Printf("[INFO] HTTPS Enabled. Verifying TLS Certificates at %s and %s\n", cfg.SSLCertPath, cfg.SSLKeyPath)
			if err := ensureTLSCertificates(cfg.SSLCertPath, cfg.SSLKeyPath); err != nil {
				log.Fatalf("[FATAL] TLS Certificate check failed: %v", err)
			}
			log.Printf("[INFO] Server listening on https://localhost%s\n", serverAddr)
			if err := srv.ListenAndServeTLS(cfg.SSLCertPath, cfg.SSLKeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("[FATAL] HTTPS Server failed to start: %v", err)
			}
		} else {
			log.Printf("[INFO] Server listening on http://localhost%s (HTTPS disabled in .env)\n", serverAddr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("[FATAL] HTTP Server failed to start: %v", err)
			}
		}
	}()

	// Block main routine until interrupt signal is received
	<-quit
	log.Println("[INFO] Shutting down server gracefully...")

	// Create shutdown context with 5-second timeout for pending requests
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("[FATAL] Server forced to shutdown: %v", err)
	}

	log.Println("[INFO] Server exited cleanly.")
}

// ensureTLSCertificates creates self-signed TLS certificates for local HTTPS testing if they do not already exist.
func ensureTLSCertificates(certPath, keyPath string) error {
	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}

	log.Println("[INFO] TLS certificate/key not found. Generating self-signed SSL certificates for development...")

	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"HMS Local Auth Dev"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %w", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	log.Println("[INFO] Generated self-signed SSL certificates successfully.")
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
