package middleware

import (
	"net/http"
	"strings"

	"hms_login/internal/config"
	"hms_login/internal/utils"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware inspects the Authorization header for a valid Bearer JWT access token.
func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.SendError(c, http.StatusUnauthorized, "Authorization header is missing", "UNAUTHORIZED", "Please provide a valid Authorization: Bearer <token> header.")
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			utils.SendError(c, http.StatusUnauthorized, "Invalid authorization format", "UNAUTHORIZED", "Authorization header format must be 'Bearer <token>'.")
			c.Abort()
			return
		}

		tokenString := parts[1]
		claims, err := utils.ValidateAccessToken(tokenString, cfg.JWTAccessSecret)
		if err != nil {
			utils.SendError(c, http.StatusUnauthorized, "Invalid or expired token", "UNAUTHORIZED", err.Error())
			c.Abort()
			return
		}

		// Store user identity details in Gin context for downstream handlers to access
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("role", claims.Role)

		c.Next()
	}
}
