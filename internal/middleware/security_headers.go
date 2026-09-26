package middleware

import "github.com/gin-gonic/gin"

// SecurityHeadersMiddleware sets modern HTTP security headers on all responses.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent clickjacking attacks
		c.Header("X-Frame-Options", "DENY")
		// Prevent MIME-sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		// Enable browser XSS filtering
		c.Header("X-XSS-Protection", "1; mode=block")
		// Enforce HTTPS HSTS header for 1 year
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		c.Next()
	}
}
