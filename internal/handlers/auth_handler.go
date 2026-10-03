package handlers

import (
	"errors"
	"net/http"
	"time"

	"hms_login/internal/models"
	"hms_login/internal/repository"
	"hms_login/internal/service"
	"hms_login/internal/utils"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles incoming HTTP requests for authentication.
type AuthHandler struct {
	authService *service.AuthService
}

// NewAuthHandler initializes a new instance of AuthHandler.
func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Register handles POST /api/v1/auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest

	// Fail-Fast Validation: Gin automatically validates struct tags (e.g. required, email, min=8).
	// If input is malformed, ShouldBindJSON fails instantly without hitting MongoDB!
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Invalid request payload", "VALIDATION_ERROR", err.Error())
		return
	}

	userResp, err := h.authService.Register(c.Request.Context(), &req)
	if err != nil {
		if errors.Is(err, repository.ErrUserAlreadyExists) {
			utils.SendError(c, http.StatusConflict, err.Error(), "USER_ALREADY_EXISTS", "A user with this email is already registered.")
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "Failed to register user", "INTERNAL_SERVER_ERROR", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusCreated, "User registered successfully", userResp)
}

// Login handles POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Invalid request payload", "VALIDATION_ERROR", err.Error())
		return
	}

	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	tokenResp, err := h.authService.Login(c.Request.Context(), &req, ipAddress, userAgent)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			utils.SendError(c, http.StatusUnauthorized, "Invalid email or password", "INVALID_CREDENTIALS", "The email or password provided does not match our records.")
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "Login failed", "INTERNAL_SERVER_ERROR", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "Login successful", tokenResp)
}

// RefreshToken handles POST /api/v1/auth/refresh (Session persistence & token rotation)
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Invalid request payload", "VALIDATION_ERROR", err.Error())
		return
	}

	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	tokenResp, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken, ipAddress, userAgent)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) || errors.Is(err, service.ErrTokenRevoked) {
			utils.SendError(c, http.StatusUnauthorized, "Invalid or expired refresh token", "INVALID_REFRESH_TOKEN", err.Error())
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "Failed to refresh token", "INTERNAL_SERVER_ERROR", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "Tokens refreshed successfully", tokenResp)
}

// ForgotPassword handles POST /api/v1/auth/forgot-password
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Invalid request payload", "VALIDATION_ERROR", err.Error())
		return
	}

	resetToken, err := h.authService.ForgotPassword(c.Request.Context(), &req)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "Failed to process forgot password request", "INTERNAL_SERVER_ERROR", err.Error())
		return
	}

	// For local testing & demonstration, we return the reset token in JSON payload.
	// In production, you would send this token via email/SMS only.
	responseData := gin.H{
		"reset_token": resetToken,
		"expires_in":  "15 minutes",
		"note":        "In production, this token is sent via email. Provided here for local API testing.",
	}

	utils.SendSuccess(c, http.StatusOK, "Password reset token generated successfully", responseData)
}

// ResetPassword handles POST /api/v1/auth/reset-password
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Invalid request payload", "VALIDATION_ERROR", err.Error())
		return
	}

	if err := h.authService.ResetPassword(c.Request.Context(), &req); err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			utils.SendError(c, http.StatusBadRequest, "Invalid or expired reset token", "INVALID_RESET_TOKEN", err.Error())
			return
		}
		utils.SendError(c, http.StatusBadRequest, err.Error(), "RESET_PASSWORD_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "Password reset successfully. Please log in with your new password.", nil)
}

// ChangePassword handles POST /api/v1/auth/change-password (Protected)
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req models.ChangePasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Invalid request payload", "VALIDATION_ERROR", err.Error())
		return
	}

	userIDVal, exists := c.Get("user_id")
	if !exists {
		utils.SendError(c, http.StatusUnauthorized, "Unauthorized access", "UNAUTHORIZED", "User identity missing from context")
		return
	}

	userIDStr := userIDVal.(string)

	if err := h.authService.ChangePassword(c.Request.Context(), userIDStr, &req); err != nil {
		if errors.Is(err, service.ErrSamePassword) {
			utils.SendError(c, http.StatusBadRequest, err.Error(), "INVALID_NEW_PASSWORD", err.Error())
			return
		}
		utils.SendError(c, http.StatusBadRequest, "Failed to change password", "CHANGE_PASSWORD_FAILED", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "Password changed successfully. All active sessions have been revoked.", nil)
}

// GetMe handles GET /api/v1/auth/me (Protected)
func (h *AuthHandler) GetMe(c *gin.Context) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		utils.SendError(c, http.StatusUnauthorized, "Unauthorized access", "UNAUTHORIZED", "User identity missing from context")
		return
	}

	userIDStr := userIDVal.(string)

	userResp, err := h.authService.GetProfile(c.Request.Context(), userIDStr)
	if err != nil {
		utils.SendError(c, http.StatusNotFound, "User profile not found", "USER_NOT_FOUND", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "User profile retrieved successfully", userResp)
}

// Logout handles POST /api/v1/auth/logout (Protected)
func (h *AuthHandler) Logout(c *gin.Context) {
	var req models.RefreshTokenRequest
	_ = c.ShouldBindJSON(&req)

	tokenID, _ := c.Get("token_id")
	tokenIDStr, _ := tokenID.(string)

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	tokenExp, _ := c.Get("token_expires_at")
	tokenExpTime, _ := tokenExp.(time.Time)

	_ = h.authService.Logout(c.Request.Context(), tokenIDStr, userIDStr, tokenExpTime, req.RefreshToken)

	utils.SendSuccess(c, http.StatusOK, "Logout successful. Access token and session revoked.", nil)
}
